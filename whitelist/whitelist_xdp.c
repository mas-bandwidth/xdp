/*
    UDP whitelist XDP program

    Reflects IPv4 UDP packets sent to port 40000 back to sender.

    USAGE:

        clang -Ilibbpf/src -g -O2 -target bpf -c whitelist_xdp.c -o whitelist_xdp.o
        sudo cat /sys/kernel/debug/tracing/trace_pipe
*/

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>

#include "shared.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x)        __builtin_bswap16(x)
#define bpf_htons(x)        __builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x)        (x)
#define bpf_htons(x)        (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

#define DEBUG 1

#if DEBUG
#define debug_printf bpf_printk
#else // #if DEBUG
#define debug_printf(...) do { } while (0)
#endif // #if DEBUG

struct {
    __uint( type, BPF_MAP_TYPE_HASH );
    __type( key, struct whitelist_key );
    __type( value, struct whitelist_value );
    __uint( max_entries, MAX_WHITELIST_ENTRIES * 2 );
    __uint( pinning, LIBBPF_PIN_BY_NAME );
} whitelist_map SEC(".maps");

SEC("whitelist_xdp") int whitelist_xdp_filter( struct xdp_md *ctx ) 
{ 
    void * data = (void*) (long) ctx->data; 

    void * data_end = (void*) (long) ctx->data_end; 
    struct ethhdr * eth = data;

    if ( (void*)eth + sizeof(struct ethhdr) < data_end )
    {
        if ( eth->h_proto == __constant_htons(ETH_P_IP) ) // IPV4
        {
            struct iphdr * ip = data + sizeof(struct ethhdr);

            if ( (void*)ip + sizeof(struct iphdr) < data_end )
            {
                if ( ip->protocol == IPPROTO_UDP ) // UDP
                {
                    struct udphdr * udp = (void*) ip + sizeof(struct iphdr);

                    if ( (void*)udp + sizeof(struct udphdr) <= data_end )
                    {
                        if ( udp->dest == __constant_htons(40000) )
                        {
                            struct whitelist_key key;
                            key.address = ip->saddr;
                            key.port = udp->source;

                            struct whitelist_value * value = (struct whitelist_value*) bpf_map_lookup_elem( &whitelist_map, &key );
                            if ( value == NULL )
                            {
                                debug_printf( "not in whitelist" );
                                return XDP_DROP;
                            }

                            debug_printf( "whitelist passed" );
                            
                            return XDP_PASS;
                        }
                    }
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
