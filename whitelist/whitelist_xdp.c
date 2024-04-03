/*
    UDP drop XDP program

    Reflects IPv4 UDP packets sent to port 40000 back to sender.

    USAGE:

        clang -Ilibbpf/src -g -O2 -target bpf -c drop_xdp.c -o drop_xdp.o
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

SEC("drop_xdp") int drop_xdp_filter( struct xdp_md *ctx ) 
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
                            // Drop packets that are too small to be valid

                            __u8 * packet_data = (void*) udp + sizeof(struct udphdr);

                            if ( (void*)packet_data + 16 > data_end )
                            {
                                debug_printf( "packet is too small" );
                                return XDP_DROP;
                            }

                            // Drop packets that are too large to be valid

                            int packet_bytes = data_end - (void*)udp - sizeof(struct udphdr);

                            if ( packet_bytes > 1400 )
                            {
                                debug_printf( "packet is too large" );
                                return XDP_DROP;
                            }

                            // Drop UDP packet if it is a fragment

                            if ( ( ip->frag_off & ~0x2000 ) != 0 )
                            {
                                debug_printf( "dropped udp fragment" );
                                return XDP_DROP;
                            }

                            // Basic packet filter

                            if ( packet_data[1] < 0x2A || packet_data[1] > 0x2D                                                           ||
                                 packet_data[2] < 0xC8 || packet_data[2] > 0xE7                                                           ||
                                 packet_data[3] < 0x05 || packet_data[3] > 0x44                                                           ||
                                 packet_data[5] < 0x4E || packet_data[5] > 0x51                                                           ||
                                 packet_data[6] < 0x60 || packet_data[6] > 0xDF                                                           ||
                                 packet_data[7] < 0x64 || packet_data[7] > 0xE3                                                           ||
                                 packet_data[8] != 0x07 && packet_data[8] != 0x4F                                                         ||
                                 packet_data[9] != 0x25 && packet_data[9] != 0x53                                                         ||
                                 packet_data[10] < 0x7C || packet_data[10] > 0x83                                                         ||
                                 packet_data[11] < 0xAF || packet_data[11] > 0xB6                                                         ||
                                 packet_data[12] < 0x21 || packet_data[12] > 0x60                                                         ||
                                 packet_data[13] != 0x61 && packet_data[13] != 0x05 && packet_data[13] != 0x2B && packet_data[13] != 0x0D ||
                                 packet_data[14] < 0xD2 || packet_data[14] > 0xF1                                                         ||
                                 packet_data[15] < 0x11 || packet_data[15] > 0x90 )
                            {
                                debug_printf( "basic packet filter dropped packet" );
                                return XDP_DROP;
                            }

                            debug_printf( "basic packet filter passed" );
                            
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
