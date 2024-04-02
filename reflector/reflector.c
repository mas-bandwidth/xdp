/*
    UDP reflector XDP program (Userspace)

    Runs on Ubuntu 22.04 LTS 64bit with Linux Kernel 6.5+ *ONLY*
*/

#include <memory.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

struct bpf_t
{
    int interface_index;
    struct xdp_program * program;
    bool attached_native;
    bool attached_skb;
};

int bpf_init( struct bpf_t * bpf, const char * interface_name )
{
    // we can only run xdp programs as root

    if ( geteuid() != 0 ) 
    {
        printf( "\nerror: this program must be run as root\n\n" );
        return 1;
    }

    // find the network interface that matches the interface name
    {
        bool found = false;

        struct ifaddrs * addrs;
        if ( getifaddrs( &addrs ) != 0 )
        {
            printf( "\nerror: getifaddrs failed\n\n" );
            return 1;
        }

        for ( struct ifaddrs * iap = addrs; iap != NULL; iap = iap->ifa_next ) 
        {
            if ( iap->ifa_addr && ( iap->ifa_flags & IFF_UP ) && iap->ifa_addr->sa_family == AF_INET )
            {
                struct sockaddr_in * sa = (struct sockaddr_in*) iap->ifa_addr;
                if ( strcmp( interface_name, iap->ifa_name ) == 0 )
                {
                    printf( "found network interface: '%s'\n", iap->ifa_name );
                    bpf->interface_index = if_nametoindex( iap->ifa_name );
                    if ( !bpf->interface_index ) 
                    {
                        printf( "\nerror: if_nametoindex failed\n\n" );
                        return 1;
                    }
                    found = true;
                    break;
                }
            }
        }

        freeifaddrs( addrs );

        if ( !found )
        {
            printf( "\nerror: could not find any network interface matching '%s'", interface_name );
            return 1;
        }
    }

    // load the reflector_xdp program and attach it to the network interface

    printf( "loading reflector_xdp...\n" );

    bpf->program = xdp_program__open_file( "reflector_xdp.o", "reflector_xdp", NULL );
    if ( libxdp_get_error( bpf->program ) ) 
    {
        printf( "\nerror: could not load reflector_xdp program\n\n");
        return 1;
    }

    printf( "reflector_xdp loaded successfully.\n" );

    printf( "attaching reflector_xdp to network interface\n" );

    int ret = xdp_program__attach( bpf->program, bpf->interface_index, XDP_MODE_NATIVE, 0 );
    if ( ret == 0 )
    {
        bpf->attached_native = true;
    } 
    else
    {
        printf( "falling back to skb mode...\n" );
        ret = xdp_program__attach( bpf->program, bpf->interface_index, XDP_MODE_SKB, 0 );
        if ( ret == 0 )
        {
            bpf->attached_skb = true;
        }
        else
        {
            printf( "\nerror: failed to attach reflector_xdp program to interface\n\n" );
            return 1;
        }
    }

    return 0;
}

void bpf_shutdown( struct bpf_t * bpf )
{
    assert( bpf );

    if ( bpf->program != NULL )
    {
        if ( bpf->attached_native )
        {
            xdp_program__detach( bpf->program, bpf->interface_index, XDP_MODE_NATIVE, 0 );
        }
        if ( bpf->attached_skb )
        {
            xdp_program__detach( bpf->program, bpf->interface_index, XDP_MODE_SKB, 0 );
        }
        xdp_program__close( bpf->program );
    }
}

static struct bpf_t bpf;

volatile bool quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = true;
}

void clean_shutdown_handler( int signal )
{
    (void) signal;
    quit = true;
}

static void cleanup()
{
    bpf_shutdown( &bpf );
    fflush( stdout );
}

int main( int argc, char *argv[] )
{
    printf( "[reflector]\n" );

    signal( SIGINT,  interrupt_handler );
    signal( SIGTERM, clean_shutdown_handler );
    signal( SIGHUP,  clean_shutdown_handler );

    // todo: read interface name from command line
    const char * interface_name = "enp4s0";

    if ( bpf_init( &bpf, interface_name ) != 0 )
    {
        cleanup();
        return 1;
    }

    while ( !quit )
    {
        usleep( 1000000 );
    }

    cleanup();

    return 0;
}
