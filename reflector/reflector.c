/*
    UDP reflector XDP program (Userspace)

    Runs on Ubuntu 22.04 LTS 64bit with Linux Kernel 6.5+ *ONLY*
*/

#include <memory.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

// todo: move bpf stuff into here
//static struct bpf_t bpf;

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
    // todo
    // bpf_shutdown( &bpf );
    fflush( stdout );
}

int main( int argc, char *argv[] )
{
    printf( "[reflectotr]\n" );

    signal( SIGINT,  interrupt_handler );
    signal( SIGTERM, clean_shutdown_handler );
    signal( SIGHUP,  clean_shutdown_handler );

    // todo: read interface name from command line

    // todo: main loop

    /*
    if ( bpf_init( &bpf, config.relay_public_address, config.relay_internal_address ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }
    */

    cleanup();

    return result;
}
