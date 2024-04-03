/*
    Crypto kernel module

    This module supports Ubuntu 22.04 LTS with Linux Kernel 6.5+ *ONLY*

    USAGE:

        sudo insmod crypto_module.ko
        lsmod
        sudo dmesg --follow
        sudo rmmod crypto_module
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/poly1305.h>
#include <crypto/chacha.h>
#include <crypto/algapi.h>
#include <linux/scatterlist.h>

MODULE_VERSION( "1.0.0" );
MODULE_LICENSE( "GPL" ); 
MODULE_AUTHOR( "Glenn Fiedler" ); 
MODULE_DESCRIPTION( "Crypto kernel module" );

__bpf_kfunc int bpf_crypto_sha256( void * data, int data__sz, void * output, int output__sz );

struct crypto_shash * sha256;

__bpf_kfunc int bpf_crypto_sha256( void * data, int data__sz, void * output, int output__sz )
{
    SHASH_DESC_ON_STACK( shash, tfm );
    shash->tfm = sha256;
    crypto_shash_digest( shash, data, data__sz, output );
    return 0;
}

BTF_SET8_START( bpf_task_set )
BTF_ID_FLAGS( func, bpf_crypto_sha256 )
BTF_SET8_END( bpf_task_set )

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_task_set,
};

// ----------------------------------------------------------------------------------------------------------------------

static int __init crypto_init( void ) 
{
    pr_info( "Crypto module initializing...\n" );

    sha256 = crypto_alloc_shash( "sha256", 0, 0 );
    if ( IS_ERR( sha256 ) )
    {
        pr_err( "can't create sha256 crypto hash algorithm\n" );
        return PTR_ERR( sha256 );
    }

    int result = register_btf_kfunc_id_set( BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set );
    if ( result != 0 )
    {
        pr_err( "failed to register crypto module kfuncs\n" );
        return -1;
    }

    pr_info( "crypto module initialized successfully\n" );

    return result;
}

static void __exit crypto_exit( void ) 
{
    pr_info( "crypto module shutting down...\n" );

    if ( !IS_ERR( sha256 ) )
    {
        crypto_free_shash( sha256 );
    }

    pr_info( "crypto module shut down successfully\n" );
}

module_init( crypto_init );
module_exit( crypto_exit );
