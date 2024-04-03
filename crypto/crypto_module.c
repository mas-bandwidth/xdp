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
    sha256_hash( data, data__sz, output );
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

    __u8 digest[32];
    sha256_hash( "test", 4, digest );
    if ( digest[0]  != 0x9f || 
         digest[1]  != 0x86 ||
         digest[2]  != 0xd0 ||
         digest[3]  != 0x81 ||
         digest[4]  != 0x88 ||
         digest[5]  != 0x4c ||
         digest[6]  != 0x7d ||
         digest[7]  != 0x65 ||
         digest[8]  != 0x9a ||
         digest[9]  != 0x2f ||
         digest[10] != 0xea ||
         digest[11] != 0xa0 ||
         digest[12] != 0xc5 ||
         digest[13] != 0x5a ||
         digest[14] != 0xd0 ||
         digest[15] != 0x15 ||
         digest[16] != 0xa3 ||
         digest[17] != 0xbf ||
         digest[18] != 0x4f ||
         digest[19] != 0x1b ||
         digest[20] != 0x2b ||
         digest[21] != 0x0b ||
         digest[22] != 0x82 ||
         digest[23] != 0x2c ||
         digest[24] != 0xd1 ||
         digest[25] != 0x5d ||
         digest[26] != 0x6c ||
         digest[27] != 0x15 ||
         digest[28] != 0xb0 ||
         digest[29] != 0xf0 ||
         digest[30] != 0x0a ||
         digest[31] != 0x08 )
    {
        pr_err( "sha256 is broken\n" );
        return -1;
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
