// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <pthread.h>
#include <stdint.h>

#include "tf_cal.h"
#include "tf_crypto.h"

#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"

int TCL_MD5_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[16] ){
	mbedtls_md5_context ctx;
	mbedtls_md5_init( &ctx );

	mbedtls_md5_starts( &ctx );
	mbedtls_md5_update( &ctx, data, len );
	if( data2 != NULL ) mbedtls_md5_update( &ctx, data2, len2 );
	mbedtls_md5_finish( &ctx, digest );

	mbedtls_md5_free( &ctx );
	return 0;
}
int TCL_MD5( const uint8_t *data, uint32_t len, uint8_t digest[16] ){
	return TCL_MD5_2( data, len, NULL, 0, digest );
}

int TCL_SHA1_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[20] ){
	mbedtls_sha1_context ctx;
	mbedtls_sha1_init( &ctx );

	mbedtls_sha1_starts( &ctx );
	mbedtls_sha1_update( &ctx, data, len );
	if( data2 != NULL ) mbedtls_sha1_update( &ctx, data2, len2 );
	mbedtls_sha1_finish( &ctx, digest );

	mbedtls_sha1_free( &ctx );
	return 0;
}
int TCL_SHA1( const uint8_t *data, uint32_t len, uint8_t digest[20] ){
	return TCL_SHA1_2( data, len, NULL, 0, digest );
}

int TCL_SHA256_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[32] ){
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init( &ctx );

	mbedtls_sha256_starts( &ctx, 0 );
	mbedtls_sha256_update( &ctx, data, len );
	if( data2 != NULL ) mbedtls_sha256_update( &ctx, data2, len2 );
	mbedtls_sha256_finish( &ctx, digest );

	mbedtls_sha256_free( &ctx );
	return 0;
}
int TCL_SHA256( const uint8_t *data, uint32_t len, uint8_t digest[32] ){
	return TCL_SHA256_2( data, len, NULL, 0, digest );
}

int TCL_SHA512_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[64] ){
	mbedtls_sha512_context ctx;
	mbedtls_sha512_init( &ctx );

	mbedtls_sha512_starts( &ctx, 0 );
	mbedtls_sha512_update( &ctx, data, len );
	if( data2 != NULL ) mbedtls_sha512_update( &ctx, data2, len2 );
	mbedtls_sha512_finish( &ctx, digest );

	mbedtls_sha512_free( &ctx );
	return 0;
}
int TCL_SHA512( const uint8_t *data, uint32_t len, uint8_t digest[64] ){
	return TCL_SHA512_2( data, len, NULL, 0, digest );
}

int TCL_SHA256_HMAC( const uint8_t *key, uint32_t key_len,
        const uint8_t *message, uint32_t message_len,
        uint8_t digest[32] ){

	TFC_SHA256_HMAC( key, key_len, message, message_len, digest );
	return 0;
}


static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;
static int _initialized = 0;
static pthread_mutex_t _rng_lock = PTHREAD_MUTEX_INITIALIZER;

int TCL_Random( uint8_t *buffer, uint32_t len )
{
	int ret;

	do { ret = pthread_mutex_lock( &_rng_lock ); } while( ret != 0 );

	if( _initialized == 0 ){
		mbedtls_ctr_drbg_init( &_ctr_drbg );
		mbedtls_entropy_init( &_entropy );
		ret = mbedtls_ctr_drbg_seed( &_ctr_drbg, mbedtls_entropy_func, &_entropy,
			(const unsigned char *)"A1", 2);
		if( ret != 0 ){
			do { ret = pthread_mutex_unlock( &_rng_lock ); } while( ret != 0 );
			return -1;
		}
		_initialized++;
	}

	ret = mbedtls_ctr_drbg_random( &_ctr_drbg, buffer, (size_t)len );
	if( ret != 0 ) ret = -1;

	do { ret = pthread_mutex_unlock( &_rng_lock ); } while( ret != 0 );
	return ret;
}

#if 0
int TCL_Ed25519_Verify( uint8_t *msg, uint32_t msg_len,
        uint8_t sig[TCL_ED25519_SIG_SIZE], const uint8_t pk[TCL_ED25519_PK_SIZE] ){
        return TFC_Ed25519_Verify(msg, msg_len, sig, pk);
}
#endif

int TCL_ECC_Verify( uint8_t pub[TCL_ECC_PUB_SIZE], uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_ECC_SIZE], int *err_details )
{
	return TFC_ECC_Verify(pub, digest, signature) == 1 ? TCL_VERIFY_OK : TCL_VERIFY_FAIL;
}

uint32_t TCL_CRC32( const void *buf, uint32_t len ){
	return TFC_CRC32( buf, len );
}

int TCL_RSA_Verify( uint8_t *pub, uint32_t publen, uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_RSA_SIZE], int *err_details )
{
	// TODO
#if 0
	mbedtls_rsa_context ctx;
	mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256 );

	mbedtls_mpi_init( &ctx.E );
	mbedtls_mpi_lset( &ctx.E, 3 ); // exponent

	mbedtls_mpi_init( &ctx.N );
	mbedtls_mpi_read_binary( &ctx.N, modulus, TCL_RSA_SIZE );

	int ret = mbedtls_rsa_pkcs1_verify( &ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC,
		MBEDTLS_MD_SHA256, TCL_SHA256_DIGEST_SIZE, digest, signature );
	mbedtls_rsa_free( &ctx );

	// 0 = ok, !0 = error
	if( ret == 0 ) return TCL_VERIFY_OK;
	else if( ret == MBEDTLS_ERR_RSA_VERIFY_FAILED ) return TCL_VERIFY_FAIL;
#endif
	return TCL_VERIFY_ERROR;
}


uint32_t TCL_AES_CTR( uint8_t *buf, uint32_t len, uint8_t key[16], uint8_t nonce[16] ){
	// TODO - if we return success, it just is pass-thru for now
	return TCL_CRYPTO_OK;
}
