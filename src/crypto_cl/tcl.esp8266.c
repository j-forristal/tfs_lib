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

	//TFC_SHA256_HMAC( key, key_len, message, message_len, digest );
	return 0;
}


extern void hwrand_fill(uint8_t *buf, size_t len);
int TCL_Random( uint8_t *buffer, uint32_t len )
{
	hwrand_fill( buffer, (uint32_t)len );
	return 0;
}

int TCL_Ed25519_Verify( uint8_t *msg, uint32_t msg_len,
        uint8_t sig[TCL_ED25519_SIG_SIZE], const uint8_t pk[TCL_ED25519_PK_SIZE] ){
#if 0
        return TFC_Ed25519_Verify(msg, msg_len, sig, pk);
#endif
	return 0;
}

int TCL_RSA_Verify( uint8_t modulus[TCL_RSA_SIZE], uint8_t digest[TCL_SHA256_DIGEST_SIZE], uint8_t signature[TCL_RSA_SIZE] ){
	return TCL_VERIFY_NOTSUPP;
}

uint32_t TCL_CRC32( const void *buf, uint32_t len ){
	return TFC_CRC32( buf, len );
}
