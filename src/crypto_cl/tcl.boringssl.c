// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <pthread.h>
#include <stdint.h>

#include "tf_cal.h"
#include "tf_crypto.h"

#include PLATFORM_H

#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#include "openssl/aes.h"

int TCL_MD5_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[16] ){
	MD5_CTX ctx;
	if( MD5_Init(&ctx) != 1 ) return 1;
	if( MD5_Update(&ctx, data, len) != 1 ) return 1;
	if( data2 != NULL ){ if( MD5_Update(&ctx, data2, len2) != 1 ) return 1; }
	if( MD5_Final( digest, &ctx ) != 1 ) return 1;
	return 0;
}
int TCL_MD5( const uint8_t *data, uint32_t len, uint8_t digest[16] ){
	return TCL_MD5_2( data, len, NULL, 0, digest );
}

int TCL_SHA1_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[20] ){
	SHA_CTX ctx;
	if( SHA1_Init(&ctx) != 1 ) return 1;
	if( SHA1_Update(&ctx, data, len) != 1 ) return 1;
	if( data2 != NULL ){ if( SHA1_Update(&ctx, data2, len2) != 1 ) return 1; }
	if( SHA1_Final( digest, &ctx ) != 1 ) return 1;
	return 0;
}
int TCL_SHA1( const uint8_t *data, uint32_t len, uint8_t digest[20] ){
	return TCL_SHA1_2( data, len, NULL, 0, digest );
}

int TCL_SHA256_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[32] ){
	SHA256_CTX ctx;
	if( SHA256_Init(&ctx) != 1 ) return 1;
	if( SHA256_Update(&ctx, data, len) != 1 ) return 1;
	if( data2 != NULL ){ if( SHA256_Update(&ctx, data2, len2) != 1 ) return 1; }
	if( SHA256_Final( digest, &ctx ) != 1 ) return 1;
	return 0;
}
int TCL_SHA256( const uint8_t *data, uint32_t len, uint8_t digest[32] ){
	return TCL_SHA256_2( data, len, NULL, 0, digest );
}

int TCL_SHA512_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[64] ){
	SHA512_CTX ctx;
	if( SHA512_Init(&ctx) != 1 ) return 1;
	if( SHA512_Update(&ctx, data, len) != 1 ) return 1;
	if( data2 != NULL ){ if( SHA512_Update(&ctx, data2, len2) != 1 ) return 1; }
	if( SHA512_Final( digest, &ctx ) != 1 ) return 1;
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

int TCL_Random( uint8_t *buffer, uint32_t len )
{
	if( RAND_bytes(buffer, len) == 1 ) return 0;
	return -1;
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
	// TODO: switch over to boringssl implementation
	return TFC_ECC_Verify(pub, digest, signature) == 1 ? TCL_VERIFY_OK : TCL_VERIFY_FAIL;
}

uint32_t TCL_CRC32( const void *buf, uint32_t len ){
	return TFC_CRC32( buf, len );
}

int TCL_RSA_Verify( uint8_t *pub, uint32_t publen, uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_RSA_SIZE], int *err_details )
{
	// TODO: implement this?
	return TCL_VERIFY_NOTSUPP;
}


uint32_t TCL_AES_CTR( uint8_t *buf, uint32_t len, uint8_t key[16], uint8_t nonce[16] )
{
	AES_KEY key_;
	uint8_t counter[16];
	uint8_t ecount_buf[16];
	unsigned int num = 0;

	TFMEMCPY(counter, nonce, 16);
	TFC_Erase(&key_, sizeof(key_));
	if( AES_set_encrypt_key(key, 128, &key_) != 0 ) return TCL_CRYPTO_ERR;
	AES_ctr128_encrypt(buf, buf, len, &key_, counter, ecount_buf, &num);
	TFC_Erase(&key_, sizeof(key_));

	return TCL_CRYPTO_OK;
}
