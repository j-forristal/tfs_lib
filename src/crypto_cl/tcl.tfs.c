// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdint.h>
#include "tf_crypto.h"
#include "tf_cal.h"

int TCL_MD5_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[16] ){
	TFC_MD5_Ctx_t ctx;
	TFC_MD5_Init(&ctx);
	TFC_MD5_Update(&ctx, data, len);
	if( data2 != NULL ) TFC_MD5_Update(&ctx, data2, len2);
	TFC_MD5_Final(&ctx, digest);
	return 0;
}
int TCL_MD5( const uint8_t *data, uint32_t len, uint8_t digest[16] ){
	return TCL_MD5_2( data, len, NULL, 0, digest );
}

int TCL_SHA1_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[20] ){
	TFC_SHA1_Ctx_t ctx;
	TFC_SHA1_Init(&ctx);
	TFC_SHA1_Update(&ctx, data, len);
	if( data2 != NULL ) TFC_SHA1_Update(&ctx, data2, len2);
	TFC_SHA1_Final(&ctx, digest);
	return 0;
}
int TCL_SHA1( const uint8_t *data, uint32_t len, uint8_t digest[20] ){
	return TCL_SHA1_2( data, len, NULL, 0, digest );
}

int TCL_SHA256_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[32] ){
	TFC_SHA256_Ctx_t ctx;
	TFC_SHA256_Init(&ctx);
	TFC_SHA256_Update(&ctx, data, len);
	if( data2 != NULL ) TFC_SHA256_Update(&ctx, data2, len2);
	TFC_SHA256_Final(&ctx, digest);
	return 0;
}
int TCL_SHA256( const uint8_t *data, uint32_t len, uint8_t digest[32] ){
	return TCL_SHA256_2( data, len, NULL, 0, digest );
}

int TCL_SHA512_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[64] ){
	TFC_SHA512_Ctx_t ctx;
	TFC_SHA512_Init(&ctx);
	TFC_SHA512_Update(&ctx, data, len);
	if( data2 != NULL ) TFC_SHA512_Update(&ctx, data2, len2);
	TFC_SHA512_Final(&ctx, digest);
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

int TCL_Random( uint8_t *buffer, uint32_t len ){
	return TFC_Random(buffer, len);
}

int TCL_Ed25519_Verify( uint8_t *msg, uint32_t msg_len,
        uint8_t sig[TCL_ED25519_SIG_SIZE], const uint8_t pk[TCL_ED25519_PK_SIZE] ){
	//return TFC_Ed25519_Verify(msg, msg_len, sig, pk);
	return TCL_VERIFY_NOTSUPP;
}

int TCL_ECC_Verify( uint8_t pub[TCL_ECC_PUB_SIZE], uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_ECC_SIZE], int *err_details )
{
	return TFC_ECC_Verify(pub, digest, signature) == 1 ? TCL_VERIFY_OK : TCL_VERIFY_FAIL;
}

int TCL_RSA_Verify( uint8_t *pub, uint32_t publen, uint8_t digest[TCL_SHA256_DIGEST_SIZE],
        uint8_t signature[TCL_RSA_SIZE], int *err_details ){
	return TCL_VERIFY_NOTSUPP;
}

uint32_t TCL_CRC32( const void *buf, uint32_t len ){
	return TFC_CRC32( buf, len );
}
