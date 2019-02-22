// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TFS_CAL_H_
#define _TFS_CAL_H_

#include <stdint.h>

#define TCL_MD5_DIGEST_SIZE	16
#define TCL_SHA1_DIGEST_SIZE	20
#define TCL_SHA256_DIGEST_SIZE	32
#define TCL_SHA512_DIGEST_SIZE	64

int TCL_MD5( const uint8_t *data, uint32_t len, uint8_t digest[TCL_MD5_DIGEST_SIZE] );
int TCL_MD5_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[TCL_MD5_DIGEST_SIZE] );
int TCL_SHA1( const uint8_t *data, uint32_t len, uint8_t digest[TCL_SHA1_DIGEST_SIZE] );
int TCL_SHA1_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[TCL_SHA1_DIGEST_SIZE] );
int TCL_SHA256( const uint8_t *data, uint32_t len, uint8_t digest[TCL_SHA256_DIGEST_SIZE] );
int TCL_SHA256_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[TCL_SHA256_DIGEST_SIZE] );
int TCL_SHA512( const uint8_t *data, uint32_t len, uint8_t digest[TCL_SHA512_DIGEST_SIZE] );
int TCL_SHA512_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[TCL_SHA512_DIGEST_SIZE] );

int TCL_SHA256_HMAC( const uint8_t *key, uint32_t key_len,
        const uint8_t *message, uint32_t message_len,
        uint8_t digest[TCL_SHA256_DIGEST_SIZE] );

int TCL_Random( uint8_t *buffer, uint32_t len );
uint32_t TCL_CRC32( const void *buf, uint32_t len );

#define TCL_VERIFY_OK		0
#define TCL_VERIFY_FAIL		-1
#define TCL_VERIFY_NOTSUPP	-2
#define TCL_VERIFY_ERROR	-3

#define TCL_ED25519_SIG_SIZE 64
#define TCL_ED25519_PK_SIZE 32
#define TCL_ED25519_SK_SIZE 32

int TCL_Ed25519_Verify( uint8_t *msg, uint32_t msg_len, uint8_t sig[TCL_ED25519_SIG_SIZE], const uint8_t pk[TCL_ED25519_PK_SIZE] );

#define TCL_RSA_SIZE		256

int TCL_RSA_Verify( uint8_t *pub, uint32_t publen, uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_RSA_SIZE], int *err_details );

#define TCL_ECC_PUB_SIZE	64
#define TCL_ECC_SIZE		64

int TCL_ECC_Verify( uint8_t pub[TCL_ECC_PUB_SIZE], uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_ECC_SIZE], int *err_details );


#define TCL_CRYPTO_OK		0
#define TCL_CRYPTO_ERR		-1
#define TCL_AES_BLOCK_SIZE	16
uint32_t TCL_AES_CTR( uint8_t *buf, uint32_t len, uint8_t key[TCL_AES_BLOCK_SIZE], 
	uint8_t nonce[TCL_AES_BLOCK_SIZE] );


#endif
