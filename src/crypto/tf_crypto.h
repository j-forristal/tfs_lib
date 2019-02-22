// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_CRYPTO_H_
#define _TF_CRYPTO_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Utils
//
extern void TFC_Erase( void *ptr, uint32_t len );
extern int TFC_Compare( const uint8_t a[16], const uint8_t b[16], size_t size );
extern uint32_t TFC_CRC32( const void *buf, uint32_t len );


//
// Random
//
extern int TFC_Random( uint8_t *buffer, uint32_t len );


//
// ChaCha20
//
#define TFC_CHACHA20_BLOCK_SIZE 64
#define TFC_CHACHA20_KEY_SIZE 32
#define TFC_CHACHA20_NONCE_SIZE 8

typedef struct {
    uint32_t schedule[16];
} TFC_ChaCha20_Ctx_t;

extern void TFC_ChaCha20_Ctx_Init( TFC_ChaCha20_Ctx_t *ctx, const uint8_t key[TFC_CHACHA20_KEY_SIZE], 
	const uint8_t nonce[TFC_CHACHA20_NONCE_SIZE] );
extern void TFC_ChaCha20_Process( TFC_ChaCha20_Ctx_t *ctx, const uint8_t *input, uint8_t *output,
        uint32_t len, uint64_t block_counter, uint32_t block_offset );


//
// AES128
//
#define TFC_AES128_BLOCK_SIZE 16
#define TFC_AES128_KEY_SIZE 16
#define TFC_AES128_IV_SIZE 16

typedef struct {
    uint8_t rkey[176];
} TFC_AES128_Ctx_t;

extern void TFC_AES128_Ctx_Init( TFC_AES128_Ctx_t *ctx, const uint8_t key[TFC_AES128_KEY_SIZE] );
extern void TFC_AES128_ECB_Encrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t input[TFC_AES128_BLOCK_SIZE], 
	uint8_t output[TFC_AES128_BLOCK_SIZE]);
extern void TFC_AES128_ECB_Decrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t input[TFC_AES128_BLOCK_SIZE], 
	uint8_t output[TFC_AES128_BLOCK_SIZE]);

extern void TFC_AES128_CBC_Encrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t* input, uint8_t* output,
    uint32_t length, const uint8_t iv[TFC_AES128_IV_SIZE]);
extern void TFC_AES128_CBC_Decrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t* input, uint8_t* output,
    uint32_t length, const uint8_t iv[TFC_AES128_IV_SIZE]);

#define TFC_AES128_KDF256_NONCE_SIZE	8
#define TFC_AES128_KDF256_TAG_SIZE	2
#define TFC_AES128_KDF256_OUTPUT_SIZE	(2 * TFC_AES128_BLOCK_SIZE)

extern void TFC_AES128_KDF256(const uint8_t key[TFC_AES128_KEY_SIZE], 
	const uint8_t nonce[TFC_AES128_KDF256_NONCE_SIZE], const uint8_t tag[TFC_AES128_KDF256_TAG_SIZE],
	uint8_t output[TFC_AES128_KDF256_OUTPUT_SIZE]);



//
// MD5
//
#define TFC_MD5_DIGEST_SIZE 16

typedef struct {
	uint32_t lo, hi;
	uint32_t a, b, c, d;
	uint32_t block[16];
	uint8_t buffer[64];
} TFC_MD5_Ctx_t;

extern void TFC_MD5_Init(TFC_MD5_Ctx_t *ctx);
extern void TFC_MD5_Update(TFC_MD5_Ctx_t *ctx, const uint8_t *data, uint32_t len);
extern void TFC_MD5_Final(TFC_MD5_Ctx_t *ctx, uint8_t digest[TFC_MD5_DIGEST_SIZE]);
extern void TFC_MD5( const uint8_t *data, uint32_t size, uint8_t result[TFC_MD5_DIGEST_SIZE] );


//
// SHA1
//
#define TFC_SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} TFC_SHA1_Ctx_t;

extern void TFC_SHA1_Init(TFC_SHA1_Ctx_t* ctx);
extern void TFC_SHA1_Update(TFC_SHA1_Ctx_t* ctx, const uint8_t* data, uint32_t len);
extern void TFC_SHA1_Final(TFC_SHA1_Ctx_t* ctx, uint8_t digest[TFC_SHA1_DIGEST_SIZE]);


//
// SHA256
//
#define TFC_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint32_t count[2];
    uint8_t buffer[64];
} TFC_SHA256_Ctx_t;

extern void TFC_SHA256_Init(TFC_SHA256_Ctx_t *ctx);
extern void TFC_SHA256_Update(TFC_SHA256_Ctx_t *ctx, const uint8_t *data, uint32_t len);
extern void TFC_SHA256_Final(TFC_SHA256_Ctx_t *ctx, uint8_t digest[TFC_SHA256_DIGEST_SIZE]);

extern void TFC_SHA256_HMAC( const uint8_t *key, uint32_t key_len,
        const uint8_t *message, uint32_t message_len,
	uint8_t digest[TFC_SHA256_DIGEST_SIZE] );


//
// SHA512
//
#define TFC_SHA512_DIGEST_SIZE 64

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} TFC_SHA512_Ctx_t;

extern void TFC_SHA512_Init(TFC_SHA512_Ctx_t *ctx);
extern void TFC_SHA512_Update(TFC_SHA512_Ctx_t *ctx, const uint8_t *data, uint32_t len);
extern void TFC_SHA512_Final(TFC_SHA512_Ctx_t *ctx, uint8_t digest[TFC_SHA512_DIGEST_SIZE]);


//
// ED25519
//
#define TFC_ED25519_SIG_SIZE 64
#define TFC_ED25519_PK_SIZE 32
#define TFC_ED25519_SK_SIZE 32

int TFC_Ed25519_Verify( uint8_t *msg, uint32_t msg_len, 
	uint8_t sig[TFC_ED25519_SIG_SIZE], const uint8_t pk[TFC_ED25519_PK_SIZE] );
int TFC_Ed25519_Sign( uint8_t *msg, uint32_t msg_len, uint8_t sig[TFC_ED25519_SIG_SIZE],
        const uint8_t pk[TFC_ED25519_PK_SIZE], const uint8_t sk[TFC_ED25519_SK_SIZE] );


//
// ECC secp256r1 verification
//
#define TFC_ECC_K_SIZE 32
#define TFC_ECC_PK_SIZE 64
#define TFC_ECC_HASH_SIZE 32
#define TFC_ECC_SIG_SIZE 64

int TFC_ECC_Sign( uint8_t k[TFC_ECC_K_SIZE], uint8_t hash[TFC_ECC_HASH_SIZE], uint8_t sig[TFC_ECC_SIG_SIZE]);
int TFC_ECC_Verify( uint8_t pk[TFC_ECC_PK_SIZE], uint8_t hash[TFC_ECC_HASH_SIZE], uint8_t sig[TFC_ECC_SIG_SIZE]);


//
// Base64
//

int TFC_Base64_Decode(const char *in, uint32_t in_len, uint8_t *out, uint32_t out_len);
int TFC_Base64_Encode(const uint8_t *in, uint32_t in_len, char *out, uint32_t out_len);


#ifdef __cplusplus
}
#endif

#endif // _TF_CRYPTO_H_
