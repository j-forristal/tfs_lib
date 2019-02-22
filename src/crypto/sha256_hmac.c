// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include "tf_crypto_private.h"
#include "tf_crypto.h"
#include "tf_cal.h"


#ifdef TFC_SHA256_HMAC_EX

void TFC_SHA256_HMAC_Ex( const uint8_t state[TFC_SHA256_DIGEST_SIZE*2],
	const uint8_t *message, uint32_t message_len,
	uint8_t digest[TFC_SHA256_DIGEST_SIZE] )
{
	TFC_SHA256_Ctx_t ctx;
	uint8_t *ptr = (uint8_t*)ctx.state;

	ctx.count[0] = 64;
	ctx.count[1] = 0;
	TFMEMCPY( ptr, state, TFC_SHA256_DIGEST_SIZE);
	TFC_SHA256_Update(&ctx, message, message_len);
	TFC_SHA256_Final(&ctx, digest);

	ctx.count[0] = 64;
	ctx.count[1] = 0;
	TFMEMCPY( ptr, &state[TFC_SHA256_DIGEST_SIZE], TFC_SHA256_DIGEST_SIZE);
	TFC_SHA256_Update(&ctx, digest, TFC_SHA256_DIGEST_SIZE);
	TFC_SHA256_Final(&ctx, digest);

	TFC_Erase(&ctx, sizeof(ctx));
}

#endif // TFC_SHA256_HMAC_EX

void TFC_SHA256_HMAC( const uint8_t *key, uint32_t key_len,
	const uint8_t *message, uint32_t message_len,
	uint8_t digest[TFC_SHA256_DIGEST_SIZE] )
{
	// NOTE: empty key & empty message (len=0) are allowed, and may
	// be desired in some cases ... so we are not making any
	// enforcements on those values.  They are unsigned, so they
	// will never be negative.
	if( key == NULL || message == NULL ) ABORT();

	TFC_SHA256_Ctx_t ctx;

#define SHA256_BLOCK_SIZE 64

	uint8_t d[SHA256_BLOCK_SIZE];
	MEMSET( d, 0, sizeof(d) );

	if( key_len > SHA256_BLOCK_SIZE ){
		TCL_SHA256( key, key_len, d );
	} else {
		TFMEMCPY(d, key, key_len);
	}

	uint8_t t[ sizeof(d) ];
	int i;

	for(i=0; i<sizeof(t); i++){
		t[i] = d[i] ^ 0x36; // ipad
	}

	TCL_SHA256_2( t, sizeof(t), message, message_len, digest );

	for(i=0; i<sizeof(t); i++){
		t[i] = d[i] ^ 0x5c; // opad
	}

	TCL_SHA256_2( t, sizeof(t), digest, TFC_SHA256_DIGEST_SIZE, digest );

	TFC_Erase(t, sizeof(t));
	TFC_Erase(d, sizeof(d));
	TFC_Erase(&ctx, sizeof(ctx));
}

