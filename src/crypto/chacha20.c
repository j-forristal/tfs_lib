// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.
/*
   This code is adapted from public domain code.
*/

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "tf_crypto_private.h"

#include PLATFORM_H

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

void TFC_ChaCha20_Ctx_Init( TFC_ChaCha20_Ctx_t *ctx, const uint8_t key[TFC_CHACHA20_KEY_SIZE], 
	const uint8_t nonce[TFC_CHACHA20_NONCE_SIZE] )
{
  const char *constants = "expand 32-byte k";

  ctx->schedule[0] = LE(constants + 0);
  ctx->schedule[1] = LE(constants + 4);
  ctx->schedule[2] = LE(constants + 8);
  ctx->schedule[3] = LE(constants + 12);

  ctx->schedule[4] = LE(key + 0);
  ctx->schedule[5] = LE(key + 4);
  ctx->schedule[6] = LE(key + 8);
  ctx->schedule[7] = LE(key + 12);
  ctx->schedule[8] = LE(key + 16);
  ctx->schedule[9] = LE(key + 20);
  ctx->schedule[10] = LE(key + 24);
  ctx->schedule[11] = LE(key + 28);

  ctx->schedule[12] = 0; //Counter
  ctx->schedule[13] = 0; //Counter

  ctx->schedule[14] = LE(nonce + 0);
  ctx->schedule[15] = LE(nonce + 4);
}


static void _block( uint32_t *in, uint32_t *out )
{
  int i;
  TFMEMCPY( out, in, (16 * sizeof(uint32_t)) );

  for( i=20; i>0; i-=2 ) {
    QUARTERROUND(out, 0, 4, 8, 12)
    QUARTERROUND(out, 1, 5, 9, 13)
    QUARTERROUND(out, 2, 6, 10, 14)
    QUARTERROUND(out, 3, 7, 11, 15)
    QUARTERROUND(out, 0, 5, 10, 15)
    QUARTERROUND(out, 1, 6, 11, 12)
    QUARTERROUND(out, 2, 7, 8, 13)
    QUARTERROUND(out, 3, 4, 9, 14)
  }

  for (i = 0; i < 16; ++i)
  {
    uint32_t tmp = out[i] + in[i];
    FROMLE((uint8_t *)(&out[i]), tmp);
  }
}

void TFC_ChaCha20_Process( TFC_ChaCha20_Ctx_t *ctx, const uint8_t *input, uint8_t *output, 
	uint32_t len, uint64_t block_counter, uint32_t block_offset )
{
	uint8_t block[64];
	int i;

	if( len == 0 ) return;
	if( block_offset >= 64 ) abort();

	ctx->schedule[12] = block_counter & 0xffffffff;
	ctx->schedule[13] = (block_counter >> 32) & 0xffffffff;

	// Resume mid-block
	if( block_offset > 0 ){
		_block( ctx->schedule, (uint32_t*)block );
		int amount = MIN(len,(64-block_offset));
		for( i=0; i<amount; i++ ){
			output[i] = input[i] ^ block[i+block_offset];
		}

		ctx->schedule[12]++;
		if( ctx->schedule[12] == 0 ) ctx->schedule[13]++;
		len -= amount;
		input += amount;
		output += amount;
	}

	// Process full blocks
	while (len >= 64){
		_block( ctx->schedule, (uint32_t*)block );
		//uint32_t *output32 = (uint32_t*)output;
		//uint32_t *input32 = (uint32_t*)input;
		//uint32_t *block32 = (uint32_t*)block;
		//for( i=0; i<16; i++ ){
		for( i=0; i<64; i++ ){
			output[i] = input[i] ^ block[i];
			//output32[i] = input32[i] & block32[i];
		}

		ctx->schedule[12]++;
		if( ctx->schedule[12] == 0 ) ctx->schedule[13]++;
		len -= 64;
		input += 64;
		output += 64;
	}

	// Trailing partial block
	if( len > 0 ){
		_block( ctx->schedule, (uint32_t*)block );
		for( i=0; i<len; i++ ){
			output[i] = input[i] ^ block[i];
		}
	}
}


