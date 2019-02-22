#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void usage(void)
{
	printf("Usage: test_app <64 char hex key> <16 char hex nonce>\n");
	exit(-1);
}

int main(int argc, char**argv)
{
	uint8_t key[32];
	uint8_t nonce[8];

	uint8_t  block_in[64];
	memset( block_in, 0, sizeof(block_in) );

	uint32_t block_out[16];

	//
	// Check usage
	//
	if( argc < 3 ) usage();

	//
	// Load in command line values
	//
	if( load_hex( argv[1], key, sizeof(key) ) != sizeof(key) ) usage();
	if( load_hex( argv[2], nonce, sizeof(nonce) ) != sizeof(nonce) ) usage();

	//
	// Init our context
	//
	TFC_ChaCha20_Ctx_t ctx;
	TFC_ChaCha20_Ctx_Init( &ctx, key, nonce );

	TFC_ChaCha20_Process( &ctx, block_in, (uint8_t*)block_out,
		sizeof(block_in), 0, 0 );

	//
	// Print out value and call it good (caller will check it's the
	// expected value)
	//
	dump_hex( (uint8_t*)block_out, sizeof(block_out) );
	return 0;
}
