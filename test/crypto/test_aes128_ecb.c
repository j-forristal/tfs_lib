#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void usage(void)
{
	printf("Usage: test_app <32 char hex key> <32 char hex plaintext>\n");
	exit(-1);
}

int main(int argc, char**argv)
{
	uint8_t key[16];
	uint8_t block_in[16];
	uint8_t block_out1[16];
	uint8_t block_out2[16];

	//
	// Check usage
	//
	if( argc < 3 ) usage();

	//
	// Load in command line values
	//
	if( load_hex( argv[1], key, sizeof(key) ) != sizeof(key) ) usage();
	if( load_hex( argv[2], block_in, sizeof(block_in) ) != sizeof(block_in) ) usage();

	//
	// Init our context
	//
	TFC_AES128_Ctx_t ctx;
	TFC_AES128_Ctx_Init( &ctx, key );

	//
	// Encrypt the data, then decrypt it and make sure we mirror back
	// to the original value
	//
	TFC_AES128_ECB_Encrypt( &ctx, block_in, block_out1 );
	TFC_AES128_ECB_Decrypt( &ctx, block_out1, block_out2 );
	if( memcmp( block_in, block_out2, 16 ) != 0 ){
		printf("ERROR: encrypt/decrypt didn't mirror\n");
		return -1;
	}

	//
	// Reset the ctx and do just a decrypt, to make sure previous
	// decrypt wasn't fake success due to leftover state from the
	// encrypt context
	//
	memset( &ctx, 0, sizeof(ctx) );
	memset( block_out2, 0, sizeof(block_out2) );

	TFC_AES128_Ctx_Init( &ctx, key );

	TFC_AES128_ECB_Decrypt( &ctx, block_out1, block_out2 );

	if( memcmp( block_in, block_out2, 16 ) != 0 ){
		printf("ERROR: encrypt/decrypt didn't mirror\n");
		return -1;
	}

	//
	// Print out encrypted value and call it good (caller will check it's the
	// expected value)
	//
	dump_hex( block_out1, sizeof(block_out1) );
	return 0;
}
