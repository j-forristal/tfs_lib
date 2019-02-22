#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void usage(void)
{
	printf("Usage: test_app <32 char hex key> <32 char hex iv> <variable char hex plaintext>\n");
	exit(-2);
}

int main(int argc, char**argv)
{
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t *block_in;
	uint32_t block_in_len;
	uint8_t *block_out1;
	uint8_t *block_out2;

	// TODO: to run on thin devices, we may not have lots of RAM
	// to alloc:
#define BLOCK_IN_SIZE 4096
	block_in = malloc( BLOCK_IN_SIZE );
	if( block_in == 0 ){
		printf("ERROR: OOM\n");
		return -2;
	}

	//
	// Check usage
	//
	if( argc < 4 ) usage();

	//
	// Load in command line values
	//
	if( load_hex( argv[1], key, sizeof(key) ) != sizeof(key) ) usage();
	if( load_hex( argv[2], iv, sizeof(iv) ) != sizeof(iv) ) usage();

	block_in_len = load_hex( argv[3], block_in, BLOCK_IN_SIZE );
	if( block_in_len <= 0 ) usage();

	block_out1 = malloc( block_in_len + 16 );
	if( block_out1 == 0 ){
		printf("ERROR: OOM2\n");
		return -2;
	}
	block_out2 = malloc( block_in_len + 16 );
	if( block_out1 == 0 ){
		printf("ERROR: OOM2\n");
		return -2;
	}

	//
	// Init our context
	//
	TFC_AES128_Ctx_t ctx;
	TFC_AES128_Ctx_Init( &ctx, key );

	//
	// Encrypt the data, then decrypt it and make sure we mirror back
	// to the original value
	//
	uint32_t out_size = block_in_len;
	if( (out_size & 0xf) > 0 )
		out_size = (out_size + 16) & ~0xf;

	TFC_AES128_CBC_Encrypt( &ctx, block_in, block_out1, out_size, iv );
	TFC_AES128_CBC_Decrypt( &ctx, block_out1, block_out2, out_size, iv );
	if( memcmp( block_in, block_out2, block_in_len ) != 0 ){
		printf("ERROR: encrypt/decrypt didn't mirror\n");
		return -1;
	}

	//
	// Reset the ctx and do just a decrypt, to make sure previous
	// decrypt wasn't fake success due to leftover state from the
	// encrypt context
	//
	memset( &ctx, 0, sizeof(ctx) );
	memset( block_out2, 0, block_in_len + 16 );

	TFC_AES128_Ctx_Init( &ctx, key );

	TFC_AES128_CBC_Decrypt( &ctx, block_out1, block_out2, out_size, iv );
	if( memcmp( block_in, block_out2, block_in_len ) != 0 ){
		printf("ERROR: encrypt/decrypt didn't mirror (2)\n");
		return -1;
	}

	//
	// Print out encrypted value and call it good (caller will check it's the
	// expected value)
	//
	dump_hex( block_out1, out_size );
	return 0;
}
