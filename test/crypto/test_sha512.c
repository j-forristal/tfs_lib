#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void usage(void)
{
	printf("Usage: test_app <char hex digest> <variable char hex plaintext>\n");
	exit(-2);
}

int main(int argc, char**argv)
{
	uint8_t *msg_in;
	int32_t msg_in_len;
	uint8_t digest[TFC_SHA512_DIGEST_SIZE];

	// Size 51200 == largest NIST test vector size
	// TODO: to run on thin devices, we may not have lots of RAM
	// to alloc:
#define BLOCK_IN_SIZE 51200
	msg_in = malloc( BLOCK_IN_SIZE );
	if( msg_in == 0 ){
		printf("ERROR: OOM\n");
		return -2;
	}

	if( argc < 2 ) usage();
	msg_in_len = load_hex( argv[1], msg_in, BLOCK_IN_SIZE );
	if( msg_in_len < 0 ) usage();

	TFC_SHA512_Ctx_t ctx;
	TFC_SHA512_Init( &ctx );
	TFC_SHA512_Update( &ctx, msg_in, msg_in_len );
	TFC_SHA512_Final( &ctx, digest );

	dump_hex( digest, sizeof(digest) );
	return 0;
}
