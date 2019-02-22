#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "tf_crypto.h"
#include <openssl/sha.h>

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );


int main(int argc, char**argv)
{
	uint8_t digest[TFC_SHA512_DIGEST_SIZE];
	uint8_t digest2[TFC_SHA512_DIGEST_SIZE];

	uint8_t msg[ 8192 * 4 ];
	assert( TFC_Random( msg, sizeof(msg) ) == 0);

	TFC_SHA512_Ctx_t ctx;

	printf("Starting...\n");
	int i;
	for( i=0; i< sizeof(msg); i++) {
		TFC_SHA512_Init( &ctx );
		TFC_SHA512_Update( &ctx, msg, i );
		TFC_SHA512_Final( &ctx, digest );

		SHA512( msg, i, digest2 );

		if( memcmp(digest, digest2, sizeof(digest)) != 0 ){
			printf("MISMATCH on ieration %d\n", i);
			return -1;
		}
	}


	printf("OK\n");
	return 0;
}
