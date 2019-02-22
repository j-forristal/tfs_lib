#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

//#include "tf_crypto.h"
#include "tf_cal.h"
#include <openssl/sha.h>
#include <openssl/md5.h>

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );


int main(int argc, char**argv)
{

	uint8_t msg[ 8192 * 4 ];
	assert( TCL_Random( msg, sizeof(msg) ) == 0);

	int i;

	uint8_t d1_512[TCL_SHA512_DIGEST_SIZE];
	uint8_t d2_512[TCL_SHA512_DIGEST_SIZE];
	for( i=0; i< sizeof(msg); i++) {
		TCL_SHA512( msg, i, d1_512 );
		SHA512( msg, i, d2_512 );

		if( memcmp(d1_512, d2_512, sizeof(d1_512)) != 0 ){
			printf("MISMATCH on SHA512 ieration %d\n", i);
			return -1;
		}
	}


	uint8_t d1_256[TCL_SHA256_DIGEST_SIZE];
	uint8_t d2_256[TCL_SHA256_DIGEST_SIZE];
	for( i=0; i< sizeof(msg); i++) {
		TCL_SHA256( msg, i, d1_256 );
		SHA256( msg, i, d2_256 );

		if( memcmp(d1_256, d2_256, sizeof(d1_256)) != 0 ){
			printf("MISMATCH on SHA256 ieration %d\n", i);
			return -1;
		}
	}

	uint8_t d1_1[TCL_SHA1_DIGEST_SIZE];
	uint8_t d2_1[TCL_SHA1_DIGEST_SIZE];
	for( i=0; i< sizeof(msg); i++) {
		TCL_SHA1( msg, i, d1_1 );
		SHA1( msg, i, d2_1 );

		if( memcmp(d1_1, d2_1, sizeof(d1_1)) != 0 ){
			printf("MISMATCH on SHA1 ieration %d\n", i);
			return -1;
		}
	}

	uint8_t d1_5[TCL_MD5_DIGEST_SIZE];
	uint8_t d2_5[TCL_MD5_DIGEST_SIZE];
	for( i=0; i< sizeof(msg); i++) {
		TCL_MD5( msg, i, d1_5 );
		MD5( msg, i, d2_5 );

		if( memcmp(d1_5, d2_5, sizeof(d1_5)) != 0 ){
			printf("MISMATCH on MD5 ieration %d\n", i);
			return -1;
		}
	}

	printf("OK\n");
	return 0;
}
