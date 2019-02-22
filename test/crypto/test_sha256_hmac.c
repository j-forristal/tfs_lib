#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void usage(void)
{
	printf("Usage: test_app <variable char hex key> <variable char hex plaintext>\n");
	exit(-2);
}

int main(int argc, char**argv)
{
	uint8_t key_in[256];
	uint32_t key_in_len;
	uint8_t msg_in[4096];
	uint32_t msg_in_len;
	uint8_t digest[TFC_SHA256_DIGEST_SIZE];

	if( argc < 3 ) usage();
	key_in_len = load_hex( argv[1], key_in, sizeof(key_in) );
	if( key_in_len <= 0 ) usage();
	msg_in_len = load_hex( argv[2], msg_in, sizeof(msg_in) );
	if( msg_in_len <= 0 ) usage();

	TFC_SHA256_HMAC( key_in, key_in_len, msg_in, msg_in_len, digest );

	dump_hex( digest, sizeof(digest) );
	return 0;
}
