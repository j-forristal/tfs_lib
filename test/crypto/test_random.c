#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void usage(void)
{
	printf("Usage: test_app <length number between 0 - 255>\n");
	exit(-2);
}

int main(int argc, char**argv)
{

#if 0
	if( argc < 2 ) usage();
	msg_in_len = load_hex( argv[1], msg_in, BLOCK_IN_SIZE );
	if( msg_in_len <= 0 ) usage();
#endif

	uint8_t buffer[64];
	memset( buffer, 0, sizeof(buffer) );

	int res = TFC_Random( buffer, sizeof(buffer) );
	if( res == 0 )
		dump_hex( buffer, sizeof(buffer) );

	return res;
}
