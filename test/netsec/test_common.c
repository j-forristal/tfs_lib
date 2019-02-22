#include <stdio.h>
#include <string.h>
#include <stdint.h>

void dump_hex( uint8_t* hex, uint32_t cnt )
{
	int i;
	for( i=0; i<cnt; i++){
		printf("%02x", hex[i]);
	}
	printf("\n");
}

int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max )
{
	int i, cnt;

	// special indicator of a zero-length message
	if( hex_in[0] == '-' ) return 0;

	cnt = (int)strlen( hex_in );
	if( (cnt & 1) == 1 ) return -3; // must be multiple of 2
	cnt = cnt >> 1; // aka divide by 2
	if( cnt > max || cnt == 0 ) return -2;

	for( i=0; i<cnt; i++ ){
		uint32_t v;
		if( sscanf( &hex_in[ i*2 ], "%02x", &v ) != 1 ){
			return -1;
		}
		binary_out[i] = (uint8_t)(v & 0xff);
	}

	return cnt;
}
