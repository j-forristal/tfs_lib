
#include <stdio.h>

#include "tf_defs.h"

int main(int argc, char **argv)
{
	TF_Defs_t defs;

	if( TFDefs_Load( &defs, argv[1], NULL, 1 ) != TFDEFS_LOAD_OK ){
		printf("Load error\n");
		return -1;
	}

	printf("Defs version=%d\n", TFDefs_Version(&defs) );

	uint8_t buffer[ 2048 ];

	uint8_t secn;
	for( secn = 0; secn < 16; secn++ ){
		if( TFDefs_Has_Section( &defs, secn ) == TFDEFS_NOT_FOUND ) continue;

		uint16_t flags, id;
		uint32_t resume = 0;
		int res = TFDefs_String_Lookup( &defs, secn, buffer, (uint16_t)sizeof(buffer),
			&resume, &flags, &id );
		if( res != TFDEFS_FOUND ) continue;

		printf("-- Section %d ----------------------\n", secn);	
		uint16_t reqlen = (buffer[1] << 8) + buffer[0];
		printf("- MAXLEN: %d\n", reqlen);

		while(1){
			res = TFDefs_String_Lookup( &defs, secn, buffer, (uint16_t)sizeof(buffer),
				&resume, &flags, &id );
			if( res == TFDEFS_NOT_FOUND ) break;
			printf("- FL:0x%d ID:%d '%s'\n", flags, id, buffer);	
		}
	}

	return 0;
}

