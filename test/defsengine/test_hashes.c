
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

	uint8_t secn = 1;
	for( secn = 0; secn < 16; secn++ ){
		if( TFDefs_Has_Section( &defs, secn ) == TFDEFS_NOT_FOUND ) continue;
		printf("-- Section %d ----------------------\n", secn);	
		TFDefs_Hash_Dump( &defs, secn );
	}

	return 0;
}

