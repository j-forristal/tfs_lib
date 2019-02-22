#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "tf_tlv.h"

typedef struct {
	uint8_t ecc[64];
	uint8_t rsa[256];
	uint8_t otp[64];

} _sig_t;


TFTLV_CALLBACK_DEF(_callback){
	printf("Item: tag=%d len=%d\n", tag, len);
	return 0;
}

TFTLV_SIGCALLBACK_DEF(_scallback){
	_sig_t *s = (_sig_t*)sig;
	printf("- Sig callback called\n");
	memcpy( otp, s->otp, TFTLV_OTP_SIZE );
	return 0;
}

int main(int argc, char** argv){

	char *fnom = argv[1];

	TFTLV_Mem_t  mt;
	if( TFTLV_Init_MemFromSignedFile( &mt, fnom, &_scallback ) != 0 ){
		printf("ERR: Init\n");
		return 1;
	}

	uint8_t r = TFTLV_Walk_Mem( &mt, &_callback, NULL );
	if( r != 0 ){ printf("ERR: walkM res=%d\n", r); return 3; }

	return 0;
}


