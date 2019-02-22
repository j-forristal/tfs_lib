#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "tf_tlv.h"

typedef struct {
	uint8_t *data;
	uint32_t len;
} inputs_t;

inputs_t inputs[4];

TFTLV_CALLBACK_DEF(_callback){
	if( data == NULL && tag == TFTLV_CB_TAG_END ){
		printf("Item: <EOF>\n");
		return TFTLV_CB_RET_STOP;
	}

	printf("Item: tag=%d len=%d\n", tag, len);
	if( inputs[tag].len != len || memcmp(data, inputs[tag].data, len) != 0 ){
		printf("ERR on %d!\n", tag);
	}

	return TFTLV_CB_RET_CONTINUE;
}

int main(void){

	unlink("/tmp/test.tf");

	int i;
	//uint32_t cnt, dlen;


	uint8_t msg1[512];
	uint16_t msg1sz = 512;
	for( i=0; i<msg1sz; i++){ msg1[i] = (uint8_t)rand(); }
	inputs[0].data = msg1;
	inputs[0].len = msg1sz;

	uint8_t msg2[250];
	uint16_t msg2sz = 250;
	for( i=0; i<msg2sz; i++){ msg2[i] = (uint8_t)rand(); }
	inputs[1].data = msg2;
	inputs[1].len = msg2sz;

	uint8_t msg3[1];
	uint16_t msg3sz = 1;
	for( i=0; i<msg3sz; i++){ msg3[i] = (uint8_t)rand(); }
	inputs[2].data = msg3;
	inputs[2].len = msg3sz;

	uint8_t msg4[] = "DDDDDDDDDDDD";
	uint16_t msg4sz = 12;
	//for( i=0; i<msg4sz; i++){ msg4[i] = (uint8_t)rand(); }
	inputs[3].data = msg4;
	inputs[3].len = msg4sz;

	//uint32_t expected_cnt = 0;
	//uint32_t expected_len = 0;

	printf("-- Basic push fill\n");

	uint8_t key[TFTLV_KEY_SIZE];

	TFTLV_File_t ft;
	TFTLV_Mem_t  mt;
	if( TFTLV_Init_ProtectedFile( &ft, "/tmp/test.tf", key ) != 0 ){
		printf("ERR: InitFile\n");
		return 1;
	}
	if( TFTLV_Init_Mem( &mt, 1000000 ) != 0 ){
		printf("ERR: InitMem\n");
		return 1;
	}

	int r;
	for( i=0; i<4; i++ ){
		r = TFTLV_Add_ToFile( &ft, i, inputs[i].data, inputs[i].len );
		if( r != 0 ){ printf("ERR: pushF inp=%d res=%d\n", i, r); return 2; }

		r = TFTLV_Add_ToMem( &mt, i, inputs[i].data, inputs[i].len );
		if( r != 0 ){ printf("ERR: pushM inp=%d res=%d\n", i, r); return 2; }
	}

	printf("-- Item check\n");
	printf("- Mem: %d\n", TFTLV_HasItems_Mem( &mt ));
	printf("- File: %d\n", TFTLV_HasItems_File( &ft ));

	printf("-- File iterate\n");
	r = TFTLV_Walk_File( &ft, _callback, NULL );
	if( r != 0 ){ printf("ERR: walkF res=%d\n", r); return 3; }

	printf("-- Memory iterate\n");
	r = TFTLV_Walk_Mem( &mt, _callback, NULL );
	if( r != 0 ){ printf("ERR: walkM res=%d\n", r); return 3; }


	printf("-- Reset\n");

	r = TFTLV_Reset_File( &ft );
	if( r != 0 ){ printf("ERR: resetF res=%d\n", r); return 4; }
	r = TFTLV_Reset_Mem( &mt );
	if( r != 0 ){ printf("ERR: resetM res=%d\n", r); return 4; }

	printf("-- Item check\n");
	printf("- Mem: %d\n", TFTLV_HasItems_Mem( &mt ));
	printf("- File: %d\n", TFTLV_HasItems_File( &ft ));

	printf("-- File re-iterate\n");

	if( TFTLV_Walk_File( &ft, _callback, NULL ) != 0 ){
		printf("ERR: walkF\n"); return 5; }

	printf("-- Memory re-iterate\n");

	if( TFTLV_Walk_Mem( &mt, _callback, NULL ) != 0 ){
		printf("ERR: walkM\n"); return 5; }


	printf("-- Filing memory\n");

	for( i=0; i<4; i++ ){
		r = TFTLV_Add_ToMem( &mt, i, inputs[i].data, inputs[i].len );
		if( r != 0 ){ printf("ERR: pushM inp=%d res=%d\n", i, r); return 2; }
	}

	printf("-- Item check\n");
	printf("- Mem: %d\n", TFTLV_HasItems_Mem( &mt ));
	printf("- File: %d\n", TFTLV_HasItems_File( &ft ));

	printf("-- Draining mem to file\n");
	if( TFTLV_Drain_MemToFile( &mt, &ft ) != 0 ){
		printf("ERR: drain\n"); return 8; }

	printf("-- Item check\n");
	printf("- Mem: %d\n", TFTLV_HasItems_Mem( &mt ));
	printf("- File: %d\n", TFTLV_HasItems_File( &ft ));

	printf("-- File re-iterate\n");

	if( TFTLV_Walk_File( &ft, _callback, NULL ) != 0 ){
		printf("ERR: walkF\n"); return 5; }

	printf("-- Memory re-iterate\n");

	if( TFTLV_Walk_Mem( &mt, _callback, NULL ) != 0 ){
		printf("ERR: walkM\n"); return 5; }

	printf("-- File reset\n");

	r = TFTLV_Reset_File( &ft );
	if( r != 0 ){ printf("ERR: resetF res=%d\n", r); return 4; }

	printf("-- File re-iterate\n");

	if( TFTLV_Walk_File( &ft, _callback, NULL ) != 0 ){
		printf("ERR: walkF\n"); return 5; }

	printf("--- OK\n");
	return 0;
}


