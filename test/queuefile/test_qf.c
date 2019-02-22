#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "tf_qf.h"


typedef struct {
	uint8_t *data;
	uint32_t len;
} inputs_t;


int main(void){

	unlink("/tmp/test.qf");


	int i;
	uint32_t cnt, dlen;

	inputs_t inputs[4];

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
	for( i=0; i<msg4sz; i++){ msg4[i] = (uint8_t)rand(); }
	inputs[3].data = msg4;
	inputs[3].len = msg4sz;

	uint32_t expected_cnt = 0;
	uint32_t expected_len = 0;

	printf("-- Basic push fill\n");

	TFQF_QueueFile_t qf;
	if( TFQF_Open( &qf, "/tmp/test.qf" ) != 0 ){
		printf("ERR: open\n");
		return 1;
	}

	cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
	if( cnt != expected_cnt || dlen != expected_len ){ 
		printf("ERR: stats0\n"); return 1; }

	for( i=0; i<4; i++ ){
		if( TFQF_Push( &qf, inputs[i].data, inputs[i].len ) != 0 ){
			printf("ERR: push inp=%d\n", i); return 2; }

		expected_cnt++;
		expected_len += inputs[i].len;

		cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
		if( cnt != expected_cnt || dlen != expected_len ){ 
			printf("ERR: stats inp=%d c=%d d=%d\n", i, cnt, dlen); return 1; }
	}

	printf("-- Memory iterate\n");

#ifndef NO_MEMORY
	TFQF_MemoryItem_t items[4];
	memset( items, 0, sizeof(items) );
	if( TFQF_Memory_Open( &qf, items, 4 ) != 4 ){
		printf("ERR: memopen\n"); return 9; }

	for( i=0; i<4; i++ ){
		printf("- item[%d] len=%d\n", i, items[i].data_len);
		if( items[i].data == NULL ){ 
			printf("ERR: mem%d null\n", i); return 8; }
		if( items[i].data_len != inputs[3-i].len ){ 
			printf("ERR: mem%d sz\n", i); return 8; }
		if( memcmp(items[i].data, inputs[3-i].data, items[i].data_len) != 0 ){
			printf("ERR: mem%d data\n", i); return 8; }

	}

	TFQF_Memory_Close( &qf );
#endif

	uint8_t buff[0xffff];
	uint16_t len = 0;

	printf("-- Basic pop drain\n");
	for( i=3; i>=0; i-- ){

		len = 0xffff;
		if( TFQF_Pop( &qf, buff, &len ) != 0 ){
			printf("ERR: pop%d len=%d qflmp=%d qfnxt=%d\n", 
				i, len, qf.lmp, qf.nxt); return 3; }
		if( len != inputs[i].len || memcmp(buff, inputs[i].data, len) != 0 ){
			printf("ERR: pop%d data\n", i); return 4; }

		expected_cnt--;
		expected_len -= len;

		cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
		if( cnt != expected_cnt || dlen != expected_len ){ 
			printf("ERR: stats%dp\n", i); return 1; }

	}

	cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
	if( cnt != 0 || dlen != 0 ){ printf("ERR: stats0p\n"); return 1; }

	len = 0xffff;
	if( TFQF_Pop( &qf, buff, &len ) == 0 && len != 0 ){
		printf("ERR: expected empty\n"); return 5; }

	TFQF_Close( &qf );


	printf("-- Add/close/open/check\n");
	if( TFQF_Open( &qf, "/tmp/test.qf" ) != 0 ){
		printf("ERR: open2\n");
		return 1;
	}

	cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
	if( cnt != 0 || dlen != 0 ){ printf("ERR: stats0.2\n"); return 1; }

	if( TFQF_Push( &qf, msg1, msg1sz ) != 0 ){
		printf("ERR: push1.2\n"); return 2; }

	TFQF_Close( &qf );


	if( TFQF_Open( &qf, "/tmp/test.qf" ) != 0 ){
		printf("ERR: open3\n");
		return 1;
	}

	cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
	if( cnt != 1 || dlen != msg1sz ){
		printf("ERR: stats1.3 c=%d d=%d\n", cnt, dlen); return 1; }

	len = 0xffff;
	if( TFQF_Pop( &qf, buff, &len ) != 0 ){
		printf("ERR: pop1.3 len=%d\n", len); return 3; }
	if( len != msg1sz || memcmp(buff, msg1, len) != 0 ){
		printf("ERR: pop1.3 data\n"); return 4; }

	TFQF_Close( &qf );


	printf("--- Pre-prune fill\n");
	if( TFQF_Open( &qf, "/tmp/test.qf" ) != 0 ){
		printf("ERR: open3\n");
		return 1;
	}

	for( i=0; i<12; i++ ){
		if( TFQF_Push( &qf, inputs[0].data, inputs[0].len ) != 0 ){
			printf("ERR: prune push %d\n", i); return 12; }
	}

	cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
	if( cnt != 12 ){
		printf("ERR: prune stats c=%d d=%d\n", cnt, dlen); return 1; }

	printf("--- Prune drain\n");
	for( i=0; i<4; i++ ){
		if( TFQF_Prune( &qf, 3 ) != 3 ){
			printf("ERR: prune%d\n", i); return 14; }
		
		cnt = dlen = 0; TFQF_Stats( &qf, &cnt, &dlen );
		if( cnt != (9 - (i*3)) ){
			printf("ERR: post-prune stats %d c=%d d=%d\n", i, cnt, dlen);
			return 14; }
	}

	printf("--- OK\n");
	return 0;
}


