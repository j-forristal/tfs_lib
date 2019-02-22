#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tf_crypto.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

int main(int argc, char**argv){

	unsigned char pk[TFC_ED25519_PK_SIZE];

	if( argc < 3 ){
		printf("ERR: usage (hex pk) (as file)\n");
		return -1;
	}

	if( load_hex(argv[1], pk, sizeof(pk)) != sizeof(pk) ){
		printf("ERR: loading pk\n");
		return -1;
	}

	printf("PK: ");
	dump_hex( pk, 32 );

	int fd = open(argv[2], O_RDWR, 0);
	if( fd == -1 ){
		printf("ERR: failed to open '%s'\n", argv[2]);
		return -1;
	}

	struct stat stt;
	if( fstat(fd, &stt) != 0 ){
		printf("ERR: stat\n");
		return -1;
	}

	uint8_t *filemem = mmap(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
	if( filemem == MAP_FAILED ){
		printf("ERR: mmap\n");
		return -1;
	}

	uint8_t *msg = filemem + 4 + TFC_ED25519_SIG_SIZE;
	uint32_t msglen = (stt.st_size - 4 - TFC_ED25519_SIG_SIZE);
	uint8_t *sig = filemem + 4;

	//printf("SIG: ");
	//dump_hex( sig, 64 );

	if( TFC_Ed25519_Verify( msg, msglen, sig, pk ) != 0 ){
		printf("Verify FAIL\n");
		return -1;
	}

	printf("Verify OK\n");
	return 0;
}
