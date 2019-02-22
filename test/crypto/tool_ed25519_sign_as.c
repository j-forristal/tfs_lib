#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "tf_crypto.h"
//#include "crypto_sign.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

int main(int argc, char**argv){

	unsigned char pk[TFC_ED25519_PK_SIZE];
	unsigned char sk[TFC_ED25519_SK_SIZE];

	if( argc < 3 ){
		printf("ERR: usage\n");
		return -1;
	}

	int fd = open(argv[1], O_RDONLY);
	if( fd == -1 ){
		printf("ERR: unable to open sk file '%s'\n", argv[1]);
		return -1;
	}
	if( read(fd, sk, sizeof(sk)) != sizeof(sk) ){
		printf("ERR: unable to read sk file\n");
		return -1;
	}
	if( read(fd, pk, sizeof(pk)) != sizeof(pk) ){
		printf("ERR: unable to read pk file\n");
		return -1;
	}
	close(fd);

	printf("PK: ");
	dump_hex( pk, 32 );
	//printf("SK: ");
	//dump_hex( sk, 32 );

	fd = open(argv[2], O_RDWR, 0);
	if( fd == -1 ){
		printf("ERR: failed to open '%s'\n", argv[2]);
		return -1;
	}

	struct stat stt;
	if( fstat(fd, &stt) != 0 ){
		printf("ERR: stat\n");
		return -1;
	}

	uint8_t *filemem = mmap(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_PRIVATE, fd, 0);
	if( filemem == MAP_FAILED ){
		printf("ERR: mmap; errno=%d\n", errno);
		return -1;
	}

	uint8_t *msg = filemem + 4 + TFC_ED25519_SIG_SIZE;
	uint32_t msglen = stt.st_size - 4 - TFC_ED25519_SIG_SIZE;

	uint8_t sig[TFC_ED25519_SIG_SIZE];
	memset( sig, 0, sizeof(sig) );

	assert( TFC_Ed25519_Sign( msg, msglen, sig, pk, sk ) == 0 );

	munmap( filemem, stt.st_size );

	//printf("SIG: ");
	//dump_hex( sig, sizeof(sig) );

	// write out the sig
	if( pwrite(fd, sig, sizeof(sig), 4) != sizeof(sig) ){
		printf("ERR: writing sig\n");
		return -1;
	}

	close(fd);
	printf("Ed25519 Signed\n");
	return 0;
}
