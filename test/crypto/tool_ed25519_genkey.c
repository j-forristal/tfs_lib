#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "tf_crypto.h"
#include "tf_cal.h"
#include "ed25519.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

int main(int argc, char **argv){

	ed25519_public_key pk;
	ed25519_secret_key sk;

	if( argc < 2 ){
		printf("ERR: usage\n");
		return -1;
	}

	int fd = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if( fd == -1 ){
		printf("ERR: unable to open '%s'\n", argv[1]);
		return -1;
	}

	// Generate a random secret key
	TCL_Random( sk, sizeof(sk) );

	// Derive the public key
	ed25519_publickey( sk, pk );

	printf("Public:\n");
	dump_hex(pk, sizeof(pk));

	if( write(fd, sk, sizeof(sk)) != sizeof(sk) ){
		printf("ERR: Unable to write sk\n");
		return -1;
	}
	if( write(fd, pk, sizeof(pk)) != sizeof(pk) ){
		printf("ERR: Unable to write pk\n");
		return -1;
	}
	close(fd);

	printf("Private key written to %s\n", argv[1]);
	return 0;
}
