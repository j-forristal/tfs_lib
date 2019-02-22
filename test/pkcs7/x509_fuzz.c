#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "tf_pkcs7.h"

void dump_hex( uint8_t* hex, uint32_t cnt );

int main(int argc, char **argv){

        int fd = open( argv[1], O_RDONLY);
	if( fd == -1 ) return 0;

        struct stat stt;
        if( fstat(fd, &stt) != 0 ) return 0;

        uint8_t *buffer = (uint8_t*)mmap(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
        if (buffer == MAP_FAILED ) return 0;
        close( fd );

	char subject[256];
	subject[0] = 0;

	uint8_t *spki;
	uint32_t spki_len;

	TFS_PKCS7_X509_Parse( buffer, stt.st_size, &spki, &spki_len, subject, "www.example.com" );
	// Doesn't matter the result, since fuzz garbage in will garbage out; the important
	// thing is that we don't crash, leak mem, overflow, etc.

        return 0;
}
