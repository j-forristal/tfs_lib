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
        assert( fd >= 0 );

        struct stat stt;
        assert( fstat(fd, &stt) == 0 );

        uint8_t *buffer = (uint8_t*)mmap(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
        assert( buffer != MAP_FAILED );
        close( fd );

	char hostname[256];
	memcpy( hostname, argv[1], strlen(argv[1]) + 1 );
	if( memcmp( &hostname[ strlen(hostname) - 4 ], ".der", 4 ) == 0 )
		hostname[ strlen(hostname) - 4 ] = 0;

	char *ptr = &hostname[ strlen(hostname) - 1 ];
	while( ptr > hostname && *ptr != '/' ) ptr--;
	if( *ptr == '/' ) ptr++;

	char subject[256];
	subject[0] = 0;
	int ret = TFS_PKCS7_X509_Parse( buffer, stt.st_size, NULL, 0, subject, ptr );
	if( ret == TFS_PKCS7_X509_OK_ERR_HOSTNAME ){
		printf("! ParseOK-HostnameFail subj='%s' file=%s\n", subject, argv[1]);
		return 1;
	}
	else if( ret == TFS_PKCS7_X509_OK ){
		printf("+ ParseOK-HostnameOK subj='%s' file=%s\n", subject, argv[1]);
		return 0;
	}

	printf("+ ParseFail res=%d file=%s\n", ret, argv[1]);
        return 2;
}
