// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "tf_crypto_private.h"

int TFC_Random( uint8_t *buffer, uint32_t len )
{

	int fd, flags = O_RDONLY;
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	// Obfuscated on purpose:
	char urp[] = "/de\x01/ur\x02nd\x03m\x00";
	urp[3]='v';
	urp[7]='a';
	urp[10]='o';

	// Strong open of /dev/urandom
	do {
		fd = OPEN( urp, flags, 0 );
		if( fd == -1 && errno == EINTR ) continue;
		if( fd == -1 ) return -1;
	} while(0);

	// Verify we got a character device
	struct stat stt;
	if( FSTAT(fd, &stt) != 0 || !S_ISCHR(stt.st_mode) ){
		CLOSE(fd); return -1; }

	// Strong read, including short-read handling
	ssize_t remain = (size_t)len;
	uint8_t *p = buffer;
	do {
		ssize_t res = READ( fd, p, remain );
		if( res == -1 && errno == EINTR ) continue;
		if( res == -1 ){ CLOSE(fd); return -1; }

		p += ((int)res);
		remain -= res;
		if( remain <= 0 ) break;
	} while(1);
	CLOSE(fd);

	// Confirm the random is not all zeros, using constant time
	int i, cnt = 0;
	for( i=0; i<len; i++){
		cnt += (buffer[i]|-buffer[i])>>31;
	}
	if( cnt == len ) return -1;

	// We read what we expected
	return 0;
}

