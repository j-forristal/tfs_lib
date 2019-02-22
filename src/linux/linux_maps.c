// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include "tf_linux.h"
#include PLATFORM_H

#define WORK_MAX	4

static const uint32_t PROCSELFMAPS[] = {0x58870f7d,0xcca7d340,0x5cd74a71,0xa5ffc14c,}; // "/proc/self/maps"

#define _STR_START      0x37f57f52
#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)

__attribute__ ((optnone,noinline))
static char *_decode( uint32_t sz, const uint32_t *in, uint32_t *work ){
        //ASSERT( sz <= WORK_MAX );
#pragma nounroll
        while( sz > 0 ){
                volatile uint32_t mask = sz << 26 | sz << 18 | sz << 10 | sz;
                work[sz] = in[sz] ^ in[sz-1] ^ 0xf557f75f ^ mask;
                sz--;
        }
        work[0] = in[0] ^ _STR_START;
        return (char*)work;
}


#define CB void (*cb)(void *state, void *start, void *end, char *perms, char *nom)

static int hex(char c)
{
	if( c >= '0' && c <= '9' ) return (int)(c - '0');
	if( c >= 'a' && c <= 'f' ) return (int)(c - 'a' + 10);
	if( c >= 'A' && c <= 'F' ) return (int)(c - 'A' + 10);
	return 0;
}

int TFLinux_Maps_Walk(void *state, CB)
{
	uint32_t work[WORK_MAX];

	int mfd;
	do { mfd = OPENAT(AT_FDCWD, _S(PROCSELFMAPS), O_RDONLY, 0); }
	while( mfd == -1 && errno == EINTR );
	if( mfd == -1 ) return -1; 

	off_t off = 0;
	char buff[8192];
	ssize_t r;
	while(1){
		do { r = PREAD(mfd, buff, sizeof(buff), off); } 
		while ( r == -1 && errno == EINTR );
		if( r <= 0 ) break;

		int i=0, s=0;
		while( i<r ){
			// start address
			uintptr_t start = 0;
			while( i<r && buff[i] != '-' ){
				start = (start << 4) + hex(buff[i]);
				i++;
			}
			i++;
			if( i>=r ) break;

			// end address
			uintptr_t end = 0;
			while( i<r && buff[i] != ' ' ){
				end = (end << 4) + hex(buff[i]);
				i++;
			}
			i++;
			if( i>=r ) break;

			char *perms = &buff[i];
			i += 5; // skip over perms + space
			if( i>=r ) break;

			// Skip over next thing (number)
			while( i<r && buff[i] != ' ' ) i++;
			if( i>=r ) break;

			i++; // space

			// fast forward over inode stuff
			while( i<r && buff[i] != ' ' ) i++;
			if( i>=r ) break;

			i++; // space

			// fast forward over inode stuff
			while( i<r && buff[i] != ' ' ) i++;
			if( i>=r ) break;

			// jump over spaces
			while( i<r && buff[i] == ' ' ) i++;
			if( i>=r ) break;

			char *nom = &buff[i];
		
			// find eol	
			while( i<r && buff[i] != '\n' ) i++;
			if( i>= r ) break;

			// save the end
			s = i + 1;

			buff[i] = 0;
			cb( state, (void*)start, (void*)end, perms, nom );

		} // while buffer iterator

		off += s; // We start at the beginning of last partial line

	} // while pread loop

	cb( state, NULL, NULL, NULL, NULL );
	while( CLOSE(mfd) == -1 && errno == EINTR );
	return 0;
}

