// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <string.h>

#include "tf_netsec.h"

#include PLATFORM_H

#define WORK_MAX	8

static const uint32_t HTTPS[] = {0x47810b3a,0x99fdc217,0x64a23d4a,}; // "https://"
static const uint32_t HTTP[] = {0x47810b3a,0xb6fdd75e,}; // "http://"

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



int TFN_Url_Parse( uint8_t *data, uint32_t datalen, TFN_Url_t *url )
{
	uint32_t work[WORK_MAX];

	if( data == NULL || url == NULL ) return -1;
	// The smallest possible url we support is "http://x/"
	if( datalen < 9 ) return -1;

	// Clear out structure and set up defaults
	MEMSET( url, 0, sizeof(TFN_Url_t) );
	url->port = 80;
	uint8_t *end = data + datalen;
	uint8_t *ptr = data + 7;
	int i;

	// Figure out the protocol
	if( MEMCMP( data, _S(HTTPS), 8 ) == 0 ){
		url->is_ssl = 1;
		url->port = 443;
		ptr++;
	}
	else if( MEMCMP( data, _S(HTTP), 7 ) != 0 ){
		// unrecognized protocol
		return -1;
	}

	// Copy the hostname
	for( i=0; i<(sizeof(url->hostname) - 1); i++){
		// We require a '/' after hostname:
		if( ptr == end ) return -1;
		if( *ptr == ':' || *ptr == '/' ) break;
		url->hostname[i] = *ptr;
		ptr++;
	}
	// NOTE: last char is already NULL due to prior memset

	// Optional: parse the port
	if( *ptr == ':' ){
		// need to parse the port
		ptr++;
		uint16_t v = 0;
		// NOTE: this code allows values > 65535 and
		// port value rollover.  It is not going to try
		// to enforce a limit.
		while(1){
			if( ptr == end ) return -1;
			if( *ptr == '/' ) break;
			if( *ptr < '0' || *ptr > '9' ) return -1;
			v = (v * 10) + (*ptr - '0');
			ptr++;
		}
		url->port = v;
	}

	// The rest is the path and query
	// NOTE: we copy the initial '/' too
	for( i=0; i<(sizeof(url->path_and_query) - 1); i++){
		if( ptr == end ) return 0;
		url->path_and_query[i] = *ptr;
		ptr++;
	}
	// NOTE: last char is already NULL due to prior memset

	// If we get here, it means we hit pq max before we hit
	// the end of the input url.  That means it's an error.
	return -1;
}
