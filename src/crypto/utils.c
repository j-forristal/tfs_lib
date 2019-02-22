// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <string.h>
#include "tf_crypto_private.h"

//
// General platform-portable volatile approach to memset; we reference the platform
// memset (which may be optimized) in a volatile way
//

static void*(* volatile memset_explicit)(void*s, int c, size_t n) = &MEMSET_REF;

void TFC_Erase( void *ptr, uint32_t len )
{
	memset_explicit( ptr, 0, len );
}

int TFC_Compare( const uint8_t a[16], const uint8_t b[16], const size_t size )
{
	uint8_t res = 0;
	size_t i;
 
	for (i = 0; i < size; i++) {
		res |= a[i] ^ b[i];
	}
	return (int)res; 
}
