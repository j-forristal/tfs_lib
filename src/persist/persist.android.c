// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "tf_persist.h"
#include PLATFORM_H

//#include "tf_crypto.h"
#include "tf_cal.h"

// Per http://android-developers.blogspot.com/2013/02/using-cryptography-to-store-credentials.html
// Basically the Google-blessed way to store stuff is write it to a file with perms o-r.  Meh. :/
// We could do kludges to store things in the Android keystore, but that's only 4.3+ and past
// experience knows that to be a highly flaky option with non-deterministic potentially
// catastrophic timing delays.
//
// So, alas, for TTM, we are going to just use an internally stored file with restricted
// permissions until we identify something better.


#define HEADER_SIZE     (sizeof(uint32_t) + TCL_AES_BLOCK_SIZE + TCL_SHA256_DIGEST_SIZE)
#define MAGIC           0x7f505501

#define PATH_SIZE	512

static int _make_path( uint8_t path[PATH_SIZE], const uint8_t *key, const uint8_t *basepath )
{
	size_t l = STRLEN((const char*)basepath);
	size_t s = STRLEN((const char*)key);
	if( (l + s + 2) >= PATH_SIZE ) return -1;
	TFMEMCPY( path, basepath, l );
	path[l] = '/';
	TFMEMCPY( &path[l+1], key, s );
	path[l + s + 1]= 0;

	return 0;
}

static int _pfile_open( const uint8_t *key, const uint8_t *basepath, int fl )
{
	uint8_t path[PATH_SIZE];
	if( _make_path(path, key, basepath) != 0 ) return -1;

	int fd;
	do {
		fd = OPENAT( AT_FDCWD, (const char*)path, fl, 0600 );
	} while(fd == -1 && errno == EINTR);
	if( fd == -1 ) return -1;

	return fd;
}


int TFP_Get_Ex( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len, 
	uint8_t *ikey, uint32_t ikey_len, char *service )
{
	// NOTE: output, ikey can be NULL!  Service is ignored.
	ASSERT(key);
	ASSERT(basepath);
	ASSERT(len);

	int fd = _pfile_open( key, basepath, O_RDONLY );
	if( fd == -1 ) return TFP_ERR;

	struct stat stt;
	if( FSTAT(fd, &stt) == -1 || stt.st_size < TCL_SHA256_DIGEST_SIZE ){
		CLOSE(fd); return TFP_ERR; }

	uint32_t limit = *len;
	*len = stt.st_size;

	if( ikey != NULL ){
		if( stt.st_size < HEADER_SIZE ){
			CLOSE(fd);
			return TFP_ERR;
		}
		*len -= HEADER_SIZE;
	}

	// If too big or no data, return error
	if( *len > limit || *len == 0 ){ CLOSE(fd); return TFP_ERR; }

	// If output is NULL, the caller was just trying to lookup the size
	if( output == NULL ){ CLOSE(fd); return TFP_OK; }

	uint8_t *ptr = MMAP(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_PRIVATE, fd, 0);
	CLOSE(fd);
	if( ptr == MAP_FAILED) return TFP_ERR;

	if( ikey == NULL ){
		TFMEMCPY( output, ptr, stt.st_size );
		MUNMAP(ptr, stt.st_size);
		return TFP_OK;
	}

	// Check the magic
	uint32_t *u32 = (uint32_t*)ptr;
	if( *u32 != MAGIC ){
		MUNMAP(ptr, stt.st_size);
		return TFP_ERR;
	}

	// Copy over to output
	TFMEMCPY( output, &ptr[HEADER_SIZE], *len );

	// Check MAC
	uint8_t digest[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256_HMAC( ikey, ikey_len, output, *len, digest );
	if( MEMCMP( digest, &ptr[sizeof(uint32_t) + TCL_AES_BLOCK_SIZE], TCL_SHA256_DIGEST_SIZE ) != 0 ){
		MUNMAP(ptr, stt.st_size);
		return TFP_INTEGRITY;
	}

	// We are going to SHA256 the ikey, then use first 16 bytes as AES128 key
	uint8_t ikey_digest[TCL_SHA256_DIGEST_SIZE];
	if( TCL_SHA256( ikey, ikey_len, ikey_digest ) != 0 ){
		MUNMAP(ptr, stt.st_size);
		return TFP_ERR;
	}

	// Decrypt (in-place)
	if( TCL_AES_CTR( output, *len, ikey_digest, &ptr[sizeof(uint32_t)] ) != TCL_CRYPTO_OK ){
		MUNMAP(ptr, stt.st_size);
		return TFP_ERR;
	}

	// All set, cleanup
	MUNMAP(ptr, stt.st_size);
	return TFP_OK;
}

int TFP_Get( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len )
{
	return TFP_Get_Ex( key, basepath, output, len, NULL, 0, NULL );
}


int TFP_Set_Ex( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len, 
	uint8_t *ikey, uint32_t ikey_len, char *service )
{
	ASSERT(key);
	ASSERT(basepath);

	if( input == NULL ){
		// This is an attempt to erase the value
		uint8_t path[PATH_SIZE];
		if( _make_path(path, key, basepath) != 0 ) return -1;
		UNLINK(path);
		return TFP_OK;
	}

	int fd = _pfile_open( key, basepath, O_RDWR|O_CREAT|O_TRUNC );
	if( fd == -1 ) return TFP_ERR;

	int tries = 3;
	ssize_t ret;

	if( ikey != NULL ){
		// UH-OH: we can't encrypt in place, as caller may be passing in data that can't be changed;
		// So we have to create a copy.  :/
		uint8_t *ptr = (uint8_t*)MMAP(NULL, len + HEADER_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
		if( ptr == MAP_FAILED ){ CLOSE(fd); return TFP_ERR; }

		// We are going to SHA256 the ikey, then use first 16 bytes as AES128 key
		uint8_t ikey_digest[TCL_SHA256_DIGEST_SIZE];
		if( TCL_SHA256( ikey, ikey_len, ikey_digest ) != 0 ){ CLOSE(fd); MUNMAP(ptr, len+HEADER_SIZE); return TFP_ERR; }

		// Memory layout:
		// U32 + NONCE[16] - SHA256_HMAC[32] - DATA[...]

		// Set up the magic value
		uint32_t *u32 = (uint32_t*)ptr;
		*u32 = MAGIC;

		// Copy over the original data to our new buffer
		TFMEMCPY( &ptr[HEADER_SIZE], input, len );

		// Allocate a random nonce
		if( TCL_Random( &ptr[4], TCL_AES_BLOCK_SIZE ) != 0 ){ CLOSE(fd); MUNMAP(ptr, len+HEADER_SIZE); return TFP_ERR; }

		// Encrypt (in-place)
		if( TCL_AES_CTR( &ptr[HEADER_SIZE], len, ikey_digest, &ptr[4] ) != TCL_CRYPTO_OK ){
			CLOSE(fd); MUNMAP(ptr, len+HEADER_SIZE); return TFP_ERR; }

		// MAC
		TCL_SHA256_HMAC( ikey, ikey_len, &ptr[HEADER_SIZE], len, &ptr[4 + TCL_AES_BLOCK_SIZE] );

		// Now write to the file
		while( tries -- > 0 ){
			do { ret = PWRITE( fd, ptr, len+HEADER_SIZE, 0 ); } while(ret == -1 && errno == EINTR);
			if( ret == -1 || ret == len+HEADER_SIZE ) break;
		}
		MUNMAP(ptr, len+HEADER_SIZE);
		CLOSE(fd);
		if( ret != len+HEADER_SIZE) return TFP_ERR;
		return TFP_OK;
	}

	// Otherwise, just write out directly
	while( tries-- > 0 ){
		do { ret = PWRITE( fd, input, len, 0 ); } while( ret == -1 && errno == EINTR );
		if( ret == -1 || ret == len ) break;
	}
	CLOSE(fd);
	if( ret != len ) return TFP_ERR; 
	return TFP_OK;
}

int TFP_Set( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len )
{
	return TFP_Set_Ex( key, basepath, input, len, NULL, 0, NULL );
}
