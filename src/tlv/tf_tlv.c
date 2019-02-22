// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/file.h>

#include PLATFORM_H

#include "tf_tlv.h"
#include "tf_cal.h"

//
// Internal structs & values
//

#define TFTLV_TYPE_SIGNED               0x01
#define TFTLV_TYPE_PROTECTED            0x02
#define TFTLV_TYPE_MEM			0x80

#define TFTLV_MAGIC 0x7f5201

typedef struct __attribute__((packed, aligned(4))) {
	uint32_t magic : 24;
	uint32_t typ : 8;
} TFTLV_Header_t;

typedef struct __attribute__((packed, aligned(4))) {
	uint8_t sig[TFTLV_SIG_SIZE];
	uint32_t magic2; // NOTE: counts as signed data
} TFTLV_Option_Signature_t;

typedef struct __attribute__((packed, aligned(4))) {
	uint8_t  nonce[TCL_SHA256_DIGEST_SIZE];
	uint8_t  nonce_check[TCL_SHA256_DIGEST_SIZE];
} TFTLV_Option_Integrity_t;

#define _OFFSET_OPTION		(sizeof(TFTLV_Header_t))
// NOTE: SIGNED_DATA includes the magic2 value at end of Signature_t
#define _OFFSET_SIGNED_DATA	(sizeof(TFTLV_Header_t) + sizeof(TFTLV_Option_Signature_t) - sizeof(uint32_t))
#define _OFFSET_PROTECTED_DATA	(sizeof(TFTLV_Header_t) + sizeof(TFTLV_Option_Integrity_t))

//
// Forward declarations
//

static uint8_t _walk( uint8_t *data, size_t sz, uint8_t *key, TFTLV_CALLBACK(callback), const void *state, int *reset );
static uint8_t _serialize( TFTLV_Mem_t *mt, uint8_t tag, uint8_t *msg, uint16_t len, uint8_t *key, int copybody );

//
// IO functions
//

static void _io_close( int fd )
{
#ifndef O_EXLOCK
	int res;
	do {
		res = FLOCK(fd, LOCK_UN);
	} while( res == -1 && errno == EINTR );
	// Even if there is an error, we will proceed
#endif

	CLOSE(fd);
}

static int _io_open_size( uint8_t *path, struct stat *stt )
{
	ASSERT(path);
	ASSERT(stt);

	int fd;
#ifdef O_EXLOCK
	stt->st_size |= (off_t)O_EXLOCK;
#endif
	do {
		fd = OPEN( (char*)path, (int)stt->st_size, 0600 );
	} while( fd == -1 && errno == EINTR );
	if( fd == -1 ) return -1;

	int res;
#ifndef O_EXLOCK
	do {
		res = FLOCK(fd, LOCK_EX);
	} while( res == -1 && errno == EINTR );
	if( res == -1 ){
		CLOSE(fd); // NOTE: no _io_close
		return -2;
	}
#endif

	do {
		res = FSTAT( fd, stt );
	} while( res == -1 && errno == EINTR );
	if( res == -1 ){
		_io_close(fd);
		return -3;
	}

	return fd;
}

static uint8_t _io_write( int fd, uint8_t *data, size_t remain)
{
	ASSERT( fd >= 0 );
	ASSERT(data);
	ASSERT(remain > 0);
	do {
		ssize_t actual = WRITE(fd, data, remain);
		if( actual < 0 ){
			if( errno == EINTR ) continue;
			return TFTLV_RET_IO;
		}
		data += actual;
		remain -= actual;
	} while(remain > 0);
	return TFTLV_RET_OK;
}


//
// Main init functions
//

// RW Memory (no file backing, no signature, no protection)
uint8_t TFTLV_Init_Mem( TFTLV_Mem_t *mt, size_t sz )
{
	// Check parameters
	if( mt ==  NULL || sz == 0 ) return TFTLV_RET_PARAMETERS;

	// Initialize structure
	MEMSET( mt, 0, sizeof(TFTLV_Mem_t) );
	mt->msg_max_size = 0x7f80;

	// We are going to add a header, so all functions can reference a base header
	sz += sizeof(TFTLV_Header_t);

	// Allocate the memory & configure the struct
	mt->mem = (uint8_t*)MMAP(NULL, sz, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if( mt->mem == MAP_FAILED ){
		mt->dbg = __LINE__;
		return TFTLV_RET_IO;
	}
	mt->mem_max_sz = sz;
	mt->tail_offset = sizeof(TFTLV_Header_t);

	// Create the placeholder header
	TFTLV_Header_t *hptr = (TFTLV_Header_t*)mt->mem;
	hptr->magic = TFTLV_MAGIC;
	hptr->typ = TFTLV_TYPE_MEM;
	
	// All set
	return TFTLV_RET_OK;
}


// RO Memory from signed file (file N/A, signature, no protection)
uint8_t TFTLV_Init_MemFromSignedMem( TFTLV_Mem_t *mt, const uint8_t *data, uint32_t len, TFTLV_SIGCALLBACK(callback) )
{
	// Check parameters
	if( mt ==  NULL || data == NULL || callback == NULL ) return TFTLV_RET_PARAMETERS;

	// If it's too small to be valid, abort
	if( len < _OFFSET_SIGNED_DATA ){
		return TFTLV_RET_FORMAT;
	}

	// Now init a memory structure
	uint8_t res = TFTLV_Init_Mem( mt, len );
	if( res != TFTLV_RET_OK ) return res;

	// Copy the file contents into the new memory at the base; this
	// tramples the fake header put there by Init_Mem()
	TFMEMCPY( mt->mem, data, len );
	mt->tail_offset = (uint32_t)len;

	// Check the header
	TFTLV_Header_t *header = (TFTLV_Header_t*)mt->mem;
	if( header->magic != TFTLV_MAGIC || header->typ != TFTLV_TYPE_SIGNED ){
		MUNMAP( mt->mem, len );
		return TFTLV_RET_FORMAT;
	}

	// Use the callback to validate the signature
	TFTLV_Option_Signature_t *signature = (TFTLV_Option_Signature_t*)&mt->mem[_OFFSET_OPTION];
	uint8_t otp[TFTLV_OTP_SIZE];
	res = callback( (uint8_t*)&mt->mem[_OFFSET_SIGNED_DATA], (uint32_t)(len - _OFFSET_SIGNED_DATA),
		signature->sig, otp );
	if( res != TFTLV_RET_OK )
	{
		// Signature failure or error
		MUNMAP( mt->mem, len );
		return res;
	}

	// Apply the OTP to the data parts
	uint8_t *ptr = (uint8_t*)&mt->mem[_OFFSET_SIGNED_DATA];
	int i;
	for( i=0; i<(len - _OFFSET_SIGNED_DATA); i++){
		*ptr = (*ptr) ^ otp[i % TFTLV_OTP_SIZE];
		ptr++;
	}

	// If OTP was successful, magic2 should now be a valid value
	if( signature->magic2 != TFTLV_MAGIC ){
		MUNMAP( mt->mem, len );
		return TFTLV_RET_FORMAT;
	}

	// TODO: lock memory/make RO?

	// Walk the data items to ensure correctness
	res = TFTLV_Walk_Mem( mt, NULL, NULL );
	if( res != TFTLV_RET_OK ){
		// Kinda weird that it would pass signature validation but not walk correctly;
		// that's a bit suspicious of integrity tampering
		// TODO: think deeper on whether to call this tampering or not
		MUNMAP( mt->mem, len );
		return res;
	}

	// All set
	return TFTLV_RET_OK;
}

// RO Memory from signed file (file backing, signature, no protection); FILE MUST EXIST
uint8_t TFTLV_Init_MemFromSignedFile( TFTLV_Mem_t *mt, const char *path, TFTLV_SIGCALLBACK(callback) )
{
	// Check parameters
	if( mt ==  NULL || path == NULL || callback == NULL ) return TFTLV_RET_PARAMETERS;

	// Open the file and figure out the size
	struct stat stt;
	stt.st_size = (off_t)(O_RDWR); // NOTE: we expect it to exist
	int fd = _io_open_size( (uint8_t*)path, &stt );
	if( fd < 0 ){
		if( errno == ENOENT ) return TFTLV_RET_NOTEXIST;
		mt->dbg = __LINE__;
		return TFTLV_RET_IO;
	}

	// If it's too small to be valid, abort
	if( stt.st_size < _OFFSET_SIGNED_DATA ){
		//CLOSE(fd);
		_io_close(fd);
		return TFTLV_RET_FORMAT;
	}

	// Map the file
	uint8_t *fmem = (uint8_t*)MMAP(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
	//CLOSE(fd); // We don't need the file handle any more
	_io_close(fd);
	if( fmem == MAP_FAILED ){
		mt->dbg = __LINE__;
		return TFTLV_RET_IO;
	}

	// Now have MemFromSignedMem do the dirty work
	uint8_t res = TFTLV_Init_MemFromSignedMem( mt, fmem, (uint32_t)stt.st_size, callback );
	MUNMAP(fmem, stt.st_size);
	return res;
}


static uint8_t _init_file( TFTLV_File_t *ft, int fd, uint8_t key[TFTLV_KEY_SIZE] )
{
	TFTLV_Header_t *hptr;
	TFTLV_Option_Integrity_t *iptr;

	uint8_t header[ _OFFSET_PROTECTED_DATA ];
	hptr = (TFTLV_Header_t*)header;
	hptr->magic = TFTLV_MAGIC;
	hptr->typ = TFTLV_TYPE_PROTECTED;

	iptr = (TFTLV_Option_Integrity_t*)&header[ _OFFSET_OPTION ];
	TCL_Random( iptr->nonce, sizeof(iptr->nonce) );
	TCL_SHA256_HMAC( key, TFTLV_KEY_SIZE, iptr->nonce, sizeof(iptr->nonce),
		iptr->nonce_check );

	return _io_write( fd, header, sizeof(header) );
}


// File (file backed, no signature, with protection); FILE MAY NOT EXIST (will be created as needed)
uint8_t TFTLV_Init_ProtectedFile( TFTLV_File_t *ft, const char *path, uint8_t key[TFTLV_KEY_SIZE] )
{
	// Check parameters
	if( ft ==  NULL || path == NULL ) return TFTLV_RET_PARAMETERS;

	// Initialize the object
	MEMSET( ft, 0, sizeof(TFTLV_File_t) );
	ft->msg_max_size = 0x7f80;

	// Copy over some persistent data items
	struct stat stt;
	stt.st_size = STRLEN(path);
	if( stt.st_size >= sizeof(ft->path) ) return TFTLV_RET_PARAMETERS;
	TFMEMCPY( ft->path, path, stt.st_size + 1 ); // +1 for NULL
	TFMEMCPY( ft->key, key, TFTLV_KEY_SIZE );

	// Open the file and figure out the size
	stt.st_size = (off_t)(O_RDWR);
	int fd = _io_open_size( ft->path, &stt );
	if( fd < 0 )
	{
		// If it doesn't exist, we consider that a successful open
		if( errno == ENOENT ) return TFTLV_RET_OK;
		ft->dbg = __LINE__;
		return TFTLV_RET_IO;
	}

	if (stt.st_size < _OFFSET_PROTECTED_DATA ) {
		// Bad size, corrupted
		//CLOSE(fd);
		_io_close(fd);
		return TFTLV_RET_FORMAT;
	}

	// If we get here, it's an existing file of at least minimum expected header size
	_io_close(fd);

	// Use a non-callback walk to verify the header and validate the TLVs
	// NOTE: walk will re-open the file from the beginning
	return TFTLV_Walk_File( ft, NULL, NULL );
}


//
// Walk the TLV tag data
//

uint8_t TFTLV_Walk_Mem( TFTLV_Mem_t *mt, TFTLV_CALLBACK(callback), const void *state )
{
	// Check parameters
	if( mt == NULL ) return TFTLV_RET_PARAMETERS;
	// NOTE: callback and state can be NULL

	// Calculate how much data this memory region holds, and where the data starts
	uint8_t *ptr = &mt->mem[ _OFFSET_OPTION ];
	if( ((TFTLV_Header_t*)mt->mem)->typ == TFTLV_TYPE_SIGNED ){
		ptr = &mt->mem[ _OFFSET_SIGNED_DATA ];
		// SPECIAL: skip over magic2 at end of Signature_t header
		ptr += sizeof(uint32_t);
	}
	uint32_t sz = mt->tail_offset - ((uint32_t)((ptr - mt->mem) & 0xffffffff));

	// If there is no data, we exit with success
	if( sz == 0 ){
		if( callback != NULL ) callback( TFTLV_CB_TAG_END, 0, NULL, state );
		return TFTLV_RET_OK;
	}

	// Lock the memory (simple spinlock)
	while( !__sync_bool_compare_and_swap( &mt->lock, 0, 1 ) ){}
	__sync_synchronize();

	// Do the walk
	int reset = 0;
	uint8_t res = _walk( ptr, sz, NULL, callback, state, &reset );
	
	// Reset while we hold the lock
	if( reset ) TFTLV_Reset_Mem( mt );

	// Unlock the memory
	__sync_synchronize();
	mt->lock = 0;
	
	// Return whatever the result was
	return res;
}

uint8_t TFTLV_Walk_File( TFTLV_File_t *ft, TFTLV_CALLBACK(callback), const void *state )
{
	uint8_t res = TFTLV_RET_FORMAT;
	void *mem;
	TFTLV_Header_t *hptr;
	TFTLV_Option_Integrity_t *iptr;
	int reset = 0;

	// Check parameters
	if( ft == NULL ) return TFTLV_RET_PARAMETERS;
	// NOTE: callback and state can be NULL

	// Open file and get size
	struct stat stt;
	stt.st_size = (off_t)(O_RDWR);
	int fd = _io_open_size( ft->path, &stt );
	if( fd < 0 ){
		if( errno == ENOENT ){
			if( callback != NULL ) callback( TFTLV_CB_TAG_END, 0, NULL, state );
			return TFTLV_RET_OK;
		}
		ft->dbg = __LINE__;
		return TFTLV_RET_IO;
	}

	// Check minimum size
	if( stt.st_size < _OFFSET_PROTECTED_DATA ){
		// Res is already set to RET_FORMAT
		goto done;
	}

	// If it's empty (we are not going to validate the headers), just return success
	if( stt.st_size == _OFFSET_PROTECTED_DATA ){
		if( callback != NULL ) callback( TFTLV_CB_TAG_END, 0, NULL, state );
		res = TFTLV_RET_OK;
		goto done;
	}

	// Map the file
	mem = MMAP( NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0 );
	if( mem == MAP_FAILED ){
		res = TFTLV_RET_IO;
		ft->dbg = __LINE__;
		goto done;
	}

	// Check the header
	hptr = (TFTLV_Header_t*)mem;
	if( hptr->magic != TFTLV_MAGIC || hptr->typ != TFTLV_TYPE_PROTECTED ){
		// res is already RET_FORMAT
		goto almost_done;
	}

	// Confirm the right HMAC key
	iptr = (TFTLV_Option_Integrity_t*)&mem[ _OFFSET_OPTION ];
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256_HMAC( ft->key, sizeof(ft->key), iptr->nonce, sizeof(iptr->nonce), hash );
	if( MEMCMP( iptr->nonce_check, hash, sizeof(hash) ) != 0 ){
		res = TFTLV_RET_WRONGKEY;
		goto almost_done;
	}

	// Do the walk
	res = _walk( &mem[ _OFFSET_PROTECTED_DATA ], (uint32_t)(stt.st_size - _OFFSET_PROTECTED_DATA),
		ft->key, callback, state, &reset );

almost_done:
	MUNMAP( mem, stt.st_size );
done:
	// Reset while the file is open (which is the EXLOCK)
	if( reset ){
		UNLINK( (char*)ft->path );
	}

	_io_close(fd);
	return res;
}

static uint8_t _walk( uint8_t *data, size_t sz, uint8_t *key, TFTLV_CALLBACK(callback), const void *state, int *reset )
{
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];

	if( data == NULL ) return TFTLV_RET_IO;
	// NOTE: Callback, key, state allowed to be NULL

	// Loop while there are at least tag & len bytes available
	while( sz >= 2 ){
		uint8_t tag = *data++;
		uint16_t len = *data++; // NOTE: assign 1 byte to 2 byte variable
		sz -= 2;

		// Check for extended length
		if( len & 0x80 ){
			if( sz == 0 ) return TFTLV_RET_FORMAT; // Corrupted/overflow
			len = ((len & 0x7f)<<8)|(*data++);
			sz--;
		}
		if( len > sz ) return TFTLV_RET_FORMAT; // Corrupted/overflow

		// Check for optional integrity
		uint16_t clen = len;
		if( key != NULL ){
			if( len < TCL_SHA256_DIGEST_SIZE ){
				// Corrupted/integrity failure
				return TFTLV_RET_FORMAT;
			}
			clen -= TCL_SHA256_DIGEST_SIZE;
			TCL_SHA256_HMAC( key, TFTLV_KEY_SIZE, 
				&data[TCL_SHA256_DIGEST_SIZE], clen, hash );
			if( MEMCMP( data, hash, sizeof(hash) ) != 0 ){
				// Corrupted/integrity failure
				return TFTLV_RET_INTEGRITY;
			}
			data += TCL_SHA256_DIGEST_SIZE;
		}

		// Call the callback, if warranted
		if( callback != NULL ){
			uint8_t cbres = callback( tag, clen, data, state );
			if( cbres & TFTLV_CB_RET_RESET ) *reset = 1;
			if( cbres & TFTLV_CB_RET_STOP ) return TFTLV_RET_OK;
		}
		sz -= len;
		data += clen;
	}

	// Inform the callback that we are done
	if( callback != NULL ){
		uint8_t cbres = callback( TFTLV_CB_TAG_END, 0, NULL, state );
		if( cbres & TFTLV_CB_RET_RESET ) *reset = 1;
	}

	if( sz > 0 ) return TFTLV_RET_FORMAT; // Trailing byte(s)
	return TFTLV_RET_OK;
}


static uint8_t _serialize( TFTLV_Mem_t *mt, uint8_t tag, uint8_t *msg, uint16_t len, 
	uint8_t *key, int copymsg )
{
	ASSERT(mt);
	ASSERT(msg);
	ASSERT(len > 0);

	uint8_t *data = &mt->mem[mt->tail_offset];
	uint8_t res = TFTLV_RET_OK;

	uint16_t dlen = len;

	// Calculate the (optional) hash 
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	if( key != NULL ){
		TCL_SHA256_HMAC( key, TFTLV_KEY_SIZE, msg, len, hash );
		dlen += TCL_SHA256_DIGEST_SIZE;
	}

	// Calculate the target size
	size_t sz = 2 + dlen;
	if( dlen > 0x7f ) sz++;

	// Make sure there is enough space
	if( (mt->tail_offset + sz) > mt->mem_max_sz ){
		res = TFTLV_RET_OVERFLOW;
		goto done;
	}

	// Construct tag and length
	data[0] = tag;
	if( dlen > 0x7f ){
		data[1] = ((dlen >> 8) & 0x7f) | 0x80;
		data++;
	}
	data[1] = dlen & 0xff;
	data += 2;

	// Optional integrity header
	if( key != NULL ){
		TFMEMCPY( data, hash, TCL_SHA256_DIGEST_SIZE );
		data += TCL_SHA256_DIGEST_SIZE;
	}

	// Copy message data
	if( copymsg > 0 ){
		TFMEMCPY( data, msg, len );
	} else {
		// We didn't write msg, so subtract it from sz
		sz -= len;
	}

	// Update the offset counter
	mt->tail_offset += sz;

done:
	return res;
}


//
// Add/append a tag to the end of a memory buffer
//
uint8_t TFTLV_Add_ToMem( TFTLV_Mem_t *mt, uint8_t tag, uint8_t *msg, uint16_t len )
{
	uint8_t res = TFTLV_RET_OK;
	if( mt == NULL || msg == NULL || len == 0 ) return TFTLV_RET_PARAMETERS;
	if( len > mt->msg_max_size ) return TFTLV_RET_BIGMSG;

	// Lock the memory (simple spinlock)
	while( !__sync_bool_compare_and_swap( &mt->lock, 0, 1 ) ){}
	__sync_synchronize();

	// Write the TLV directly to the memory buffer
	res = _serialize( mt, tag, msg, len, NULL, 1 );

	// Unlock the memory
	__sync_synchronize();
	mt->lock = 0;
	
	// Return whatever the serialize result was
	return res;
}


//
// Add/append a tag to the end of the (protected) file
//
uint8_t TFTLV_Add_ToFile( TFTLV_File_t *ft, uint8_t tag, uint8_t *msg, uint16_t len )
{
	uint8_t res = TFTLV_RET_OK;
	struct stat stt;
	int fd;

	if( ft == NULL || msg == NULL || len == 0 ) return TFTLV_RET_PARAMETERS;
	if( len > ft->msg_max_size ) return TFTLV_RET_BIGMSG;

	uint8_t mem[ TCL_SHA256_DIGEST_SIZE + 8 ];
	size_t sz = sizeof(mem) + len; // SPECIAL: have to include msg len, but we won't copy it

	// Construct a memory struct to wrap the temp buffer
	TFTLV_Mem_t mt;
	mt.mem = mem;
	mt.tail_offset = 0;
	mt.mem_max_sz = (uint32_t)sz;
	// NOTE: .lock, .msg_max_size are don't care/unused values

	// Serialize the data (header) into temp buffer; we don't actually
	// serialize the msg itself, to save a copy
	res = _serialize( &mt, tag, msg, len, ft->key, 0 );
	if( res != TFTLV_RET_OK ) goto done;

	// Open the file for append
	stt.st_size = (off_t)(O_RDWR|O_APPEND|O_CREAT);
	fd = _io_open_size( ft->path, &stt );
	if( fd < 0 ){
		ft->dbg = __LINE__;
		res = TFTLV_RET_IO;
		goto done;
	}

	// Check if we need to create a new header
	if( stt.st_size == 0 ){
		if( _init_file( ft, fd, ft->key ) != TFTLV_RET_OK ){
			ft->dbg = __LINE__;
			res = TFTLV_RET_IO;
			goto almost_done;
		}
		stt.st_size = _OFFSET_PROTECTED_DATA;
	}

	// Confirm minimum possible header length (although we don't actually validate
	// the header, we just append to whatever is there; some future walk will validate
	// and throw an error).  This does risk appending our data to some other file, but
	// in order to get here, the file had to go through TFTLV_Init_ProtectedFile(),
	// which means it was our valid file at some point ... so appending blindly is
	// a reasonable calculated risk.
	if( stt.st_size < _OFFSET_PROTECTED_DATA ){
		res = TFTLV_RET_FORMAT;
		goto almost_done;
	}

	// Now append it to the file -- first the msg header, then the msg itself
	res = _io_write( fd, mt.mem, mt.tail_offset );
	if( res == TFTLV_RET_OK ){
		res = _io_write( fd, msg, len );
	}

almost_done:
	// Clean up our open descriptor (which also releases our EXLOCK)
	_io_close(fd);

done:
	// Return the result
	return res;
}

uint8_t TFTLV_Reset_Mem( TFTLV_Mem_t *mt )
{
	if( mt == NULL ) return TFTLV_RET_PARAMETERS;

	// Reset of a memory buffer is basically just updating
	// the tail offset back to the beginning
	// NOTE: a Signed memory buffer won't reset
	if( ((TFTLV_Header_t*)mt->mem)->typ == TFTLV_TYPE_MEM )
		mt->tail_offset = _OFFSET_OPTION;

	return TFTLV_RET_OK;
}

uint8_t TFTLV_Reset_File( TFTLV_File_t *ft )
{
	uint8_t res = TFTLV_RET_OK;
	//int r;

	if( ft == NULL ) return TFTLV_RET_PARAMETERS;

	struct stat stt;
	stt.st_size = (size_t)O_RDWR;
	int fd = _io_open_size( ft->path, &stt );
	if( fd < 0 ){
		//if( errno == ENOENT ) return TFTLV_RET_NOTEXIST;
		if( errno == ENOENT ) return TFTLV_RET_OK;
		ft->dbg = __LINE__;
		return TFTLV_RET_IO;
	}

	if( UNLINK((char*)ft->path) != 0 ) res = TFTLV_RET_IO;
	_io_close(fd);
	return res;
}

uint8_t TFTLV_HasItems_Mem( TFTLV_Mem_t *mt )
{
	if( mt == NULL ) return 0;

        uint8_t *ptr = &mt->mem[ _OFFSET_OPTION ];
        if( ((TFTLV_Header_t*)mt->mem)->typ == TFTLV_TYPE_SIGNED ){
                ptr = &mt->mem[ _OFFSET_SIGNED_DATA ];
                // SPECIAL: skip over magic2 at end of Signature_t header
                ptr += sizeof(uint32_t);
        }
        uint32_t sz = mt->tail_offset - ((uint32_t)((ptr - mt->mem) & 0xffffffff));

        // If there is no data, we exit with success
        if( sz == 0 ) return 0;
	return 1;
}

uint8_t TFTLV_HasItems_File( TFTLV_File_t *ft )
{
	if( ft == NULL ) return 0;

        // Open file and get size
        struct stat stt;
        stt.st_size = (off_t)(O_RDWR); 
        int fd = _io_open_size( ft->path, &stt );
        if( fd < 0 ) return 0;
	_io_close(fd);

	// Using simple size check to see if we have "items"
	if( stt.st_size > _OFFSET_PROTECTED_DATA ) return 1;
	return 0;
}

typedef struct {
	TFTLV_File_t *ft;
	int wrote;
	int err;
} _drain_st_t;

static TFTLV_CALLBACK_DEF(_draincb){

	ASSERT(state);
	_drain_st_t *st = (_drain_st_t*)state;

	// Are we done walking? If so, reset the mq
	if( data == NULL && tag == TFTLV_CB_TAG_END ){
		if( st->err == 0 ) return TFTLV_CB_RET_RESET;
		return TFTLV_CB_RET_STOP;
	}

	// Write the item to the file
	uint8_t qres = TFTLV_Add_ToFile( st->ft, tag, data, len );
	if( qres == TFTLV_RET_OK ){
		st->wrote++;
		return TFTLV_CB_RET_CONTINUE;
	}

	// Error situation
	st->err++;
	return TFTLV_CB_RET_STOP;
}

uint8_t TFTLV_Drain_MemToFile( TFTLV_Mem_t *mt, TFTLV_File_t *ft )
{
	// Check parameters
	if( mt == NULL || ft == NULL ) return TFTLV_RET_PARAMETERS;

	// Set up our walk state
	_drain_st_t st;
	st.ft = ft;
	st.wrote = 0;
	st.err = 0;

	// Walk the mem queue, to drain it to file queue
	uint8_t qres = TFTLV_Walk_Mem( mt, _draincb, &st );
	if( qres == TFTLV_RET_OK && st.err == 0 ) return TFTLV_RET_OK;

	// Error situation
	if( st.err > 0 && qres == TFTLV_RET_OK ) qres = TFTLV_RET_IO;
	return qres;
}
