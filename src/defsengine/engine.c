// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>

#include "tf_defs.h"

#include PLATFORM_H

uint32_t TFDefs_Version( TF_Defs_t *defs ){ return defs->version; }

int TFDefs_Load( TF_Defs_t *defs, const char *defsfile, TFDefs_CALLBACK(callback), uint16_t ident )
{
	ASSERT(defs);
	ASSERT(defsfile);
	// Callback can be NULL
	int errno_;
	int res = TFDEFS_LOAD_ERR;

	MEMSET( defs, 0, sizeof(TF_Defs_t) );

	// mmap our file
	int fd = OPEN(defsfile, O_RDONLY, 0);
	ASSERT( fd != -1 );
	if( fd == -1 ) return res; // pass thru errno

	struct stat stt;
	if( FSTAT(fd, &stt) != 0 ){
		ASSERT( fd == -1 );
		errno_ = errno;
		CLOSE(fd);
		errno = errno_;
		return res;
	}
	if( stt.st_size < sizeof(TF_Defs_Header_t) ){ errno = ENOEXEC; return res; }

	// Allocate read-only temp map of file
	void *map_tmp = MMAP(0, (size_t)stt.st_size, PROT_READ, MAP_PRIVATE|MAP_FILE, fd, 0);
	errno_ = errno;
	CLOSE(fd);
	errno = errno_;
	ASSERT( map_tmp != MAP_FAILED );
	if( map_tmp == MAP_FAILED ) { return res; } // pass thru errno

	res = TFDefs_Load_From_Mem( defs, (uint8_t*)map_tmp, stt.st_size, callback, ident );
	MUNMAP(map_tmp, stt.st_size);
	return res;
}


int TFDefs_Load_From_Mem( TF_Defs_t *defs, const uint8_t *defs_mem, uint32_t defs_mem_len,
		TFDefs_CALLBACK(callback), uint16_t ident )
{
	int errno_;
	int res = TFDEFS_LOAD_ERR;

	// Sanity check the parameters
	ASSERT(defs);
	ASSERT(defs_mem);
	// Callback can be NULL
	if( defs == NULL || defs_mem == NULL ){ errno = ENOEXEC; return res; }

	// Sanity check the size
	if( defs_mem_len <= sizeof(TF_Defs_Header_t) ){ errno = ENOEXEC; return res; }

	//
	// Security note: if we mmap a file on disk, we have to constantly re-validate
	// it upon every use, because anyone can edit it on disk and affect our
	// in-memory view.  To prevent this, we are going to load the whole thing into
	// anonymous memory, which prevents having to checksum/revalidate for
	// reflected disk content changes.
	//

	// Create new read-write map of anon memory
	defs->map = MMAP(0, (size_t)defs_mem_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	ASSERT( defs->map != MAP_FAILED );
	if( defs->map == MAP_FAILED ){ 
		return res; // pass thru errno
	}

	// Copy file contents to anon memory, and make it RO
	TFMEMCPY( defs->map, defs_mem, (size_t)defs_mem_len );
	MPROTECT( defs->map, (size_t)defs_mem_len, PROT_READ );

	// Validate the header
	TF_Defs_Header_t *h = (TF_Defs_Header_t*)defs->map;
	if( h->magic != TFDEFS_MAGIC ){ errno = ENOEXEC; goto err; }
	if( h->ident != ident ){ errno = ENOMSG; goto err; }
	defs->version = h->version;

	// Validate our signature
	if( callback != NULL ){
		if( callback(h, (uint8_t*)&h->magic2, (defs_mem_len - (sizeof(h->magic) + sizeof(h->sig_ecc) + 
				sizeof(h->sig_rsa) ))) != TFDEFS_LOAD_OK ){
			errno = EBADMSG; res = TFDEFS_LOAD_ERR_SIGN; goto err;
		}
	}
	if( h->magic2 != TFDEFS_MAGIC ){ errno = ENOEXEC; goto err; }

	// Parse our sections
	uint8_t *p = (uint8_t*)&h[1]; //(defs->map) + sizeof(TF_Defs_Header_t);
	uint8_t len = p[0];
	p++;
	int i;
	for( i=0; i < len; i++){
		uint8_t snum = p[0];
		uint8_t styp = p[1];
		// Due to unaligned access, we are going to parse the uint32_t
		// manually.  NOTE: this is LE.
		uint32_t soff = (p[2]) | ((uint32_t)p[3]) << 8 | 
			((uint32_t)p[4]) << 16 | ((uint32_t)p[5]) << 24;
#if 0
		uint32_t slen = (p[6]) | ((uint32_t)p[7]) << 8 | 
			((uint32_t)p[8]) << 16 | ((uint32_t)p[9]) << 24;
		slen++; // temp for compiler complaint, if checksumming disabled
#endif
		defs->sections[ snum ] = (uint8_t*)(defs->map) + soff;
		defs->stypes[ snum ] = styp;

		p += 10;
	}

	return TFDEFS_LOAD_OK;
err:
	errno_ = errno;
	MUNMAP(defs->map, defs_mem_len);
	errno = errno_;
	return res;
}

int TFDefs_Has_Section( TF_Defs_t *defs, uint8_t section_type )
{
	if( section_type >= TFDEFS_SECTION_MAX ) return TFDEFS_NOT_FOUND;
	if( defs->sections[section_type] != NULL ) return TFDEFS_FOUND;
	return TFDEFS_NOT_FOUND;
}

int TFDefs_Hash_Lookup( TF_Defs_t *defs, uint8_t section_type, uint8_t hash[TFDEFS_HASH_LEN], 
	uint32_t *flags, uint16_t *id )
{
	ASSERT( defs );
	ASSERT( flags );
	ASSERT( hash );
	ASSERT( id );

	if( section_type >= TFDEFS_SECTION_MAX ) return TFDEFS_NOT_FOUND;
	if( defs->sections[section_type] == NULL ) return TFDEFS_NOT_FOUND;
	if( defs->stypes[section_type] != TFDEFS_STYPE_HASH ) return TFDEFS_WRONG_TYPE;
	void *section_start = defs->sections[section_type];
	// Table base is also the section base
	uint16_t *table = (uint16_t*)section_start;

	// Found our slice record offset in the table
	uint16_t record_offset = table[ hash[0] ];
	if( record_offset == 0 ) return TFDEFS_NOT_FOUND;

	// Data starts at the slice offset
	uint8_t *data = ((uint8_t*)section_start) + (256 * sizeof(uint16_t));
	record_offset--;
	data += (TFDEFS_RECORD1_LEN * record_offset);

	// Search within the given slice
	while( data[0] == hash[0] ){
		int mr = MEMCMP( hash, data, TFDEFS_HASH_LEN );

		// Found a match
		if( mr == 0 ){
			uint16_t *f = (uint16_t*)(data + TFDEFS_HASH_LEN);
			if( f[0] & 0x8000 ) *flags = (uint32_t)(1 << (f[0] & 0x1F));
			else *flags = (uint32_t)f[0];
			*id = f[1];
			return TFDEFS_FOUND;
		}
		// Our hash is smaller than data, which means data doesn't have
		// our match.  We're done.
		else if( mr < 0 ) return TFDEFS_NOT_FOUND;

		// Move to next record
		data += TFDEFS_RECORD1_LEN;
	}

	// Searched the whole slice, no matches.
	return TFDEFS_NOT_FOUND;
}


int TFDefs_HashMatch_Lookup( TF_Defs_t *defs, uint8_t section_type,
        uint8_t hash[TFDEFS_HASH_LEN], uint8_t match[TFDEFS_HASH_LEN],
        uint32_t *flags, uint16_t *id )
{
	ASSERT( defs );
	ASSERT( flags );
	ASSERT( hash );
	ASSERT( match );
	ASSERT( id );

	if( section_type >= TFDEFS_SECTION_MAX ) return TFDEFS_NOT_FOUND;
	if( defs->sections[section_type] == NULL ) return TFDEFS_NOT_FOUND;
	if( defs->stypes[section_type] != TFDEFS_STYPE_HASHMATCH ) return TFDEFS_WRONG_TYPE;
	void *section_start = defs->sections[section_type];
	// Table base is also the section base
	uint16_t *table = (uint16_t*)section_start;

	// Found our slice record offset in the table
	uint16_t record_offset = table[ hash[0] ];
	if( record_offset == 0 ) return TFDEFS_NOT_FOUND;

	// Data starts at the slice offset
	uint8_t *data = ((uint8_t*)section_start) + (256 * sizeof(uint16_t));
	record_offset--;
	data += (TFDEFS_RECORD2_LEN * record_offset);

	// Search within the given slice
	int res = TFDEFS_NOT_FOUND;
	while( data[0] == hash[0] ){
		int mr = MEMCMP( hash, data, TFDEFS_HASH_LEN );

		// Found a hash match
		if( mr == 0 ){
			// report the flags/id that we matched regardless
			uint16_t *f = (uint16_t*)(data + (TFDEFS_HASH_LEN*2));
			if( f[0] & 0x8000 ) *flags = (uint32_t)(1 << (f[0] & 0x1F));
			else *flags = (uint32_t)f[0];
			*id = f[1];
			if( MEMCMP( match, (data + TFDEFS_HASH_LEN), TFDEFS_HASH_LEN ) != 0 ){
				// doesn't match, so we keep looking but if we don't find
				// a match, it means we return a mismatch
				res = TFDEFS_FOUND_MISMATCH;
			} else {
				// match, we're done
				return TFDEFS_FOUND;
			}
		}
		// Our hash is smaller than data, which means data doesn't have
		// our match.  We're done.
		else if( mr < 0 ) return res;

		// Move to next record
		data += TFDEFS_RECORD2_LEN;
	}

	// Searched the whole slice, no matches.
	return res;
}


int TFDefs_String_Lookup( TF_Defs_t *defs, uint8_t section_type, uint8_t *buffer, 
	uint16_t len, uint32_t *resume, uint32_t *flags, uint16_t *id )
{
	ASSERT( defs );
	ASSERT( flags );
	ASSERT( buffer );
	ASSERT( resume );
	ASSERT( id );

	if( section_type >= TFDEFS_SECTION_MAX ) return TFDEFS_NOT_FOUND;
	if( defs->sections[section_type] == NULL ) return TFDEFS_NOT_FOUND;
	if( defs->stypes[section_type] != TFDEFS_STYPE_STRING ) return TFDEFS_WRONG_TYPE;

	uint8_t *section_start = defs->sections[section_type];
	uint16_t *table = (uint16_t*)section_start;
	uint16_t table_maxlen = table[0];
	uint16_t table_basechar = table[1];

	// if it's discovery, return the metadata
	if( *resume == 0 ){
		buffer[0] = table_maxlen & 0xff;
		buffer[1] = (table_maxlen >> 8) & 0xff;
		*resume = 4;
		return TFDEFS_FOUND;
	}

	// make sure the buffer is big enough
	if( len < table_maxlen ) return TFDEFS_WRONG_LEN;

	// Initialize the buffer on first actual string read
	if( *resume == 4 )
		MEMSET( buffer, (uint8_t)(table_basechar & 0xff), table_maxlen );

	// resume to the right offset
	uint16_t *header = (uint16_t*)(section_start + *resume);

	uint16_t str_len, str_off;
	uint8_t *data;
	if( (header[0] & 0x8000) == 0 ){
		// compressed form
		str_off = (header[0] >> 8) & 0xff;
		str_len = header[0] & 0xff;
		if( header[1] & 0x8000 ) *flags = (uint32_t)(1 << (header[1] & 0x1F));
		else *flags = (uint32_t)header[1];
		*id = header[2];
		data = (uint8_t*)&header[3];
	} else {
		// uncompressed form
		str_off = header[0] & 0x7fff;
		str_len = header[1];
		if( header[2] & 0x8000 ) *flags = (uint32_t)(1 << (header[2] & 0x1F));
		else *flags = (uint32_t)header[2];
		*id = header[3];
		data = (uint8_t*)&header[4];
	}

	// Check if this is the last record
	if( str_len == 0 ){
		buffer[0] = 0;
		return TFDEFS_NOT_FOUND;
	}

	// Now mix in the new data
	int i;
	for( i=str_off; i<(str_off+str_len); i++){
		buffer[i] ^= *data;
		data++;
	}

	// Always force the NULL
	buffer[i] = 0;

	// All set
	*resume = (uint32_t)(data - section_start);
	return TFDEFS_FOUND;
}



#ifndef NDEBUG

#include <stdio.h>

void TFDefs_Hash_Dump( TF_Defs_t *defs, uint8_t section_type )
{
	if( defs->stypes[section_type] != TFDEFS_STYPE_HASH ) return;
	void *section_start = defs->sections[section_type];
	uint16_t *table = (uint16_t*)section_start;
	uint8_t *database = ((uint8_t*)section_start) + (256 * sizeof(uint16_t));

	int t;
	for( t=0; t<256; t++ ){
		uint16_t rec_off = table[t];
		if( rec_off == 0 ) continue;
		printf("- [%x] = %x\n", t, rec_off);
		if( rec_off == 0 ) continue;
		rec_off--;

		uint8_t *data = database + (TFDEFS_RECORD1_LEN * rec_off);
		while( data[0] == t ){
			printf("\t%02x%02x%02x%02x%02x%02x%02x%02x",
				data[0],data[1],data[2],data[3],
				data[4],data[5],data[6],data[7]);
			printf("%02x%02x%02x%02x%02x%02x%02x%02x",
				data[8],data[9],data[10],data[11],
				data[12],data[13],data[14],data[15]);
			uint16_t *f = (uint16_t*)(data + TFDEFS_HASH_LEN);
			printf("  0x%02x  %d\n", f[0], f[1]);

#if 1
			// Self check
			uint32_t v1=0;
			uint16_t v2=0;
			uint8_t hash[TFDEFS_HASH_LEN];
			TFMEMCPY( hash, data, TFDEFS_HASH_LEN );
			if( TFDefs_Hash_Lookup( defs, section_type, hash, &v1, &v2 ) != TFDEFS_FOUND){
				printf("ERR: Unable to re-lookup last hash!\n");
			}
			if( v1 != f[0] || v2 != f[1] )
				printf("ERR: Lookup values don't match (%d=%d / %d=%d)\n",
					v1, f[0], v2, f[1]);
#endif
			data += TFDEFS_RECORD1_LEN;
		}
	}
}
#endif

