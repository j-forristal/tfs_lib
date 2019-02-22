// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <errno.h>

#include "tf_qf.h"
#include PLATFORM_H

#ifdef TFQF_INTEGRITY
//#include "tf_crypto.h"
#include "tf_cal.h"
#endif

typedef struct {
        uint32_t magic;
	uint16_t pmp; // prev msg page (offset)
        uint16_t len;
#ifdef TFQF_INTEGRITY
	uint8_t  hash[16]; // Currently: first half of SHA256-HMAC
#endif
} TFQF_Message_t;
#define TFQF_MAX_MESSAGE_SIZE	(0xffff - sizeof(TFQF_Message_t))

typedef struct {
        uint32_t magic;
        uint32_t lmp; // last message page
#ifdef TFQF_INTEGRITY
	uint8_t  nonce[32];
	uint8_t  nonce_check[32]; // Currently: SHA256-HMAC of nonce
#endif
} TFQF_Page0_t;
#define TFQF_LMP_OFFSET 4



static int _io_sync( TFQF_QueueFile_t *qf )
{
#ifndef TFQF_NO_FSYNC
	ASSERT(qf);
	do {
		int fd = qf->fd;
		if( fd == -1 ) break;
		int res = FSYNC( fd );
		if( res == -1 && errno == EINTR ) continue;
		return res;
	} while(1);
#endif
	return 0;
}



static int _io_size_set( TFQF_QueueFile_t *qf, uint32_t len )
{
	ASSERT(qf);
	ASSERT( len >= TFQF_PAGE_SIZE );
	ASSERT( (len % TFQF_PAGE_SIZE) == 0 );
	off_t l = (off_t)len;
	do {
		int res = FTRUNCATE(qf->fd, l);
		if( res == -1 && errno == EINTR ) continue;
		return res;
	} while(1);
}



static ssize_t _io_size( TFQF_QueueFile_t *qf )
{
	ASSERT(qf);
	struct stat stt;
	int res = FSTAT( qf->fd, &stt );
	if( res != 0 ) return -1;
	return stt.st_size;
}



#define _IO_READ  1
#define _IO_WRITE 0
static int _io_page( TFQF_QueueFile_t *qf, 
	uint8_t page[TFQF_PAGE_SIZE], uint32_t page_offset, int io_typ )
{
	ASSERT(qf);
	int res = -1; 
	off_t offset = (page_offset * TFQF_PAGE_SIZE);
	size_t remain = TFQF_PAGE_SIZE;
	if( qf->fd == -1 ) return res;

	do {
		ssize_t actual = (io_typ == _IO_READ) ?
			PREAD(qf->fd, page, remain, offset) :
			PWRITE(qf->fd, page, remain, offset);
		if( actual == 0 ) break; 
		if( actual > 0 ){
			remain -= actual;
			offset += actual;
			page += actual;
			if( remain == 0 ){
				res = 0;
				break;
			}
			continue;
		}
		if( actual == -1 ){
			if( errno == EINTR ) continue;
			break;
		}
	} while(1);
	return res;
}



static int _io_lmp_set( TFQF_QueueFile_t *qf, uint32_t lmp )
{
	ASSERT(qf);
	do {
		ssize_t res = PWRITE(qf->fd, &lmp, 4, TFQF_LMP_OFFSET);
		if( res == 4 ) return 0;
		if( res == -1 && errno == EINTR ) continue;
		if( res == -1 ) return -1;
	} while(1);
}



int TFQF_Push( TFQF_QueueFile_t *qf, uint8_t *msg, uint16_t len )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL || msg == NULL || len == 0 || len > TFQF_MAX_MESSAGE_SIZE ){
		errno = EINVAL; return -1;
	}
	if( qf->fd == -1 ){
		errno = EBADF; return -1;
	}
#endif
#ifndef TFQF_NO_MEMORY
	if( qf->mem != NULL ){ errno = EBUSY; return -1; }
#endif
	ASSERT( len > 0 );
	ASSERT( len <= TFQF_MAX_MESSAGE_SIZE );
	int res = -1;
	uint8_t page[TFQF_PAGE_SIZE];
	TFQF_Message_t *m = (TFQF_Message_t*)page;
	MEMSET( page, 0, TFQF_PAGE_SIZE );

	ssize_t qsize = _io_size( qf );
	if( qsize == -1 ) goto done;
#ifndef NO_DEFENSIVE
	if( qsize < (qf->nxt * TFQF_PAGE_SIZE) ) goto corrupted;
#endif

	// Round up the desired len to a page boundary
	uint32_t len_p = len + sizeof(TFQF_Message_t);
	if( (len_p % TFQF_PAGE_SIZE) > 0 )
		len_p += TFQF_PAGE_SIZE - (len_p % TFQF_PAGE_SIZE);
	ASSERT( (len_p % TFQF_PAGE_SIZE) == 0 );

	// Write the first message page, which includes the header
	uint32_t page_offset = qf->nxt;
	ASSERT( page_offset > 0 );
	m->magic = TFQF_MAGIC;
	m->len = len;
	m->pmp = (qf->lmp == 0) ? 0 : (qf->nxt - qf->lmp);
#ifdef TFQF_INTEGRITY
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256_HMAC( qf->hmac_key, sizeof(qf->hmac_key), msg, len, hash );
	TFMEMCPY( m->hash, hash, sizeof(m->hash) );
#endif

	uint32_t amount = (TFQF_PAGE_SIZE - sizeof(TFQF_Message_t));
	if( amount > len ) amount = len;
	TFMEMCPY( &page[ sizeof(TFQF_Message_t) ], msg, amount );

	// Do the actual write, then keep writing more pages until done
	uint16_t len_ = len;
	do {
		// Finish existing page setup
		if( _io_page( qf, page, page_offset, _IO_WRITE ) != 0 ) goto done;
		page_offset++;
		len_ -= amount;
		if( len_ == 0 ) break;
		msg += amount;

		// Next page start
		amount = TFQF_PAGE_SIZE;
		if( amount > len_ ){ 
			amount = len_;
			MEMSET( &page[amount], 0, (TFQF_PAGE_SIZE-amount) );
		}
		TFMEMCPY( page, msg, amount );
	} while(1);

	// Synchronize the message data
	if( _io_sync( qf ) != 0 ) goto done;

	if( _io_lmp_set(qf, qf->nxt) != 0 ) goto done;
	_io_sync( qf ); // Ignoring response, best-effort

	qf->lmp = qf->nxt;
	qf->nxt = page_offset;
	qf->cnt++;
	qf->data_len += len;
	res = 0;
done:
	return res;

corrupted:
	// NOT-MVP-TODO
	return res;
}



int TFQF_Pop( TFQF_QueueFile_t *qf, uint8_t *buffer, uint16_t *len )
{
#ifndef NO_DEFENSIVE
	// NOTE: buffer is allowed to be NULL, for size discovery
	if( qf == NULL || len == NULL || *len == 0 ){
		errno = EINVAL; return -1;
	}
	if( qf->fd == -1 ){
		errno = EBADF; return -1;
	}
#endif
#ifndef TFQF_NO_MEMORY
	if( qf->mem != NULL ){ errno = EBUSY; return -1; }
#endif
	int res = -1;
	uint8_t page[TFQF_PAGE_SIZE];
	TFQF_Message_t *m = (TFQF_Message_t*)page;

	uint32_t lmp = qf->lmp;
	if( lmp == 0 ){ // Nothing in the queue
		*len = 0;
		res = 0;
		goto done;
	}
	ssize_t sz = _io_size( qf );
	if( sz == -1 ) goto done;
#ifndef NO_DEFENSIVE
	if( (lmp * TFQF_PAGE_SIZE) > (sz - TFQF_PAGE_SIZE) ) goto corrupted;
#endif
	if( _io_page(qf, page, lmp, _IO_READ) != 0 ) goto done;

	// NOT-MVP-TODO: if this message is wrong, should we try to fix up
	// lmp or just call the whole thing corrupted?
	if( m->magic != TFQF_MAGIC ) goto corrupted;
	if( m->len == 0 || m->len > TFQF_MAX_MESSAGE_SIZE ) goto corrupted;

	// Make sure the message isn't past EOF
	if( ((lmp * TFQF_PAGE_SIZE) + m->len) > sz ) goto corrupted;
	if( buffer == NULL ){ // Caller just wanted size
		*len = m->len;
		res = 0;
		goto done;
	}
	if( *len < m->len ){ // Caller buffer too small
		errno = EOVERFLOW; goto done;
	}

	// Copy rest of the first page
	uint32_t page_offset = lmp;
	uint16_t l = m->len;
	uint16_t pmp = m->pmp;
#ifdef TFQF_INTEGRITY
	uint8_t msg_hash[sizeof(m->hash)];
	TFMEMCPY( msg_hash, m->hash, sizeof(m->hash) );
#endif
	*len = 0;
	uint16_t amount = (TFQF_PAGE_SIZE - sizeof(TFQF_Message_t));
	if( amount > l ) amount = l;
	uint8_t *ptr = &page[ sizeof(TFQF_Message_t) ];

	do {
		// Do the copy from the page
		TFMEMCPY( buffer, ptr, amount );
		l -= amount;
		*len += amount;
		if( l == 0 ) break;

		// Setup for the next page
		ptr = page;
		page_offset++;
		buffer += amount;
		amount = TFQF_PAGE_SIZE;
		if( amount > l ) amount = l;
		if( _io_page(qf, page, page_offset, _IO_READ) != 0 )
			goto done;
	} while(1);

	ASSERT( l == 0 );
	if( lmp == 1 ){ // This was the first message, so we can just clear
		res = TFQF_Clear( qf );
		goto done;
	}
	if( _io_size_set(qf,(lmp * TFQF_PAGE_SIZE)) != 0 ) goto done;
	if( _io_lmp_set(qf, (lmp-pmp)) != 0 ) goto done;
	qf->lmp = (lmp-pmp);
	qf->nxt = lmp;
	qf->cnt--;
	qf->data_len -= *len;
	_io_sync( qf ); // Ignoring return on purpose, best-effort

#ifdef TFQF_INTEGRITY
	// NOTE we basically prune the message regardless, and we return the
	// whole thing except we we still return err/ENOMSG.  Savvy callers
	// can still use the message even if they choose to ignore ENOMSG.
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256_HMAC( qf->hmac_key, sizeof(qf->hmac_key), buffer, *len, hash );
	if( MEMCMP( msg_hash, hash, sizeof(msg_hash) ) != 0 ){
		errno = ENOMSG;
		qf->integrity_violations++;
	}
	else res = 0;
#else
	res = 0;
#endif

done:
	return res;
corrupted:
	// NOT-MVP-TODO
	return res;
}



static int _new( TFQF_QueueFile_t *qf, uint8_t page[TFQF_PAGE_SIZE] )
{
	ASSERT( qf );
	ASSERT( qf->fd != -1 );
	MEMSET(page, 0, TFQF_PAGE_SIZE);
	TFQF_Page0_t *p0 = (TFQF_Page0_t*)page;
	p0->magic = TFQF_MAGIC;
	p0->lmp = 0;
#ifdef TFQF_INTEGRITY
	ASSERT( sizeof(p0->nonce_check) <= TCL_SHA256_DIGEST_SIZE );
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	if( TCL_Random( p0->nonce, sizeof(p0->nonce) ) != 0 ) return -1;
	TCL_SHA256_HMAC( qf->hmac_key, sizeof(qf->hmac_key), p0->nonce, sizeof(p0->nonce), hash );
	TFMEMCPY( p0->nonce_check, hash, sizeof(p0->nonce_check) );
#endif
	int res = _io_page(qf, page, 0, _IO_WRITE);
	if( res == 0 ){
		qf->lmp = 0;
		qf->nxt = 1;
		qf->cnt = 0;
		qf->data_len = 0;
		qf->integrity_violations = 0;
	}
	return res;
}



int TFQF_Clear( TFQF_QueueFile_t *qf )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL ){
		errno = EINVAL; return -1;
	}
#endif
#ifndef TFQF_NO_MEMORY
	if( qf->mem != NULL ){ errno = EBUSY; return -1; }
#endif
	int res = -1;
	if( _io_size_set(qf, TFQF_PAGE_SIZE) != 0 ) goto done;
	if( _io_lmp_set(qf, 0 ) != 0 ) goto done;
	qf->lmp = qf->cnt = qf->data_len = 0;
	qf->nxt = 1;
	res = 0;
done:
	return res;
}


#ifdef TFQF_INTEGRITY
int TFQF_Open_Keyed( TFQF_QueueFile_t *qf, const char *path, 
	uint8_t hmac_key[TFQF_HMAC_KEY_SIZE] )
#else
int TFQF_Open( TFQF_QueueFile_t *qf, const char *path )
#endif
{
	int _errno;

#ifndef NO_DEFENSIVE
	if( qf == NULL || path == NULL ){
		errno = EINVAL; return -1;
	}
	MEMSET( qf, 0, sizeof(TFQF_QueueFile_t) );
#endif
	do {
		qf->fd = OPEN( path, O_RDWR|O_CREAT, 0600);
	} while( qf->fd == -1 && errno == EINTR );
ASSERT( qf->fd != -1 );
	if( qf->fd == -1 ) return -1;

#ifdef TFQF_INTEGRITY
	TFMEMCPY( qf->hmac_key, hmac_key, TFQF_HMAC_KEY_SIZE );
#endif

	uint8_t page[TFQF_PAGE_SIZE];
	TFQF_Page0_t *p0 = (TFQF_Page0_t*)page;
	TFQF_Message_t *m = (TFQF_Message_t*)page;

	ssize_t sz = _io_size( qf );
	if( sz == -1 ) goto err;
	if( sz == 0 ){ // New file, initialize new header
		if( _new(qf, page) != 0 ) goto err;
		return 0;
	}
	else if( sz < TFQF_PAGE_SIZE ){ // Not an TFQF file
		errno = EBADF; goto err;
	}

	// If we get here, sz >= TFQF_PAGE_SIZE. Validate page0
	if( _io_page(qf, page, 0, _IO_READ) != 0 ) goto err;
	if( p0->magic != TFQF_MAGIC ){ // Not an TFQF file
		errno = EBADF; goto err;
	}
	qf->lmp = p0->lmp;
	qf->nxt = 1;

#ifdef TFQF_INTEGRITY
	// Confirm we are using the right key
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256_HMAC( qf->hmac_key, sizeof(qf->hmac_key), p0->nonce, sizeof(p0->nonce), hash );
	if( MEMCMP( p0->nonce_check, hash, sizeof(p0->nonce_check) ) != 0 ){
		// Not using the right key
		qf->integrity_violations++;
		errno = EBADF; goto err;
	}
#endif

	// Walk the file and prune at the first corrupted msg
	ssize_t tsz;
	uint32_t po = 1, lmp = 0;
	do {
		if( lmp == qf->lmp ) break;
		if( _io_page(qf, page, po, _IO_READ) != 0 ) goto err;
		if( m->magic != TFQF_MAGIC || m->len == 0 ) break;
		// validate pmp

		tsz = sizeof(TFQF_Message_t) + m->len;
		if( (tsz + (po * TFQF_PAGE_SIZE)) > sz ) break;
		lmp = po;
		while( tsz > 0 ){
			po++;
			tsz -= TFQF_PAGE_SIZE;
		}
		qf->nxt = po;
		qf->cnt++;
		qf->data_len += m->len;
	} while(1);

	tsz = qf->nxt * TFQF_PAGE_SIZE;
	if( tsz > sz ){ // We need to truncate the extra
		if( _io_size_set(qf, tsz) != 0 ) goto err;
	}

	if( lmp != qf->lmp ){ // Need to update LMP value
		if( _io_lmp_set(qf, lmp) != 0 ) goto err;
		qf->lmp = lmp;
	}

#if defined(TFQF_INTEGRITY) && !defined(NO_MEMORY)
	// Now call open memory, which will validate the integrity of
	// all the items.  This is a special usage of Memory_Open.
	if( TFQF_Memory_Open( qf, NULL, qf->cnt ) == -1 ) goto err;
	TFQF_Memory_Close( qf );
	if( qf->integrity_violations > 0 ){ errno = EFAULT; goto err; }
#endif

	return 0;
err:
	_errno = errno;
	CLOSE(qf->fd);
	errno = _errno;
	return -1;
}



void TFQF_Close( TFQF_QueueFile_t *qf )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL ) return;
#endif
#ifndef TFQF_NO_MEMORY
	TFQF_Memory_Close(qf);
#endif
	int fd = qf->fd;
	if( fd != -1 ){
		CLOSE(fd);
		qf->fd = -1;
	}
}



void TFQF_Stats( TFQF_QueueFile_t *qf, uint32_t *count, uint32_t *data_len )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL || count == NULL || data_len == NULL ) return;
#endif
	*count = qf->cnt;
	*data_len = qf->data_len;
}



int TFQF_Prune( TFQF_QueueFile_t *qf, uint32_t count )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL ){ errno = EINVAL; return -1; }
	if( qf->fd == -1 ){
		errno = EBADF; return -1;
	}
#endif
	if( count == 0 ) return 0;
	if( count >= qf->cnt ){
		if( TFQF_Clear( qf ) != 0 ) return -1;
		return count;
	}

	uint8_t page[TFQF_PAGE_SIZE];
	TFQF_Message_t *m = (TFQF_Message_t*)page;

	uint32_t lmp = qf->lmp;
	uint32_t nxt = qf->nxt;
	ASSERT( lmp > 0 );
	uint32_t cnt = 0;
	while( cnt < count ){
		if( _io_page(qf, page, lmp, _IO_READ) != 0 ) break;
		nxt = lmp;
		lmp = lmp - m->pmp;
		cnt++;
	}

	int res = -1;
	if( cnt > 0 ){
		if( _io_size_set(qf,(nxt * TFQF_PAGE_SIZE)) != 0 ) return -1;
		if( _io_lmp_set(qf, lmp) != 0 ) return -1;
		qf->lmp = lmp;
		qf->nxt = nxt;
		qf->cnt -= cnt;
		res = cnt;
	}
	return res;
}



#ifndef TFQF_NO_MEMORY

#include <sys/mman.h>

int TFQF_Memory_Open( TFQF_QueueFile_t *qf, TFQF_MemoryItem_t *items, uint32_t item_cnt )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL ){ errno = EINVAL; return -1; }
#endif
	if( qf->fd == -1 ){ errno = EBADF; return -1; }
	if( qf->mem != NULL ){ errno = EEXIST; return -1; }
	if( qf->cnt < item_cnt ){ errno = EINVAL; return -1; }

	// Map the file into memory
	qf->mem_len = qf->nxt * TFQF_PAGE_SIZE;
	qf->mem = (uint8_t*)MMAP( NULL, qf->mem_len, PROT_READ, 
		MAP_SHARED|MAP_FILE, qf->fd, 0 );
	if( qf->mem == MAP_FAILED ){ qf->mem = NULL; return -1; }

	// Walk backwards and fill in the items array
	uint32_t cnt = 0;
	uint32_t lmp = qf->lmp;
	while( cnt < item_cnt ){
		TFQF_Message_t *msg = (TFQF_Message_t*)&qf->mem[ lmp * TFQF_PAGE_SIZE ];
		uint8_t *ptr = (uint8_t*)msg;

		if( items != NULL ){
			items[cnt].data = &ptr[ sizeof(TFQF_Message_t) ];
			items[cnt].data_len = msg->len;
		}

#ifdef TFQF_INTEGRITY
		uint8_t hash[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256_HMAC( qf->hmac_key, sizeof(qf->hmac_key), &ptr[ sizeof(TFQF_Message_t) ], msg->len, hash );
		if( MEMCMP( msg->hash, hash, sizeof(msg->hash) ) != 0 ){
			qf->integrity_violations++;
			// Integrity violation, don't return this item
			if( items != NULL ){
				items[cnt].data = NULL;
				items[cnt].data_len = 0;
			}
		}
#endif
		cnt++;
		if( msg->pmp == 0 ) break;
		lmp = lmp - msg->pmp;
	}

	// All set
	return cnt;
}

void TFQF_Memory_Close( TFQF_QueueFile_t *qf )
{
#ifndef NO_DEFENSIVE
	if( qf == NULL ){ return; }
#endif
	if( qf->mem == NULL ){ return; }

	MUNMAP( qf->mem, qf->mem_len );
	qf->mem = NULL;
	qf->mem_len = 0;
}


#endif // NO_MEMORY
