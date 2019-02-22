#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "tf_crypto.h"
#include "tf_cal.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

uint8_t* file_load( char *f, size_t *sz, int wr ){
        int fd = open(f, (wr > 0) ? O_RDWR : O_RDONLY );
        if( fd == -1 ){
                printf("ERR: unable to open file '%s'\n", f);
                return NULL;
        }

        struct stat stt;
        if( fstat(fd, &stt) != 0 ){
                printf("ERR: stat on '%s'\n", f);
                return NULL;
        }
        *sz = stt.st_size;

        void *m = mmap(NULL, stt.st_size, (wr > 0) ? (PROT_READ|PROT_WRITE) : PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
        close(fd);
        if( m == MAP_FAILED ){
                printf("ERR: unable to mmap file '%s'\n", f);
                return NULL;
        }
        return (uint8_t*)m;
}

int main(int argc, char**argv){

	if( argc < 3 ){
		printf("ERR: usage\n");
		return -1;
	}

	size_t sz_ecc;
	uint8_t *m_ecc = file_load( argv[1], &sz_ecc, 0 );
	assert( sz_ecc = TFC_ECC_K_SIZE );

	size_t sz_dat;
	uint8_t *m_dat = file_load( argv[2], &sz_dat, 1 );
	assert( sz_dat > (4 + 64) );


	// walk backwards, looking for 'INTEGRITY'
	uint8_t *ptr = m_dat + sz_dat - 64;
	while( ptr > m_dat ){
		if( *ptr == 'I' && memcmp(ptr, "INTEGRITY", 9) == 0 ) break;
		ptr--;
	}

	if( ptr == m_dat ){
		printf("ERR: unable to find INTEGRITY marker");
		return -1;
	}

	uint32_t offset = (uint32_t)(ptr - m_dat);
	printf("Found INTEGRITY marker @ 0x%x\n", offset);

	uint32_t *u32 = (uint32_t*)ptr;
	*u32 = offset + 4;

	msync( m_dat, sz_dat, MS_SYNC );

	// Calculate the digest
	uint8_t digest[TFC_SHA256_DIGEST_SIZE];
	TCL_SHA256( m_dat, (offset + 4), digest ); // Include offset in signature

	// Calculate the ECDSA signature
	uint8_t sig_ecc[TFC_ECC_SIG_SIZE];
	assert( TFC_ECC_Sign(m_ecc, digest, sig_ecc) == 1 );

	memcpy( ptr+4, sig_ecc, sizeof(sig_ecc) );
	msync( m_dat, sz_dat, MS_SYNC );
	munmap( m_dat, sz_dat );

	printf("ECC Signed\n");
	return 0;
}
