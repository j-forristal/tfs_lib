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
#include "tf_tlv.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );


typedef struct __attribute__((packed, aligned(4))) {
        uint8_t ecc[64];
        uint8_t rsa[256];
        uint8_t otp[TFTLV_OTP_SIZE];
} _tlvsig_t;


uint8_t* file_load( char *f, size_t *sz ){
	int fd = open(f, O_RDWR);
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

	void *m = mmap(NULL, stt.st_size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
	close(fd);
	if( m == MAP_FAILED ){
		printf("ERR: unable to mmap file '%s'\n", f);
		return NULL;
	}
	return (uint8_t*)m;
}


int main(int argc, char**argv){

	if( argc < 4 ){
		printf("ERROR: dual_sign ecc.key.raw rsa.key.der target\n");
		return -1;
	}

	size_t sz_ecc;
	uint8_t *m_ecc = file_load( argv[1], &sz_ecc );
	assert( sz_ecc == TCL_ECC_PUB_SIZE );
	size_t sz_rsa;
	uint8_t *m_rsa = file_load( argv[2], &sz_rsa );
	assert( sz_rsa > 256 );
	size_t sz_dat;
	uint8_t *m_dat = file_load( argv[3], &sz_dat );
	assert( sz_dat >= (4 + 64 + 256) );


	// Figure out what kind of file it is
	uint32_t *u32 = (uint32_t*)m_dat;
	size_t hash_start;
	if( (*u32) == 0x097f5201 ){
		// Defs
		hash_start = 4 + 64 + 256;
	} else {
		// TLV
		hash_start = 4 + 64 + 256 + TFTLV_OTP_SIZE;
	}
	printf("- Data len: %lu\n", (sz_dat - hash_start));


	// Calculate the digest of the data
	uint8_t digest[TFC_SHA256_DIGEST_SIZE];
	TCL_SHA256( &m_dat[hash_start], (sz_dat - hash_start), digest);

	printf("- Digest: ");
	dump_hex(digest, sizeof(digest));


	// Verify the ECDSA signature
	int err = 0;
	int res = TCL_ECC_Verify(m_ecc, digest, &m_dat[4], &err);
	if( res != TCL_VERIFY_OK ){
		printf("ERROR: ECC verify; res=%d err=%d\n", res, err);
		return -1;
	}
	printf("- ECC verified\n");


	// Verify the RSA signature
	err = 0;
	res = TCL_RSA_Verify(m_rsa, sz_rsa, digest, &m_dat[4 + 64], &err);
	if( res != TCL_VERIFY_OK ){
		printf("ERROR: RSA verify; res=%d err=%d\n", res, err);
		return -1;
	}
	printf("- RSA verified\n");

	return 0;
}
