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

	if( argc < 4 ){
		printf("ERROR: dual_sign ecc.key.raw rsa.key.der target\n");
		return -1;
	}

	size_t sz_ecc;
	uint8_t *m_ecc = file_load( argv[1], &sz_ecc, 0 );
	assert( sz_ecc == TFC_ECC_K_SIZE );
#if 0
	size_t sz_rsa;
	uint8_t *m_rsa = file_load( argv[2], &sz_rsa, 0 );
	assert( sz_rsa > 256 );
#endif
	size_t sz_dat;
	uint8_t *m_dat = file_load( argv[3], &sz_dat, 1 );
	assert( sz_dat > (4 + 64 + 256) );


	// Figure out what kind of file it is
	uint32_t *u32 = (uint32_t*)m_dat;
	size_t hash_start;
	if( (*u32) == 0x097f5201 ){ 
		// Defs
		hash_start = 4 + 64 + 256;
	} else {
		// TLV
		hash_start = 4 + 64 + 256 + TFTLV_OTP_SIZE;

		// Verify the OTP value is all NULL, which is a sign
		// this may already have been signed
		uint8_t *otp = &m_dat[4 + 64 + 256];
		int i;
		for( i=0; i<(TFTLV_OTP_SIZE); i++ ){
			if( otp[i] != 0 ){
				printf("ERROR: OTP value is non-zero (already signed?)\n");
				return -1;
			}
		}

		// Create a new random OTP value
		TCL_Random( otp, TFTLV_OTP_SIZE );

		// Transform the data with the OTP value, for obfuscation/hiding
		for( i=0; i<(sz_dat - hash_start); i++){
			m_dat[hash_start + i] ^= otp[i % TFTLV_OTP_SIZE];
		}

		// NOTE: would prefer to have an external mix-in, but dual-key use
		// makes prior key-based mix-in impossible.  TBD.
#if 0
		// Now mix in the key to the OTP value that we save to the file
		for( i=0; i<TFTLV_OTP_SIZE; i++){
			otp[i] ^= m_ecc[i % sz_ecc];
		}
#endif

		printf("- OTP: ");
		dump_hex(otp, TFTLV_OTP_SIZE);
	}
	printf("- Data len: %lu\n", (sz_dat - hash_start));


	// Calculate the digest of the data
	uint8_t digest[TFC_SHA256_DIGEST_SIZE];
	TCL_SHA256( &m_dat[hash_start], (sz_dat - hash_start), digest);

	printf("- Digest: ");
	dump_hex(digest, sizeof(digest));


	// Calculate the ECDSA signature
	uint8_t sig_ecc[TFC_ECC_SIG_SIZE];
	assert( TFC_ECC_Sign(m_ecc, digest, sig_ecc) == 1 );


	// Write it to data memory view
	memcpy( &m_dat[4], sig_ecc, sizeof(sig_ecc) );
	printf("- Signed ECC\n");


	// Write out the digest to a temp file
	char path[256];
	memcpy(path, "/tmp/dualsign.XXXXXX", strlen("/tmp/dualsign.XXXXXX")+1 ); // +1 for NULL
	char *f_tmp = mktemp(path);
	assert( f_tmp != NULL );
	printf("- Digest file: %s\n", f_tmp);

	int fd = open(f_tmp, O_RDWR|O_CREAT|O_TRUNC, 0600);
	assert( fd != -1 );
	assert( write(fd, digest, sizeof(digest)) == sizeof(digest) );
	close(fd);


	// Allocate a destination signature output file
	char path2[256];
	memcpy(path2, "/tmp/dualsign.XXXXXX", strlen("/tmp/dualsign.XXXXXX")+1 ); // +1 for NULL
	char *f_sig = mktemp(path2);
	assert( f_sig != NULL );
	printf("- Sig file: %s\n", f_sig);


	// Run the OpenSSL RSA sign command
	char cmd[1024] = {0};
	sprintf(cmd, "openssl rsautl -sign -pkcs -in %s -inkey %s -keyform DER -out %s",
		f_tmp, argv[2], f_sig);
	//printf("- Openssl cmd: %s\n", cmd);
	int res = system(cmd);
	//printf("- Openssl res: %d\n", res);
	assert( res == 0 );


	// Read in the signature result
	size_t sz_sig;
	uint8_t *m_sig = file_load( f_sig, &sz_sig, 0 );
	assert( sz_sig == 256 );


	// Write it to data memory view
	memcpy( &m_dat[4 + 64], m_sig, sz_sig );
	printf("- Signed RSA\n");


	// Flush the memory view back to the file
	msync(m_dat, sz_dat, MS_SYNC);


	// Clean up our temp files
	unlink(f_tmp);
	unlink(f_sig);


	// All done
	printf("- Signed successfully\n");
	return 0;
}
