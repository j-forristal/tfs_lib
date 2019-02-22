#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#include "tf_crypto.h"
#include "crypto_sign.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

void randombytes(unsigned char * b,unsigned long long l){
	TFC_Random(b, l);
}

int main(void){

	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];

	assert( crypto_sign_keypair(pk,sk) == 0 );

	unsigned char msg[512];
	unsigned char smsg[512+crypto_sign_BYTES];
	unsigned long long mlen = sizeof(msg);
	unsigned long long smlen = sizeof(smsg);

	memset(msg, 'A', sizeof(msg));

	assert( crypto_sign(smsg,&smlen,msg,mlen,sk) == 0 );

	uint8_t sig[TFC_ED25519_SIG_SIZE];
	memcpy( sig, smsg, TFC_ED25519_SIG_SIZE );
	assert( TFC_ED25519_SIG_SIZE == crypto_sign_BYTES );

#define PERF_COUNT (8 * 1024)
	int i;

	time_t t1 = time(0);
	for(i=0;i<PERF_COUNT;i++){
		assert( TFC_Ed25519_Verify( msg, sizeof(msg), sig, pk ) == 0 );
	}
	time_t t2 = time(0);
	printf("ASC time for %d iterations: %ds\n", i, (int)(t2 - t1));

	return 0;
}
