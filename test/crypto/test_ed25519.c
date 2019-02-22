#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "tf_crypto.h"
#include "ed25519.h"

extern int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );
extern void dump_hex( uint8_t* hex, uint32_t cnt );

int main(void)
{
	ed25519_public_key pk;
	ed25519_secret_key sk;

	// Generate a new key pair
	assert( TFC_Random( sk, sizeof(sk) ) == 0 );
	ed25519_publickey( sk, pk );

	// Get a random message
	uint8_t msg[8192 * 4];
	assert( TFC_Random( msg, sizeof(msg) ) == 0 );


	uint8_t sig1[TFC_ED25519_SIG_SIZE];
	uint8_t sig2[TFC_ED25519_SIG_SIZE];

	int i;
	for( i=0; i<sizeof(msg); i++){

		// Sign it 
		if( TFC_Ed25519_Sign( msg, i, sig1, pk, sk ) != 0 ){
			printf("FAIL sign on iteration %d\n", i);
			return -1;
		}
		ed25519_sign( msg, i, sk, pk, sig2 );


		// Verify it
		if( TFC_Ed25519_Verify( msg, i, sig1, pk ) != 0 ){
			printf("FAIL verify (sig1) on iteration %d\n", i);
			return -1;
		}
		if( TFC_Ed25519_Verify( msg, i, sig2, pk ) != 0 ){
			printf("FAIL verify (sig2) on iteration %d\n", i);
			return -1;
		}
		if( ed25519_sign_open( msg, i, pk, sig1 ) != 0 ){
			printf("FAIL verify (orig) on iteration %d\n", i);
		}

	}

	printf("Ed25519 OK\n");
	return 0;
}
