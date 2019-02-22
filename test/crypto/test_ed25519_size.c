#include <stdio.h>
#include <string.h>

#include "tf_crypto.h"


int main(void){
	// Non-functional, simply for linked size purposes
	uint8_t sig[TFC_ED25519_SIG_SIZE];
	uint8_t pk[TFC_ED25519_PK_SIZE];
	TFC_Ed25519_Verify( NULL, 0, sig, pk );
	return 0;
}
