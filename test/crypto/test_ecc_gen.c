#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "tf_crypto.h"
#include "uECC.h"

int main(void){
	uint8_t digest[TFC_SHA1_DIGEST_SIZE];
	TFC_SHA1_Ctx_t ctx;
	TFC_SHA1_Init(&ctx);
	TFC_SHA1_Update(&ctx,(uint8_t*)"hello",5);
	TFC_SHA1_Final(&ctx,digest);

	uint8_t pk[64];
	uint8_t sk[32];
	assert( uECC_make_key( pk, sk, uECC_secp256k1() ) == 1 );

	uint8_t sig[64];	
	assert( uECC_sign( sk, digest, TFC_SHA1_DIGEST_SIZE, sig,
		uECC_secp256k1() ) == 1 );

	int res = uECC_verify( pk, digest, TFC_SHA1_DIGEST_SIZE,
		sig, uECC_secp256k1() );
	printf("uECC_verify = %d\n", res);

	return 0;
}
