#include <stdio.h>
#include <string.h>

#include "tf_crypto.h"

int main(void){

	// To make apples-to-apples compare to ed25519, we
	// are including a sha512 linkage
	uint8_t digest[TFC_SHA512_DIGEST_SIZE];
	TFC_SHA512_Ctx_t ctx;
	TFC_SHA512_Init(&ctx);
	TFC_SHA512_Update(&ctx,(uint8_t*)"a",1);
	TFC_SHA512_Final(&ctx,digest);

	uint8_t pk[TFC_ECC_PK_SIZE];
	uint8_t hash[TFC_ECC_HASH_SIZE];
        uint8_t sig[TFC_ECC_SIG_SIZE];
	TFC_ECC_Verify(pk,0,hash,0,sig,0);
	return 0;
}
