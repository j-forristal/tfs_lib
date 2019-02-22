// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <string.h>
#include <stdint.h>

#include "tf_crypto_private.h"
#include "ed25519.h"

int TFC_Ed25519_Verify( uint8_t *msg, uint32_t msg_len, uint8_t sig[TFC_ED25519_SIG_SIZE],
	const uint8_t pk[TFC_ED25519_PK_SIZE] )
{
	return ed25519_sign_open( msg, msg_len, pk, sig ); 
}

int TFC_Ed25519_Sign( uint8_t *msg, uint32_t msg_len, uint8_t sig[TFC_ED25519_SIG_SIZE],
	const uint8_t pk[TFC_ED25519_PK_SIZE], const uint8_t sk[TFC_ED25519_SK_SIZE] )
{
	ed25519_sign( msg, msg_len, sk, pk, sig );
	return 0;
}
