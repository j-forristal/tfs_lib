// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <string.h>

#include "tf_crypto_private.h"
#include "uECC.h"

int TFC_ECC_Verify( uint8_t pk[64], uint8_t hash[32], uint8_t sig[64])
{
	return uECC_verify(pk, hash, 32, sig, uECC_secp256r1());
}

int TFC_ECC_Sign( uint8_t k[64], uint8_t hash[32], uint8_t sig[64])
{
	return uECC_sign(k, hash, 32, sig, uECC_secp256r1());
}

