// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdio.h>
#include <stdint.h>
#include "tf_crypto.h"
#include "tf_cal.h"

#include PLATFORM_H

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>
#include <Security/SecKey.h>
#include <Security/SecRandom.h>
#include <CoreFoundation/CoreFoundation.h>

int TCL_MD5_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[16] ){
	CC_MD5_CTX ctx;
	CC_MD5_Init( &ctx );
	CC_MD5_Update( &ctx, data, len );
	if( data2 != NULL ) CC_MD5_Update(&ctx, data2, len2);
	CC_MD5_Final(digest, &ctx);
	return 0;
}
int TCL_MD5( const uint8_t *data, uint32_t len, uint8_t digest[16] ){
	return TCL_MD5_2( data, len, NULL, 0, digest );
}

int TCL_SHA1_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[20] ){
	CC_SHA1_CTX ctx;
	CC_SHA1_Init(&ctx);
	CC_SHA1_Update(&ctx, data, len);
	if( data2 != NULL ) CC_SHA1_Update(&ctx, data2, len2);
	CC_SHA1_Final(digest, &ctx);
	return 0;
}
int TCL_SHA1( const uint8_t *data, uint32_t len, uint8_t digest[20] ){
	return TCL_SHA1_2( data, len, NULL, 0, digest );
}

int TCL_SHA256_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[32] ){
	CC_SHA256_CTX ctx;
	CC_SHA256_Init(&ctx);
	CC_SHA256_Update(&ctx, data, len);
	if( data2 != NULL ) CC_SHA256_Update(&ctx, data2, len2);
	CC_SHA256_Final(digest, &ctx);
	return 0;
}
int TCL_SHA256( const uint8_t *data, uint32_t len, uint8_t digest[32] ){
	return TCL_SHA256_2( data, len, NULL, 0, digest );
}

int TCL_SHA512_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[64] ){
	CC_SHA512_CTX ctx;
	CC_SHA512_Init(&ctx);
	CC_SHA512_Update(&ctx, data, len);
	if( data2 != NULL ) CC_SHA512_Update(&ctx, data2, len2);
	CC_SHA512_Final(digest, &ctx);
	return 0;
}
int TCL_SHA512( const uint8_t *data, uint32_t len, uint8_t digest[64] ){
	return TCL_SHA512_2( data, len, NULL, 0, digest );
}

int TCL_SHA256_HMAC( const uint8_t *key, uint32_t key_len,
        const uint8_t *message, uint32_t message_len,
        uint8_t digest[32] ){

	CCHmac( kCCHmacAlgSHA256, key, key_len, message, message_len, digest );
	return 0;
}

int TCL_Random( uint8_t *buffer, uint32_t len ){
	return SecRandomCopyBytes( kSecRandomDefault, len, buffer );
}

#if 0
int TCL_Ed25519_Verify( uint8_t *msg, uint32_t msg_len,
        uint8_t sig[TCL_ED25519_SIG_SIZE], const uint8_t pk[TCL_ED25519_PK_SIZE] ){
	return TFC_Ed25519_Verify(msg, msg_len, sig, pk);
}
#endif

int TCL_ECC_Verify( uint8_t pub[TCL_ECC_PUB_SIZE], uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_ECC_SIZE], int *err_details )
{
#if TARGET_OS_IPHONE
	return TCL_VERIFY_NOTSUPP;
#else
	int res = TFC_ECC_Verify(pub, digest, signature);
	if( err_details != NULL ) *err_details = res;
	return (res == 1) ? TCL_VERIFY_OK : TCL_VERIFY_FAIL;
#endif
}

// NOTE: we get warns on this symbol not existing:
OSStatus SecKeyRawVerify(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen);

static volatile int _rsa_lock;

int TCL_RSA_Verify( uint8_t *pub, uint32_t publen, uint8_t digest[TCL_SHA256_DIGEST_SIZE],
	uint8_t signature[TCL_RSA_SIZE], int *err_details )
{
	// We support 2048-bit keys, which means >= 256 bits
	if( publen < 256 ){
		if( err_details != NULL ) *err_details = 1;
		return TCL_VERIFY_ERROR;
	}

	uint8_t *ptr = pub;

#if TARGET_OS_IPHONE
	// We verified we have at least 256 bytes to work with, so we can safely do all the ops below
	// (which add up to about ~150 bytes max)

	if( MEMCMP(ptr, "\x30\x82\x01\x20", 4) == 0 ) ptr += 4;
	if( MEMCMP(ptr, "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00", 15) == 0 ) ptr += 15;

	// Skip over the tag & length
	if( (*ptr) != 0x03 ){
		if( err_details != NULL ) *err_details = 2;
		return TCL_VERIFY_ERROR;
	}
	ptr++;
	if( (*ptr) > 0x80){ ptr += (*ptr) - 0x80 + 1; }
	else { ptr++; }
	if( (*ptr) != 0 ){
		if( err_details != NULL ) *err_details = 3;
		return TCL_VERIFY_ERROR;
	}
	ptr++;

	// Update the publen to reflect the new (shortended) size
	publen -= (uint32_t)(((uintptr_t)ptr) - ((uintptr_t)pub));

#endif

	// Predeclare our variables, for goto finalizer
	CFDataRef pk_data = NULL;
	CFMutableDictionaryRef pk_dict = NULL;
	SecKeyRef pk = NULL;
	OSStatus s;
	int res = TCL_VERIFY_ERROR;

	// Create a NSData holder for the pubkey
	pk_data = CFDataCreate( NULL, ptr, publen );
	if( pk_data == NULL ){
		if( err_details != NULL ) *err_details = 4;
		res = TCL_VERIFY_ERROR;
		goto done;
	}

	// Allocate our dictionary, used for all the Sec* calls
	pk_dict = CFDictionaryCreateMutable( NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks );
	if( pk_dict == NULL ){
		if( err_details != NULL ) *err_details = 5;
		res =  TCL_VERIFY_ERROR;
		goto done;
	}

	CFDictionaryAddValue( pk_dict, kSecClass, kSecClassKey ); // no return value
	CFDictionaryAddValue( pk_dict, kSecAttrKeyType, kSecAttrKeyTypeRSA ); // no return value
	CFDictionaryAddValue( pk_dict, kSecAttrKeyClass, kSecAttrKeyClassPublic ); // no return value
#if TARGET_OS_IPHONE
	// Needed for IOS, not OSX:
	CFDictionaryAddValue( pk_dict, kSecAttrApplicationTag, pk_data ); // no return value
#endif

	// Simple spinlock mutex
	while( !__sync_bool_compare_and_swap( &_rsa_lock, 0, 1 ) ){}
	__sync_synchronize();

#if TARGET_OS_IPHONE
	//
	// On IOS, we have to add to the keychain (SecItemAdd)
	//

	// Delete any existing
	s = SecItemDelete((CFDictionaryRef)pk_dict); // Return value doesn't matter

	// Add new item
	CFDictionaryAddValue( pk_dict, kSecReturnRef, kCFBooleanTrue ); // no return value
	CFDictionaryAddValue( pk_dict, kSecValueData, pk_data ); // no return value

	s = SecItemAdd((CFDictionaryRef)pk_dict, (CFTypeRef*)&pk);
#else
	//
	// On OSX, we use straight-forward SecKeyCreateFromData()
	//
	pk = SecKeyCreateFromData((CFDictionaryRef)pk_dict, pk_data, NULL);
	s = (pk == NULL) ? errSecParam : noErr; // Actual error doesn't matter
#endif

	// Confirm the last operation (SecItemAdd or SecKeyCreateFromData)
	if( pk == NULL || s != noErr ){
		if( err_details != NULL ) *err_details = 6;
		res = TCL_VERIFY_ERROR;
		goto done;
	}

	// Use the SecKeyRef to do the RSA verification
	if( res == TCL_VERIFY_OK ) { res = TCL_VERIFY_FAIL; goto done; } // integrity check
	s = SecKeyRawVerify(pk, kSecPaddingPKCS1, digest, TCL_SHA256_DIGEST_SIZE, signature, TCL_RSA_SIZE);
	if( s == errSecSuccess ) res = TCL_VERIFY_OK;
	else if( s == errSecVerifyFailed ) res = TCL_VERIFY_FAIL;
	else { 
		if( err_details != NULL ) *err_details = (int)s;
		res = TCL_VERIFY_ERROR;
	}

done:

#if TARGET_OS_IPHONE
	// Delete what we just added to the keychain
	if( pk_dict != NULL ){
		s = SecItemDelete((CFDictionaryRef)pk_dict); // Return value doesn't matter
		if( s != noErr ){
			//if( err_details != NULL ) *err_details = 8;
		}
	}
#endif

	// Unlock the mutex
	__sync_synchronize();
	_rsa_lock = 0;

	// Clean up our referrences
	if( pk != NULL ) CFRelease(pk);
	if( pk_dict != NULL ) CFRelease(pk_dict);
	if( pk_data != NULL ) CFRelease(pk_data);

	// All set
	return res;
}


uint32_t TCL_CRC32( const void *buf, uint32_t len ){
	return TFC_CRC32( buf, len );
}

uint32_t TCL_AES_CTR( uint8_t *buf, uint32_t len, uint8_t key[16], uint8_t nonce[16] ){

	//
	// Allocate temp working memory
	//
	size_t sz = (len & 0xFFFFF000) + 0x1000; // Round up to nearest 4k
	uint8_t *mem = MMAP(NULL, sz, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if( mem == MAP_FAILED ){
		return TCL_CRYPTO_ERR;
	}

	//
	// Seed our tmp buffer w/ nonce + counter data (for CTR mode)
	//
	uint32_t i = 0;
	uint32_t *u32 = (uint32_t*)mem;
	while( i < len ){
		TFMEMCPY(u32, nonce, 16);
		u32 += 3;
		*u32 = (*u32) + 1;
		u32++;
		i += 16;
	}

	//
	// Now ECB encrypt the tmp memory
	//
	size_t moved = 0;
	CCCryptorStatus cs = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode,
		key, 16, NULL, mem, i, mem, i, &moved );
	if( cs != kCCSuccess || moved != i ){
		MUNMAP(mem, sz);
		return TCL_CRYPTO_ERR;
	}

	//
	// XOR it with buffer, for CTR mode encrypt/decrypt
	//
	for( i=0; i<len; i++){
		buf[i] ^= mem[i];
	}

	//
	// All done
	//
	MUNMAP(mem, sz);
	return TCL_CRYPTO_OK;
}
