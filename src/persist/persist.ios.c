// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.


#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "tf_persist.h"
#include "tf_cal.h"
#include PLATFORM_H

//
//http://useyourloaf.com/blog/simple-iphone-keychain-access/
//

#define HEADER_SIZE 	(sizeof(uint32_t) + TCL_AES_BLOCK_SIZE + TCL_SHA256_DIGEST_SIZE)
#define MAGIC		0x7f505501

static CFMutableDictionaryRef _create_dict( const uint8_t *key, char *service )
{
	ASSERT(key);

	CFMutableDictionaryRef dict = CFDictionaryCreateMutable( NULL, 0, &kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks );
	if( dict == NULL ) return dict;

	CFDictionaryAddValue( dict, kSecClass, kSecClassGenericPassword );

	CFDataRef keyname = CFDataCreate( NULL, key, STRLEN((const char*)key) );
	if( keyname == NULL ){
		CFRelease(dict);
		return NULL;
	}
	CFDictionaryAddValue( dict, kSecAttrGeneric, keyname );
	CFDictionaryAddValue( dict, kSecAttrAccount, keyname );
	CFRelease(keyname);

	CFDictionaryAddValue( dict, kSecAttrAccessible, kSecAttrAccessibleAlwaysThisDeviceOnly );

	if( service != NULL ){
		CFStringRef s = CFStringCreateWithCString(NULL, service, kCFStringEncodingMacRoman);
		if( s == NULL ){
			CFRelease( dict );
			return NULL;
		}
		CFDictionaryAddValue( dict, kSecAttrService, s );
		CFRelease( s );
	} else {
		// NOT-MVP-TODO: obfuscate this string?
		CFDictionaryAddValue( dict, kSecAttrService, CFSTR("tft") );
	}
	return dict;
}

int TFP_Get_Ex( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len,
        uint8_t *ikey, uint32_t ikey_len, char *service )
{
	// NOTE: basepath is ignored; output, ikey can be NULL
	ASSERT(key);
	ASSERT(len);

	CFMutableDictionaryRef dict = _create_dict( key, service );
	if( dict == NULL ) return TFP_ERR;

	CFDictionaryAddValue( dict, kSecMatchLimit, kSecMatchLimitOne );
	CFDictionaryAddValue( dict, kSecReturnData, kCFBooleanTrue );

	CFDataRef data;
	OSStatus status = SecItemCopyMatching( dict, (const void**)&data );
	CFRelease( dict );

	if( status != errSecSuccess ) return TFP_ERR;

	CFIndex dlen = CFDataGetLength(data);
	uint32_t limit = *len;
	*len = dlen;
	
	if( ikey != NULL ){
		if( dlen < HEADER_SIZE ){
			CFRelease(data);
			return TFP_ERR;
		}
		*len -= HEADER_SIZE;
	}

	if( *len > limit || *len == 0 ){
		CFRelease(data);
		return TFP_ERR;
	}

	if( output == NULL ) return TFP_OK;

	if( ikey == NULL ){
		CFDataGetBytes( data, CFRangeMake(0,*len), output );
		CFRelease(data);
		return TFP_OK;
	}

	// We are going to SHA256 the ikey, then use first 16 bytes as AES128 key
	uint8_t ikey_digest[TCL_SHA256_DIGEST_SIZE];
	if( TCL_SHA256( ikey, ikey_len, ikey_digest ) != 0 ){
		CFRelease(data);
		return TFP_ERR;
	}

	uint32_t mlen = (dlen & 0xfffff000) + 0x1000;
	uint8_t *tmp = MMAP(NULL, mlen, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if( tmp == MAP_FAILED ){
		CFRelease(data);
		return TFP_ERR;
	}

	CFDataGetBytes( data, CFRangeMake(0,dlen), tmp );
	CFRelease(data);

	// Check the magic
	uint32_t *u32 = (uint32_t*)tmp;
	if( *u32 != MAGIC ){
		MUNMAP(tmp, mlen);
		return TFP_ERR;
	}

	// Check MAC
	uint8_t digest[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256_HMAC( ikey, ikey_len, &tmp[HEADER_SIZE], *len, digest );
	if( MEMCMP( digest, &tmp[sizeof(uint32_t) + TCL_AES_BLOCK_SIZE], TCL_SHA256_DIGEST_SIZE ) != 0 ){
		MUNMAP(tmp, mlen);
		return TFP_INTEGRITY;
	}

	// Decrypt (in-place)
	if( TCL_AES_CTR( &tmp[HEADER_SIZE], *len, ikey_digest, &tmp[sizeof(uint32_t)] ) != TCL_CRYPTO_OK ){
		MUNMAP(tmp, mlen);
		return TFP_ERR;
	}

	// Copy over to output	
	TFMEMCPY( output, &tmp[HEADER_SIZE], *len );

	// All set, cleanup
	MUNMAP(tmp, mlen);
	return TFP_OK;
}

int TFP_Get( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len )
{
	return TFP_Get_Ex( key, basepath, output, len, NULL, 0, NULL );
}

int TFP_Set_Ex( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len,
        uint8_t *ikey, uint32_t ikey_len, char *service )
{
	uint8_t *dptr = input;
	uint32_t dlen = len;

	uint32_t mlen = 0;
	if( ikey != NULL ){
		// We are going to SHA256 the ikey, then use first 16 bytes as AES128 key
		uint8_t ikey_digest[TCL_SHA256_DIGEST_SIZE];
		if( TCL_SHA256( ikey, ikey_len, ikey_digest ) != 0 ) return TFP_ERR;

		mlen = (dlen & 0xfffff000) + 0x2000; // +0x1000 is for rounding, then +0x1000 for header
		dptr = MMAP(NULL, mlen, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
		if( dptr == MAP_FAILED ) return TFP_ERR;

		// Memory layout:
		// U32 + NONCE[16] - SHA256_HMAC[32] - DATA[...]

		// Set up the magic value
		uint32_t *u32 = (uint32_t*)dptr;
		*u32 = MAGIC;

		// Copy over the original data to our new buffer
		TFMEMCPY( &dptr[HEADER_SIZE], input, len );

		// Allocate a random nonce
		if( TCL_Random( &dptr[sizeof(uint32_t)], TCL_AES_BLOCK_SIZE ) != 0 ){
			MUNMAP(dptr, mlen);
			return TFP_ERR;
		}

		// Encrypt (in-place)
		if( TCL_AES_CTR( &dptr[HEADER_SIZE], len, ikey_digest, &dptr[sizeof(uint32_t)] ) != TCL_CRYPTO_OK ){
			MUNMAP(dptr, mlen);
			return TFP_ERR;
		}

		// MAC (this is Encrypt-then-MAC)
		TCL_SHA256_HMAC( ikey, ikey_len, &dptr[HEADER_SIZE], len, &dptr[sizeof(uint32_t) + TCL_AES_BLOCK_SIZE] );

		// Adjust the total data size
		dlen = len + HEADER_SIZE;
	}

	// we try to add; if we get a duplicate error, we update instead
	
	CFMutableDictionaryRef dict = _create_dict( key, service );
	if( dict == NULL ) return TFP_ERR;

	CFDataRef data = CFDataCreate( NULL, dptr, dlen );
	if( mlen > 0 ) MUNMAP( dptr, mlen );
	if( data == NULL ){
		CFRelease(dict);
		return TFP_ERR;
	}

	CFMutableDictionaryRef dict_up = CFDictionaryCreateMutable( NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks );
	if( dict_up == NULL ){
		CFRelease(data);
		CFRelease(dict);
	}

	CFDictionaryAddValue( dict_up, kSecValueData, data );

	// Try to update existing
	OSStatus status = SecItemUpdate( dict, dict_up );
	CFRelease(dict_up);

	if( status == errSecSuccess ){
		// Updated
		CFRelease(data);
		CFRelease(dict);
		return TFP_OK;
	}

	if( status != errSecItemNotFound ){
		// Some other fatal error
		CFRelease(data);
		CFRelease(dict);
		return TFP_ERR;
	}

	// Item not found, so now try to add it

	CFDictionaryAddValue( dict, kSecValueData, data );
	CFRelease(data);

	// Attempt an add
	status = SecItemAdd( dict, NULL );
	CFRelease(dict);

	if( status == errSecSuccess ) return TFP_OK;
	return TFP_ERR;
}

int TFP_Set( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len )
{
	return TFP_Set_Ex( key, basepath, input, len, NULL, 0, NULL );
}
