// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "tf_persist.h"
#include PLATFORM_H

#define DICT_NOM "com.example"

//
//http://useyourloaf.com/blog/simple-iphone-keychain-access/
//

static CFMutableDictionaryRef _create_dict( const uint8_t *key )
{
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

	CFDictionaryAddValue( dict, kSecAttrService, CFSTR(DICT_NOM) );
	return dict;
}

int TFP_Get( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len )
{
	CFMutableDictionaryRef dict = _create_dict( key );
	if( dict == NULL ) return TFP_ERR;

	CFDictionaryAddValue( dict, kSecMatchLimit, kSecMatchLimitOne );
	CFDictionaryAddValue( dict, kSecReturnData, kCFBooleanTrue );

	CFDataRef data;
	OSStatus status = SecItemCopyMatching( dict, (const void**)&data );
	CFRelease( dict );

	if( status != errSecSuccess ) return TFP_ERR;

	if( CFDataGetLength(data) > *len ){
		CFRelease(data);
		return TFP_ERR;
	}
	*len = CFDataGetLength(data);

	CFDataGetBytes( data, CFRangeMake(0,*len), output );
	CFRelease(data);
	return TFP_OK;
}

int TFP_Set( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len )
{
	// we try to add; if we get a duplicate error, we update instead
	
	CFMutableDictionaryRef dict = _create_dict( key );
	if( dict == NULL ) return TFP_ERR;

	CFDataRef data = CFDataCreate( NULL, input, len );
	if( data == NULL ){
		CFRelease(dict);
		return TFP_ERR;
	}

	CFMutableDictionaryRef dict_up = CFDictionaryCreateMutable( NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks );
	if( dict_up == NULL ){
		CFRelease(data);
		CFRelease(dict);
		return TFP_ERR;
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
