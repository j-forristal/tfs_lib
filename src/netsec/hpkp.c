// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include "tf_netsec.h"
#include "tf_crypto.h"

int TFN_HPKP_Configure( TFN_HPKP_Manager_t *hm, TFN_WebRequest_t *req )
{
	return 0;
}

int TFN_HPKP_Header_Load( TFN_HPKP_Manager_t *hm, uint8_t *headerval, uint32_t headerval_len )
{
	// RFC7469
	// We ignore max-age and report-uri, and only
	// recognize pin-sha256 values

	// forward scan for "pin-sha256="
	int i;
	for( i=0; i<headerval_len; i++ ){
		// skip whitespace or semicolon
		if( headerval[i] == ' ' || headerval[i] == '\t' || headerval[i] == ';' ) continue;

		// check key name
		if( headerval[i] == 'i' && (headerval_len-i) >= 17 && 
			MEMCMP(&headerval[i], "includeSubDomains", 17) == 0 ){
			// TODO - subdomain flag
			i += 17;
			continue;
		}

		if( headerval[i] != 'p' || (headerval_len-i) < 12 || 
			MEMCMP(&headerval[i], "pin-sha256=\"", 12 ) != 0 ){
			// some other key, skip to semicolon or end of string
			for( ; i<headerval_len; i++ ){
				if( headerval[i] != ';' ) break; }
			continue;
		}

		// we have key of value pin-sha256="
		i += 12;

		// a sha256 base64-encode value will always be 44 chars
		if( (i+44) >= headerval_len || headerval[i+44] != '"' ){
			return -1; } // malformed

		uint8_t digest[TFC_SHA256_DIGEST_SIZE];
		if( TFC_Base64_Decode( &headerval[i], 44, digest, sizeof(digest) ) != 0 ){
			return -1; } // malformed

		// TODO log the digest
	}

	return 0;
}

