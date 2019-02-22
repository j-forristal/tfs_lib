// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

static int _cert_callback( void *p, uint8_t *crt, uint32_t crt_len, int depth, int is_proxy )
{
	if( crt == NULL ) return TFN_CERT_DENY;

	ASSERT(p);
	conn_t *conn = (conn_t*)p;

	// Parse the X509
	uint8_t *spki;
	uint32_t spki_len;
	char subject[TFS_PKCS7_SUBJECT_SIZE];
	int res = TFS_PKCS7_X509_Parse( crt, crt_len, &spki, &spki_len, subject, 
		(depth == 0) ? conn->request->hostname : NULL );
	if( res != TFS_PKCS7_X509_OK && res != TFS_PKCS7_X509_OK_ERR_HOSTNAME ){
		return TFN_CERT_DENY;
	}

	// Hand it to the callback, if configured; by default, we fall back to PASS
	int callbackres = TFN_CERT_PASS;
	if( conn->request->cert_callback != NULL ){
		uint32_t flags = (depth << 16);
		if( res == TFS_PKCS7_X509_OK_ERR_HOSTNAME ) flags |= 1;
		callbackres = conn->request->cert_callback( conn->request, 
			(uint8_t*)subject, flags, is_proxy,
			crt, crt_len, spki, spki_len );
	}

	// If depth=0 and the callback explicitly says allow, then we override the
	// X509 hostname validation result (which may be invalid) with allow, since
	// a callback validating a specific cert implies it expects that subject even
	// if it's not a matching hostname.
	// NOTE: we will be tolerant of hostname mismatches for proxies, since it
	// doesn't expose more than going direct
	if( depth == 0 && (callbackres == TFN_CERT_ALLOW || is_proxy) ) res = TFS_PKCS7_X509_OK;
	if( depth == 0 && res == TFS_PKCS7_X509_OK_ERR_HOSTNAME ){
		return TFN_CERT_DENY;
	}

	if( callbackres == TFN_CERT_PASS || callbackres == TFN_CERT_ALLOW ) return callbackres;
	return TFN_CERT_DENY;
}

