// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <poll.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "tf_netsec.h"
#include "tf_cal.h"
#include "tf_pkcs7.h"

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecureTransport.h>

#include PLATFORM_H


///////////////////////////////////////////////////////////////
//
// Local structures
//

typedef struct conn_t {
        int sock;
	uint32_t timeout_ms;
	SSLContextRef ssl_ctx;
	SSLContextRef ssl_ctx_proxy;
	TFN_WebRequest_t *request;
	uint32_t cert_flags;

	// Behaviors for proxy support
	uint8_t is_draining : 1;
} conn_t;



#include "web.certcb.inline.c"
#include "web.commontop.inline.c"
#include "web.commonio.inline.c"

///////////////////////////////////////////////////////////////
//
// Implementation
//



//
// _sslwrite() and _sslread() are Darwin-specific I/O handlers that take SSL data, and
// perform native network I/O
//
static OSStatus _sslwrite( SSLConnectionRef connection, const void *data, size_t *dataLength )
{
	conn_t *conn = (struct conn_t*)connection;
	ASSERT(conn);
	ASSERT(data);
	ASSERT(dataLength);

	ssize_t r = _io_native( conn, (uint8_t*)data, *dataLength, 1, 0 );
	if( r > 0 ){
		*dataLength = r;
		return noErr;
	}
	else if( r == 0 ) return errSSLClosedGraceful;
	else if( r == -1 && errno == EAGAIN ) return errSSLWouldBlock;
	return errSSLPeerInternalError;
}
static OSStatus _sslread( SSLConnectionRef connection, void *data, size_t *dataLength )
{
	conn_t *conn = (struct conn_t*)connection;
	ASSERT(conn);
	ASSERT(data);
	ASSERT(dataLength);

	ssize_t r = _io_native( conn, data, *dataLength, 0, 0 );
	if( r > 0 ){
		*dataLength = (size_t)r;
		return noErr;
	}
	else if( r == 0 ) return errSSLClosedGraceful;
	else if( r == -1 && errno == EAGAIN ) return errSSLWouldBlock;
	return errSSLPeerInternalError;
}



//
// _sslwrite_proxy() and _sslread_proxy() are Darwin-specific I/O handlers that take SSL data, and
// and shuffle it to another (lower) SSLRead/SSLWrite call, for SSL within SSL (i.e. HTTPS proxy)
//
static OSStatus _sslwrite_proxy( SSLConnectionRef connection, const void *data, size_t *dataLength )
{
	conn_t *conn = (struct conn_t*)connection;
	ASSERT(conn);
	ASSERT(data);
	ASSERT(dataLength);
	ASSERT(conn->ssl_ctx_proxy);

	return SSLWrite( conn->ssl_ctx_proxy, data, *dataLength, dataLength );
}
static OSStatus _sslread_proxy( SSLConnectionRef connection, void *data, size_t *dataLength )
{
	conn_t *conn = (struct conn_t*)connection;
	ASSERT(conn);
	ASSERT(data);
	ASSERT(dataLength);
	ASSERT(conn->ssl_ctx_proxy);

	//
	// SPECIAL: testing has shown that the parent SSLHandshake() is not very tolerant
	// of partial reads.  So we must loop around trying to read the full requested
	// amount, otherwise the layer above will likely abort the operation.
	//

	size_t temp;
	size_t remain = *dataLength;
	uint8_t *ptr = (uint8_t*)data;

	while( remain > 0 ){
		OSStatus s = SSLRead( conn->ssl_ctx_proxy, ptr, remain, &temp );
		if( s ){
			// Error of some kind, just pass through
			return s;
		} else {
			remain -= temp;
			ptr += temp;
			if( remain == 0 ) break;
		}
	}

	*dataLength = (*dataLength - remain);
	return noErr;
}



//
// _send/_recv are the highest level calls, used by all common code, to perform network
// data I/O with all the underlying SSL accounted for.  NOTE: these functions either
// perform native I/O, or pass through to conn->ssl_ctx (top SSL layer).  There
// may be more underlying SSL layers (e.g. conn->ssl_ctx_proxy) at play.
//
static ssize_t _recv( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	ASSERT(conn);
	ASSERT(data);

	if( conn->ssl_ctx == NULL )
		return _io_native( conn, data, data_len, 0, 0 );

	//
	// SPECIAL: for draining situations, we do not want to read more
	// than what is already buffered, since it risks making a read
	// call that can stall (e.g. after proxy CONNECT).  So if there
	// is something buffered, we will perform a short-read based
	// on the buffered amount first.
	//
	size_t sz = 0;
	OSStatus oss = SSLGetBufferedReadSize( conn->ssl_ctx, &sz );
	if( oss ){
		// Interpret the Darwin error code back to something POSIX-y
		errno = EIO;
		return -1;
	}
	if( sz > 0 &&  sz < data_len ) data_len = sz;

	oss = SSLRead( conn->ssl_ctx, data, data_len, &sz );
	if( oss ){
		// Interpret the Darwin error code back to something POSIX-y
		errno = EIO;
		if( oss == errSSLWouldBlock ) errno = EAGAIN;
		return -1;
	}
	return (ssize_t)sz;
}

static ssize_t _send( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	ASSERT(conn);
	ASSERT(data);

	if( conn->ssl_ctx == NULL )
		return _io_native( conn, data, data_len, 1, 0 );

	size_t processed = 0;
	OSStatus oss = SSLWrite( conn->ssl_ctx, data, data_len, &processed );
	if( oss ){
		// Interpret the Darwin error code back to something POSIX-y
		errno = EIO;
		if( oss == errSSLWouldBlock ) errno = EAGAIN;
		return -1;
	}
	return (ssize_t)processed;
}


static int _ssl_handshake( conn_t *conn, int is_proxy )
{
	ASSERT(conn);
	ASSERT(conn->ssl_ctx);

	// need to do an SSL handshake
	SSLContextRef ssl_ctx = conn->ssl_ctx;

	int did_check = 0, success = 0, failed = 0;
	do {
		OSStatus sres = SSLHandshake( ssl_ctx );

		if( sres == errSSLWouldBlock ){
			// Special: if there is an underlying SSL layer, we can't poll the
			// socket since the underlying SSL record layer may have already
			// cached the data we are waiting on.  So we just directly re-handshake
			// and let the underlying layer handle it.
			if( conn->ssl_ctx_proxy != NULL ) continue;

			// Poll and loop on direct socket
			int r = _poll( conn->sock, POLLIN, conn->timeout_ms );
			if( r > 0 ) continue; // ready, so try again
			if( r == 0 ){
				return TFN_ERR_TIMEOUT;
			}
		}

		else if( sres == errSSLServerAuthCompleted ){
			// Interrupted handshake, now check the server cert
			did_check++;
			SecTrustRef trust = NULL;
        		sres = SSLCopyPeerTrust( ssl_ctx, &trust);
			if( sres || trust == NULL ) return TFN_ERR_SSLHANDSHAKE;

			SecTrustResultType trust_result = 0;
			if( SecTrustEvaluate( trust, &trust_result ) ){
				CFRelease( trust );
				return TFN_ERR_SSLHANDSHAKE;
			}

			// kSecTrustResultRecoverableTrustFailure should occur when it's a valid
			// chain but missing an anchor.
			// kSecTrustResultProceed is when we match an anchor.
			// kSecTrustResultUnspecified when things look OK, but the user didn't specify
			if( trust_result != kSecTrustResultRecoverableTrustFailure &&
				trust_result != kSecTrustResultProceed &&
				trust_result != kSecTrustResultUnspecified ){
				// The chain looks bad, don't allow it

				if( conn->request->cert_failed_callback != NULL && SecTrustGetCertificateCount( trust ) > 0 ){
					SecCertificateRef cert = SecTrustGetCertificateAtIndex( trust, 0 );
					if( cert ){
						CFDataRef cert_der = SecCertificateCopyData( cert );
						if( cert_der ){
							uint8_t *cder = (uint8_t*)CFDataGetBytePtr( cert_der );
							CFIndex cder_len = CFDataGetLength( cert_der );
                                        		conn->request->cert_failed_callback(conn->request, is_proxy, cder, cder_len);
							CFRelease( cert_der );
						}
						//CFRelease( cert ); // CLANG ANALYZER
					}
				}
				CFRelease( trust );
				return TFN_ERR_PINVIOLATION;
			}

			// Chain looks ok, so look for our pin by walking the chain backwards.
			// We also purposefully land on the first cert, so we can do some
			// extra leaf validation.

			CFIndex cert_count = SecTrustGetCertificateCount( trust );
			int i, res = TFN_CERT_DENY, allowed = 0;

			// Walk backwards so we finish on the leaf cert, for reporting:
			for( i=(cert_count - 1); i>=0; i-- ){

				// NOTE: by default, if we can't get the cert, we act as if DENY
				res = TFN_CERT_DENY;
				SecCertificateRef cert = SecTrustGetCertificateAtIndex( trust, i );

				if( cert ){
					CFDataRef cert_der = SecCertificateCopyData( cert );
					if( cert_der ){
						uint8_t *cder = (uint8_t*)CFDataGetBytePtr( cert_der );
						CFIndex cder_len = CFDataGetLength( cert_der );

						res = _cert_callback( conn, cder, cder_len, i, is_proxy );

						// If we got an explicit deny, or we got down to the first
						// cert without an explicit allow (i.e. we got pass), then
						// we didn't match
						if( (i == 0 && allowed == 0 && res == TFN_CERT_PASS) || res == TFN_CERT_DENY ){
                                			// Didn't encountered a pin, or had a deny or an error, so we're done
                                			if( conn->request->cert_failed_callback != NULL ){
                                        			conn->request->cert_failed_callback(conn->request,
									is_proxy, cder, cder_len);
								failed++;
							}
						}
						CFRelease( cert_der );
					}
					//CFRelease( cert ); // CLANG ANALYZER
				}
				if( res == TFN_CERT_ALLOW ) { allowed = 1; }
				if( res == TFN_CERT_DENY ) break;
			}

			CFRelease( trust );
			if( res == TFN_CERT_DENY ) return TFN_ERR_PINVIOLATION;
			if( allowed > 0 ){ success = 1; }

			// Loop to finish the handshake
		}
		else if( sres == 0 ){
			// Handshake success, done
			break;
		}
		else if( sres == errSSLRecordOverflow || sres == errSecParam || sres == errSSLClosedAbort ){
			// This is witnessed in testing, causing an infinite loop;
			// so if we see it, immediately be done
			return TFN_ERR_SSLHANDSHAKE;
		}

	} while(1);

	// Integrity protection: some hooks will override SSLHandshake and basically
	// skip the AuthComplete return; so we check and see we actually got one
	if( did_check == 0 ){
		// We didn't get an AuthComplete, but it says success.
		return TFN_ERR_PINNOTCHECKED;
	}

	// If we marked success (and did_check), then things look good
	if( success > 0 ) return TFN_SUCCESS;

	// Allow would return success, above.  if we get here, it's basically considered
	// a pin volation.
	if( failed == 0 ){
		if( conn->request->cert_failed_callback != NULL )
			conn->request->cert_failed_callback(conn->request, is_proxy, NULL, 0);
	}
	return TFN_ERR_PINVIOLATION;
}


static int _close_ret( conn_t *conn, int ret )
{
	ASSERT(conn);

	int errno_ = errno; // backup the errno
	if( conn->ssl_ctx != NULL ){
		SSLClose( conn->ssl_ctx );

		// TODO BUG BUG BUG: docs say we have to CFRelease our value returned
		// by SSLCreateContext (which we use).  However, when we do that, we
		// get a segfault.
		//CFRelease( conn->ssl_ctx );
		conn->ssl_ctx = NULL;
	}
	if( conn->ssl_ctx_proxy != NULL ){
		SSLClose( conn->ssl_ctx_proxy );

		// TODO BUG BUG BUG: docs say we have to CFRelease our value returned
		// by SSLCreateContext (which we use).  However, when we do that, we
		// get a segfault.
		//CFRelease( conn->ssl_ctx_proxy );
		conn->ssl_ctx_proxy = NULL;
	}
	if( conn->sock != -1 ){
		CLOSE( conn->sock );
		conn->sock = -1;
	}
	errno = errno_; // restore the errno
	return ret;
}


static int _ssl_setup_and_handshake(conn_t *conn, int is_proxy)
{
	ASSERT(conn);
	ASSERT(conn->request);

	conn->ssl_ctx = SSLCreateContext( NULL, kSSLClientSide, kSSLStreamType );
	if( conn->ssl_ctx == NULL ){
		return _close_ret( conn, TFN_ERR_SYSTEM );
	}

	// If proxy is SSL, then we need to use different IO funcs
	if( is_proxy == 0 && (conn->request->flags & TFN_WEBREQUEST_FLAG_PROXY_SSL) ){
		if( SSLSetIOFuncs( conn->ssl_ctx, _sslread_proxy, _sslwrite_proxy) ){
			return _close_ret( conn, TFN_ERR_SYSTEM );
		}
	} else {
		if( SSLSetIOFuncs( conn->ssl_ctx, _sslread, _sslwrite) ){
			return _close_ret( conn, TFN_ERR_SYSTEM );
		}
	}

	// Pass our connection object to the underlying SSL functions
	if( SSLSetConnection( conn->ssl_ctx, (SSLConnectionRef)conn ) ){
		return _close_ret( conn, TFN_ERR_SYSTEM );
	}

	if( !is_proxy ){
		ASSERT(conn->request->hostname);
		if( SSLSetPeerDomainName( conn->ssl_ctx, conn->request->hostname, 
			STRLEN(conn->request->hostname) )){
			return _close_ret( conn, TFN_ERR_SYSTEM );
		}
	}

	// Break on auth, which let's our SSL pinning work
	if( SSLSetSessionOption( conn->ssl_ctx, kSSLSessionOptionBreakOnServerAuth, true ) ){
		return _close_ret( conn, TFN_ERR_SYSTEM );
	}

	// Tampering can override the SetOption, so check it's turned on
	Boolean v;
	if( SSLGetSessionOption( conn->ssl_ctx, kSSLSessionOptionBreakOnServerAuth, &v) != 0 || v != true ){
		return _close_ret( conn, TFN_ERR_SYSTEM );
	}

	// Handle ssl handshake & cert enforcement
	int res = _ssl_handshake( conn, is_proxy );
	if( res != TFN_SUCCESS ){ 
		if( is_proxy ){
			// Adjust the error codes to be proxy-related error codes
			if ( res == TFN_ERR_TIMEOUT ) res = TFN_ERR_TIMEOUT_PROXY;
			else if ( res == TFN_ERR_NETWORK ) res = TFN_ERR_NETWORK_PROXY;
			else if ( res == TFN_ERR_SSLHANDSHAKE ) res = TFN_ERR_SSLHANDSHAKE_PROXY;
		}
		return _close_ret( conn, res );
	}

	return TFN_SUCCESS;
}


//
// Main Init function
//

int TFN_Web_Init()
{
	ASSERT( TFN_WEB_PINSHA256_SIZE == TCL_SHA256_DIGEST_SIZE );
	return 0;
}


//
// Main Request function
//

int TFN_Web_Request( TFN_WebRequest_t *request )
{
	if( request == NULL ) return TFN_ERR_PARAMETERS;
	uint32_t work[WORK_MAX]; // for obfuscated strings

	// Check we have sufficient working buffer space
	ASSERT(request->response_data);
	ASSERT(request->response_data_max >= 256);
	if( request->response_data == NULL || request->response_data_max < 256 ){
		return TFN_ERR_PARAMETERS;
	}

#if 0
        char *buffer = (char*)request->response_data;
	size_t buffer_sz = request->response_data_max;
#endif

	// our connection tracking object
	conn_t conn;
	MEMSET( &conn, 0, sizeof(conn) );
	conn.request = request;
	conn.timeout_ms = request->timeout_ms;
	if( conn.timeout_ms == 0 ) conn.timeout_ms = TFN_TIMEOUT_MS_DEFAULT;

	// reset output values
	request->error_debug = 0;
	request->response_code = 0;
	request->response_data_len = 0;
	request->response_data_body_offset = 0;

	// sanity check the configuration
	if( (request->flags & (TFN_WEBREQUEST_FLAG_SSL|TFN_WEBREQUEST_FLAG_PROXY_SSL))
		&& request->cert_callback == NULL ){
		// Bad config - will effectively always deny
		return TFN_ERR_PARAMETERS;
	}


	///////////////////////////////////////////////////////////
	// Dial stage
	//

	// create a nonblock socket
#if defined(SOCK_NONBLOCK)
	conn.sock = SOCKET(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
	if( conn.sock == -1 ){ request->error_debug=1; return TFN_ERR_SYSTEM; }
#elif defined(O_NONBLOCK)
	conn.sock = SOCKET(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if( conn.sock == -1 ){ request->error_debug=1; return TFN_ERR_SYSTEM; }
	int flags = FCNTL(conn.sock, F_GETFL, 0);
	//if( flags == -1 ){ request->error_debug=1; return TFN_ERR_SYSTEM; }
	if( flags == -1 || FCNTL(conn.sock, F_SETFL, flags|O_NONBLOCK) == -1 ){
		CLOSE(conn.sock); request->error_debug=1; return TFN_ERR_SYSTEM; }
#else
#error no SOCK_NONBLOCK/O_NONBLOCK
#endif

	// Connect to destination; NOTE: that destination is either the URL
	// destination, or the proxy destination -- that is handled external to this function
	// (which let's caller decide things like multi-DNS answer retry, etc.)
	int res = _connect( &conn, &request->destination );
	if( res != 0 ){
		if( errno == ETIMEDOUT )
			res = (request->flags & TFN_WEBREQUEST_FLAG_PROXY) ? TFN_ERR_TIMEOUT_PROXY : TFN_ERR_TIMEOUT;
		else if( errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETDOWN ||
			errno == ENETUNREACH || errno == ECONNRESET ){
			request->error_debug |= (1 << 24);
			res = (request->flags & TFN_WEBREQUEST_FLAG_PROXY) ? TFN_ERR_NETWORK_PROXY : TFN_ERR_NETWORK;
		} else { request->error_debug=4; res = TFN_ERR_SYSTEM; }
		return _close_ret( &conn, res );
	}



	///////////////////////////////////////////////////////////
	// Proxy setup stage
	//

	// Do SSL handshake with proxy, if warranted
	if( (request->flags & (TFN_WEBREQUEST_FLAG_PROXY|TFN_WEBREQUEST_FLAG_PROXY_SSL)) == 
			(TFN_WEBREQUEST_FLAG_PROXY|TFN_WEBREQUEST_FLAG_PROXY_SSL) ){
		int r = _ssl_setup_and_handshake( &conn, 1 );
		if( r != TFN_SUCCESS) return r; // Already close_ret
	}

	// Run through the HTTPS proxy, if warranted
#include "web.commonproxy.inline.c"


	///////////////////////////////////////////////////////////
	// Client stage
	//

	// Set up client HTTPS
	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){

		// If proxy is SSL, then save the current CTX
		if( request->flags & TFN_WEBREQUEST_FLAG_PROXY_SSL ){
			conn.ssl_ctx_proxy = conn.ssl_ctx;
			conn.ssl_ctx = NULL;
		}

		int r = _ssl_setup_and_handshake( &conn, 0 );
		if( r != TFN_SUCCESS) return r; // Already close_ret
	}

	// Common request/response handling
#include "web.commonclient.inline.c"

	// Common client code returns the success value
}
