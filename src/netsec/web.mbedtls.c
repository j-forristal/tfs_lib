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
//#include "tf_crypto.h"
#include "tf_cal.h"
#include "tf_pkcs7.h"

#include PLATFORM_H

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


///////////////////////////////////////////////////////////////
//
// Local structures
//

typedef struct conn_t {
        int sock;
	uint32_t timeout_ms;
	TFN_WebRequest_t *request;
	uint32_t cert_flags;

	mbedtls_ssl_context ssl;
	mbedtls_ssl_context ssl_proxy;

	// For proxy stuff:
	uint8_t has_ssl;
	uint8_t has_ssl_proxy;
	uint8_t is_proxy;
	uint8_t is_draining;

} conn_t;

static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;
static mbedtls_ssl_config _conf;

#include "web.certcb.inline.c"
#include "web.commontop.inline.c"
#include "web.commonio.inline.c"


///////////////////////////////////////////////////////////////
//
// Implementation
//

static void _handle_mbedtls_error( conn_t *conn, int *res )
{
	ASSERT(res);
	ASSERT(conn);
	ASSERT(conn->request);

	if( *res < 0 ){ 
		ASSERT( (*res) != MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

		conn->request->error_debug = *res;
		if( (*res) == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ){
			*res = 0;
			return;
		}
		if( (*res) == MBEDTLS_ERR_SSL_WANT_READ || (*res) == MBEDTLS_ERR_SSL_WANT_WRITE ) 
			errno = EAGAIN; 
		else errno = EIO; 
		*res = -1;
	} 
}


//
// _sslwrite & _sslread are mbedtls-specific network I/O handlers
//
static int _sslwrite( void *ctx, const unsigned char *buf, size_t len )
{
	conn_t *conn = (conn_t*)ctx;
	ASSERT(conn);
	ASSERT(buf);

	ssize_t r = _io_native( conn, (uint8_t*)buf, len, 1, 0 );
	if( r > 0 ) return (int)r;
	else if( r == 0 ) return MBEDTLS_ERR_SSL_CONN_EOF;
	else if( r == -1 && errno == EAGAIN ) return MBEDTLS_ERR_SSL_WANT_WRITE;
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int _sslread( void *ctx, unsigned char *buf, size_t len )
{
	conn_t *conn = (conn_t*)ctx;
	ASSERT(conn);
	ASSERT(buf);

	ssize_t r = _io_native( conn, (uint8_t*)buf, len, 0, 0 );
	if( r > 0 ) return (int)r;
	else if( r == 0 ) return MBEDTLS_ERR_SSL_CONN_EOF;
	else if( r == -1 && errno == EAGAIN ) return MBEDTLS_ERR_SSL_WANT_READ;
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}


//
// _sslwrite_proxy & _sslread_proxy are mbedtls-specific network I/O handlers that
// pass thru to another SSL layer
//
static int _sslwrite_proxy( void *ctx, const unsigned char *buf, size_t len )
{
	conn_t *conn = (conn_t*)ctx;
	ASSERT(conn);
	ASSERT(buf);
	ASSERT(conn->has_ssl_proxy);

	return mbedtls_ssl_write( &conn->ssl_proxy, buf, len );
}
static int _sslread_proxy( void *ctx, unsigned char *buf, size_t len )
{
	conn_t *conn = (conn_t*)ctx;
	ASSERT(conn);
	ASSERT(buf);
	ASSERT(conn->has_ssl_proxy);

	return mbedtls_ssl_read( &conn->ssl_proxy, buf, len );
}



//
// _send and _recv are high-level IO calls
//

static ssize_t _recv( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	ASSERT(conn);
	ASSERT(data);

	if( conn->has_ssl == 0 )
		return _io_native( conn, data, data_len, 0, 0 );

	int res = mbedtls_ssl_read( &conn->ssl, data, data_len );
	_handle_mbedtls_error(conn, &res);
	return (size_t)res;
}

static ssize_t _send( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	ASSERT(conn);
	ASSERT(data);

	if( conn->has_ssl == 0 )
		return _io_native( conn, data, data_len, 1, 0 );

	ASSERT(conn->ssl.conf);
	int res = mbedtls_ssl_write( &conn->ssl, data, data_len );
	_handle_mbedtls_error(conn, &res);
	return (size_t)res;
}


static int _ssl_handshake( conn_t *conn, int is_proxy )
{
	// need to do an SSL handshake
	do {
		int r = mbedtls_ssl_handshake( &conn->ssl );
		_handle_mbedtls_error(conn,&r);
		if( r >= 0 ) return r;
		if( r == -1 && errno == EAGAIN ){
			r = _poll( conn->sock, POLLIN, conn->timeout_ms );
			if( r > 0 ) continue; // ready, so try again
			if( r == 0 ){
				errno = ETIMEDOUT;
				r = -1;
			}
			// fall through with res == -1
		}
		return r;
	} while(1);
}


static int _close_ret( conn_t *conn, int ret )
{
	int errno_ = errno; // backup errno
	if( conn->has_ssl ){
		mbedtls_ssl_close_notify( &conn->ssl );
		mbedtls_ssl_free( &conn->ssl );
		conn->has_ssl = 0;
	}
	if( conn->has_ssl_proxy ){
		mbedtls_ssl_close_notify( &conn->ssl_proxy );
		mbedtls_ssl_free( &conn->ssl_proxy );
		conn->has_ssl_proxy = 0;
	}
	if( conn->sock != -1 ){
		CLOSE( conn->sock );
		conn->sock = -1;
	}
	errno = errno_; // restore errno
	return ret;
}

#ifdef MBEDTLS_IS_PATCHED
//
// MBedtls cert callback function, only used in patched versions of mbedtls
//
static int _m_cert_callback( void *p, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
	if( crt == NULL || crt->raw.p == NULL ) goto bad;
	ASSERT(p);
	conn_t *conn = (conn_t*)p;

	// No callback means pass thru
	ASSERT(conn->request);
	if( conn->request->cert_callback == NULL ) return 0;

	// Call the centralized callback handler
	int res = _cert_callback( conn, crt->raw.p, crt->raw.len, depth, conn->is_proxy );
        conn->cert_flags |= res;
        if( res == TFN_CERT_DENY ) goto bad;
        return 0; // allow or pass

bad:
	ASSERT(flags);
        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        return 1;
}
#endif


static int _ssl_setup_and_handshake(conn_t *conn, int is_proxy)
{
	ASSERT(conn);
	ASSERT(conn->request);

	// Thread safety: clone our global config into local config:
	mbedtls_ssl_config local_conf_;
	TFMEMCPY( &local_conf_, &_conf, sizeof(mbedtls_ssl_config) );

#ifdef MBEDTLS_IS_PATCHED
	// Set up our cert callback with connection local parameter:
	mbedtls_ssl_conf_verify( &local_conf_, _m_cert_callback, conn );
#endif

	// Now init ssl objects
	mbedtls_ssl_init( &conn->ssl ); // no return value
	conn->has_ssl = 1;
	if( mbedtls_ssl_setup( &conn->ssl, &local_conf_ ) != 0 ){
		conn->request->error_debug=2;
		return _close_ret( conn, TFN_ERR_SYSTEM );
	}

	// NOTE: mbedtls_ssl_set_bio() does not return a value
	if( is_proxy == 0 && (conn->request->flags & TFN_WEBREQUEST_FLAG_PROXY_SSL) ){
		mbedtls_ssl_set_bio( &conn->ssl, conn, &_sslwrite_proxy, &_sslread_proxy, NULL );
	} else {
		mbedtls_ssl_set_bio( &conn->ssl, conn, &_sslwrite, &_sslread, NULL );
	}

	if( !is_proxy ){
		if( mbedtls_ssl_set_hostname( &conn->ssl, conn->request->hostname ) != 0 ){
			conn->request->error_debug=3;
			return _close_ret( conn, TFN_ERR_SYSTEM );
		}
	}

	// Do the handshake
	conn->is_proxy = is_proxy;
	int res = _ssl_handshake( conn, is_proxy );

	// NOTE: may be null:
	const mbedtls_x509_crt *peercert = mbedtls_ssl_get_peer_cert( &conn->ssl );

	if( res < 0 ){ 
		// handshake failed; if we have a cert, report it as part of failure
		if( conn->request->cert_failed_callback != NULL && peercert != NULL && peercert->raw.p != NULL )
			conn->request->cert_failed_callback(conn->request, 0, peercert->raw.p, peercert->raw.len);
		return _close_ret( conn, TFN_ERR_SSLHANDSHAKE );
	}

	// NOTE: if MBEDTLS_IS_PATCHED, then the cert callbacks happen as part of the handshake
	// (i.e. calls to _m_cert_callback)

#ifndef MBEDTLS_IS_PATCHED
	//
	// Check if this cert is allowed; this only can check the leaf cert (depth=0)
	//
	if( peercert != NULL && peercert->raw.p != NULL ){
		res = _cert_callback( conn, peercert->raw.p, peercert->raw.len, 0, 0 );
		conn.cert_flags |= res;
	}
#endif

	// We need to see an ALLOW to keep going
	if( (conn->cert_flags & TFN_CERT_DENY) || ((conn->cert_flags & TFN_CERT_ALLOW) == 0) ){
		// Didn't encounter a pin
		if( conn->request->cert_failed_callback != NULL && peercert != NULL && peercert->raw.p != NULL )
			conn->request->cert_failed_callback(conn->request, 0, peercert->raw.p, peercert->raw.len);
		return _close_ret( conn, TFN_ERR_PINVIOLATION );
	}

	// We saw an allowed cert, so keep going...
	return TFN_SUCCESS;
}


void _debug(void *v, int level, const char *file, int line, const char *l){
	printf("%s\n", l);
}


//
// Main Init function
//

int TFN_Web_Init()
{
	uint32_t work[WORK_MAX];
	int ret;

	ASSERT( TFN_WEB_PINSHA256_SIZE == TCL_SHA256_DIGEST_SIZE );

	mbedtls_ssl_config_init( &_conf ); 
	mbedtls_ctr_drbg_init( &_ctr_drbg );
	mbedtls_entropy_init( &_entropy );

	ret = mbedtls_ctr_drbg_seed( &_ctr_drbg, mbedtls_entropy_func, &_entropy,
		(const unsigned char *)_S(ADDSEC), 6);
	if( ret != 0 ) return -1;

	ret = mbedtls_ssl_config_defaults( &_conf, MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT );
	if( ret != 0 ) return -1;

#ifdef MBEDTLS_IS_PATCHED
	// Patched mode uses optional verification (without a CA), so
	// cert chain verification will still happen and our callback will
	// be called to notice a proper pin anywhere in the chain
	mbedtls_ssl_conf_authmode( &_conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
#else
	// Unpatched mbedtls expects a CA to do any verification, so we have
	// to turn verification fully off and then later validate (just)
	// the leaf cert.  We lose access to the full chain.
	mbedtls_ssl_conf_authmode( &_conf, MBEDTLS_SSL_VERIFY_NONE );
#endif

	//_conf.f_dbg = _debug;
	//mbedtls_debug_set_threshold(1);

	mbedtls_ssl_conf_rng( &_conf, mbedtls_ctr_drbg_random, &_ctr_drbg );
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
		// Bad config 
		return TFN_ERR_PARAMETERS;
	}


	/////////////////////////////////////////////////////////////
	// Dial operations
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


	/////////////////////////////////////////////////////////////
	// Proxy setup phase
	//
        // Do SSL handshake with proxy, if warranted
        if( (request->flags & (TFN_WEBREQUEST_FLAG_PROXY|TFN_WEBREQUEST_FLAG_PROXY_SSL)) ==
                        (TFN_WEBREQUEST_FLAG_PROXY|TFN_WEBREQUEST_FLAG_PROXY_SSL) ){
                int r = _ssl_setup_and_handshake( &conn, 1 );
                if( r != TFN_SUCCESS) return r; // Already close_ret
        }


	// Run through the HTTPS proxy, if warranted
#include "web.commonproxy.inline.c"


	/////////////////////////////////////////////////////////////
	// Client request phase
	//

	// SPECIAL: mbedtls shares the global config object in the ssl context,
	// and it's the only place to pass per-session parameters for SSL
	// verify callback.  So, we need to make a copy of the global config
	// for any SSL connection to keep things thread-safe.  This was verified
	// by source code audit of mbedtls cert handling.
	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){

		// If proxy is SSL, then save the current CTX
		if( request->flags & TFN_WEBREQUEST_FLAG_PROXY_SSL ){
			TFMEMCPY(&conn.ssl_proxy, &conn.ssl, sizeof(conn.ssl));
			conn.has_ssl = 0;
			conn.has_ssl_proxy = 1;
		}

                int r = _ssl_setup_and_handshake( &conn, 0 );
                if( r != TFN_SUCCESS) return r; // Already close_ret
	}

	// Everything after here is generic HTTP client
#include "web.commonclient.inline.c"

	// Common client code returns the success value
}
