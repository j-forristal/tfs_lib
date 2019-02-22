// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <poll.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "tf_netsec.h"
#include "tf_cal.h"
#include "tf_pkcs7.h"

#include PLATFORM_H

typedef struct conn_t {
        int sock;
	uint32_t timeout_ms;
        SSL *ssl;
	TFN_WebRequest_t *request;
	uint8_t is_pin_found : 1;
	uint8_t is_draining : 1;
} conn_t;


#include "web.certcb.inline.c"
#include "web.commontop.inline.c"
#include "web.commonio.inline.c"

///////////////////////////////////////////////////////////////
//
// Implementation
//


static int _close_ret( conn_t *conn, int ret );

static void _handle_openssl_error( conn_t *conn, int *res, SSL *ssl )
{
	ASSERT(conn);
	ASSERT(res);
	ASSERT(ssl);

	if( *res < 0 ){ 
		*res = -1;
		int err = SSL_get_error( ssl, *res );
		if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) 
			errno = EAGAIN; 
		else if ( err ==  SSL_ERROR_ZERO_RETURN ) *res = 0; 
		else errno = EIO; 
	} 
}


static ssize_t _recv( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	ASSERT(conn);
	ASSERT(data);

	if( conn->ssl == NULL )
		return _io_native( conn, data, data_len, 0, 0 );

	int res = 0;
	uint32_t left = data_len;

	while(left > 0){

		// attempt our read
		res = SSL_read( conn->ssl, data, left );
		_handle_openssl_error(conn, &res, conn->ssl);

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			res = _poll( conn->sock, POLLIN|POLLOUT, conn->timeout_ms );
			if( res > 0 ) continue; // ready, so read again
			// fall through with res == -1 or res == 0
		}

		// poll or read error
		if( res == -1 ){
			// if we had data, then let's return it as a partial read;
			// this risks the caller making another read and having the
			// error again, but that's acceptable.
			if( left != data_len ) break;
			// otherwise it's all an error
			return -1;
		}

		// read EOF or poll timeout, either way we're done
		if( res == 0 ) break;

		// we read something, so do accounting and read more/loop
		if( res > 0 ){
			data += res;
			left -= res;
			continue;
		}
	}

	// return how much we actually read, which might be 0 if we read nothing
	// (which appropriately would be an EOF condition)
	return (ssize_t)(data_len - left);
}


static ssize_t _send( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	ASSERT(conn);
	ASSERT(data);

	if( conn->ssl == NULL )
		return _io_native( conn, data, data_len, 1, 0 );

	int res = 0;
	uint32_t left = data_len;

	while(left > 0){

		// attempt our write
		res = SSL_write( conn->ssl, data, left );
		_handle_openssl_error(conn, &res, conn->ssl);

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			res = _poll( conn->sock, POLLIN|POLLOUT, conn->timeout_ms );
			if( res > 0 ) continue; // ready, so write again
			// fall through with res == -1 or res == 0
		}

		// poll or write error
		if( res == -1 ){
			// if we had data, then let's return it as a partial write;
			// this risks the caller making another write and having the
			// error again, but that's acceptable.
			if( left != data_len ) break;
			// otherwise it's all an error
			return -1;
		}

		// poll timeout, we're done
		if( res == 0 ) break;

		// we wrote something, so do accounting and write more/loop
		if( res > 0 ){
			data += res;
			left -= res;
			continue;
		}
	}

	// return how much we actually wrote, which might be 0 if we wrote nothing
	// TODO if it's zero, should we instead return -1?
	return (ssize_t)(data_len - left);
}


static int _ssl_handshake( conn_t *conn, int is_proxy )
{
	ASSERT(conn);
	ASSERT(conn->ssl);

	// need to do an SSL handshake
	do {
		int r = SSL_connect( conn->ssl );
		_handle_openssl_error(conn, &r, conn->ssl);
		if( r >= 0 ) return r;
		if( r == -1 && errno == EAGAIN ){
			r = _poll( conn->sock, POLLOUT|POLLIN, conn->timeout_ms );
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


static SSL_CTX* _ssl_ctx = NULL;
static int _ssl_exdata_idx = 0;


static int _ssl_setup_and_handshake(conn_t *conn, int is_proxy)
{
	ASSERT(_ssl_ctx);
	ASSERT(conn);
	ASSERT(conn->request);

	conn->ssl = SSL_new( _ssl_ctx );
	if( conn->ssl == NULL || 
		SSL_set_fd( conn->ssl, conn->sock ) != 1 || 
		SSL_set_ex_data( conn->ssl, _ssl_exdata_idx, conn ) != 1 )
	{
		return _close_ret( conn, TFN_ERR_SYSTEM );
	}

	int res = _ssl_handshake( conn, is_proxy );
	X509 *peercert = SSL_get_peer_certificate( conn->ssl );
	if( res <= 0 ){
		if( errno == ETIMEDOUT ) res = TFN_ERR_TIMEOUT;
		else res = TFN_ERR_SSLHANDSHAKE;

		if( conn->request->cert_failed_callback != NULL ){
			if( peercert != NULL ){
				uint8_t *cert_buf = NULL;
				int cert_len = i2d_X509(peercert, &cert_buf);
				if( cert_buf != NULL && cert_len > 0 ){
					conn->request->cert_failed_callback(conn->request, is_proxy, cert_buf, cert_len);
					OPENSSL_free(cert_buf);
				} else {
					conn->request->cert_failed_callback(conn->request, is_proxy, NULL, 0);
				}
			} else {
				conn->request->cert_failed_callback(conn->request, is_proxy, NULL, 0);
			}
		}
		if( peercert != NULL ) X509_free(peercert);

		return _close_ret( conn, res );
	}

	if( conn->is_pin_found == 0 ){
		// Didn't encounter a pin
		if( conn->request->cert_failed_callback != NULL ){
			if( peercert != NULL ){
				uint8_t *cert_buf = NULL;
				int cert_len = i2d_X509(peercert, &cert_buf);
				if( cert_buf != NULL && cert_len > 0 ){
					conn->request->cert_failed_callback(conn->request, is_proxy, cert_buf, cert_len);
					OPENSSL_free(cert_buf);
				} else {
					conn->request->cert_failed_callback(conn->request, is_proxy, NULL, 0);
				}
			} else {
				conn->request->cert_failed_callback(conn->request, is_proxy, NULL, 0);
			}
		}
		if( peercert != NULL ) X509_free(peercert);

		return _close_ret( conn, TFN_ERR_PINVIOLATION );
	}

	if( peercert != NULL ) X509_free(peercert);
	return TFN_SUCCESS;
}

static int _verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	ASSERT(cert);

	int err = X509_STORE_CTX_get_error(x509_ctx);
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);

	SSL *ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ASSERT(ssl);
	conn_t *conn = (conn_t*)SSL_get_ex_data(ssl, _ssl_exdata_idx);
	ASSERT(conn);

	uint8_t *buf = NULL;
	int cert_len = i2d_X509(cert, &buf);
	if( buf == NULL || cert_len <= 0 ){
		// Debatable what to do here; if we can't get the cert, we are considering it
		// a validation failure
		return 0;
	}
	int res = _cert_callback( conn, buf, cert_len, depth, 0 );
	OPENSSL_free(buf);

	if( res == TFN_CERT_DENY ) return 0;
	else if( res == TFN_CERT_ALLOW ) {
		// Pin was found
		conn->is_pin_found = 1;
		return 1;
	}

	// Errors related to untrusted certs are basically overridden, then checked against
	// finding a pin. But any error related to cert parsing or chain verification is
	// a problem.
	// https://wiki.openssl.org/index.php/Manual:X509_STORE_CTX_get_error(3)
	if( err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT || err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
		err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN || err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
		err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE )
	{
		// Chain verification issue; return success
		return 1;
	}

	// Return whatever preverify said
	return preverify_ok;
}


int TFN_Web_Init()
{
	ASSERT( TFN_WEB_PINSHA256_SIZE == TCL_SHA256_DIGEST_SIZE );
	SSL_library_init();

#define SSL_METHOD	SSLv23_client_method()
	_ssl_ctx = SSL_CTX_new( SSL_METHOD );
	if( _ssl_ctx == NULL ) return -1;

	_ssl_exdata_idx = SSL_get_ex_new_index(0, "", NULL, NULL, NULL);

	SSL_CTX_set_verify( _ssl_ctx, SSL_VERIFY_PEER, _verify_callback );
	SSL_CTX_set_options( _ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET );
	return 0;
}

static int _close_ret( conn_t *conn, int ret )
{
	ASSERT(conn);
	int errno_ = errno; // backup the errno

	if( conn->ssl != NULL ){
		SSL_shutdown( conn->ssl );
		SSL_free( conn->ssl );
		conn->ssl = NULL;
	}
	if( conn->sock != -1 ){
		CLOSE( conn->sock );
		conn->sock = -1;
	}
	errno = errno_; // restore the errno
	return ret;
}

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
		// Not supported
		return _close_ret( &conn, TFN_ERR_PARAMETERS );
	}

	// Run through the proxy, if warranted
#include "web.commonproxy.inline.c"



	///////////////////////////////////////////////////////////
	// Client stage
	//

	// Set up client HTTPS
	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){
		int r = _ssl_setup_and_handshake( &conn, 0 );
		if( r != TFN_SUCCESS) return r; // Already close_ret
	}

	// Common request/response handling
#include "web.commonclient.inline.c"

	// Common client code returns the success value

}

