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
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "tf_netsec.h"
//#include "tf_crypto.h"
#include "tf_cal.h"

#include PLATFORM_H

#include "ssl.h"

//#define WDEBUG


///////////////////////////////////////////////////////////////
//
// Local structures
//

typedef struct conn_t {
        int sock;
	uint32_t timeout_ms;
	TFN_WebRequest_t *request;
	SSL *ssl;
	uint32_t cert_flags;

	// proxy stuff:
	uint8_t is_direct : 1;
	uint8_t is_draining : 1;
} conn_t;


#include "web.commontop.inline.c"


///////////////////////////////////////////////////////////////
//
// Implementation
//

static void _handle_error( conn_t *conn, int *res )
{
#ifdef WDEBUG
	int errno_ = errno;
	printf("HERR: res=%d errno=%d\n", *res, errno);
	errno = errno_;
#endif

	if( *res == SSL_OK && (errno == EAGAIN || errno == EWOULDBLOCK) ){
		errno = EAGAIN;
		*res = -1;
		return;
	}

	if( *res < 0 ){ 
		conn->request->error_debug = *res;
		if( *res == SSL_CLOSE_NOTIFY ){
			*res = 0;
			return;
		}
		errno = EIO; 
		*res = -1;
	} 
	return;
}


static int _poll( int sock, short ev, uint32_t timeout_ms )
{
	struct pollfd pfd = { sock, ev, 0 };
	do {
		int res = POLL( &pfd, 1, timeout_ms );
		if( res == -1 && errno == EINTR ) continue;
		return res;
	} while(1);
}

static ssize_t _io( conn_t *conn, uint8_t *data, uint32_t data_len, int which )
{
	int res = 0;
	uint32_t left = data_len;
	uint8_t *ptr = NULL;

	while(left > 0){
		if( conn->is_direct == 0 && conn->request->flags & TFN_WEBREQUEST_FLAG_SSL ){
			if( which > 0 ) res = ssl_write( conn->ssl, data, left );
			else res = ssl_read( conn->ssl, &ptr );
			_handle_error(conn,&res);
		} else {
			if( which > 0 ) res = SEND( conn->sock, data, left, 0 );
			else res = RECV( conn->sock, data, left, 0 );
			if( res == -1 && errno == EINTR ) continue;
		}

#ifdef WDEBUG
	int errno_ = errno;
	printf("IO: which=%d res=%d errno=%d left=%d\n", which, res, errno, left);
	errno = errno_;
#endif

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			res = _poll( conn->sock, (which>0)?POLLOUT:POLLIN, conn->timeout_ms );
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

		// we read/wrote something, so do accounting and do more/loop
		if( res > 0 ){
			if( res > left ) res = left;

			// Have to move the data over from the internal buffer
			if( which == 0 && conn->request->flags & TFN_WEBREQUEST_FLAG_SSL ){
				TFMEMCPY( data, ptr, res );
			}

			data += res;
			left -= res;

			// Proxy special: end if draining
			if( which == 0 && conn->is_draining ) break;

			continue;
		}
	}

	// return how much we actually wrote, which might be 0 if we wrote nothing
	// NOT-MVP-TODO if it's zero, should we instead return -1?
	return (ssize_t)(data_len - left);
}


static int _ssl_handshake( conn_t *conn )
{
	// need to do an SSL handshake
	int r = ssl_handshake_status( conn->ssl );
#ifdef WDEBUG
	int errno_ = errno;
	printf("Handshake: res=%d errno=%d\n", r, errno);
	errno = errno_;
#endif
	if( r != SSL_OK ){
		// TODO
		errno = ETIMEDOUT;
		return -1;
	}
	return 0;
}

static ssize_t _recv( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	return _io(conn, data, data_len, 0);
}

static ssize_t _send( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	return _io(conn, data, data_len, 1);
}


static int _connect( conn_t *conn, struct sockaddr_in *sin )
{
	do {
		int res = CONNECT(conn->sock, (struct sockaddr*)sin, sizeof(struct sockaddr_in));
		if( res == -1 ){
			if( errno == EINTR || errno == EAGAIN ) continue;
			else if( errno == EINPROGRESS ){
				res = _poll( conn->sock, POLLOUT|POLLIN, conn->timeout_ms );
				if( res > 0 ) break;
				if( res == 0 ){
					errno = ETIMEDOUT;
					return -1; 
				}
			}
			return -1;
		}
		break;
	} while(1);

	// check if connected
	struct sockaddr_in sin2;
	socklen_t slen = sizeof(sin2);
	if( GETPEERNAME( conn->sock, (struct sockaddr*)&sin2, &slen ) != 0 ){
		if( errno == ENOTCONN 
		|| errno == EBADF 
#ifdef __APPLE__
                // NOTE: Apple EINVAL here means "socket has been shut down"
                || errno == EINVAL
#endif
		) errno = EHOSTUNREACH;
		return -1;
	}

	return 0;
}

static int _close_ret( conn_t *conn, int ret )
{
	int errno_ = errno;
	if( conn->request->flags & TFN_WEBREQUEST_FLAG_SSL ){
		ssl_free( conn->ssl );
	}
	if( conn->sock != -1 ) CLOSE( conn->sock );
	errno = errno_;
	return ret;
}


//
// Main Init function
//

static SSL_CTX *_ssl_ctx;

int TFN_Web_Init()
{
	//uint32_t work[WORK_MAX];
	//int ret;

	ASSERT( TFN_WEB_PINSHA256_SIZE == TCL_SHA256_DIGEST_SIZE );

	// Set up global context
	_ssl_ctx = ssl_ctx_new( SSL_SERVER_VERIFY_LATER, SSL_DEFAULT_CLNT_SESS );
	if( _ssl_ctx == NULL ){
			// TODO
	}
	
	return 0;
}




//
// Main Request function
//

int TFN_Web_Request( TFN_WebRequest_t *request )
{
	if( request == NULL ) return TFN_ERR_PARAMETERS;
	uint32_t work[WORK_MAX]; // for obfuscated strings

        // TODO: deal with this buffer:
        char buffer[256] = {0};         // Internal working buffer

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
	if( request->flags & TFN_WEBREQUEST_FLAG_SSL && request->cert_callback == NULL ){
		// Bad config 
		return TFN_ERR_PARAMETERS;
	}

	// create a nonblock socket
#if defined(SOCK_NONBLOCK)
	conn.sock = SOCKET(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
	if( conn.sock == -1 ){ request->error_debug=1; return TFN_ERR_SYSTEM; }
#elif defined(O_NONBLOCK)
	conn.sock = SOCKET(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if( conn.sock == -1 ){ request->error_debug=1; return TFN_ERR_SYSTEM; }
	int flags = FCNTL(conn.sock, F_GETFL, 0);
	if( flags == -1 ){ request->error_debug=1; return TFN_ERR_SYSTEM; }
	if( FCNTL(conn.sock, F_SETFL, flags|O_NONBLOCK) == -1 ){
		request->error_debug=1; return TFN_ERR_SYSTEM; }
#else
#error no SOCK_NONBLOCK/O_NONBLOCK
#endif

	// connect to destination
	int res = _connect( &conn, &request->destination );
	if( res != 0 ){
		if( errno == ETIMEDOUT ) res = TFN_ERR_TIMEOUT;
		else if( errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETDOWN ||
			errno == ENETUNREACH || errno == ECONNRESET ){
			request->error_debug |= (1 << 24);
			res = TFN_ERR_NETWORK;
		} else { request->error_debug=4; res = TFN_ERR_SYSTEM; }
		return _close_ret( &conn, res );
	}

#include "web.commonproxy.inline.c"

	// handle ssl handshake & cert enforcement
	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){

		conn.ssl = ssl_client_new( _ssl_ctx, conn.sock );
		if( conn.ssl == NULL ){
			// TODO
		}

		res = _ssl_handshake( &conn );
		if( res < 0 ){ 
#if 0
			// handshake failed; if we have a cert, report it as part of failure
			if( request->cert_failed_callback != NULL && peercert != NULL && peercert->raw.p != NULL )
				request->cert_failed_callback(request, peercert->raw.p, peercert->raw.len);
#endif
			return _close_ret( &conn, TFN_ERR_SSLHANDSHAKE );
		}

#if 0
		//
		// Check if this cert is allowed
		//
		// extract pubkey
		if( peercert != NULL ){
			uint8_t pkbuf[1024]; 
			int pk_sz = mbedtls_pk_write_pubkey_der( (mbedtls_pk_context*)&peercert->pk, pkbuf, sizeof(pkbuf) );
			if( pk_sz > 0 ){
				// SPECIAL: pk_write_pubkey_der writes to end of buffer
				res = request->cert_callback( request, peercert->raw.p, peercert->raw.len,
					&pkbuf[sizeof(pkbuf)-pk_sz], pk_sz );

				conn.cert_flags |= res;
			}
		}

		// We need to see an ALLOW to keep going
		if( (conn.cert_flags & TFN_CERT_ALLOW) == 0 ){
			// Didn't encounter a pin
			if( request->cert_failed_callback != NULL )
				request->cert_failed_callback(request, peercert->raw.p, peercert->raw.len);
			return _close_ret( &conn, TFN_ERR_PINVIOLATION );
		}
		// We saw an allowed cert, so keep going...
#endif

	}

	//
	// Everything after here is generic HTTP client
	//

#include "web.commonclient.inline.c"

}
