// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#if 0
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include PLATFORM_H

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/api.h"

#include "tf_netsec.h"
#include "tf_cal.h"


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
	mbedtls_ssl_context ssl;
	mbedtls_net_context sslnet;
	TFN_WebRequest_t *request;
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

static void _handle_mbedtls_error( conn_t *conn, int *res )
{
	if( *res < 0 ){ 
		conn->request->error_debug = *res;
		if( *res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ){
			*res = 0;
			return;
		}
		if( *res == MBEDTLS_ERR_SSL_WANT_READ || *res == MBEDTLS_ERR_SSL_WANT_WRITE ) 
			errno = EAGAIN; 
		else errno = EIO; 
		*res = -1;
	} 
}


static ssize_t _io( conn_t *conn, uint8_t *data, uint32_t data_len, int which )
{
	int res = 0;
	uint32_t left = data_len;

	while(left > 0){
		if( conn->is_direct==0 && conn->request->flags & TFN_WEBREQUEST_FLAG_SSL ){
			if( which > 0 ) res = mbedtls_ssl_write( &conn->ssl, data, left );
			else res = mbedtls_ssl_read( &conn->ssl, data, left );
			_handle_mbedtls_error(conn,&res);
		} else {
			if( which > 0 ) res = SEND( conn->sock, data, left, 0 );
			else res = RECV( conn->sock, data, left, 0 );
			if( res == -1 && errno == EINTR ) continue;
		}

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			continue;
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

			// Proxy special: end if draining
			if( conn->is_draining && which == 0 ) break;

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
	do {
		int r = mbedtls_ssl_handshake( &conn->ssl );
		_handle_mbedtls_error(conn,&r);
		if( r >= 0 ) return r;
		if( r == -1 && errno == EAGAIN ){
			continue;
		}
		return r;
	} while(1);
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
				continue;
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
		mbedtls_ssl_close_notify( &conn->ssl );
		mbedtls_net_free( &conn->sslnet );
		mbedtls_ssl_free( &conn->ssl );
	}
	if( conn->sock != -1 ) CLOSE( conn->sock );
	errno = errno_;
	return ret;
}

//
// Main Init function
//

static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;
static mbedtls_ssl_config _conf;

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

	//mbedtls_ssl_conf_authmode( &_conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
	mbedtls_ssl_conf_authmode( &_conf, MBEDTLS_SSL_VERIFY_NONE );
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

	conn.sock = SOCKET(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// SPECIAL: mbedtls shares the global config object in the ssl context,
	// and it's the only place to pass per-session parameters for SSL
	// verify callback.  So, we need to make a copy of the global config
	// for any SSL connection to keep things thread-safe.  This was verified
	// by source code audit of mbedtls cert handling.
	mbedtls_ssl_config local_conf_;
	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){
		// Thread safety: clone our global config into local config:
		TFMEMCPY( &local_conf_, &_conf, sizeof(mbedtls_ssl_config) );

		// Now init like normal:
		mbedtls_ssl_init( &conn.ssl );
		mbedtls_net_init( &conn.sslnet );
		conn.sslnet.fd = conn.sock;
		if( mbedtls_ssl_setup( &conn.ssl, &local_conf_ ) != 0 ){
			request->error_debug=2;
			return _close_ret( &conn, TFN_ERR_SYSTEM );
		}
		mbedtls_ssl_set_bio( &conn.ssl, &conn.sslnet, mbedtls_net_send,
			mbedtls_net_recv, NULL );
		if( mbedtls_ssl_set_hostname( &conn.ssl, request->hostname ) != 0 ){
			request->error_debug=3;
			return _close_ret( &conn, TFN_ERR_SYSTEM );
		}
	}

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
		res = _ssl_handshake( &conn );
		// NOTE: may be null:
		const mbedtls_x509_crt *peercert = mbedtls_ssl_get_peer_cert( &conn.ssl );
		if( res < 0 ){ 
			// handshake failed; if we have a cert, report it as part of failure
			if( request->cert_failed_callback != NULL && peercert != NULL && peercert->raw.p != NULL )
				request->cert_failed_callback(request, peercert->raw.p, peercert->raw.len);
			return _close_ret( &conn, TFN_ERR_SSLHANDSHAKE );
		}

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
	}

	//
	// Everything after here is generic HTTP client
	//

#include "web.commonclient.inline.c"

}
