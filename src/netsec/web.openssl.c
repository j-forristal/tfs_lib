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
#include <assert.h>
#include <unistd.h>
#include <sys/uio.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "tf_netsec.h"

#define POLLAGAIN	0x7fffffff

// TODO:
static SSL_CTX* sslCtx = NULL;


typedef struct conn_t {
        int sock;
        SSL *ssl;

	TFN_WebRequest_t *request;
        int (*callback)(struct conn_t *);

	// request/write
	struct iovec *iov;
	uint16_t iov_current;
	uint16_t iov_count;

	// response/read
	uint8_t *in;
	uint32_t in_max;

	short pf;

} conn_t;


#define HANDLE_OPENSSL_ERROR(res) \
	if( res < 0 ){ \
		res = -1; \
		int err = SSL_get_error( conn->ssl, res ); \
		if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) \
			errno = EAGAIN; \
		else errno = EIO; } \


static ssize_t _recv( conn_t *conn ){
	size_t amount = (conn->in_max - conn->request->response_data_len);
	if( amount == 0 ) return 0;

	if( conn->ssl != NULL ){
		int res = SSL_read( conn->ssl, 
			&conn->in[ conn->request->response_data_len ], amount );
		HANDLE_OPENSSL_ERROR(res);
		return (ssize_t)res;
	}

	return recv( conn->sock, &conn->in[ conn->request->response_data_len ], 
		amount, 0 );
}

static int _read_ready_handler( conn_t *conn )
{
	ssize_t res;

recv_again:
	res = _recv( conn );
	if( res == -1 ){
		if( errno == EINTR ) goto recv_again;
		if( errno == EAGAIN ) return POLLAGAIN;
		return TFN_ERR_NETWORK; 
	}

	if( res == 0 ){
		if( conn->request->response_code == 0 ||
			conn->request->response_data_body_offset == 0 )
			return TFN_ERR_PROTOCOL;

		// TODO
		return TFN_SUCCESS;
	}

	if( res > 0 ){
		conn->request->response_data_len += res;

		// HTTP header check
		if( conn->request->response_code == 0 &&
			conn->request->response_data_len > 12 )
		{
			if( memcmp(conn->in, "HTTP/1.", 7) != 0 || conn->in[8] != ' ' ){
				return TFN_ERR_PROTOCOL; // Not HTTP
			}
			uint8_t save = conn->in[12];
			conn->in[12] = 0;
			int code = atoi((const char*)&conn->in[9]);
			conn->in[12] = save;

			if( code < 100 || code >= 600 )
				return TFN_ERR_PROTOCOL;

			conn->request->response_code = (uint16_t)code;

			// we are done on non-200, unless flags say we should read more
			if( code != 200 && (conn->request->flags & 
				TFN_WEBREQUEST_FLAG_READ_NON200) == 0 )
				return TFN_SUCCESS;
		}


		// body content pointer check
		if( conn->request->response_data_body_offset == 0 ){
			int start = conn->request->response_data_len - res;
			if( start < 2 ) start = 2;

			int i;
			for(i=start; i < conn->request->response_data_len; i++){
				if( conn->in[i] == '\n' ){
					if( conn->in[i-1] == '\n' || 
						(conn->in[i-2] == '\n' && conn->in[i-1] == '\r') ){
						conn->request->response_data_body_offset = i+1;
						break;
					}
				}
			}
		}

		// if we are at max, we are done	
		if( conn->request->response_data_len == conn->in_max )
			return TFN_SUCCESS;

	}

	return POLLAGAIN;
}


static ssize_t _send( conn_t *conn ){
	if( conn->ssl != NULL ){
		// we only write out the current iov due to SSL_write limitations
		int res = SSL_write( conn->ssl, (conn->iov[conn->iov_current].iov_base),
			(int)(conn->iov[conn->iov_current].iov_len) );
		HANDLE_OPENSSL_ERROR(res);
		return (ssize_t)res;
	}

	//return send(conn->sock, buffer, bufferlen, 0 );
	return writev(conn->sock, &conn->iov[conn->iov_current],
		(conn->iov_count - conn->iov_current) );
}

static int _write_ready_handler( conn_t *conn )
{
	ssize_t res;

send_again:
	res = _send( conn );
	if( res == -1 ){
		if( errno == EINTR ) goto send_again;
		if( errno == EAGAIN ) return POLLAGAIN;
		return TFN_ERR_NETWORK;
	}

	// we wrote something, adjust our write pointers
	do {
		if( res < conn->iov[conn->iov_current].iov_len ){
			uint8_t *ptr = (uint8_t*)conn->iov[conn->iov_current].iov_base;
			conn->iov[conn->iov_current].iov_base = (ptr + res);
			conn->iov[conn->iov_current].iov_len -= res;
			return POLLAGAIN;
		}

		res -= conn->iov[conn->iov_current].iov_len;
		conn->iov_current++;

	} while( conn->iov_current < conn->iov_count );

	// we wrote the request, move on to reading the response
	if( conn->ssl == NULL ) conn->pf = POLLIN;
	conn->callback = _read_ready_handler;
	return conn->callback( conn );
}


static int _ssl_handshake_handler( conn_t *conn )
{
	// need to do an SSL handshake
	int r = SSL_connect( conn->ssl );
	if( r == 0 ) return TFN_ERR_SSLHANDSHAKE;
	if( r < 0 ){
		int err = SSL_get_error( conn->ssl, r );
		if( err == SSL_ERROR_WANT_READ ){
			conn->pf = POLLIN;
			return POLLAGAIN;
		}
		else if( err == SSL_ERROR_WANT_WRITE ){
			conn->pf = POLLOUT;
			return POLLAGAIN;
		}
		return TFN_ERR_SSLHANDSHAKE;
	}

	// if we get here, we handshaked; move to next handler
	conn->pf = POLLIN|POLLOUT;
	conn->callback = _write_ready_handler;
	return conn->callback( conn );
}

static int _connect_handler( conn_t *conn )
{
	// save existing so_error
	socklen_t slen = sizeof(errno);
	int errno_ = 0;
	if( getsockopt( conn->sock, SOL_SOCKET, SO_ERROR, &errno_, &slen ) != 0 )
		return TFN_ERR_INTERNAL;

	// fastpath handle obvious non-block items
	if( errno_ == EALREADY || errno_ == EINPROGRESS || errno_ == EAGAIN )
		return POLLAGAIN;

	// check if connected
	struct sockaddr_in sin;
	slen = sizeof(sin);
	if( getpeername( conn->sock, (struct sockaddr*)&sin, &slen ) != 0 ){
		if( errno != ENOTCONN ) return TFN_ERR_INTERNAL;
		return TFN_ERR_NETWORK; // this is the failure to connect
	}

	// connected, set up next handler
	if( conn->ssl != NULL ){
		if( !SSL_set_fd( conn->ssl, conn->sock ) ) return TFN_ERR_INTERNAL;
		conn->callback = _ssl_handshake_handler;
		conn->pf = POLLIN|POLLOUT;
	} else {
		conn->callback = _write_ready_handler;
		conn->pf = POLLOUT;
	}
	return conn->callback( conn );
}


static int _reactor( conn_t *conn )
{
	struct pollfd pollfds[1];
	pollfds[0].fd = conn->sock;

poll_again:
	pollfds[0].events = conn->pf; // update our desired flags
	int res = poll( pollfds, 1, conn->request->timeout_ms );
	if( res == -1 && (errno == EAGAIN || errno == EINTR ) ) goto poll_again;
	if( res == 0 ) return TFN_ERR_TIMEOUT;

	if( res > 0 ){

		if( pollfds[0].revents & POLLHUP ){
			// TODO
			if( conn->request->response_data_len > 0 ) return TFN_SUCCESS;
			return TFN_ERR_NETWORK;
		}

		if( pollfds[0].revents & POLLERR ){
			/*
			socklen_t slen = sizeof(errno);
			int errno_ = 0;
			if( getsockopt( pollfds[0].fd, SOL_SOCKET, SO_ERROR, &errno_, &slen ) != 0 )
				return TFN_ERR_INTERNAL;

			if( errno_ == EALREADY || errno_ == EINPROGRESS || errno_ == EAGAIN )
				goto poll_again;
			*/
			return TFN_ERR_NETWORK;
		}

		if( pollfds[0].revents & (POLLIN|POLLOUT) ){
			res = conn->callback( conn );
			if( res != POLLAGAIN ) return res;
		}

		goto poll_again;
	}

	// poll res == -1
	return TFN_ERR_INTERNAL;
}



int TFN_Web_Init(){
	SSL_library_init();

	// Create a shared context for all connections
#define SSL_METHOD	SSLv23_client_method()
	SSL_CTX* sslCtx = SSL_CTX_new( SSL_METHOD );
	if( sslCtx == NULL ) abort();

	// TODO:
	SSL_CTX_set_verify( sslCtx, SSL_VERIFY_NONE, NULL );

	return 0;
}

int TFN_Web_Request( TFN_WebRequest_t *request )
{
	if( request == NULL ) return TFN_ERR_PARAMETERS;
	if( request->hostname != NULL && strlen(request->hostname) > 255 )
		return TFN_ERR_PARAMETERS;
	if( request->request_method != NULL && strlen(request->request_method) > 14 )
		return TFN_ERR_PARAMETERS;
	if( request->request_data_ctype != NULL && strlen(request->request_data_ctype) > 64 )
		return TFN_ERR_PARAMETERS;

	char method_buffer[16] = {0};	// Method + space
	uint8_t code_buffer[16] = {0};	// For code-only mode input
	char buffer[512] = {0};		// For our header construction

	conn_t conn;
	bzero( &conn, sizeof(conn) );
	conn.request = request;

	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){
		conn.ssl = SSL_new( sslCtx );
		if( conn.ssl == NULL ) return TFN_ERR_INTERNAL;
	}

	// reset output values
	request->response_code = 0;
	request->response_data_len = 0;

	// set up input values
	if( request->response_data == NULL ){
		conn.in = code_buffer;
		conn.in_max = sizeof(code_buffer);
	} else {
		conn.in = request->response_data;
		conn.in_max = request->response_data_max;
	}

	// construct write data
	struct iovec iov[4];

	iov[0].iov_base = method_buffer;
	iov[0].iov_len = sprintf(method_buffer, "%s ", 
		request->request_method == NULL ? "GET" : request->request_method );

	iov[1].iov_base = request->request_pq != NULL ? request->request_pq : "/";
	iov[1].iov_len = strlen(iov[1].iov_base);

	int do_body = 0;
	if( request->request_data != NULL && request->request_data_len > 0 ){
		do_body++;
	}

	iov[2].iov_base = buffer;
	if( do_body ){
		sprintf(buffer, " HTTP/1.1\r\nContent-Type: %s\r\nContent-Length: %d\r\n",
			(request->request_data_ctype != NULL ? request->request_data_ctype :
				"binary/octet-stream"), request->request_data_len);
	} else {
		strcpy(buffer, " HTTP/1.1\r\n");
	}
	if( request->hostname != NULL )
		sprintf( &buffer[strlen(buffer)], "Host: %s\r\n", request->hostname );
	strcat(buffer,"Connection: close\r\n\r\n");
	iov[2].iov_len = strlen(buffer);

	if( do_body ){
		iov[3].iov_base = request->request_data;
		iov[3].iov_len = request->request_data_len;
	}

	conn.iov = iov;
	conn.iov_count = do_body ? 4 : 3;

	// set up callback, poll, and socket

	conn.callback = _connect_handler;
	conn.pf = POLLIN|POLLOUT;
	conn.sock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
	if( conn.sock == -1 ) return TFN_ERR_INTERNAL;

	int res;
connect_eintr:
	res = connect(conn.sock, (struct sockaddr*)&request->destination, 
		sizeof(&request->destination));
	if( res == -1 && errno == EINTR ) goto connect_eintr;
	// NOTE: if there is an error, reactor/handler will handle it
	res = _reactor( &conn );

	// force shutdown everything
	if( conn.ssl != NULL ){
		SSL_shutdown( conn.ssl );
		SSL_free( conn.ssl );
	}
	close( conn.sock );

	assert( res != POLLAGAIN );
	return res;
}

