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


typedef struct conn_t {
        int sock;
	uint32_t timeout_ms;
        SSL *ssl;
	TFN_WebRequest_t *request;
} conn_t;


static void _handle_openssl_error( conn_t *conn, int *res )
{
	if( *res < 0 ){ 
		*res = -1;
		int err = SSL_get_error( conn->ssl, *res );
		if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) 
			errno = EAGAIN; 
		else if ( err ==  SSL_ERROR_ZERO_RETURN ) *res = 0; 
		else errno = EIO; 
	} 
}


static int _poll( int sock, short ev, uint32_t timeout_ms )
{
	struct pollfd pfd = { sock, ev, 0 };
	do {
		int res = poll( &pfd, 1, timeout_ms );
		if( res == -1 && errno == EINTR ) continue;
		return res;
	} while(1);
}

static ssize_t _recv( conn_t *conn, uint8_t *data, uint32_t data_len )
{
	int res = 0;
	uint32_t left = data_len;

	while(left > 0){

		// attempt our read
		if( conn->ssl != NULL ){
			res = SSL_read( conn->ssl, data, left );
			_handle_openssl_error(conn,&res);
		} else {
			res = recv( conn->sock, data, left, 0 );
			if( res == -1 && errno == EINTR ) continue;
		}

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			res = _poll( conn->sock, POLLIN, conn->timeout_ms );
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
	int res = 0;
	uint32_t left = data_len;

	while(left > 0){

		// attempt our write
		if( conn->ssl != NULL ){
			res = SSL_write( conn->ssl, data, left );
			_handle_openssl_error(conn,&res);
		} else {
			res = send( conn->sock, data, left, 0 );
			if( res == -1 && errno == EINTR ) continue;
		}

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			res = _poll( conn->sock, POLLOUT, conn->timeout_ms );
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


static int _ssl_handshake( conn_t *conn )
{
	// need to do an SSL handshake
	do {
		int r = SSL_connect( conn->ssl );
		_handle_openssl_error(conn,&r);
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

static int _connect( conn_t *conn, struct sockaddr_in *sin )
{
	do {
		int res = connect(conn->sock, (struct sockaddr*)sin, sizeof(struct sockaddr_in));
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
	if( getpeername( conn->sock, (struct sockaddr*)&sin2, &slen ) != 0 ){
		if( errno == ENOTCONN ) errno = EHOSTUNREACH;
		return -1;
	}

	return 0;
}


static SSL_CTX* sslCtx = NULL;

int TFN_Web_Init()
{
	SSL_library_init();

#define SSL_METHOD	SSLv23_client_method()
	sslCtx = SSL_CTX_new( SSL_METHOD );
	if( sslCtx == NULL ) abort();

	SSL_CTX_set_verify( sslCtx, SSL_VERIFY_NONE, NULL );
	return 0;
}

static int _close_ret( conn_t *conn, int ret )
{
	if( conn->ssl != NULL ){
		SSL_shutdown( conn->ssl );
		SSL_free( conn->ssl );
	}
	if( conn->sock != -1 ) close( conn->sock );
	return ret;
}

void _header( TFN_WebRequest_t *request, uint8_t *ptr, uint32_t len )
{
	if( ptr[len-1] == '\r' ) len--;
	if( len == 0 ) return;
	//printf("HEADER: (%d) %.*s\n", len, len, ptr);
}

int TFN_Web_Request( TFN_WebRequest_t *request )
{
	if( request == NULL ) return TFN_ERR_PARAMETERS;

	// our connection tracking object
	conn_t conn;
	bzero( &conn, sizeof(conn) );
	conn.request = request;
	conn.timeout_ms = request->timeout_ms;
	if( conn.timeout_ms == 0 ) conn.timeout_ms = 15000; // TODO define this

	// reset output values
	request->response_code = 0;
	request->response_data_len = 0;
	request->response_data_body_offset = 0;

	conn.sock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
	if( conn.sock == -1 ) return TFN_ERR_SYSTEM;

	if( request->flags & TFN_WEBREQUEST_FLAG_SSL ){
		conn.ssl = SSL_new( sslCtx );
		if( conn.ssl == NULL ) return _close_ret( &conn, TFN_ERR_SYSTEM );
		if( SSL_set_fd( conn.ssl, conn.sock ) != 1 )
			return _close_ret( &conn, TFN_ERR_SYSTEM );
	}

	int res = _connect( &conn, &request->destination );
	if( res != 0 ){
		if( errno == ETIMEDOUT ) res = TFN_ERR_TIMEOUT;
		else if( errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETDOWN ||
			errno == ENETUNREACH || errno == ECONNRESET )
			res = TFN_ERR_NETWORK;
		else res = TFN_ERR_SYSTEM;
		return _close_ret( &conn, res );
	}

	if( conn.ssl != NULL ){
		res = _ssl_handshake( &conn );
		if( res <= 0 ) return _close_ret( &conn, TFN_ERR_SSLHANDSHAKE );
	}


	char method_buffer[16] = {0};	// Method + space
	int l = sprintf(method_buffer, "%s ", 
		request->request_method == NULL ? "GET" : request->request_method );
	if( _send( &conn, (uint8_t*)method_buffer, l ) != l ) 
		return _close_ret( &conn, TFN_ERR_NETWORK );


	uint8_t *ptr = (uint8_t*)"/";
	l = 1;
	if( request->request_pq != NULL ){
		ptr = (uint8_t*)request->request_pq;
		l = (int)strlen(request->request_pq);
	}
	if( _send(&conn, ptr, l) != l ) 
		return _close_ret( &conn, TFN_ERR_NETWORK );


	int do_body = 0;
	if( request->request_data != NULL && request->request_data_len > 0 ) do_body++;

	char buffer[512] = {0};		// For our header construction
	if( do_body ){
		sprintf(buffer, " HTTP/1.0\r\nContent-Type: %s\r\nContent-Length: %d\r\n",
			(request->request_data_ctype != NULL ? request->request_data_ctype :
				"binary/octet-stream"), request->request_data_len);
	} else {
		memcpy(buffer, " HTTP/1.0\r\n", 11);
	}
	if( request->hostname != NULL )
		sprintf( &buffer[strlen(buffer)], "Host: %s\r\n", request->hostname );
	strcat(buffer,"Connection: close\r\n\r\n");

	l = (int)strlen(buffer);
	if( _send(&conn, (uint8_t*)buffer, l) != l ) 
		return _close_ret( &conn, TFN_ERR_NETWORK );
	
	if( do_body ){
		l = request->request_data_len;
		if( _send(&conn, request->request_data, l) != l )
			return _close_ret( &conn, TFN_ERR_NETWORK );
	}

	uint8_t code_buffer[16] = {0};	// For code-only mode input
	ptr = (uint8_t*)request->response_data;
	int buffer_internal = (ptr == NULL || request->response_data_max < 16) ? 1 : 0;
	if( buffer_internal ) ptr = code_buffer;
	if( _recv(&conn, ptr, 16) != 16 ) return _close_ret( &conn, TFN_ERR_NETWORK );
	request->response_data_len = 16;

	// check basic protocol expectations
	if( memcmp(ptr, "HTTP/1.", 7) != 0 || ptr[8] != ' ' || ptr[12] != ' ' )
		return _close_ret( &conn, TFN_ERR_PROTOCOL );

	// null terminate the status code and parse it
	ptr[12] = 0;
	int code = atoi((const char*)&ptr[9]);
	ptr[12] = ' '; // we checked, above, that this was previously a space

	if( code < 100 || code >= 600 ) return _close_ret( &conn, TFN_ERR_PROTOCOL );
	request->response_code = (uint16_t)code;

	// we are done on non-200, unless flags say we should read more
	if( code != 200 && (request->flags & TFN_WEBREQUEST_FLAG_READ_NON200) == 0 )
		return _close_ret( &conn, TFN_SUCCESS );

	// We are done if caller didn't want the response body
	if( buffer_internal ) return _close_ret( &conn, TFN_SUCCESS );

	// read rest of response body, up to max
	ptr += request->response_data_len;
	while( request->response_data_len < request->response_data_max ){
		l = request->response_data_max - request->response_data_len;
		res = _recv( &conn, ptr, l );
		if( res <= 0 ) break;
		ptr += res;
		request->response_data_len += res;
	}

	// We know we at least read something, since we parsed the status code.  So
	// parse the buffer and see if we got the HTTP CRLFCRLF terminator.
	int i, prev=0;
	ptr = request->response_data;
	for( i=12; i < request->response_data_len; i++ ){
		if( ptr[i] != '\n' ) continue;
		_header( request, &ptr[prev], (i-prev) );
		prev = i+1;
		if( ptr[i-1] == '\n' || (ptr[i-2] == '\n' && ptr[i-1] == '\r') ){
			request->response_data_body_offset = i+1;
			break;
		}
	}
		
	return _close_ret( &conn, TFN_SUCCESS );
}

