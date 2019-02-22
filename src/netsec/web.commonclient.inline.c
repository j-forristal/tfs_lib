// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

//
// Common web client operations across all HTTP clients
//

	struct iovec iov[6];
	uint8_t get[4];
	TFMEMCPY(get, _S(GET), 3);

	if( request->request_method != NULL ){
		iov[0].iov_len = STRLEN(request->request_method);
		iov[0].iov_base = request->request_method;
	} else {
		iov[0].iov_len = 3;
		iov[0].iov_base = get;
	}

	iov[1].iov_len = 1;
	iov[1].iov_base = " ";

	int ic = 2;

	// Send absolute URL, but only if proxy & !ssl
	if( (request->flags & TFN_WEBREQUEST_FLAG_PROXY) && ((request->flags & TFN_WEBREQUEST_FLAG_SSL) == 0)){
		iov[ic].iov_len = 7;
		iov[ic].iov_base = _S(HTTP);
		ic++;

		iov[ic].iov_len = STRLEN(request->hostname);
		iov[ic].iov_base = request->hostname;
		ic++;
	}

	if( request->request_pq != NULL ){
		iov[ic].iov_len = STRLEN(request->request_pq);
		iov[ic].iov_base = request->request_pq;
	} else {
		iov[ic].iov_len = 1;
		iov[ic].iov_base = "/";
	}
	ic++;

	int ii;
	for( ii=0; ii<ic; ii++){
		// NOT-MVP-TODO: handle short sends?
		if( _send( &conn, iov[ii].iov_base, iov[ii].iov_len) != iov[ii].iov_len ){
			request->error_debug |= (3 << 24);
			return _close_ret( &conn, TFN_ERR_NETWORK );
		}
	}

	int l;

	// Send the rest of the headers, which factor in body & host
	int do_body = 0;
	if( request->request_data != NULL && request->request_data_len > 0 ) do_body++;

	char *bptr = (char*)BUFFER;
	if( do_body ){
		ASSERT( BUFFER_SZ >= 256 );
		TFMEMCPY( bptr, _S(HTTP10RNCONTENTTYPE), 25 ); bptr += 25;
		if( request->request_data_ctype != NULL ){
			l = STRLEN(request->request_data_ctype);
			if( l > 200 ){
				request->error_debug |= (4 << 24);
				return _close_ret( &conn, TFN_ERR_PARAMETERS );
			}
			TFMEMCPY( bptr, request->request_data_ctype, l ); bptr += l;
		} else {
			TFMEMCPY( bptr, _S(BINARYOCTETSTREAM), 19 ); bptr += 19; 
		}
		TFMEMCPY( bptr, _S(RNCONTENTLENGTH), 18 ); bptr += 18;
		bptr += ITOA( request->request_data_len, bptr );
	} else {
		TFMEMCPY(bptr, _S(HTTP10), 9); bptr += 9;
	}

	int b_remain = BUFFER_SZ - ((uintptr_t)bptr - (uintptr_t)BUFFER);

	if( request->hostname != NULL ){
		l = STRLEN(request->hostname);
		if( b_remain < (8 + l) ){
			request->error_debug |= (4 << 24);
			return _close_ret( &conn, TFN_ERR_OVERFLOW );
		}
		TFMEMCPY( bptr, _S(RNHOST), 8); bptr += 8;
		TFMEMCPY( bptr, request->hostname, l ); bptr += l;
		b_remain -= (l + 8);
	}

	// Check if more headers are expected
	if( b_remain < 23 ){
		request->error_debug |= (4 << 24);
		return _close_ret( &conn, TFN_ERR_OVERFLOW );
	}
	if( request->request_headers != NULL ){
		// More headers, so don't end request
		TFMEMCPY( bptr, _S(RNCONNECTIONCLOSERNRN), 21 ); bptr += 21;
	} else {
		// No more headers, so end request
		TFMEMCPY( bptr, _S(RNCONNECTIONCLOSERNRN), 23 ); bptr += 23;
	}

	// Send everything up to now
	l = (int)((uintptr_t)bptr - (uintptr_t)BUFFER);
	if( _send(&conn, BUFFER, l) != l ){
		request->error_debug |= (5 << 24);
		return _close_ret( &conn, TFN_ERR_NETWORK );
	}

	// Optional: send extra headers
	if( request->request_headers != NULL ){
		// Send the extra headers
		l = (int)STRLEN(request->request_headers);
		if( _send(&conn, (uint8_t*)request->request_headers, l) != l ){
			request->error_debug |= (6 << 24);
			return _close_ret( &conn, TFN_ERR_NETWORK );
		}

		// End the request -- not ideal to do a send() for 2 chars,
		// but oh well
		if( _send( &conn, (uint8_t*)"\r\n", 2 ) != 2 ){
			request->error_debug |= (7 << 24);
			return _close_ret( &conn, TFN_ERR_NETWORK );
		}
	}

	// Optional: Send the body	
	if( do_body ){
		l = request->request_data_len;
		if( _send(&conn, request->request_data, l) != l ){
			request->error_debug |= (8 << 24);
			return _close_ret( &conn, TFN_ERR_NETWORK );
		}
	}

	// Now read the initial header response
	ASSERT( BUFFER_SZ >= 16 );
	uint8_t *ptr = BUFFER;

	uint32_t read_res = _recv(&conn, ptr, 16);
	if( read_res < 16 ){
		request->error_debug |= (9 << 24);
		return _close_ret( &conn, TFN_ERR_NETWORK );
	}
	request->response_data_len = read_res;

	// check basic protocol expectations
	if( MEMCMP(ptr, _S(HTTP1), 7) != 0 || ptr[8] != ' ' || ptr[12] != ' ' )
		return _close_ret( &conn, TFN_ERR_PROTOCOL );

	// parse the status code
	int code = ATOI((const char*)&ptr[9], 3);
	if( code < 100 || code >= 600 ) return _close_ret( &conn, TFN_ERR_PROTOCOL );
	request->response_code = (uint16_t)code;

	// We are done if caller wants to skip body reading
	// TODO: fix, this skips headers & body, just need to skip body
	if( (request->flags & TFN_WEBREQUEST_FLAG_SKIP_BODY) )
		return _close_ret( &conn, TFN_SUCCESS );

	// we are done on non-200/201, unless flags say we should read more
	if( code != 200 && code != 201 && ((request->flags & TFN_WEBREQUEST_FLAG_READ_NON200) == 0) )
		return _close_ret( &conn, TFN_SUCCESS );

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
		if( request->header_callback != NULL )
			request->header_callback( request, &ptr[prev], (i-prev), 0 );
		prev = i+1;
		if( ptr[i-1] == '\n' || (ptr[i-2] == '\n' && ptr[i-1] == '\r') ){
			request->response_data_body_offset = i+1;
			break;
		}
	}
		
	return _close_ret( &conn, TFN_SUCCESS );

