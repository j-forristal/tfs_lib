// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

//
// Common web client operations across all HTTP clients, for HTTPS proxy support
//

	if( (request->flags & (TFN_WEBREQUEST_FLAG_PROXY|TFN_WEBREQUEST_FLAG_SSL)) ==
			(TFN_WEBREQUEST_FLAG_PROXY|TFN_WEBREQUEST_FLAG_SSL) ){
		// HTTPS proxy is warranted

		if( request->hostname == NULL ){
			// hostname is required
			request->error_debug |= (0x81 << 24);
			return _close_ret( &conn, TFN_ERR_PARAMETERS ); 
		}

		// Generally speaking, since buffer_sz is prior checked to be >= 256,
		// unless we have an extremely long hostname here, everythign should
		// work out fine, buffer-size-wise
		int cctl = STRLEN(request->hostname);
		if( (cctl + 8 + 24) > BUFFER_SZ ){
			request->error_debug |= (0x82 << 24);
			return _close_ret( &conn, TFN_ERR_OVERFLOW ); 
		}

		TFMEMCPY( (char*)BUFFER, _S(CONNECT), 8 ); 
		TFMEMCPY( &BUFFER[8], request->hostname, cctl );
		cctl += 8;

		BUFFER[cctl] = ':';
		cctl++;
		cctl += ITOA( request->port, (char*)&BUFFER[cctl] );
		TFMEMCPY( &BUFFER[cctl], _S(HTTP10RNRN), 14 ); // NOTE: +1 for NULL

		// Send the request
		cctl = STRLEN((char*)BUFFER);
		if( _send( &conn, (uint8_t*)BUFFER, cctl ) != cctl ){
			request->error_debug |= (0x83 << 24);
			return _close_ret( &conn, TFN_ERR_NETWORK_PROXY ); 
		}

		// Read the response ("HTTP/x.x YYY")
		int cct_res = _recv(&conn, (uint8_t*)BUFFER, 12 );
		if( cct_res < 12 ){
			request->error_debug |= (0x84 << 24);
			return _close_ret( &conn, TFN_ERR_NETWORK_PROXY ); 
		}

		// check basic protocol expectations
		if( MEMCMP(BUFFER, _S(HTTP1), 7) != 0 || BUFFER[8] != ' '){
			request->error_debug |= (0x85 << 24);
			return _close_ret( &conn, TFN_ERR_PROTOCOL_PROXY );
		}

		// anything not 200 means proxy error
		if( BUFFER[9] != '2' || BUFFER[10] != '0' || BUFFER[11] != '0' ){
			request->error_debug |= (0x86 << 24);
			return _close_ret( &conn, TFN_ERR_NON200_PROXY ); 
		}

		// We got proxy 200 response, which means we have to drain the socket
		// until end of request, before we can continue to the SSL handshake.
		// Draining is simply reading *something* (at least one byte), but not 
		// blocking to necessarily fill our buffer to the specified max.
		//
		// To catch end-of-request (\r\n\r\n) crossing over a read boundary,
		// we have to keep track of the last 4 chars received.
		//
		uint8_t last_4[4] = {0,0,0,0};
		TFMEMCPY( last_4, &BUFFER[cct_res-4], 4 );
		conn.is_draining = 1;
		while( 1 ){
			cct_res = _recv(&conn, (uint8_t*)BUFFER, BUFFER_SZ );
			if( cct_res > 0 ){
				// construct the last 4 chars seen
				if( cct_res >= 4 )
					TFMEMCPY(last_4, &BUFFER[ cct_res - 4 ], 4 );
				else
					TFMEMCPY(&last_4[4-cct_res], BUFFER, cct_res );
			}
			else {
				// Loop since we haven't seen end of response yet
				if( cct_res == -1 && errno == EAGAIN ) continue;

				// EOF or other error
				request->error_debug |= (0x87 << 24);
				return _close_ret( &conn, TFN_ERR_NETWORK_PROXY ); 
			}

			// see if the last 4 qualify as end-of-request
			if( last_4[3] == '\n' && (last_4[2] == '\n' || (last_4[2] == '\r' && last_4[1] == '\n' ) ) )
				break; // end of request, we are done

		}

		// If we get here, the proxy did a successful CONNECT and we drained the response,
		// meaning we are ready to proceed with SSL handshake (as if it was a direct
		// connection).

		// No longer want draining
		conn.is_draining = 0;
	}

