// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.


static int _poll( int sock, short ev, uint32_t timeout_ms )
{
	struct pollfd pfd = { sock, ev, 0 };
	do {
		int res = POLL( &pfd, 1, timeout_ms );
		if( res == -1 && errno == EINTR ) continue;
		return res;
	} while(1);
}


static ssize_t _io_native( conn_t *conn, uint8_t *data, uint32_t data_len, int which, int notagain )
{
	int res = 0;
	uint32_t left = data_len;

	ASSERT(conn);
	ASSERT(data);

	while(left > 0){
		if( which > 0 ) res = SEND( conn->sock, data, left, 0 );
		else res = RECV( conn->sock, data, left, 0 );
		if( res == -1 && errno == EINTR ) continue;

		// if it's EAGAIN, we have to poll loop	
		if( res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ){
			if( notagain || conn->is_draining ){ errno = EAGAIN; return -1; }
			res = _poll( conn->sock, (which>0)?POLLOUT:POLLIN, conn->timeout_ms );
			if( res > 0 ) continue; // ready, so try again
			// fall through with res == -1 or res == 0
			errno = EAGAIN;
		}

		// poll or io error
		if( res == -1 ){
			// if we had data, then let's return it as a partial read/write;
			// this risks the caller making another read/write and having the
			// error again, but that's acceptable.
			if( left != data_len ) break;
			// otherwise it's all an error
			return -1;
		}

		// poll timeout, we're done
		if( res == 0 ){
			// If we wrote nothing, than bubble up the ETIMEDOUT
			if( data_len == left ){
				errno = ETIMEDOUT;
				return -1;
			}
			break;
		}

		// we wrote/read something, so do accounting and do more/loop
		if( res > 0 ){
			data += res;
			left -= res;

			// proxy special: done when we read something
			if( which == 0 && conn->is_draining ) break;

			continue;
		}
	}

	// return how much we actually wrote, which might be 0 if we wrote nothing
	return (ssize_t)(data_len - left);
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
#ifdef __APPLE__
		// NOTE: Apple EINVAL here means "socket has been shut down"
		|| errno == EINVAL 
#endif
		) errno = EHOSTUNREACH;
		return -1;
	}

	return 0;
}


