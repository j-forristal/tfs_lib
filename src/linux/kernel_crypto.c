// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

/*
Background: AF_ALG was added in 2.6.38, circa March 2011
- "hash" - MD5, SHA1, SHA256, SHA512 w/ HMAC
- "skcipher" - aes w/ CTR, CBC, ECB

As of 3.0, various HW support for accellerators are in kernel,
which AF_ALG could (or not) leverage by default.

Random and AEAD was added circa 2014. AEAD was then disabled
later for a change.
https://bugzilla.redhat.com/show_bug.cgi?id=1273811
https://patchwork.kernel.org/patch/5285811/
https://lwn.net/Articles/620811/

No RSA (work in progress, circa 2016)

VERDICT: only good for AES and SHA/HMAC

Note: Vulns prior to 3.18.5, CVE-2014-9644 & CVE-2013-7421

Reference:

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

*/

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>

#include _PLATFORM_H

#include "tf_linux.h"
#include "tf_crypto.h"

#define TFC_LK_ALG_SHA1		0
#define TFC_LK_ALG_SHA256	1
#define TFC_LK_ALG_HMACSHA256	2
#define TFC_LK_ALG_AESCBC	3
#define TFC_LK_ALG_AESCTR	4

#define _MAX_ALGS		5

static int _SOCKS[_MAX_ALGS] = {0};
static const char * _NOMS[_MAX_ALGS] = {"sha1","sha256","hmac(sha256)","cbc(aes)","ctr(aes)"};

static const uint32_t _SUPPORT_FLAGS = 0;

void TFC_LK_Init(){

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = NULL
	};

	int idx;
	for( idx=0; idx<_MAX_ALGS; idx++){
		sa.salg_name = _NOMS[idx];
		if( idx >= TFC_LK_ALG_AESCBC ) sa.salg_type = "skcipher";

		_SOCKS[idx] = SOCKET(AF_ALG, SOCK_SEQPACKET, 0);
		if( _SOCKS[idx] == -1 ){
			if( errno == EAFNOSUPPORT ){
				// AF_ALG not in kernel
				_SUPPORT_FLAGS |= 0x40000000;
				return;
			}
			// TODO: what to do here?  Most likely
			// reason is ENOMEM, EMFILE, or ENFILE
			_SUPPORT_FLAGS |= 0x20000000;
			return;
		}
		if( BIND(_SOCKS[idx], (struct sockaddr*)&sa, sizeof(sa)) != 0){
			CLOSE(_SOCKS[idx]);
			_SOCKS[idx] = -1;

			if( errno == ENOENT ){
				// This algo is not supported,
				// fall through
			} else {
				// Some other unexplained error
				_SUPPORT_FLAGS |= 0x10000000;
			}
			continue;
		}

		// If we get here, the socket is allocated and the algorithm
		// is bound, meaning this algorithm is supported
		_SUPPORT_FLAGS |= (1 << idx);
	}

	// Top bit indicates initialization
	_SUPPORT_FLAGS |= 0x80000000;

}

static int _lk_sock( int idx, uint8_t *key, uint32_t keylen ){
	ASSERT(idx < _MAX_ALGS);

	if( (_SUPPORT_FLAGS & 0x80000000) == 0 ){
		// Not initialized
		return -1;
	}

	if( (_SUPPORT_FLAGS & (1 << idx)) == 0 ){
		// This algorithm is not supported
		return -1;
	}

	int fd;
	do {
		fd = ACCEPT(_SOCKS[idx], NULL, 0);
	} while(fd == -1 && errno == EINTR);

	if( fd != -1 && key != NULL && keylen > 0 ){
		// NOTE: setsockopt doesn't EINTR
		if( SETSOCKOPT(fd, SOL_ALG, ALG_SET_KEY, key, (socklen_t)keylen) != 0 ){
			CLOSE(fd);
			return -1;
		}
	}

	return fd;
}

static int _lk_hash( const int idx, const uint8_t *key, const uint32_t key_len,
	const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2,
	uint8_t *digest, uint32_t digest_len )
{
	ASSERT(idx < _MAX_ALGS);

	int fd = _lk_sock( idx, key, key_len );
	if( fd < 0 ) return -1;

	int fl = 0;
	if( data2 != NULL ) fl = MSG_MORE;

	size_t s;
	do {
		s = SEND(fd, data, len, fl);
	} while( s == -1 && errno == EINTR );
	if( s != len ) goto err;
	if( data2 != NULL ){
		do {
			s = SEND(fd, data2, len2, 0);
		} while( s == -1 && errno == EINTR );
		if( s != len2 ) goto err;
	}

	do {
		s = RECV(fd, digest, digest_len);
	} while( s == -1 && errno == EINTR );
	if( s != digest_len ) goto err;

	CLOSE(fd);
	return 0;
err:
	CLOSE(fd);
	return -1;
}

int TFC_LK_SHA1_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[20] ){

	int res = _lk_hash( TFC_LK_ALG_SHA1, NULL, 0, data, len, data2, len2, digest, 20 );
	if( res == 0 ) return res;

	// Fallback
	TFC_SHA1_Ctx_t ctx;
	TFC_SHA1_Init(&ctx);
	TFC_SHA1_Update(&ctx, data, len);
	if( data2 != NULL ) TFC_SHA1_Update(&ctx, data2, len2);
	TFC_SHA1_Final(&ctx, digest);
	return 0;
}

int TFC_LK_SHA256_2( const uint8_t *data, uint32_t len, const uint8_t *data2, uint32_t len2, uint8_t digest[32] ){

	int res = _lk_hash( TFC_LK_ALG_SHA256, NULL, 0, data, len, data2, len2, digest, 32 );
	if( res == 0 ) return res;

	// Fallback
	TFC_SHA256_Ctx_t ctx;
	TFC_SHA256_Init(&ctx);
	TFC_SHA256_Update(&ctx, data, len);
	if( data2 != NULL ) TFC_SHA256_Update(&ctx, data2, len2);
	TFC_SHA256_Final(&ctx, digest);
	return 0;
}

int TFC_LK_SHA256_HMAC( const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t len, uint8_t digest[32] ){

	int res = _lk_hash( TFC_LK_ALG_HMACSHA256, key, key_len, data, len, NULL, 0, digest, 32 );
	if( res == 0 ) return res;

	// Fallback
	TFC_SHA256_HMAC( key, key_len, message, message_len, digest );
	return 0;
}

