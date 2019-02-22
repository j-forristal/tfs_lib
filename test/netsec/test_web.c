#include <stdio.h>
#include <strings.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>

#include <assert.h>

#include "tf_netsec.h"
#include "tf_cal.h"

void dump_hex( uint8_t* hex, uint32_t cnt );
int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );

#if 0

uint8_t digest[TCL_MD5_DIGEST_SIZE];

static void _failed_cert_callback( void *req, uint8_t *data, uint32_t data_len ){

	TCL_MD5( data, data_len, digest );
	//printf("FAILED CERT PIN: ");
	//dump_hex( digest, sizeof(digest) );
}

int main(void)
{
	TFN_Web_Init();

	TFN_WebRequest_t req;
	bzero( &req, sizeof(req) );

	char buff[4096];
	bzero(buff, sizeof(buff));

	req.flags = TFN_WEBREQUEST_FLAG_SSL | TFN_WEBREQUEST_FLAG_PIN_LEAF_MD5;
	req.timeout_ms = 5000;
	req.hostname = "www.google.com";
	req.response_data = (uint8_t*)buff;
	req.response_data_max = (uint32_t)sizeof(buff);

	//load_hex( "6280e2332205e99d94701640f2e3f271", req.pin_leaf_md5, sizeof(req.pin_leaf_md5) );

	assert( TFN_DNS_Lookup( req.hostname, 443, &req.destination ) == 0 );

	//
	// TEST 1: Pin enforce on, no pin set; expect error
	//
	assert( TFN_Web_Request( &req ) == TFN_ERR_PINVIOLATION );

	//
	// Test 2: Again, with a callback; this will capture the pin
	//
	req.cert_failed_callback = _failed_cert_callback;
	assert( TFN_Web_Request( &req ) == TFN_ERR_PINVIOLATION );

	//
	// Test 3: now try it with the right pin
	//
	memcpy( req.pin_leaf_md5, digest, sizeof(digest) );
	assert( TFN_Web_Request( &req ) == TFN_SUCCESS );
	assert( req.response_code == 200 );

	//
	// Test 4: break the pin
	//
	req.pin_leaf_md5[0] ^= 0x55;
	assert( TFN_Web_Request( &req ) == TFN_ERR_PINVIOLATION );
	req.pin_leaf_md5[0] ^= 0x55;


	printf("OK\n");
	return 0;
}

#endif

int main(void){ return 0; }
