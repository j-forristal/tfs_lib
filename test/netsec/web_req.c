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
#include "tf_pkcs7.h"

void dump_hex( uint8_t* hex, uint32_t cnt );
int load_hex( char* hex_in, uint8_t *binary_out, uint32_t max );

static void _cert_failed_callback( void *req, uint8_t *data, uint32_t data_len )
{
	printf("FAILED CERT\n");
}

static int _cert_callback(void *req, uint8_t *cert, uint32_t cert_len,
        uint8_t *spki, uint32_t spki_len)
{
	printf("CERT Callback\n");

	if( spki != NULL && spki_len > 0 ){
		uint8_t digest[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256( spki, spki_len, digest );
		int i;
		printf("- SPKI SHA256: ");
		for( i=0; i<TCL_SHA256_DIGEST_SIZE; i++){
			printf("%02x", digest[i]);
		}
		printf("\n");
	}

	char subj[TFS_PKCS7_SUBJECT_SIZE];
	memset(subj, 0, sizeof(subj));
	if( TFS_PKCS7_X509_Parse( cert, cert_len, NULL, NULL, subj ) == TFS_PKCS7_ERR_OK ){
		printf("- Subject: %s\n", subj);
	}
	return TFN_CERT_PASS;
}

int main(int argc, char **argv)
{
	TFN_Web_Init();

	TFN_WebRequest_t req;
	bzero( &req, sizeof(req) );

	char buff[4096];
	bzero(buff, sizeof(buff));

	req.flags = TFN_WEBREQUEST_FLAG_SSL;
	req.timeout_ms = 5000;

	req.hostname = "www.google.com";
	//req.hostname = "www.howsmyssl.com";

	printf("Host: %s\n", req.hostname);

	req.request_method = "GET";
	//req.request_method = "POST";

	//req.request_pq = "/v1/msg";
	//req.request_pq = "/a/check"; // howsmyssl

	//req.request_data_ctype = "application/octet-stream";
	//req.request_data = (uint8_t*)"X";
	//req.request_data_len = 1;

	req.response_data = (uint8_t*)buff;
	req.response_data_max = (uint32_t)sizeof(buff);

	req.cert_callback = _cert_callback;
	req.cert_failed_callback = _cert_failed_callback;

	printf("---------------\n");

	assert( TFN_DNS_Lookup( req.hostname, 443, &req.destination ) == 0 );

	int ret = TFN_Web_Request( &req );
	printf("API response: %d\n", ret);
	printf("HTTP code: %d\n", req.response_code);

	if( req.response_data != NULL ){
		printf("---------------\n");
		buff[ sizeof(buff) - 1 ] = 0;
		if( req.response_data_len < sizeof(buff) )
			buff[ req.response_data_len ] = 0;
		printf("%s\n", buff);
	}

	assert( req.response_code == 200 );

	return 0;
}
