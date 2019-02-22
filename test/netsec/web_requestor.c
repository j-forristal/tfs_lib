#include <stdio.h>
#include <stdlib.h>
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

static void _cert_failed_callback( void *req, int is_proxy, uint8_t *data, uint32_t data_len )
{
	printf("- FAILED CERT\n");
}

static int _cert_callback(void *req, uint8_t *subject, uint32_t flags, int is_proxy,
	uint8_t *cert, uint32_t cert_len, uint8_t *spki, uint32_t spki_len)
{
	//TFN_WebRequest_t *r = (TFN_WebRequest_t*)req;

	uint16_t depth = (flags >> 16);
	int hostname_check_failed = (flags & 1);
	
	if( spki != NULL && spki_len > 0 ){
		uint8_t digest[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256( spki, spki_len, digest );
		int i;
		printf("- Cert[%d] SPKI SHA256: ", depth);
		for( i=0; i<TCL_SHA256_DIGEST_SIZE; i++){
			printf("%02x", digest[i]);
		}
		printf("\n");
	}

	if( hostname_check_failed > 0){
		printf("- Cert[%d] !Failed Hostname Check\n", depth);
	}

	printf("- Cert[%d] Subject: '%s'\n", depth, subject);

	// Depth = 0 & no hostname failures means we will allow
	if( depth == 0 ) return TFN_CERT_ALLOW;

	return TFN_CERT_PASS;
}

int main(int argc, char **argv)
{
	TFN_WebRequest_t req;
	bzero( &req, sizeof(req) );

	if( argc < 2 ){
		printf("ERR: specify target URL\n");
		return -1;
	}

	TFN_Url_t url;
	bzero( &url, sizeof(url) );
	assert(TFN_Url_Parse( (uint8_t*)argv[1], strlen(argv[1]), &url) == 0);

	printf("- Target: http%s://%s:%d%s\n", (url.is_ssl?"s":""), url.hostname,
		url.port, url.path_and_query);

	TFN_Url_t proxy_url;
	int use_proxy = 0;
	bzero( &proxy_url, sizeof(proxy_url) );
	if( argc > 2 ){
		assert(TFN_Url_Parse( (uint8_t*)argv[2], strlen(argv[2]), &proxy_url) == 0);
		printf("- Proxy: http%s://%s:%d\n", (url.is_ssl?"s":""),
			proxy_url.hostname, proxy_url.port);
		req.flags |= TFN_WEBREQUEST_FLAG_PROXY;
		if( proxy_url.is_ssl )
			req.flags |= TFN_WEBREQUEST_FLAG_PROXY_SSL;
		use_proxy++;
	}

	TFN_Web_Init();


	char buff[4096];
	bzero(buff, sizeof(buff));

	req.timeout_ms = 5000;
	req.hostname = (char*)url.hostname;
	req.port = url.port;
	if( url.is_ssl){
		req.flags |= TFN_WEBREQUEST_FLAG_SSL;
	}

	req.request_method = "GET";
	req.request_pq = (char*)url.path_and_query;

	req.response_data = (uint8_t*)buff;
	req.response_data_max = (uint32_t)sizeof(buff);

	req.cert_callback = _cert_callback;
	req.cert_failed_callback = _cert_failed_callback;

	int res;
	if( use_proxy ){
		res = TFN_DNS_Lookup( (char*)proxy_url.hostname, proxy_url.port, &req.destination );
	} else {
		res = TFN_DNS_Lookup( (char*)url.hostname, url.port, &req.destination );
	}
	if( res != 0 ){
		printf("ERR: DNS lookup; API=%d\n", res);
		return -1;
	}

	int ret = TFN_Web_Request( &req );
	printf("- Result: API=%d HTTP=%d debug=0x%x\n", ret, req.response_code, req.error_debug);

#if 0
	if( req.response_data != NULL ){
		printf("---------------\n");
		buff[ sizeof(buff) - 1 ] = 0;
		if( req.response_data_len < sizeof(buff) )
			buff[ req.response_data_len ] = 0;
		printf("%s\n", buff);
	}
#endif

	assert( req.response_code == 200 );
	return 0;
}
