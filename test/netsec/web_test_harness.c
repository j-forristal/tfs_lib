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

uint8_t PIN[TCL_SHA256_DIGEST_SIZE];

uint32_t header_ctr = 0;

static void _header_callback( void *req, uint8_t *data, uint32_t data_len, int is_proxy )
{
	while( data_len > 0 && (data[data_len-1] == '\r' || data[data_len-1] == '\n') ){ data_len--; }

	if( data_len == 0 ) return;

	// Escape some JSON-sensitive chars
	int i;
	for( i=0; i<data_len; i++){
		if( data[i] == '"' ) data[i] = '\'';
		else if( data[i] == '\\' ) data[i] = '/';
	}

	if( is_proxy )
		printf("\"proxy_header_%d\":\"%.*s\",\n", header_ctr, data_len, data);
	else
		printf("\"header_%d\":\"%.*s\",\n", header_ctr, data_len, data);

	header_ctr++;
}

static void _cert_failed_callback( void *req, int is_proxy, uint8_t *data, uint32_t data_len )
{
	uint8_t digest[TCL_SHA256_DIGEST_SIZE];
	TCL_SHA256( data, data_len, digest );

	if( is_proxy )
		printf("\"proxy_failure_callback\":\"");
	else
		printf("\"failure_callback\":\"");
	int i;
	for( i=0; i<TCL_SHA256_DIGEST_SIZE; i++){
		printf("%02x", digest[i]);
	}
	printf("\",\n");
}

static int _cert_callback(void *req, uint8_t *subject, uint32_t flags, int is_proxy,
	uint8_t *cert, uint32_t cert_len, uint8_t *spki, uint32_t spki_len)
{
	uint16_t depth = (flags >> 16);
	int hostname_check_failed = (flags & 1);

	if( hostname_check_failed > 0){
		if (is_proxy) 
			printf("\"proxy_hostname_check\":\"failed\",\n");
		else
			printf("\"hostname_check\":\"failed\",\n");
	}

	if ( subject != NULL ){
		if (is_proxy)
			printf("\"proxy_cert_callback_subj_%d\":\"%s\",\n", depth, subject);
		else
			printf("\"cert_callback_subj_%d\":\"%s\",\n", depth, subject);
	}

	int i;

	int res = TFN_CERT_PASS;

	if( cert != NULL && cert_len > 0 ){
		uint8_t digest[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256( cert, cert_len, digest );

		if( is_proxy )
			printf("\"proxy_cert_callback_cert_%d\":\"", depth);
		else
			printf("\"cert_callback_cert_%d\":\"", depth);

		for( i=0; i<TCL_SHA256_DIGEST_SIZE; i++){
			printf("%02x", digest[i]);
		}
		printf("\",\n");
	}
	
	if( spki != NULL && spki_len > 0 ){
		uint8_t digest[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256( spki, spki_len, digest );
	
		if (is_proxy)	
			printf("\"proxy_cert_callback_spki_%d\":\"", depth);
		else
			printf("\"cert_callback_spki_%d\":\"", depth);

		for( i=0; i<TCL_SHA256_DIGEST_SIZE; i++){
			printf("%02x", digest[i]);
		}
		printf("\",\n");

		// Check SPKI pin
		if( is_proxy == 0 ){
			if( memcmp(PIN, digest, sizeof(digest)) == 0 ){
				res = TFN_CERT_ALLOW;
			}
		}
	}

	// Proxy is never blocked based on pins
	if( is_proxy ) res = TFN_CERT_ALLOW;

	if(is_proxy)
		printf("\"proxy_cert_callback_res_%d\":%d,\n", depth, res);
	else
		printf("\"cert_callback_res_%d\":%d,\n", depth, res);
	return res;
}

int main(int argc, char **argv)
{
	printf("{\n");

	if( argc < 4 ){
		printf("\"err\":\"parameters\"}\n");
		return -1;
	}

	TFN_WebRequest_t req;
	bzero( &req, sizeof(req) );

	// Target URL config
	TFN_Url_t url;
	bzero( &url, sizeof(url) );
	assert(TFN_Url_Parse( (uint8_t*)argv[1], strlen(argv[1]), &url) == 0);
	printf("\"target\":\"http%s://%s:%d%s\",\n", (url.is_ssl?"s":""), url.hostname,
		url.port, url.path_and_query);

	// SPKI pin
	load_hex(argv[2], PIN, sizeof(PIN));
	printf("\"pin_spki\":\"%s\",\n", argv[2]);

	// DNS hostname
	char * lookup_name = argv[3];

	// Optional proxy config
	TFN_Url_t proxy_url;
	bzero( &proxy_url, sizeof(proxy_url) );
	if( argc > 4 ){
		assert(TFN_Url_Parse( (uint8_t*)argv[4], strlen(argv[4]), &proxy_url) == 0);
		printf("\"proxy\":\"http%s://%s:%d\",\n", (proxy_url.is_ssl?"s":""),
			proxy_url.hostname, proxy_url.port);

		req.flags |= TFN_WEBREQUEST_FLAG_PROXY;
		if( proxy_url.is_ssl )
			req.flags |= TFN_WEBREQUEST_FLAG_PROXY_SSL;
	}


	// Initialization and data setup
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
	req.header_callback = _header_callback;

	// We either connect to host or proxy
	int res;
	if( req.flags & TFN_WEBREQUEST_FLAG_PROXY )
		res = TFN_DNS_Lookup( (char*)proxy_url.hostname, proxy_url.port, &req.destination );
	else
		res = TFN_DNS_Lookup( (char*)lookup_name, url.port, &req.destination );
	if( res != 0 ){
		printf("\"err\":\"DNS lookup; API=%d\"}\n", res);
		return 0;
	}

	int ret = TFN_Web_Request( &req );
	printf("\"api\":%d,\n", ret);
	printf("\"http\":%d,\n", req.response_code);

	if( req.response_data != NULL ){
		printf("\"response_len\":%d,\n", req.response_data_len);

		uint32_t offs = req.response_data_body_offset;
		size_t sz = req.response_data_len - req.response_data_body_offset;
		if( req.response_data_body_offset > req.response_data_len )
			sz = 0;

		if( sz > sizeof(buff) )
			sz = sizeof(buff);
		
		uint8_t digest[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256( (uint8_t*)&buff[offs], sz, digest );

		printf("\"response_data\":\"");
		int i;
		for( i=0; i<TCL_SHA256_DIGEST_SIZE; i++){
			printf("%02x", digest[i]);
		}
		printf("\",\n");
	}

	printf("\"debug_err\":%d,\n", req.error_debug);
	printf("\"complete\":1}\n");
	return 0;
}
