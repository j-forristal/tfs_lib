#include <stdio.h>
#include <string.h>

#include "tf_netsec.h"

typedef struct {
	char *url;
	char *host;
	char *pq;
	uint16_t port;
	uint16_t ssl;
} test_t;


int main(void){

	test_t tests[] = {
		{ "http://host/path", "host", "/path", 80, 0 },
		{ "https://host/path", "host", "/path", 443, 1 },
		{ "http://host:8080/path", "host", "/path", 8080, 0 },
		{ "https://host:8080/path", "host", "/path", 8080, 1 },
		{ "https://host:8080/", "host", "/", 8080, 1 },
		{ "http://host/", "host", "/", 80, 0 },
	};


	int count = sizeof(tests) / sizeof(tests[0]);
	int i;

	for( i=0; i<count; i++ ){
		TFN_Url_t url;
		int res = TFN_Url_Parse( (uint8_t*)tests[i].url,
			strlen(tests[i].url), &url );
		if( res != 0 ){
			if( tests[i].host == NULL ) continue;
			printf("ERR: failed on test %d\n", i);
			return 1;
		}

		if( strcmp((char*)url.hostname, tests[i].host) != 0 ){
			printf("ERR: test[%d] host\n", i);
			return 1;
		}
		if( strcmp((char*)url.path_and_query, tests[i].pq) != 0 ){
			printf("ERR: test[%d] pq\n", i);
			return 1;
		}
		if( url.port != tests[i].port ){
			printf("ERR: test[%d] port\n", i);
			return 1;
		}
		if( url.is_ssl != tests[i].ssl ){
			printf("ERR: test[%d] ssl\n", i);
			return 1;
		}

		printf("test[%d] OK\n", i);
	}

	return 0;
}
