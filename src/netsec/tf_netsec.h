// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_NETSEC_H_
#define _TF_NETSEC_H_

#include <stdint.h>

#ifdef LWIP
 #include "lwip/ip_addr.h"
 #include "lwip/sockets.h"
#else
 #include <netinet/in.h>
#endif

#define TFN_WEB_PINSHA256_SIZE	32
#define TFN_TIMEOUT_MS_DEFAULT	15000

//
// Web Request Functions
//
typedef struct {
	//
	// Inputs
	//

	// operational configuration
	uint32_t flags;
	uint32_t timeout_ms;

	// network destination (direct or proxy)
	struct sockaddr_in destination;	

	// HTTP basics
	char *hostname;
	char *request_method;
	char *request_pq; // path & query

	// optional request body (e.g. POST)
	uint8_t *request_data;
	uint32_t request_data_len;
	char *request_data_ctype;

	// optional additional headers to send
	char *request_headers;

	// the hostname port 
	uint16_t port;

	//
	// Outputs
	//

	// output status flags
	uint16_t response_flags;

	// http response code & data
	uint16_t response_code;
	uint16_t response_data_body_offset;
	uint8_t *response_data;
	uint32_t response_data_max;
	uint32_t response_data_len;

	//
	// Special
	//

	// Callback for all certificates encountered in handshake --
	// must return ALLOW, DENY, or PASS
	// Params: TFN_WebRequest_t, subject, depth, full_cert/len, pubkey/len
	int (*cert_callback)(void* webreq, uint8_t *subject, uint32_t depth, int is_proxy,
		uint8_t *cert_data, uint32_t cert_len,
		uint8_t *spki_data, uint32_t spki_len);

	// Callback for leaf SSL certificate that fails to verify/violate pins
	void (*cert_failed_callback)(void* webreq, int is_proxy,
		uint8_t *cert_data, uint32_t cert_len);

	// Callback for any encountered headers
	void (*header_callback)(void*, uint8_t *, uint32_t, int is_proxy);

	// This is the underlying transport error
	int error_debug;

	// This is a caller-specific state object
	void *state_ref;

} TFN_WebRequest_t;

#define TFN_WEBREQUEST_FLAG_SSL			1
#define TFN_WEBREQUEST_FLAG_READ_NON200		2
#define TFN_WEBREQUEST_FLAG_SKIP_BODY		4
#define TFN_WEBREQUEST_FLAG_PROXY		8
#define TFN_WEBREQUEST_FLAG_PROXY_SSL		16

#define TFN_CERT_PASS		0
#define TFN_CERT_ALLOW		1
#define TFN_CERT_DENY		2

#define TFN_SUCCESS		0
#define TFN_ERR_PARAMETERS	-1
#define TFN_ERR_INTERNAL	-2
#define TFN_ERR_TIMEOUT		-3
#define TFN_ERR_NETWORK		-4
#define TFN_ERR_SSLHANDSHAKE	-5
#define TFN_ERR_PROTOCOL	-6
#define TFN_ERR_SYSTEM		-7
#define TFN_ERR_PINVIOLATION	-8
#define TFN_ERR_PINNOTCHECKED	-9
#define TFN_ERR_TIMEOUT_PROXY	-10
#define TFN_ERR_NETWORK_PROXY	-11
#define TFN_ERR_PROTOCOL_PROXY	-12
#define TFN_ERR_NON200_PROXY	-13
#define TFN_ERR_SSLHANDSHAKE_PROXY	-14
#define TFN_ERR_OVERFLOW	-15

extern int TFN_Web_Init();
extern int TFN_Web_Request( TFN_WebRequest_t *request );




//
// URL Parsing Functions
//

// We allow external override of the max hostname & pq
#ifndef TFN_MAX_HOSTNAME
#define TFN_MAX_HOSTNAME 64
#endif

#ifndef TFN_MAX_PATHQUERY
#define TFN_MAX_PATHQUERY 128
#endif

typedef struct {
        uint8_t hostname[TFN_MAX_HOSTNAME];
	uint8_t path_and_query[TFN_MAX_PATHQUERY];
	uint16_t port;
	uint16_t is_ssl : 1;
} TFN_Url_t;

int TFN_Url_Parse( uint8_t *data, uint32_t datalen, TFN_Url_t *url );




//
// DNS Functions
//

int TFN_DNS_Lookup( char *host, uint16_t port, struct sockaddr_in *out );
int TFN_DNS_Lookup2( char *host, uint16_t port, struct sockaddr_in *out, struct sockaddr_in *out2 );

#if 0
//
// HPKP Functions
//

struct {

} TFN_HPKP_Manager_t;
#endif


#endif // _TF_NETSEC_H_
