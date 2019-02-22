// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifdef LWIP
 #include "lwip/err.h"
 #include "lwip/sockets.h"
 #include "lwip/dns.h"
#else
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netdb.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
#endif

#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "tf_netsec.h"

#include PLATFORM_H

int TFN_DNS_Lookup2( char *host, uint16_t port, struct sockaddr_in *out, struct sockaddr_in *out2 )
{
	struct addrinfo *ai;
	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;

	int res = getaddrinfo( host, NULL, &hints, &ai );
	if( res != 0 ){
		// NOT-MVP-TODO: sort out the errors; see man getaddrinfo.
		// None of the errors are really recoverable, so not sure it's worth handling
		// any explicitly.  Fail one, fail all.
		return -1;
	}


	// We set the port to zero as an indicator if we found something
// KNOWN CLANG ANDROID BUG FOR ARM64; disable the warning
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wasm-operand-widths"
	out->sin_port = 0;
	if( out2 != NULL ) out2->sin_port = 0;
#pragma clang diagnostic pop

	res = -1;
	struct addrinfo *cur = ai;
	struct sockaddr_in * si_p = out;
	do {
		if( cur == NULL ) break;
		if( cur->ai_family == AF_INET && cur->ai_addrlen == sizeof(struct sockaddr_in) ){
			TFMEMCPY( si_p, cur->ai_addr, sizeof(struct sockaddr_in) );

// KNOWN CLANG ANDROID BUG FOR ARM64; disable the warning
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wasm-operand-widths"
			si_p->sin_port = htons(port);
#pragma clang diagnostic pop

			// We got at least one, so it's a success
			res = 0;

			// If this is our second, or we don't want a second, we're done
			if( si_p == out2 || out2 == NULL ) break;

			// Set up out2 for our second round
			si_p = out2;
		}
		cur = cur->ai_next;
	} while(1);

	// Fix some double addressing issues
	if( out2 != NULL && MEMCMP(out, out2, sizeof(struct sockaddr_in)) == 0 ){
// KNOWN CLANG ANDROID BUG FOR ARM64; disable the warning
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wasm-operand-widths"
		si_p->sin_port = 0;
#pragma clang diagnostic pop
	}

	freeaddrinfo(ai);
	return res;
}

int TFN_DNS_Lookup( char *host, uint16_t port, struct sockaddr_in *out )
{
	return TFN_DNS_Lookup2( host, port, out, NULL );
}
