// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

///////////////////////////////////////////////////////////////
//
// Obfuscated strings
//

#define WORK_MAX	12

static const uint32_t GET[] = {0x17a13a15,0xe6f2c94b,}; // "GET "
static const uint32_t HTTP10RNCONTENTTYPE[] = {0x63a13772,0xbcc3eb7c,0x2961911,0x9eb98c22,0x2fd31f17,0xf4f58c34,0x19ba634d,}; // " HTTP/1.0\r\nContent-Type: "
static const uint32_t BINARYOCTETSTREAM[] = {0x569b1630,0xc8e79c1c,0x41dd1722,0xcaf29f53,0x2fd8196d,}; // "binary/octet-stream"
static const uint32_t RNCONTENTLENGTH[] = {0x58b6755f,0xc780f26f,0x5f932046,0xcebcbc74,0x2bfb7b15,}; // "\r\nContent-Length: "
static const uint32_t HTTP10[] = {0x63a13772,0xbcc3eb7c,0x419c1411,}; // " HTTP/1.0"
static const uint32_t RNHOST[] = {0x58bd755f,0x89d4f272,0x748b0d2f,}; // "\r\nHost: "
static const uint32_t RNCONNECTIONCLOSERNRN[] = {0x58b6755f,0xca80e86f,0x59b07e46,0xcc88a520,0x24aa3114,0xc5e3df44,}; // "\r\nConnection: close\r\n\r\n"
static const uint32_t RNCONNECTIONCLOSERN[] = {0x58b6755f,0xca80e86f,0x59b07e46,0xcc88a520,0x24aa3114,0xc5e9d244,}; // "\r\nConnection: close\r\n"
static const uint32_t HTTP1[] = {0x67a12b1a,0x96dce96b,}; // "HTTP/1."
static const uint32_t ADDSEC[] = {0x64b13b13,0x95e28b08,}; // "ADDSEC"
static const uint32_t RN[] = {0x37f5755f,}; // "\r\n"
static const uint32_t HTTP[] = {0x47810b3a,0xb6fdd75e,}; // "http://"
static const uint32_t CONNECT[] = {0x79bb3011,0xa8bc800a,0x55e37f57,}; // "CONNECT "
static const uint32_t HTTP10RNRN[] = {0x63a13772,0xbcc3eb7c,0x4c961911,0xb5cde247,}; // " HTTP/1.0\r\n\r\n"

#define _STR_START      0x37f57f52
#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)

__attribute__ ((optnone,noinline))
static char *_decode( uint32_t sz, const uint32_t *in, uint32_t *work ){
        //ASSERT( sz <= WORK_MAX );
#pragma nounroll
        while( sz > 0 ){
                volatile uint32_t mask = sz << 26 | sz << 18 | sz << 10 | sz;
                work[sz] = in[sz] ^ in[sz-1] ^ 0xf557f75f ^ mask;
                sz--;
        }
        work[0] = in[0] ^ _STR_START;
        return (char*)work;
}


#define BUFFER	(request->response_data)
#define BUFFER_SZ (request->response_data_max)
