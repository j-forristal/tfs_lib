// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "tf_crypto_private.h"
#include "rotate_bits.h"

void TFC_SHA512_Init(TFC_SHA512_Ctx_t *p)
{
  p->state[0] = 0x6a09e667f3bcc908;
  p->state[1] = 0xbb67ae8584caa73b;
  p->state[2] = 0x3c6ef372fe94f82b;
  p->state[3] = 0xa54ff53a5f1d36f1;
  p->state[4] = 0x510e527fade682d1;
  p->state[5] = 0x9b05688c2b3e6c1f;
  p->state[6] = 0x1f83d9abfb41bd6b;
  p->state[7] = 0x5be0cd19137e2179;
  p->count[0] = p->count[1] = 0;
}


static const uint64_t K[80] = {
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define S0(x) (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x, 39))
#define S1(x) (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x, 41))
#define s0(x) (ROTR64(x, 1) ^ ROTR64(x,8 ) ^ (x >> 7))
#define s1(x) (ROTR64(x,19) ^ ROTR64(x,61) ^ (x >> 6))
#define Ch(x,y,z) ((z)^((x)&((y)^(z))))
#define Maj(x,y,z) (((x)&(y))|((z)&(x|y)))

static void _process(TFC_SHA512_Ctx_t *p)
{
  // load chunk into message schedule, convert from big-endian to host/little endian
  uint64_t W[80];
  uint32_t i;
  for (i = 0; i < 16; i++){
    W[i] =
      ((uint64_t)(p->buffer[i * 8    ]) << 56) +
      ((uint64_t)(p->buffer[i * 8 + 1]) << 48) +
      ((uint64_t)(p->buffer[i * 8 + 2]) << 40) +
      ((uint64_t)(p->buffer[i * 8 + 3]) << 32) +
      ((uint64_t)(p->buffer[i * 8 + 4]) << 24) +
      ((uint64_t)(p->buffer[i * 8 + 5]) << 16) +
      ((uint64_t)(p->buffer[i * 8 + 6]) <<  8) +
      ((uint64_t)(p->buffer[i * 8 + 7]));
  }
  // extend the rest of the working schedule
  for (; i < 80; i++){
	W[i] = W[i-16] + s0((W[i-15])) + W[i-7] + s1((W[i-2]));
  }

  // init the working variables
  uint64_t a = p->state[0];
  uint64_t b = p->state[1];
  uint64_t c = p->state[2];
  uint64_t d = p->state[3];
  uint64_t e = p->state[4];
  uint64_t f = p->state[5];
  uint64_t g = p->state[6];
  uint64_t h = p->state[7];

  // compression function main loop
  uint64_t t1, t2;
  for (i=0; i<80; i++){
	t1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i];
	t2 = S0(a) + Maj(a,b,c);
	h=g;
	g=f;
	f=e;
	e=d+t1;
	d=c;
	c=b;
	b=a;
	a=t1+t2;
  }

  // update hash value
  p->state[0] += a;
  p->state[1] += b;
  p->state[2] += c;
  p->state[3] += d;
  p->state[4] += e;
  p->state[5] += f;
  p->state[6] += g;
  p->state[7] += h;
}

#undef S0
#undef S1
#undef s0
#undef s1
#undef Ch
#undef Maj

void TFC_SHA512_Update(TFC_SHA512_Ctx_t *p, const uint8_t *data, uint32_t size)
{
  uint32_t n, o;

  while( size > 0 ) {
	o = p->count[0] & 0x7f;
	n = 128 - o;
	if( size < n ) n = size;

	TFMEMCPY( &p->buffer[o], data, n );
	p->count[0] += n;
	data += n;
	size -= n;

	if( (p->count[0] & 0x7f) == 0 )
		_process(p);
  }
}


void TFC_SHA512_Final(TFC_SHA512_Ctx_t *p, uint8_t digest[TFC_SHA512_DIGEST_SIZE])
{
  uint32_t i;
  uint8_t finalcount[16];
  // convert bytes to bits; note that with a uint64_t, we don't expect the value
  // of count[0] to overflow
  uint64_t bits = p->count[0] << 3;
  MEMSET( finalcount, 0, 8 );
  for (i=15; i>=8; i--){
    finalcount[i] = bits & 0xff;
    bits = bits >> 8;
  }

  // separator
  TFC_SHA512_Update(p, (uint8_t*)"\x80", 1);

  // finish padding out
#if 0
  uint32_t c = p->count[0] & 0x7f;
  if( c > (128 - 16) ){
    // not enough room in current buffer; finish it off
    MEMSET( &p->buffer[c], 0, (128 - c) );
    p->count[0] += (128 - c);
    _process(p);

    // now ready the next fill
    MEMSET( &p->buffer[c], 0, (128-16) );
    p->count[0] += (128 - 16);
  } else {
    // complete the current
    MEMSET( &p->buffer[c], 0, (128-16-c) );
    p->count[0] += (128-16-c);
  }

#else 
  // TODO: ICKY 1-byte loop:
  while( (p->count[0] & 0x7f) != (128 - 16) ){
    TFC_SHA512_Update(p, (uint8_t*)"\x00", 1);
  }
#endif

  // final count, which should be aligned and cause a transform
  TFC_SHA512_Update(p, finalcount, 16);

  for (i = 0; i < 8; i++)
  {
    *digest++ = (unsigned char)(p->state[i] >> 56);
    *digest++ = (unsigned char)(p->state[i] >> 48);
    *digest++ = (unsigned char)(p->state[i] >> 40);
    *digest++ = (unsigned char)(p->state[i] >> 32);
    *digest++ = (unsigned char)(p->state[i] >> 24);
    *digest++ = (unsigned char)(p->state[i] >> 16);
    *digest++ = (unsigned char)(p->state[i] >> 8);
    *digest++ = (unsigned char)(p->state[i]);
  }
}

