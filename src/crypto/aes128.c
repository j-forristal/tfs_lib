// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

/* 
   Some of this code is taken from public domain from here:
   https://github.com/kokke/tiny-AES128-C
*/

#include <stdint.h>
#include <string.h> 
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "tf_crypto_private.h"


// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher; for AES-128, it's 10
#define Nr 10


typedef uint8_t aes_state_t[4][4];



// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
// Use it with care as with GCC 4.9 on a Cortex-M3 setting this caused slow down
// of decryption by a factor of 6.
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif

// Setting this may improve performance a bit with negligible effect on code size
#ifndef XTIME_AS_A_MACRO
  #define XTIME_AS_A_MACRO 0
#endif

static const uint8_t sbox[256] =   {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static void _key_expansion(const uint8_t* key, TFC_AES128_Ctx_t *ctx)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  uint8_t *rkey = ctx->rkey;
  
  for(i = 0; i < Nk; ++i)
  {
    rkey[(i * 4) + 0] = key[(i * 4) + 0];
    rkey[(i * 4) + 1] = key[(i * 4) + 1];
    rkey[(i * 4) + 2] = key[(i * 4) + 2];
    rkey[(i * 4) + 3] = key[(i * 4) + 3];
  }

  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=rkey[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    rkey[i * 4 + 0] = rkey[(i - Nk) * 4 + 0] ^ tempa[0];
    rkey[i * 4 + 1] = rkey[(i - Nk) * 4 + 1] ^ tempa[1];
    rkey[i * 4 + 2] = rkey[(i - Nk) * 4 + 2] ^ tempa[2];
    rkey[i * 4 + 3] = rkey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

static void AddRoundKey(uint8_t round, const TFC_AES128_Ctx_t *ctx, aes_state_t* state)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= ctx->rkey[round * Nb * 4 + i * Nb + j];
    }
  }
}

static void SubBytes(aes_state_t* state)
{
  uint8_t i, j;
  for(i = 0; i < 4; ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[j][i] = sbox[(*state)[j][i]];
    }
  }
}

static void ShiftRows(aes_state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp       = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp       = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

#if XTIME_AS_A_MACRO
static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}
#else
#define xtime(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))
#endif

static void MixColumns(aes_state_t* state)
{
  uint8_t i;
  uint8_t Tmp,Tm,t;
  for(i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

static void InvMixColumns(aes_state_t* state)
{
  int i;
  uint8_t a,b,c,d;
  for(i=0;i<4;++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


static void InvSubBytes(aes_state_t* state)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j=0;j<4;++j)
    {
      (*state)[j][i] = rsbox[(*state)[j][i]];
    }
  }
}

static void InvShiftRows(aes_state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp=(*state)[3][1];
  (*state)[3][1]=(*state)[2][1];
  (*state)[2][1]=(*state)[1][1];
  (*state)[1][1]=(*state)[0][1];
  (*state)[0][1]=temp;

  // Rotate second row 2 columns to right 
  temp=(*state)[0][2];
  (*state)[0][2]=(*state)[2][2];
  (*state)[2][2]=temp;

  temp=(*state)[1][2];
  (*state)[1][2]=(*state)[3][2];
  (*state)[3][2]=temp;

  // Rotate third row 3 columns to right
  temp=(*state)[0][3];
  (*state)[0][3]=(*state)[1][3];
  (*state)[1][3]=(*state)[2][3];
  (*state)[2][3]=(*state)[3][3];
  (*state)[3][3]=temp;
}


static void Cipher( const TFC_AES128_Ctx_t *ctx, aes_state_t* state)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, ctx, state); 
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < Nr; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, ctx, state);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, ctx, state);
}

static void InvCipher( const TFC_AES128_Ctx_t *ctx, aes_state_t* state)
{
  uint8_t round=0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, ctx, state); 

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=Nr-1;round>0;round--)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, ctx, state);
    InvMixColumns(state);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, ctx, state);
}

static void _block128_copy(uint8_t* output, const uint8_t* input)
{
  uint8_t i;
  for (i=0;i<KEYLEN;++i)
  {
    output[i] = input[i];
  }
}


void TFC_AES128_Ctx_Init( TFC_AES128_Ctx_t *ctx, const uint8_t key[TFC_AES128_KEY_SIZE] )
{
  _key_expansion( key, ctx );
}



void TFC_AES128_ECB_Encrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t input[TFC_AES128_BLOCK_SIZE], 
	uint8_t output[TFC_AES128_BLOCK_SIZE])
{
  // Copy input to output, and work in-memory on output
  _block128_copy(output, input);
  aes_state_t* state = (aes_state_t*)output;
  Cipher(ctx, state);
}

void TFC_AES128_ECB_Decrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t input[TFC_AES128_BLOCK_SIZE], 
	uint8_t output[TFC_AES128_BLOCK_SIZE])
{
  // Copy input to output, and work in-memory on output
  _block128_copy(output, input);
  aes_state_t* state = (aes_state_t*)output;
  InvCipher(ctx, state);
}


static void XorWithIv(uint8_t* buf, const uint8_t* iv)
{
  uint8_t i;
  for(i = 0; i < KEYLEN; ++i)
  {
    buf[i] ^= iv[i];
  }
}

void TFC_AES128_CBC_Encrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t* input, uint8_t* output, 
    uint32_t length, const uint8_t iv[TFC_AES128_IV_SIZE])
{
  uint32_t i;
  uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */
  aes_state_t* state; // = (aes_state_t*)output;
  uint8_t* iv_ = (uint8_t*)iv;

  //_block128_copy(output, input);

  for(i = 0; i < length; i += KEYLEN)
  {
    _block128_copy(output, input);
    XorWithIv(output, iv_);
    state = (aes_state_t*)output;
    Cipher(ctx, state);
    iv_ = output;
    input += KEYLEN;
    output += KEYLEN;
  }

  if(remainders)
  {
    _block128_copy(output, input);
    MEMSET(output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
    //NEEDED?: XorWithIv(output, iv_);
    state = (aes_state_t*)output;
    Cipher(ctx, state);
  }
}

void TFC_AES128_CBC_Decrypt(const TFC_AES128_Ctx_t *ctx, const uint8_t* input, uint8_t* output, 
    uint32_t length, const uint8_t iv[TFC_AES128_IV_SIZE])
{
  uint32_t i;
  uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */
  aes_state_t* state; // = (state_t*)output;
  const uint8_t* iv_ = iv;

  //_block128_copy(output, input);

  for(i = 0; i < length; i += KEYLEN)
  {
    _block128_copy(output, input);
    state = (aes_state_t*)output;
    InvCipher(ctx, state);
    XorWithIv(output, iv_);
    iv_ = input;
    input += KEYLEN;
    output += KEYLEN;
  }

  if(remainders)
  {
    _block128_copy(output, input);
    MEMSET(output+remainders, 0, KEYLEN - remainders); /* add 0-padding */
    state = (aes_state_t*)output;
    InvCipher(ctx, state);
  }
}



#ifdef TFC_INCLUDE_AESKDF

__attribute__((always_inline))
static inline void _roll128( uint8_t in[TFC_AES128_BLOCK_SIZE], uint8_t out[TFC_AES128_BLOCK_SIZE] )
{
    int i;
    uint8_t carry_bit = 0;

    // start at the right/LSB, shift up, and
    // add in any previous carry bit
    for( i=15; i>=0; i--){
	out[i] = (in[i]<<1) | carry_bit;
	carry_bit = ((in[i] & 0x80) >> 7);
    }
}

__attribute__((always_inline))
static inline void _cmac_subkeys128( const uint8_t K[TFC_AES128_KEY_SIZE], 
	uint8_t K1[TFC_AES128_KEY_SIZE] )
{
    // allocate storage for L result
    uint8_t L[TFC_AES128_BLOCK_SIZE];
    TFC_Erase( L, sizeof(L) ); // L contains all zeros

    // perform L = CIPHk(0b); L contains all zeros as input, we do
    // in-place encryption
    TFC_AES128_Ctx_t ctx;
    TFC_AES128_Ctx_Init( &ctx, K );
    TFC_AES128_ECB_Encrypt( &ctx, L, L );
    TFC_Erase( &ctx, sizeof(ctx) );

    // OPTIMIZATION: both cases require roll128.  Then,
    // depending upon MSB, we also xor.  Xor by Rb is just
    // xor 15th byte by 0x87 when block len is 128 bits.
    _roll128( L/*input*/, K1/*output*/ );
    if( (L[0] & 0x80 ) > 0 )
	K1[15] ^= 0x87; // xor by Rb

    // NIST REQUIREMENT: any intermediate value in the computation
    // of the subkey shall be secret.  We no longer need L, so lets
    // clean it up.
    TFC_Erase( L, sizeof(L) );

    // OPTIMIZATION: K2 is not needed/used due to parent constraints
    // on block alignment.  So we will not compute.
}


static void _cmac128( const uint8_t K[TFC_AES128_KEY_SIZE], uint8_t* M, int M_len, 
	uint8_t T[TFC_AES128_BLOCK_SIZE] )
{
    assert( M_len == TFC_AES128_BLOCK_SIZE );

    uint8_t K1[TFC_AES128_KEY_SIZE];
    _cmac_subkeys128( K, K1 );

    uint8_t work[TFC_AES128_BLOCK_SIZE];

    // Xor the only block we have (M1) with K1 to get a working value
    int q;
    for( q=0; q<TFC_AES128_BLOCK_SIZE; q++){
	work[q] = K1[q] ^ M[q];
    }
    TFC_Erase( K1, sizeof(K1) );

    // OPTIMIZATION: C0 is all zeros; then, we are supposed to M1 xor C0 before
    // encryption.  M1 xor (all zeros) == M1, so we can ECB encrypt the first
    // block directly (which is the same as CBC encrypting the first block with
    // an IV of all zeros).  We encrypt it straight to the output.
    TFC_AES128_Ctx_t ctx;
    TFC_AES128_Ctx_Init( &ctx, K );
    TFC_AES128_ECB_Encrypt( &ctx, work, T );

    TFC_Erase( work, sizeof(work) );
    TFC_Erase( &ctx, sizeof(ctx) );
}



static void _kdf128_256( const uint8_t Ki[TFC_AES128_KEY_SIZE], 
	uint8_t input_data[TFC_AES128_BLOCK_SIZE], 
	uint8_t out[TFC_AES128_KDF256_OUTPUT_SIZE] )
{
    // EXPECTATIONS:
    // - Ki is 128 bits key (h=128)
    // - Counter is 8 bits
    // - input_data is premade 128 bits -> ctr||Label||0x00||Context||L
    // - caller allows us to change the first byte of input_data
    // - out is 256 bits (L=256)

    // OPTIMIZATION: we know we need 2 blocks (L=256 & h=128, so n=2).
    // We can directly process our cmac into the output

    input_data[0] = 1; // i=1 counter
    _cmac128( Ki, input_data, TFC_AES128_BLOCK_SIZE, out );

    input_data[0] = 2; // i=2 counter
    _cmac128( Ki, input_data, TFC_AES128_BLOCK_SIZE, &out[TFC_AES128_BLOCK_SIZE] );
}


void TFC_AES128_KDF256(const uint8_t key[TFC_AES128_KEY_SIZE],
        const uint8_t nonce[TFC_AES128_KDF256_NONCE_SIZE], 
	const uint8_t tag[TFC_AES128_KDF256_TAG_SIZE],
        uint8_t output[TFC_AES128_KDF256_OUTPUT_SIZE])
{
    uint8_t input[TFC_AES128_BLOCK_SIZE];

    // purposefully skip input[0], it's overwritten as a counter

    // Label
    input[1] = tag[0];
    input[2] = tag[1];

    // 3 == null separator
    input[3] = 0;

    // Context
    TFMEMCPY( &input[4], nonce, TFC_AES128_KDF256_NONCE_SIZE );
    // input[12] thru [13] are null
    input[12] = 0;
    input[13] = 0;

    // L
    input[14] = (256 >> 8) & 0xff;
    input[15] = (256) & 0xff;

    _kdf128_256( key, input, output );
}

#endif // TFC_INCLUDE_AESKDF

