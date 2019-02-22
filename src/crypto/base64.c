// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.
/*
   This code is adapted from public domain code.
*/

#include "tf_crypto_private.h"

static const uint8_t base64enc_tab[64]= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t base64dec_tab[256]= {
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
	 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
	255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

int TFC_Base64_Decode(const char *in, uint32_t in_len, uint8_t *out, uint32_t out_len) 
{
	uint32_t ii, io, v, rem;

	for(io=0,ii=0,v=0,rem=0;ii<in_len;ii++) {
		uint8_t ch;
		if( in[ii] == '\r' || in[ii] == '\n' || in[ii] == '\t' || in[ii] == ' ')
			continue;
		if(in[ii]=='=') break;
		ch=base64dec_tab[(uint8_t)in[ii]];
		if(ch==255) break;
		v=(v<<6)|ch;
		rem+=6;
		if(rem>=8) {
			rem-=8;
			if(io>=out_len) return -1;
			out[io++]=(v>>rem)&255;
		}
	}
	if(rem>=8) {
		rem-=8;
		if(io>=out_len) return -1;
		out[io++]=(v>>rem)&255;
	}
	return io;
}

int TFC_Base64_Encode(const uint8_t *in, uint32_t in_len, char *out, uint32_t out_len) 
{
	uint32_t ii, io, v, rem;

	for(io=0,ii=0,v=0,rem=0;ii<in_len;ii++) {
		uint8_t ch;
		ch=in[ii];
		v=(v<<8)|ch;
		rem+=8;
		while(rem>=6) {
			rem-=6;
			if(io>=out_len) return -1;
			out[io++]=base64enc_tab[(v>>rem)&63];
		}
	}
	if(rem) {
		v<<=(6-rem);
		if(io>=out_len) return -1;
		out[io++]=base64enc_tab[v&63];
	}
	while(io&3) {
		if(io>=out_len) return -1;
		out[io++]='=';
	}
	if(io>=out_len) return -1;
	out[io]=0;
	return io;
}

