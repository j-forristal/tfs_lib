#include <stdio.h>
#include <string.h>

#include "tf_crypto.h"
#include "uECC.h"

extern void dump_hex( uint8_t* hex, uint32_t cnt );

static const uint8_t SIG[]={
0x30,0x45,0x02,0x20,0x47,0x10,0xd9,0x2c,0xed,0x94,0x9c,0xc5,0x83,0x6a,0x95,0xe4,0x1e,0x88,0x88,0xb7,0x86,0xf2,0x71,0x21,0xd4,0xd3,0xf4,0x58,0x7a,0x27,0xac,0x3b,0xf7,0xf2,0xef,0x3c,0x02,0x21,0x00,0xd8,0x40,0xf9,0x82,0x51,0x1b,0x35,0xd0,0xa3,0x92,0x29,0xbd,0x36,0x27,0x8b,0x81,0xa3,0x09,0xf4,0xdb,0x13,0xde,0x65,0xcb,0xd4,0xc7,0x5d,0x33,0x66,0xdb,0xbd,0x70 };

static const uint8_t PK[]={
0xc2,0x82 ,0x41 ,0x20 ,0x4c ,0x61,0x54 ,0xba ,0xeb ,0x64 ,0x4d ,0x52 ,0xa3 ,0xf5,
0x6e ,0xd0 ,0xbc ,0xbe ,0x26 ,0xdd ,0x72 ,0xad,0x33 ,0xdd ,0x2a ,0xf1 ,0xe7 ,0xd6 ,0x3b ,0x03,
0x49 ,0x6b ,0xf0 ,0xb0 ,0x43 ,0xca ,0xb3 ,0xdf,0xae ,0xae ,0xa4 ,0x88 ,0x2d ,0x6f ,0x29 ,0x27,
0x40 ,0x34 ,0x73 ,0x71 ,0x84 ,0x8d ,0x42 ,0x5d,0x71 ,0x8e ,0x8d ,0xf8 ,0x7a ,0xde ,0xc0 ,0x91,
0x0f ,0xc8
};

int main(void){
	uint8_t digest[TFC_SHA256_DIGEST_SIZE];
	TFC_SHA256_Ctx_t ctx;
	TFC_SHA256_Init(&ctx);
	TFC_SHA256_Update(&ctx,(uint8_t*)"hello\n",6);
	TFC_SHA256_Final(&ctx,digest);

	int res = TFC_ECC_Verify( (uint8_t*)PK, sizeof(PK),
		digest, TFC_SHA256_DIGEST_SIZE, (uint8_t*)SIG, sizeof(SIG) );
	printf("Verify = %d\n", res);

	return 0;
}
