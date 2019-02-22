#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

#include "tf_crypto.h"

#define COUNT_MD5 (1024 * 1024)
#define COUNT_SHA1 (1024 * 1024)
#define COUNT_SHA256 (512 * 1024)
#define COUNT_SHA512 (256 * 1024)

int main(void){

	uint8_t msg[1024];
	memset(msg, 'A', sizeof(msg));

	int i;
	uint8_t digest[128];
	time_t t1, t2;

	TFC_MD5_Ctx_t a_md5_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_MD5; i++ ){
		TFC_MD5_Init(&a_md5_ctx);
		TFC_MD5_Update(&a_md5_ctx, msg, sizeof(msg));
		TFC_MD5_Final(&a_md5_ctx, digest);
	}
	t2 = time(0);
	printf("TFC MD5 iter=%d in %ds\n", i, (int)(t2-t1));



	TFC_SHA1_Ctx_t a_sha1_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA1; i++ ){
		TFC_SHA1_Init(&a_sha1_ctx);
		TFC_SHA1_Update(&a_sha1_ctx, msg, sizeof(msg));
		TFC_SHA1_Final(&a_sha1_ctx, digest);
	}
	t2 = time(0);
	printf("TFC SHA1 iter=%d in %ds\n", i, (int)(t2-t1));



	TFC_SHA256_Ctx_t a_sha256_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA256; i++ ){
		TFC_SHA256_Init(&a_sha256_ctx);
		TFC_SHA256_Update(&a_sha256_ctx, msg, sizeof(msg));
		TFC_SHA256_Final(&a_sha256_ctx, digest);
	}
	t2 = time(0);
	printf("TFC SHA256 iter=%d in %ds\n", i, (int)(t2-t1));




	TFC_SHA512_Ctx_t a_sha512_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA512; i++ ){
		TFC_SHA512_Init(&a_sha512_ctx);
		TFC_SHA512_Update(&a_sha512_ctx, msg, sizeof(msg));
		TFC_SHA512_Final(&a_sha512_ctx, digest);
	}
	t2 = time(0);
	printf("TFC SHA12 iter=%d in %ds\n", i, (int)(t2-t1));


	return 0;
}
