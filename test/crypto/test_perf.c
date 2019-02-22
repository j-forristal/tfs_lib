#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/md5.h>
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

	MD5_CTX o_md5_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_MD5; i++ ){
		MD5_Init(&o_md5_ctx);
		MD5_Update(&o_md5_ctx, msg, sizeof(msg));
		MD5_Final(digest, &o_md5_ctx);
	}
	t2 = time(0);
	printf("OS MD5 iter=%d in %ds\n", i, (int)(t2-t1));
	TFC_MD5_Ctx_t a_md5_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_MD5; i++ ){
		TFC_MD5_Init(&a_md5_ctx);
		TFC_MD5_Update(&a_md5_ctx, msg, sizeof(msg));
		TFC_MD5_Final(&a_md5_ctx, digest);
	}
	t2 = time(0);
	printf("ASC MD5 iter=%d in %ds\n", i, (int)(t2-t1));



	SHA_CTX o_sha1_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA1; i++ ){
		SHA1_Init(&o_sha1_ctx);
		SHA1_Update(&o_sha1_ctx, msg, sizeof(msg));
		SHA1_Final(digest, &o_sha1_ctx);
	}
	t2 = time(0);
	printf("OS SHA1 iter=%d in %ds\n", i, (int)(t2-t1));
	TFC_SHA1_Ctx_t a_sha1_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA1; i++ ){
		TFC_SHA1_Init(&a_sha1_ctx);
		TFC_SHA1_Update(&a_sha1_ctx, msg, sizeof(msg));
		TFC_SHA1_Final(&a_sha1_ctx, digest);
	}
	t2 = time(0);
	printf("ASC SHA1 iter=%d in %ds\n", i, (int)(t2-t1));




	SHA256_CTX o_sha256_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA256; i++ ){
		SHA256_Init(&o_sha256_ctx);
		SHA256_Update(&o_sha256_ctx, msg, sizeof(msg));
		SHA256_Final(digest, &o_sha256_ctx);
	}
	t2 = time(0);
	printf("OS SHA256 iter=%d in %ds\n", i, (int)(t2-t1));
	TFC_SHA256_Ctx_t a_sha256_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA256; i++ ){
		TFC_SHA256_Init(&a_sha256_ctx);
		TFC_SHA256_Update(&a_sha256_ctx, msg, sizeof(msg));
		TFC_SHA256_Final(&a_sha256_ctx, digest);
	}
	t2 = time(0);
	printf("ASC SHA256 iter=%d in %ds\n", i, (int)(t2-t1));




	SHA512_CTX o_sha512_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA512; i++ ){
		SHA512_Init(&o_sha512_ctx);
		SHA512_Update(&o_sha512_ctx, msg, sizeof(msg));
		SHA512_Final(digest, &o_sha512_ctx);
	}
	t2 = time(0);
	printf("OS SHA512 iter=%d in %ds\n", i, (int)(t2-t1));
	TFC_SHA512_Ctx_t a_sha512_ctx;
	t1 = time(0);
	for( i=0; i<COUNT_SHA512; i++ ){
		TFC_SHA512_Init(&a_sha512_ctx);
		TFC_SHA512_Update(&a_sha512_ctx, msg, sizeof(msg));
		TFC_SHA512_Final(&a_sha512_ctx, digest);
	}
	t2 = time(0);
	printf("ASC SHA12 iter=%d in %ds\n", i, (int)(t2-t1));


	return 0;
}
