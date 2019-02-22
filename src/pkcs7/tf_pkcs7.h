// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_PKCS7_
#define _TF_PKCS7_

#include <stdint.h>

#define TFS_PKCS7_ERR_OK		0x0
#define TFS_PKCS7_ERR_PARSING		0x1
#define TFS_PKCS7_ERR_NOSIGNER		0x2
#define TFS_PKCS7_ERR_MAXSIGNERS	0x3

#define TFS_PKCS7_X509_OK		0x0
#define TFS_PKCS7_X509_OK_ERR_HOSTNAME	0x1
// all other TFS_PKCS7_X509 values are errors

#define TFS_PKCS7_SUBJECT_SIZE		256

// NOTE: Apple cert has 12 items...
#define TFS_PKCS7_NAME_SET_MAX 16

typedef struct _name_set {
	uint8_t *p;
	size_t p_len;
	uint8_t *oid[TFS_PKCS7_NAME_SET_MAX];
	size_t   oid_sz[TFS_PKCS7_NAME_SET_MAX];
	uint8_t *val[TFS_PKCS7_NAME_SET_MAX];
	size_t   val_sz[TFS_PKCS7_NAME_SET_MAX];
} TFS_NameSet_t;

typedef struct _signer_info {
	TFS_NameSet_t name;
	uint8_t *cert;
	size_t cert_len;
	uint8_t *spki;
	size_t spki_len;
} TFS_SignerInfo_t;

int TFS_PKCS7_Parse( uint8_t *buf, size_t buflen, TFS_SignerInfo_t *signers, size_t signers_len );
int TFS_PKCS7_Name( TFS_NameSet_t *set, char output[TFS_PKCS7_SUBJECT_SIZE] );
int TFS_PKCS7_X509_Parse( uint8_t *cert_start, uint32_t cert_len, uint8_t **spki,
        uint32_t *spki_len, char subject[TFS_PKCS7_SUBJECT_SIZE], char *hostname_check );

#endif
