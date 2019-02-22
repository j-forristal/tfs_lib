// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_DEFS_H_
#define _TF_DEFS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "tf_cal.h"

#define TFDEFS_SECTION_MAX	16

#define TFDEFS_HASH_LEN		16

// Hash record:
#define TFDEFS_STYPE_HASH	1
#define TFDEFS_RECORD1_LEN	20

// Hash match record:
#define TFDEFS_STYPE_HASHMATCH	2
#define TFDEFS_RECORD2_LEN	36

// String record:
#define TFDEFS_STYPE_STRING	3
// NOTE: record3 is a 2-byte length header + variable length data:
#define TFDEFS_RECORD3_LEN	2

#define TFDEFS_MAGIC	0x097f5201

typedef struct __attribute__((packed, aligned(4))) {
	// NOTE: this is parity to TLV header format, for reusable signing tools
	uint32_t magic;
	uint8_t sig_ecc[TCL_ECC_SIZE]; // 64 bytes
	uint8_t sig_rsa[TCL_RSA_SIZE]; // 256 bytes
	uint32_t magic2;
	uint32_t version;
	uint16_t ident;
	uint16_t flags;
} TF_Defs_Header_t;

typedef struct {
	uint32_t version;
	void * map;
	void * sections[TFDEFS_SECTION_MAX];
	uint8_t stypes[TFDEFS_SECTION_MAX];
} TF_Defs_t;

#define TFDEFS_FOUND 		0
#define TFDEFS_NOT_FOUND	-1
#define TFDEFS_FOUND_MISMATCH	-2
#define TFDEFS_WRONG_TYPE	-3
#define TFDEFS_WRONG_LEN	-4

#define TFDEFS_LOAD_OK		0
#define TFDEFS_LOAD_ERR		-1
#define TFDEFS_LOAD_ERR_SIGN	-2

#define TFDefs_CALLBACK(nom) int(*(nom))(TF_Defs_Header_t *header, uint8_t *data, uint32_t len)
#define TFDefs_CALLBACK_DEF(nom) int(nom)(TF_Defs_Header_t *header, uint8_t *data, uint32_t len)

int TFDefs_Load( TF_Defs_t *defs, const char *defsfile, TFDefs_CALLBACK(callback), uint16_t ident );
int TFDefs_Load_From_Mem( TF_Defs_t *defs, const uint8_t *defs_mem, uint32_t defs_mem_len,
		TFDefs_CALLBACK(callback), uint16_t ident );

int TFDefs_Has_Section( TF_Defs_t *defs, uint8_t section_type );

int TFDefs_Hash_Lookup( TF_Defs_t *defs, uint8_t section_type, 
	uint8_t hash[TFDEFS_HASH_LEN], uint32_t *flags, uint16_t *id );

int TFDefs_HashMatch_Lookup( TF_Defs_t *defs, uint8_t section_type, 
	uint8_t hash[TFDEFS_HASH_LEN], uint8_t match[TFDEFS_HASH_LEN], 
	uint32_t *flags, uint16_t *id );

int TFDefs_String_Lookup( TF_Defs_t *defs, uint8_t section_type, uint8_t *buffer,
        uint16_t len, uint32_t *resume, uint32_t *flags, uint16_t *id );

uint32_t TFDefs_Version( TF_Defs_t *defs );

#ifndef NDEBUG
void TFDefs_Hash_Dump( TF_Defs_t *defs, uint8_t section_type );
#endif

#ifdef __cplusplus
}
#endif

#endif // _TF_DEFS_H_
