// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_TLV_
#define _TF_TLV_

#include <stdint.h>
#include <limits.h>

#define TFTLV_KEY_SIZE	16
#define TFTLV_OTP_SIZE	64
// Header has room for OTP nonce, ECC P-256 sig, and RSA-2048 sig:
#define TFTLV_SIG_SIZE	(64 + 256 + TFTLV_OTP_SIZE)

#define TFTLV_RET_OK		0
#define TFTLV_RET_IO		1
#define TFTLV_RET_FORMAT	2
#define TFTLV_RET_INTEGRITY	3
#define TFTLV_RET_NOTEXIST	4
#define TFTLV_RET_PARAMETERS	5
#define TFTLV_RET_WRONGKEY	6
#define TFTLV_RET_OVERFLOW	7
#define TFTLV_RET_BIGMSG	8

#define TFTLV_CB_RET_CONTINUE	0
#define TFTLV_CB_RET_STOP	1
#define TFTLV_CB_RET_RESET	2

#define TFTLV_CB_TAG_END	0xff

typedef struct {
	int      fd;
	uint16_t dbg;
	uint16_t msg_max_size;
	uint8_t  path[PATH_MAX];
	uint8_t  key[TFTLV_KEY_SIZE]; // TODO: how to protect this from mem reading?
} TFTLV_File_t;

typedef struct {
	uint8_t  *mem;
	uint32_t tail_offset;
	uint32_t mem_max_sz;
	uint16_t msg_max_size;
	uint16_t dbg;
	volatile int lock;
} TFTLV_Mem_t;

#define TFTLV_CALLBACK(nom)  uint8_t(*(nom))(uint8_t tag, uint16_t len, uint8_t* data, const void* state)
#define TFTLV_CALLBACK_DEF(nom)  uint8_t (nom)(uint8_t tag, uint16_t len, uint8_t* data, const void* state)

#define TFTLV_SIGCALLBACK(nom)  uint8_t(*(nom))(uint8_t* data, uint32_t data_len, uint8_t sig[TFTLV_SIG_SIZE], uint8_t otp[TFTLV_OTP_SIZE])
#define TFTLV_SIGCALLBACK_DEF(nom)  uint8_t (nom)(uint8_t* data, uint32_t data_len, uint8_t sig[TFTLV_SIG_SIZE], uint8_t otp[TFTLV_OTP_SIZE])

uint8_t TFTLV_Init_Mem( TFTLV_Mem_t *mt, size_t sz );
uint8_t TFTLV_Init_MemFromSignedFile( TFTLV_Mem_t *mt, const char *path, TFTLV_SIGCALLBACK(callback) );
uint8_t TFTLV_Init_MemFromSignedMem( TFTLV_Mem_t *mt, const uint8_t *data, uint32_t len, TFTLV_SIGCALLBACK(callback) );
uint8_t TFTLV_Init_ProtectedFile( TFTLV_File_t *ft, const char *path, uint8_t key[TFTLV_KEY_SIZE] );
uint8_t TFTLV_Walk_Mem( TFTLV_Mem_t *mt, TFTLV_CALLBACK(callback), const void *state );
uint8_t TFTLV_Walk_File( TFTLV_File_t *ft, TFTLV_CALLBACK(callback), const void *state );
uint8_t TFTLV_Add_ToMem( TFTLV_Mem_t *mt, uint8_t tag, uint8_t *msg, uint16_t len );
uint8_t TFTLV_Add_ToFile( TFTLV_File_t *ft, uint8_t tag, uint8_t *msg, uint16_t len );
uint8_t TFTLV_Reset_Mem( TFTLV_Mem_t *mt );
uint8_t TFTLV_Reset_File( TFTLV_File_t *ft );
uint8_t TFTLV_HasItems_Mem( TFTLV_Mem_t *mt );
uint8_t TFTLV_HasItems_File( TFTLV_File_t *ft );
uint8_t TFTLV_Drain_MemToFile( TFTLV_Mem_t *mt, TFTLV_File_t *ft );

#endif
