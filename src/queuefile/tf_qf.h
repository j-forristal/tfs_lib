// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_QF_H_
#define _TF_QF_H_

#include <stdint.h>

#define TFQF_PAGE_SIZE		256

#ifdef TFQF_INTEGRITY
  #define TFQF_MAGIC		0x04add5ec
#else
  #define TFQF_MAGIC		0x03add5ec
#endif

#define TFQF_HMAC_KEY_SIZE	16


typedef struct {
	int fd;
	uint32_t lmp;
	uint32_t nxt;
	uint32_t cnt;
	uint32_t data_len;
#ifndef TFQF_NO_MEMORY
	uint8_t *mem;
	uint32_t mem_len;
#endif
#ifdef TFQF_INTEGRITY
	uint8_t hmac_key[TFQF_HMAC_KEY_SIZE];
	uint32_t integrity_violations;
#endif
} TFQF_QueueFile_t;


#ifndef TFQF_NO_MEMORY
typedef struct {
	uint8_t *data;
	uint32_t data_len;
        uint32_t flags;
} TFQF_MemoryItem_t;
#endif

#ifdef TFQF_INTEGRITY
int TFQF_Open_Keyed( TFQF_QueueFile_t *qf, const char *path, 
	uint8_t hmac_key[TFQF_HMAC_KEY_SIZE] );
#else
int TFQF_Open( TFQF_QueueFile_t *qf, const char *path );
#endif

void TFQF_Close( TFQF_QueueFile_t *qf );
void TFQF_Stats( TFQF_QueueFile_t *qf, uint32_t *count, uint32_t *data_len );
int TFQF_Clear( TFQF_QueueFile_t *qf );
int TFQF_Push( TFQF_QueueFile_t *qf, uint8_t *msg, uint16_t len );
int TFQF_Pop( TFQF_QueueFile_t *qf, uint8_t *buffer, uint16_t *buffer_len);
int TFQF_Prune( TFQF_QueueFile_t *qf, uint32_t count );

#ifndef TFQF_NO_MEMORY
int TFQF_Memory_Open( TFQF_QueueFile_t *qf, TFQF_MemoryItem_t *items, uint32_t item_cnt );
void TFQF_Memory_Close( TFQF_QueueFile_t *qf );
#endif


#endif
