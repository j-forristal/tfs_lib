// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_PERSIST_H_
#define _TF_PERSIST_H_

#include <stdint.h>

int TFP_Get( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len );
int TFP_Set( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len );

int TFP_Get_Ex( const uint8_t *key, const uint8_t *basepath, uint8_t *output, uint32_t *len,
        uint8_t *ikey, uint32_t ikey_len, char *service );
int TFP_Set_Ex( const uint8_t *key, const uint8_t *basepath, uint8_t *input, uint32_t len,
        uint8_t *ikey, uint32_t ikey_len, char *service );

#define TFP_OK	0
#define TFP_ERR	1
#define TFP_INTEGRITY 2

#endif
