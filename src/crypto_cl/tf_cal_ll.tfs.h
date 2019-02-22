// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TFS_CAL_LL_TFS_H_
#define _TFS_CAL_LL_TFS_H_

#include <stdint.h>

#include "tf_crypto.h"
#include "tf_cal.h"

#define TCLL_MD5_DIGEST_SIZE	16
typedef TFC_MD5_Ctx_t TCLL_MD5_Ctx_t;
#define TCLL_MD5_Init(ctx) TFC_MD5_Init(ctx)
#define TCLL_MD5_Update(ctx,data,len) TFC_MD5_Update(ctx,data,len)
#define TCLL_MD5_Final(ctx,digest) TFC_MD5_Final(ctx,digest)

#define TCLL_SHA1_DIGEST_SIZE	20
typedef TFC_SHA1_Ctx_t TCLL_SHA1_Ctx_t;
#define TCLL_SHA1_Init(ctx) TFC_SHA1_Init(ctx)
#define TCLL_SHA1_Update(ctx,data,len) TFC_SHA1_Update(ctx,data,len)
#define TCLL_SHA1_Final(ctx,digest) TFC_SHA1_Final(ctx,digest)

#define TCLL_Random(buffer,len) TFC_Random(buffer, len)

#endif
