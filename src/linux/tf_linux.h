// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#ifndef _TF_LINUX_H_
#define _TF_LINUX_H_

#include <stdint.h>

uint32_t TFLinux_Version();
int TFLinux_Maps_Walk( void *state, void (*cb)(void*,void*,void*,char*,char*) );
int TFLinux_Proc_Walk( void *state, void (*cb)(void*,int,int,int,int,char*) );

#endif // _TF_LINUX_H_
