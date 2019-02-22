// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdint.h>
#include <sys/utsname.h>

static uint32_t _atoi_d( char *ptr ){
	uint32_t temp = 0;
	while( *ptr != '.' && *ptr != 0 ){
		if( *ptr < '0' || *ptr > '9' ) return 0;
		temp = (temp * 10) | (*ptr - '0');
		ptr++;
	}
	return temp;
}

uint32_t TFLinux_Version(){

	struct utsname utsn;
	if( uname(&utsn) != 0 ) return 0;

	if( utsn.release[0] < '2' || utsn.release[0] > '9' ) return 0;
	if( utsn.release[1] != '.' ) return 0;

	uint32_t res = (utsn.release[0] - '0') << 24;

	char *ptr = &utsn.release[2];

	res |= ((_atoi_d(ptr) & 0xff) << 16);

	if( *ptr == 0 ) return res;
	ptr++;

	res |= _atoi_d(ptr) & 0xffff;

	return res
}
