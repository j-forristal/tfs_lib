// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "tf_linux.h"
#include PLATFORM_H

#define CB void (*cb)(void*,int,int,int,int,char*)

struct linux_dirent64 {
	off64_t        d_ino;    /* 64-bit inode number */
	off64_t        d_off;    /* 64-bit offset to next structure */
	unsigned short d_reclen; /* Size of this dirent */
	unsigned char  d_type;   /* File type */
	char           d_name[]; /* Filename (null-terminated) */
};

static int getdents64(unsigned int fd, void *dirp,
	unsigned int count)
{
	return SYSCALL( SYS_getdents64, fd, dirp, count );
}

static void proc_process(int pfd, char *nom, void *state, CB)
{
	uint8_t buf[512], buf2[512];
	uint8_t *n, *ptr = buf;
	int pid = 0;
	while( *nom != 0 ){ pid = (pid * 10) + (*nom - 0x30); nom++; }

	int dfd;
	do { dfd = OPENAT(pfd, nom, O_RDONLY|O_DIRECTORY, 0); }
	while( dfd == -1 && errno == EINTR );
	if( dfd == -1 ) return;

	struct stat stt;
	int sfd;
	if( FSTATAT(pfd, nom, &stt, 0) == -1 ) goto done; // no EINTR

	{
		char st[] = "st\x01t";
		st[2] = 'a';
		do { sfd = OPENAT(dfd, st, O_RDONLY, 0); }
		while( sfd == -1 && errno == EINTR );
		if( sfd == -1 ) goto done;
	}

	{
		ssize_t r;
		do { r = PREAD(sfd, buf, sizeof(buf), 0); }
		while( r == -1 && errno == EINTR );
		while( CLOSE(sfd) == -1 && errno == EINTR );
		if( r <= 0 ) goto done;
		buf[ sizeof(buf) - 1 ] = 0;
	}

	{
		// 44 (kthrotld) S 2 0
		while( *ptr != '(' && *ptr != 0 ) ptr++;
		if( *ptr == 0 ) goto done;

		// name
		n = (++ptr);
		while( *ptr != ')' && *ptr != 0 ) ptr++;
	}

	{
		// load a potentially better name
		char cl[] = "cm\x01li\x02e";
		cl[2] = 'd';
		cl[5] = 'n';
		int clfd;
		do { clfd = OPENAT(dfd, cl, O_RDONLY, 0); }
		while( clfd == -1 && errno == EINTR );
		if( clfd != -1 ){
			ssize_t r;
			do { r = PREAD(clfd, buf2, sizeof(buf2), 0); }
			while( r == -1 && errno == EINTR );
			while( CLOSE(clfd) == -1 && errno == EINTR );
			if( r > 0 ){
				buf2[r] = 0;
				n = buf2;
			}
		}
	}

	if( *ptr == 0 || *(ptr+1) != ' ' || *(ptr+2) == 0 || *(ptr+3) != ' ' ){
		cb( state, pid, 0, stt.st_uid, stt.st_gid, (char*)n );
	} else {
		*ptr = 0;
		//if( *(ptr+2) == 'T' ){ printf("TRACED\n"); }
		//if( *(ptr+2) == 't' ){ printf("TRACED\n"); }
		ptr+=4;
		int ppid = 0;
		while( *ptr != ' ' && *ptr != 0 ){
			ppid = (ppid * 10) + (*ptr - 0x30); ptr++; }
		cb( state, pid, ppid, stt.st_uid, stt.st_gid, (char*)n );
	}

done:
	while( CLOSE(dfd) == -1 && errno == EINTR );
	return;
}

int TFLinux_Proc_Walk(void *state, CB)
{
	char p[] = "/p\x00oc";
	p[2] = 'r';
	int pfd;
	do { pfd = OPENAT(AT_FDCWD, p, O_RDONLY|O_DIRECTORY, 0); }
	while( pfd == -1 && errno == EINTR );
	if( pfd == -1 ) return -1;

	char buf[8192];
	struct linux_dirent64 *d;
	for( ; ; ){
		int nread = getdents64(pfd, buf, sizeof(buf)); // no EINTR
		if( nread == 0 ) break;
		if( nread == -1 ){
			while( CLOSE(pfd) == -1 && errno == EINTR ){}; return -1; }

		int bpos = 0;;
		while( bpos < nread ) {
			d = (struct linux_dirent64 *)(buf + bpos);
			if( d->d_name[0] >= '0' && d->d_name[0] <= '9' )
				proc_process( pfd, d->d_name, state, cb );
			bpos += d->d_reclen;
		}
	}

	cb( state, 0, 0, 0, 0, NULL );
	while( CLOSE(pfd) == -1 && errno == EINTR );
	return 0;
}

