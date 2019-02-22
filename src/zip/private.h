#ifndef PRIVATE_H
#define PRIVATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct Zipentry {
    unsigned long fileNameLength;
    const unsigned char* fileName;
    unsigned short compressionMethod;
    unsigned int uncompressedSize;
    unsigned int compressedSize;
    const unsigned char* data;
    
    struct Zipentry* next;
} Zipentry;

typedef struct Zipfile
{
    // whole file mmap'ing
    uint8_t *buf;
    size_t bufsize;

    // Central directory values
    uint16_t entryCount;
    uint32_t centralDirSize;
    uint32_t centralDirOffest;

    Zipentry* entries;
} Zipfile;

int read_central_dir(Zipfile* file);

uint32_t read_le_int(const uint8_t* buf);
uint16_t read_le_short(const uint8_t* buf);

#endif // PRIVATE_H

