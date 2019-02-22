#include "private.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include PLATFORM_H

enum {
    // finding the directory
    CD_SIGNATURE = 0x06054b50,
    EOCD_LEN     = 22,        // EndOfCentralDir len, excl. comment
    MAX_COMMENT_LEN = 65535,
    MAX_EOCD_SEARCH = MAX_COMMENT_LEN + EOCD_LEN,

    // central directory entries
    ENTRY_SIGNATURE = 0x02014b50,
    ENTRY_LEN = 46,          // CentralDirEnt len, excl. var fields

    // local file header
    LFH_SIZE = 30,
};

uint16_t read_le_short(const uint8_t* buf)
{
    return buf[0] | (buf[1] << 8);

}

uint32_t read_le_int(const uint8_t* buf)
{
    return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}


static int read_central_dir_values(Zipfile* file, uint8_t* buf, size_t len)
{
    // sanity
    if (file == NULL || buf == NULL || len < EOCD_LEN) {
        return -1;
    }

    // length sanity
    uint16_t commentLen = read_le_short(&buf[0x14]);
    if (commentLen > 0 && (EOCD_LEN + commentLen > len) ) {
        return -1;
    }

    // multi-zip file
    if( read_le_short(&buf[0x04]) != 0 ||
	read_le_short(&buf[0x06]) != 0 ||
	// make sure entryCount == totalEntryCount:
	read_le_short(&buf[0x08]) != read_le_short(&buf[0x0a]) ){
	return -1;
    }

    // values we need to reference
    file->entryCount = read_le_short(&buf[0x08]);
    file->centralDirSize = read_le_int(&buf[0x0c]);
    file->centralDirOffest = read_le_int(&buf[0x10]);

    return 0;
}

static int read_central_directory_entry(Zipfile* file, Zipentry* entry,
    const unsigned char** buf, ssize_t* len)
{
    const unsigned char* p;

    unsigned short  extraFieldLength;
    unsigned short  fileCommentLength;
    unsigned long   localHeaderRelOffset;
    unsigned int dataOffset;

    p = *buf;

    if (*len < ENTRY_LEN)  return -1;
    if (read_le_int(&p[0x00]) != ENTRY_SIGNATURE) return -1;

    entry->compressionMethod = read_le_short(&p[0x0a]);
    entry->compressedSize = read_le_int(&p[0x14]);
    entry->uncompressedSize = read_le_int(&p[0x18]);
    entry->fileNameLength = read_le_short(&p[0x1c]);
    extraFieldLength = read_le_short(&p[0x1e]);
    fileCommentLength = read_le_short(&p[0x20]);
    localHeaderRelOffset = read_le_int(&p[0x2a]);

    p += ENTRY_LEN;

    // filename
    if (entry->fileNameLength != 0) {
        entry->fileName = p;
    } else {
        entry->fileName = NULL;
    }
    p += entry->fileNameLength;

    // extra field
    p += extraFieldLength;

    // comment, if any
    p += fileCommentLength;

    *buf = p;

    // the size of the extraField in the central dir is how much data there is,
    // but the one in the local file header also contains some padding.
    p = file->buf + localHeaderRelOffset;
    extraFieldLength = read_le_short(&p[0x1c]);

    dataOffset = localHeaderRelOffset + LFH_SIZE + entry->fileNameLength + extraFieldLength;
    entry->data = file->buf + dataOffset;

    return 0;
}

int read_central_dir(Zipfile *file)
{
    int err;

    const unsigned char* buf = file->buf;
    long bufsize = file->bufsize;
    const unsigned char* eocd;
    const unsigned char* p;
    const unsigned char* start;
    ssize_t len;
    int i;

    // too small to be a ZIP archive?
    if (bufsize < EOCD_LEN)  return -1;

    // find the end-of-central-dir magic
    if (bufsize > MAX_EOCD_SEARCH) {
        start = buf + bufsize - MAX_EOCD_SEARCH;
    } else {
        start = buf;
    }
    p = buf + bufsize - 4;
    while (p >= start) {
        if (*p == 0x50 && read_le_int(p) == CD_SIGNATURE) {
            eocd = p;
            break;
        }
        p--;
    }
    if (p < start) return -1;

    // extract eocd values
    err = read_central_dir_values(file, (uint8_t*)eocd, (buf+bufsize)-eocd);
    if (err != 0)  return -1;

    // Loop through and read the central dir entries.
    p = buf + file->centralDirOffest;
    len = (buf+bufsize)-p;
    for (i=0; i < file->entryCount; i++) {
        Zipentry* entry = MALLOC(sizeof(Zipentry));
        MEMSET(entry, 0, sizeof(Zipentry));

        err = read_central_directory_entry(file, entry, &p, &len);
        if (err != 0) {
            free(entry);
            return -1;
        }

        // add it to our list
        entry->next = file->entries;
        file->entries = entry;
    }

    return 0;
}
