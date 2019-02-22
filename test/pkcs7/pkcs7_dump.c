#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "tf_pkcs7.h"
#include "tf_crypto.h"

void dump_hex( uint8_t* hex, uint32_t cnt );

void _cert_dump( int i, TFS_SignerInfo_t *signer )
{
	if( signer->cert == NULL ) return;

	printf("Signer[%d]:\n", i);

	uint8_t digest[ TFC_SHA256_DIGEST_SIZE ];
	TFC_SHA256_Ctx_t sha256_ctx;
	TFC_SHA256_Init( &sha256_ctx );
	TFC_SHA256_Update( &sha256_ctx, signer->cert, signer->cert_len );
	TFC_SHA256_Final( &sha256_ctx, digest );

	printf("- Cert SHA256: ");
	dump_hex( digest, sizeof(digest) );

	if( signer->spki != NULL ){
		TFC_SHA256_Ctx_t sha256_ctx;
		TFC_SHA256_Init( &sha256_ctx );
		TFC_SHA256_Update( &sha256_ctx, signer->spki, signer->spki_len );
		TFC_SHA256_Final( &sha256_ctx, digest );

		printf("- SPKI SHA256: ");
		dump_hex( digest, sizeof(digest) );
	}
}

int main(int argc, char **argv){

        int fd = open( argv[1], O_RDONLY);
        assert( fd >= 0 );

        struct stat stt;
        assert( fstat(fd, &stt) == 0 );

        uint8_t *buffer = (uint8_t*)mmap(NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
        assert( buffer != MAP_FAILED );
        close( fd );

        TFS_SignerInfo_t signers[4];

        int ret = TFS_PKCS7_Parse( buffer, stt.st_size, signers, 4 );
        if( ret == TFS_PKCS7_ERR_OK ){
                printf("OK - %s\n", argv[1]);
		int i;
		for( i=0; i<4; i++ ){
			_cert_dump( i, &signers[i] );
		}
        } else {
                printf("ERR %d/%d/%d - %s\n", (ret & 0xff),
                        ((ret>>8) & 0xff), (ret>>16) & 0xff, argv[1]);
        }
        return ret;
}
