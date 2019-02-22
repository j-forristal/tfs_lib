// TFS_LIB
// Written 2019 by Jeff Forristal, jeff@forristal.com
// To the extent possible under law, the author(s) have dedicated all copyright and related
// and neighboring rights to this software to the public domain worldwide. This software is
// distributed without any warranty. Please see CC0 Public Domain Dedication.

#include <stdint.h>
#include <string.h>

#include "tf_pkcs7.h"
#include PLATFORM_H

#define ASN1_PRIMITIVE		0x00
#define ASN1_BOOLEAN		0x01
#define ASN1_INTEGER		0x02
#define ASN1_BIT_STRING		0x03
#define ASN1_OCTET_STRING	0x04
#define ASN1_OID		0x06
#define ASN1_UTF8_STRING	0x0C
#define ASN1_SEQUENCE		0x10
#define ASN1_SET		0x11
#define ASN1_PRINTABLE_STRING	0x13
#define ASN1_T61_STRING		0x14
#define ASN1_IA5_STRING		0x16
#define ASN1_UNIVERSAL_STRING	0x1C
#define ASN1_BMP_STRING		0x1E
#define ASN1_CONSTRUCTED	0x20
#define ASN1_CONTEXT_SPECIFIC	0x80

// These are for code brevity:
#define ASN1_CONST_SEQ  (ASN1_CONSTRUCTED|ASN1_SEQUENCE)
#define ASN1_CONST_SET  (ASN1_CONSTRUCTED|ASN1_SET)
#define ASN1_CONST_CTX  (ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC)

#define ASN1_OID_PKCS		"\x2a\x86\x48\x86\xf7\x0d\x01"
#define PKCS7_SIGNEDDATA	ASN1_OID_PKCS "\x07\x02"



// Internal TLV tracking, minus the T
typedef struct _tlv {
	uint8_t *p;
	size_t len;
} tlv_t;

static int asn1_get_len( uint8_t **p, const uint8_t *end, size_t *len, int indef )
{
    // Make sure we have at least one byte
    if( ( end - *p ) < 1 ) return -1;

    // Decode the first byte
    if( ( (**p) & 0x80 ) == 0 ){
	// Straight length
	*len = **p;
	(*p)++;

    } else {

	uint8_t v = (**p) & 0x7f;
        switch( v )
        {
	case 0:
	    // Only allow if we are in indef mode
            if( indef == 0 ) return -2;

            if( ( end - *p ) < 1 ) return -3;
            *len = 0; // Indefinite length == 0
            break;

        case 1:
            if( ( end - *p ) < 2 ) return -4;
            *len = (*p)[1];
            break;

        case 2:
            if( ( end - *p ) < 3 ) return -5;
            *len = ( (size_t)(*p)[1] << 8 ) | (*p)[2];
            break;

        case 3:
            if( ( end - *p ) < 4 ) return -6;
            *len = ( (size_t)(*p)[1] << 16 ) | ( (size_t)(*p)[2] << 8  ) | (*p)[3];
            break;

        case 4:
            if( ( end - *p ) < 5 ) return -7;
            *len = ( (size_t)(*p)[1] << 24 ) | ( (size_t)(*p)[2] << 16 ) |
                   ( (size_t)(*p)[3] << 8  ) | (*p)[4];
            break;

        default:
		return -8;
        }

	// Skip forward over the indicated size
	(*p) += (v + 1);
    }

    // SECURITY - check len fits in the container bounds/doesn't wrap:
    uint8_t *check = (*p) + (*len);
    if( check < (*p) || check > end ) return -9;
#if 0
    if( ((*p) + (*len)) > end ) return -9; 
    //if( *len > (size_t) ( end - *p ) ) return -9;
    if( ((*p) + (*len)) < (*p) ) return -10; // wrap
#endif
    return 0;
}

static int asn1_get_tag_and_len( uint8_t **p, const uint8_t *end, size_t *len, int tag )
{
    if( (( end - *p ) < 1) || **p != tag ) return -1;
    (*p)++; // skip over tag
    return asn1_get_len( p, end, len, 0 );
}

static int asn1_get_tag_and_len_indef( uint8_t **p, const uint8_t *end, size_t *len, int tag )
{
    if( (( end - *p ) < 1) || **p != tag ) return -1;
    (*p)++; // skip over tag
    return asn1_get_len( p, end, len, 1 );
}


static int asn1_get_tlv_int( uint8_t **p, const uint8_t *end, int *val )
{
    int ret;
    size_t len;
    *val = 0;

    if( ( ret = asn1_get_tag_and_len( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return ret;

    if( len > sizeof( int ) || ( **p & 0x80 ) != 0 ) return -1;

    while( len-- > 0 )
    {
        *val = ( *val << 8 ) | **p;
        (*p)++;
    }

    return 0;
}


// Helper function to skip past a sequence
static int _skip_set_or_seq( uint8_t **p, uint8_t *end, int which )
{
	size_t len;
	if( *p >= end ) return 1; 
	if( asn1_get_tag_and_len( p, end, &len, which) != 0 ) return 2;
	(*p) += len;
	return 0;
}

static int _get_serial( uint8_t **p, uint8_t *end, tlv_t *serial )
{
	// Make sure we're not past our designated end
	if( *p > end ) return 1;

	// Serial can be one of two types
	if( **p != (ASN1_CONTEXT_SPECIFIC|ASN1_PRIMITIVE|2) &&
		**p != ASN1_INTEGER ) return 2;
	(*p)++; // skip past tag byte

	// Get the length
	if( asn1_get_len( p, end, &serial->len, 0 ) != 0 ) return 3;

	// Save the binary value
	serial->p = *p;
	*p += serial->len;
	return 0; 
}

static int _get_name( uint8_t **p, uint8_t *end, TFS_NameSet_t *name_set )
{
	size_t len;
	uint8_t *container_end;

        // Init the name_set
        MEMSET( name_set, 0, sizeof(TFS_NameSet_t) );
        int name_set_i = 0;

	// Save a reference to the full set (for optmized compares)
	name_set->p = *p;
	name_set->p_len = (end - (*p));

	// Name is a sequence of sets
	while(1) // Walk through the sequence (of sets)
	{
		// The container for top level sets is the incoming buffer
		container_end = end;

		// Expect a SET
		if( asn1_get_tag_and_len( p, container_end, &len, ASN1_CONST_SET) != 0 )
			return 1;

		// Now the container is the set
		container_end = (*p + len);

		// Now enum through the SET
		while(1)
		{
			// SEQUENCE
			if( asn1_get_tag_and_len( p, container_end, &len, ASN1_CONST_SEQ) != 0 )
				return 2;

			uint8_t *seq_end = ((*p) + len);

			// OBJECT IDENTIFIER
			if( asn1_get_tag_and_len( p, seq_end, &len, ASN1_OID ) != 0 ) return 5;

			// Save the location of the oid
			name_set->oid[name_set_i] = *p;
			name_set->oid_sz[name_set_i] = len;

			// advance over the value
			*p += len;

			// Make sure we have at least 2 bytes
			if( ((*p) + 2) >= seq_end ) return 7;

			// Choice of STRING
			switch(**p){
				case ASN1_BMP_STRING:
				case ASN1_UTF8_STRING:
				case ASN1_IA5_STRING:
				case ASN1_UNIVERSAL_STRING:
				case ASN1_T61_STRING:
				case ASN1_PRINTABLE_STRING:
				case ASN1_BIT_STRING:
					break;
				default:
					return 8;
			}
			(*p)++; // skip over the tag byte
			if( asn1_get_len( p, seq_end, &len, 0) != 0 ) return 9;

			// Save the location of the value
			name_set->val[name_set_i] = *p;
			name_set->val_sz[name_set_i] = len;

			// Advance our name pointer
			name_set_i++;
			if( name_set_i >= TFS_PKCS7_NAME_SET_MAX ) return 20;

			// Advance over the value
			*p += len;

			// Check if we are done
			if( *p >= container_end ) break;

		} // end SET

		if( *p >= end ) break;

	} // end SEQUENCE of SETS

	*p = end;
	return 0;
}

#define _NOT_FOUND 99999
static int _find_cert( uint8_t *buf, size_t buflen, TFS_NameSet_t *target_name, 
	tlv_t *target_serial, TFS_SignerInfo_t *signer )
{
	size_t len = buflen;
	uint8_t *p = buf;
	int ret;

	// Buffer is a pointer to PCKS7 SignedData ExtendedCertificatesAndCertificates entry
	// RFC says that is a SET OF ExtendedCertificateOrCertificate, which is ::= CHOICE {
	//	certificate Certificate, (x509)
	//	extendedCertificate [0] IMPLICIT ExtendedCertificate  (pkcs6)
	// }
	//
	// CMS changes this to be ::= CHOICE {
	// 	certificate Certificate, (x509),
	//	extendedCertificate [0] IMPLICIT ExtendedCertificate  (pkcs6)
	//	v1AttrCert [1] IMPLICIT ... (x509 extended)
	//	v2AttrCert [2] IMPLICIT ... (x509 extended)
	// 	other [3] Implicit ... (arbitrary)
	//
	// For CMS, extendedCert and v1AttrCert are obsolete.
	//
	// We currently only support X.509
	//
	// Our asn1parse dump of Android PKCS7 indicates it's a SEQUENCE and not a SET
	//

	uint8_t *container_end = buf + buflen;
	uint8_t *next;

	while(1)
	{
		uint8_t *cert_start = p;

		// X.509 Certificate ::= SEQUENCE {
		if( asn1_get_tag_and_len( &p, container_end, &len, ASN1_CONST_SEQ) != 0 ) return 3;

		// New subcontainer
		uint8_t *seq_end = p + len;

		// Save a pointer to the next in the sequence
		next = seq_end;
		size_t cert_len = (size_t)(next - cert_start);

		// tbsCertificate ::= SEQUENCE {
		if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) return 5;

		// this is our new containing sequence
		seq_end = p + len;

		// version [0] INTEGER (0,1,2) (pkcs7)
		// Later: version [0] INTEGER default 1
		int ver = 1;
		if( *p == (ASN1_CONST_CTX|0) ){
			if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_CTX|0 ) != 0 )
				return 7;
			if( asn1_get_tlv_int( &p, (p + len), &ver ) != 0 ) return 8;
		}
		if( ver < 0 || ver > 2 ) return 9;

		// serialNumber CertificateSerialNumber
		tlv_t b_serial;
		ret = _get_serial( &p, seq_end, &b_serial );
		if( ret != 0 ) return (ret << 8 ) | 10;

		// signature AlgorithmIdentifier ::= SEQ
		ret = _skip_set_or_seq( &p, seq_end, ASN1_CONST_SEQ);
		if( ret != 0 ) return (ret << 8 ) | 11;

		// issuer Name ::= SEQ
		if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) return 14;
		uint8_t *seq2_end = p + len;
		ret = _get_name( &p, seq2_end, &signer->name );
		if( ret != 0 ) return (ret << 8) | 16;

		// Check if our serials match
		if( target_serial->len == b_serial.len 
			&& MEMCMP( target_serial->p, b_serial.p, b_serial.len) == 0 )
		{
			// Serials match, so now match all the RDNs
			int cert_found = 0;

			// FASTPATH name match; works 98% of the time
			// (471 out of 477 live Android test cases)
			if( signer->name.p_len == target_name->p_len &&
				MEMCMP( signer->name.p, target_name->p,
					signer->name.p_len) == 0 ){
				// They match
				cert_found = 1;
			}

			// Slower RDN searching -- need for some corner stuff
			if( cert_found == 0 ){
				int i, j;
				cert_found = 1;
				for( i=0; i<TFS_PKCS7_NAME_SET_MAX; i++ ){
					if( target_name->val[i] == NULL ) break;
					int attr_found = 0;

					// Look for the current target attr in the signer
					for( j=0; j<TFS_PKCS7_NAME_SET_MAX; j++ ){
						if( signer->name.val[j] == NULL ) break;

						// Check for a matching OID
						if( signer->name.oid_sz[j] != target_name->oid_sz[i] ) continue;
						if( MEMCMP( signer->name.oid[j], target_name->oid[i], 
							signer->name.oid_sz[j]) != 0 ) continue;

						// OIDs match, now check values
						if( signer->name.val_sz[j] != target_name->val_sz[i] ) continue;
						if( MEMCMP( signer->name.val[j], target_name->val[i], 
							signer->name.val_sz[j]) != 0 ) continue;

						// OID and value match, we found it
						attr_found = 1;
						break;
					}

					// If we didn't find one of our attrs, we're done
					if( attr_found == 0 ){
						cert_found = 0;
						break;
					}
				}
			}

			if( cert_found > 0 ){
				signer->cert = cert_start;
				signer->cert_len = cert_len;

				// We want the SPKI, so skip over the unneded parts.
				// Validity ::= SEQ
				ret = _skip_set_or_seq( &p, seq_end, ASN1_CONST_SEQ);
				if( ret != 0 ) return (ret << 8 ) | 30;

				// SubjectName ::= SEQ
				ret = _skip_set_or_seq( &p, seq_end, ASN1_CONST_SEQ);
				if( ret != 0 ) return (ret << 8 ) | 31;

				// subjectPublicKeyInfo spki ::= SEQUENCE
				signer->spki = p;
				if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ){
					signer->spki = NULL; return 20; }
				if( (p + len) > seq_end) { signer->spki=NULL; return 21; }
				signer->spki_len = (size_t)((p + len) - signer->spki);

				// We found it, so we're done
				return 0;
			}
		}

		// ... everything else ... we don't bother to parse;
		// jump to the next in the sequence
		p = next;

		// If this is the last one, we're done
		if( p >= container_end ) break;

	} // sequence

	// If we get here, we didn't find a signer
	return _NOT_FOUND;
}


#define PKCS7_OID_LEN	9

#define parse_err( v ) { ret = (v); goto _parse_error; }
#define maxsigners_err( v ) { ret = (v); goto _maxsigners_error; }
#define nosigner_err( v ) { ret = (v); goto _nosigner_error; }

int TFS_PKCS7_Parse( uint8_t *buf, size_t buflen, TFS_SignerInfo_t *signers, size_t signers_len )
{
	uint8_t *p, *container_end, *certs_start, *set_end, *seq_end, 
		*seq2_end, *next, *seq3_end;
	size_t certs_len, len = buflen;
	int ret, i, ver;
	tlv_t b_serial;
	TFS_NameSet_t signer_name;

	p = buf;
	container_end = p + len;

	MEMSET( signers, 0, sizeof(TFS_SignerInfo_t) * signers_len );

	// ContentInfo := SEQUENCE {
	if( asn1_get_tag_and_len_indef( &p, container_end, &len, ASN1_CONST_SEQ) != 0 )
		parse_err( 1 );
	if( len == 0 ) len = (container_end - p); // indefinite handling
	else container_end = p + len; // new outer container

	// ContentType ::= OBJECT_IDENTIFIER
	if( asn1_get_tag_and_len( &p, container_end, &len, ASN1_OID) != 0) parse_err( 3 );
	if( (p + len) >= container_end || len != PKCS7_OID_LEN 
		|| MEMCMP(p, PKCS7_SIGNEDDATA, len) != 0 )
		parse_err( 4 );
	p += len;

	// content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
	// NOTE: this is OPTIONAL, but we require it for SignedData uses
	if( asn1_get_tag_and_len_indef( &p, container_end, &len, ASN1_CONST_CTX|0 ) != 0 )
		parse_err( 5 );
	if( len == 0 ) len = (container_end - p); // indefinite handling
	else container_end = p + len; // new outer container

	// SignedData ::= SEQUENCE {
	if( asn1_get_tag_and_len_indef( &p, container_end, &len, ASN1_CONST_SEQ) != 0 )
		parse_err( 7 );
	if( len == 0 ) len = (container_end - p); // indefinite handling
	else container_end = p + len; // new outer container

	// version ::= INTEGER
	if( asn1_get_tlv_int( &p, container_end, &ver ) != 0 ) parse_err( 9 );
	// CMS has lots of versions; we support 1, 3, 4
	if( ver != 1 && ver != 3 && ver != 4 ) parse_err( 10 );

	// DigestAlgo ::= SET / get constructed set, skip the whole set 
	ret = _skip_set_or_seq( &p, container_end, ASN1_CONST_SET );
	if( ret != 0 ) parse_err( ((ret << 8) | 11) );

	// ContentInfo ::= SEQUENCE / get constructed sequence, skip the whole sequence 
	// NOTE: in Apple CMS, this is indefinite
	if( asn1_get_tag_and_len_indef( &p, container_end, &len, ASN1_CONST_SEQ) != 0 ) 
		parse_err( ((1 << 8)|12) );
	if( len > 0 ){
		// definite, just skip over it
		p += len;
	} else {
		// indefinite - we have to parse it to find the length
		// OBJECT IDENTIFIER
		if( asn1_get_tag_and_len( &p, container_end, &len, ASN1_OID) != 0)
			parse_err( ((2<<8)|12) );
		p += len; // skip over the OID

		// eContent [0] EXPLICIT OCTET STRING OPTIONAL
		if( *p == (ASN1_CONST_CTX|0) ){
			if( asn1_get_tag_and_len( &p, container_end, &len, ASN1_CONST_CTX|0) != 0)
				parse_err( ((3<<8)|12) );
			p += len; // skip over the data
		}

		// EOC - two NULLs
		if( (container_end - p) < 2 ) parse_err( ((4<<8)|12) );
		if( *p != 0 || *(p+1) != 0 ) parse_err( ((5<<8)|12) );
		p += 2;
	}

	// Certificates [0] IMPLICIT OPTIONAL
	// NOTE: while it's technically OPTIONAL, we require it for SignedData
	if( asn1_get_tag_and_len( &p, container_end, &len, ASN1_CONST_CTX|0 ) != 0 )
		parse_err( 13 );

	// SPECIAL: save a reference to the certs; we will parse it later
	certs_start = p;
	certs_len = len;
	p += len; // jump over the cert data

	// CRLS [1] IMPLICIT OPTIONAL
	if( *p == (ASN1_CONST_CTX|1) ){
		// optional element is present
		ret = asn1_get_tag_and_len( &p, container_end, &len, ASN1_CONST_CTX|1 );
		if( ret != 0 ) parse_err( ((ret << 8)|15) );
		// it exists, so we have to jump over it
		p += len;
	}

	// SET SignerInfos
	if( asn1_get_tag_and_len( &p, container_end, &len, ASN1_CONST_SET ) != 0 )
		parse_err( 17 );

	// Process the set
	// NOTE: we expect there to be at least one SignerInfo, so we jump straight
	// into expecting the first item.  If it is an empty set, it will be a
	// parsing error.
	set_end = p + len;
	while( 1 )
	{
		// SignerInfo ::= SEQUENCE
		if( asn1_get_tag_and_len( &p, set_end, &len, ASN1_CONST_SEQ) != 0 )
			parse_err( 19 );

		seq_end = p + len;
		next = seq_end; // save where this entity is supposed to end

		// version INTEGER
		if( asn1_get_tlv_int( &p, seq_end, &ver ) != 0 ) parse_err( 21 );

		// version == 1 (for IssuerAndSerialNumber) or 3 (for subjectKeyIdentifier)
		if( ver != 1 ) parse_err( 22 );

		// TODO: CMS allows CHOICE of subjectKeyIdentifier too...
		// If that happens, version will be 3

		// IssuerAndSerialNumber ::= SEQUENCE {
		if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) parse_err( 23 );

		seq2_end = p + len;

		// issuer Name ...
		// Name ::= SEQUENCE
		if( asn1_get_tag_and_len( &p, seq2_end, &len, ASN1_CONST_SEQ) != 0 ) parse_err( 25 );

		seq3_end = p + len;

		ret = _get_name( &p, seq3_end, &signer_name );
		if( ret != 0 ) parse_err( ((ret << 8) | 27) );

		// serialNumber CertificateSerialNumber
		ret = _get_serial( &p, seq2_end, &b_serial );
		if( ret != 0 ) parse_err( ((ret << 8) | 28) );

		// find the next open signer slot
		for( i=0; i<signers_len; i++){ if( signers[i].cert == NULL ) break; }
		if( i == signers_len ) maxsigners_err( 29 ); 

		// match this serialnum & issuer
		ret = _find_cert( certs_start, certs_len, &signer_name, &b_serial, &signers[i] );
		if( ret == _NOT_FOUND ) nosigner_err( 30 );
		if( ret != 0 ) parse_err( ((ret << 8) | 30) );

		// ... everything else we skip, we only need the cert identifiers
		p = next; // jump to the next entity/end of this entity

		if( p >= set_end ) break;

	} // while SET

	ret = 0 | TFS_PKCS7_ERR_OK;
	return ret;

_parse_error:
	ret = (ret << 8) | TFS_PKCS7_ERR_PARSING;
	return ret;
_maxsigners_error:
	ret = (ret << 8) | TFS_PKCS7_ERR_MAXSIGNERS;
	return ret;
_nosigner_error:
	ret = (ret << 8) | TFS_PKCS7_ERR_NOSIGNER;
	return ret;
}


#define ANS1_OID_CN	"\x55\x04\x03" // CommonName
#define ANS1_OID_SN	"\x55\x04\x05" // Serial Number
#define ASN1_OID_C	"\x55\x04\x06" // Country
#define ASN1_OID_L	"\x55\x04\x07" // Locality
#define ASN1_OID_ST	"\x55\x04\x08" // State
#define ASN1_OID_O	"\x55\x04\x0a" // Org
#define ASN1_OID_OU	"\x55\x04\x0b" // Org Unit

int TFS_PKCS7_Name( TFS_NameSet_t *set, char output[TFS_PKCS7_SUBJECT_SIZE] )
{
	int o = 0;
	MEMSET(output, 0, TFS_PKCS7_SUBJECT_SIZE);

	int i;
	for( i=0; i<TFS_PKCS7_NAME_SET_MAX; i++){
		if( set->oid[i] == NULL || set->val[i] == NULL ) break;
		if( (o + set->val_sz[i] + 4) >= TFS_PKCS7_SUBJECT_SIZE ) break;
		if( set->oid_sz[i] == 3 && set->oid[i][0] == 0x55 && set->oid[i][1] == 0x04 ){
			output[o++] = '/';
			switch( set->oid[i][2] ){
			case 3: output[o++]='C'; output[o++]='N'; output[o++]='='; break;
			case 5: output[o++]='S'; output[o++]='N'; output[o++]='='; break;
			case 6: output[o++]='C'; output[o++]='='; break;
			case 7: output[o++]='L'; output[o++]='='; break;
			case 8: output[o++]='S'; output[o++]='T'; output[o++]='='; break;
			case 0x0a: output[o++]='O'; output[o++]='='; break;
			case 0x0b: output[o++]='O'; output[o++]='U'; output[o++]='='; break;
			default: output[o++]='?'; output[o++]='='; break;
			}
		} else {
			output[o++] = '/';

			// Special handling of Apple ID
			if( set->oid_sz[i] == 10 && 
				MEMCMP( &set->oid[i][0], "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x01", 10 ) == 0 ){
				output[o++] = 'I';
				output[o++] = 'D';
			} else {
				// Don't know what it is
				output[o++] = '?';
			}
			output[o++] = '=';
		}
		TFMEMCPY( &output[o], set->val[i], set->val_sz[i] );
		o += set->val_sz[i];
	}

	return o;
}

static int _hostname_check( char *hostname, uint8_t *target, int len )
{
	ASSERT( hostname );
	ASSERT( target );
	size_t s = STRLEN(hostname);
	if( s == 0 || len == 0 ) return 0; // no match

	// Normalize trailing dots by shortening the lengths
	if( hostname[ s - 1 ] == '.' ) s--;
	if( target[ len - 1 ] == '.' ) len--;

//printf("PKCS7_X509: check '%.*s'=>'%.*s'\n", s, hostname, len, target);

	if( len < 2 ) return 0; // no match

	if( target[0] == '*' && target[1] == '.' ){
		// Wildcard, hack off leading '*'
		target++;
		len--;

		// By definition, s must be > then len to be valid
		if( s <= len ) return 0; // no match

		// Match the ending anchor
		if( MEMCMP( &hostname[ s - len ], target, len ) != 0 )
			return 0; // no match

		// We matched the anchor, but we need to ensure no other
		// dots in the hostname.  If we encounter one, it's not
		// a match (foo.bar.baz.com != *.baz.com)
		int i;
		for( i=0; i<(s - len - 1); i++ ){
			if( hostname[i] == '.' ) return 0; // invalid match
		}

		// If we get here, no dots found and we matched the anchor,
		// so call it a match
		return 1; // match

	} else {
		// Exact match check
		if( len == s && MEMCMP( hostname, target, len ) == 0 ) return 1; // match
	}

	return 0; // no match
}


#define ASN1_OID_IDCE_SAN	"\x55\x1d\x11"

int TFS_PKCS7_X509_Parse( 
	uint8_t *cert_start, uint32_t cert_len, 
	uint8_t **spki, uint32_t *spki_len, 
	char subject[TFS_PKCS7_SUBJECT_SIZE],
	char *hostname_check
	)
{
	uint8_t *seq_end = cert_start + cert_len;
	uint8_t *p = cert_start;
	size_t len = cert_len;
	int ret;

	// X.509 Certificate ::= SEQUENCE {
	if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) return 5;

	// New subcontainer
	seq_end = p + len;

	// tbsCertificate ::= SEQUENCE {
	if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) return 6;

	// this is our new containing sequence
	seq_end = p + len;

	// version [0] INTEGER (0,1,2) (pkcs7)
	// Later: version [0] INTEGER default 1
	int ver = 1;
	if( *p == (ASN1_CONST_CTX|0) ){
		if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_CTX|0 ) != 0 )
			return 7;
		if( asn1_get_tlv_int( &p, (p + len), &ver ) != 0 ) return 8;
	}
	if( ver < 0 || ver > 2 ) return 9;

	// serialNumber CertificateSerialNumber
	tlv_t b_serial;
	ret = _get_serial( &p, seq_end, &b_serial );
	if( ret != 0 ) return (ret << 8 ) | 10;

	// signature AlgorithmIdentifier ::= SEQ
	ret = _skip_set_or_seq( &p, seq_end, ASN1_CONST_SEQ);
	if( ret != 0 ) return (ret << 8 ) | 11;

	// issuer Name ::= SEQ
	ret = _skip_set_or_seq( &p, seq_end, ASN1_CONST_SEQ);
	if( ret != 0 ) return (ret << 8) | 12;

	// Validity ::= SEQ
	ret = _skip_set_or_seq( &p, seq_end, ASN1_CONST_SEQ);
	if( ret != 0 ) return (ret << 8 ) | 13;

	// SubjectName ::= SEQ
	TFS_NameSet_t subj;
	if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) return 14;
	uint8_t *seq2_end = p + len;
	ret = _get_name( &p, seq2_end, &subj );
	if( ret != 0 ) return (ret << 8 ) | 15;

	// Convert subject to readable string
	TFS_PKCS7_Name( &subj, subject );
	// Even in error (ret==0), we just have empty string...go with it

	// subjectPublicKeyInfo spki ::= SEQUENCE
	if( spki != NULL ){ *spki = p; }
	if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ){
		if( spki != NULL ) *spki = NULL;
		return 20; 
	}
	if( (p + len) > seq_end) { 
		if( spki != NULL ) *spki=NULL; 
		return 21; 
	}
	if( spki != NULL ){ *spki_len = (size_t)((p + len) - *spki); }
	p += len;

	// If there is no hostname to check, we don't have to go past here
	if( hostname_check == NULL ) return TFS_PKCS7_X509_OK;

	// If we get here, hostname checking was requested. Start with the
	// subject in hand, then move on to SAN only if it doesn't match.
	// Technically the RFC says to check SAN first then fallback to
	// subject CN, but a lot of certs use subj CN.
	int j;
	for( j=0; j<TFS_PKCS7_NAME_SET_MAX; j++){
		if( subj.oid[j] == NULL || subj.val[j] == NULL ) break;
		if( subj.oid_sz[j] == 3 &&  subj.oid[j][0] == 0x55 
			&& subj.oid[j][1] == 0x04 && subj.oid[j][2] == 0x03 ){
			// This is the CN

			if( _hostname_check( hostname_check, subj.val[j], subj.val_sz[j] ) > 0 ){
				// Hostname matched, we don't have to go any further
				return TFS_PKCS7_X509_OK;
			}

			// We already found the CN, we don't have to keep looking
			// through the subject.  Proceed to looking at the SubjAltName
			break;
		}
	}
	
	// are we at the end?
	if( p >= seq_end ){
		return (hostname_check != NULL) ? TFS_PKCS7_X509_OK_ERR_HOSTNAME : TFS_PKCS7_X509_OK;
	}

	// issuerUniqueID [1] IMPLICIT OPTIONAL
	if( *p == (ASN1_CONST_CTX|1) ){
		// optional element is present
		ret = asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_CTX|1 );
		if( ret != 0 ) return( ((ret << 8)|25) );
		// it exists, so we have to jump over it
		p += len;
	}

	// subjectUniqueID [2] IMPLICIT OPTIONAL
	if( *p == (ASN1_CONST_CTX|2) ){
		// optional element is present
		ret = asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_CTX|2 );
		if( ret != 0 ) return( ((ret << 8)|26) );
		// it exists, so we have to jump over it
		p += len;
	}

	// extensions [3] EXPLICIT Extensions OPTIONAL; SEQUENCE of Extension
	if( p >= seq_end || asn1_get_tag_and_len_indef( &p, seq_end, &len, ASN1_CONST_CTX|3 ) != 0 ){
		return (hostname_check != NULL) ? TFS_PKCS7_X509_OK_ERR_HOSTNAME : TFS_PKCS7_X509_OK;
	}
	if( len == 0 ) len = (seq_end - p); // indefinite handling
	else seq_end = p + len; // new outer container

	// SEQUENCE
	if( asn1_get_tag_and_len( &p, seq_end, &len, ASN1_CONST_SEQ) != 0 ) return 27;
	seq_end = p + len;

	// walk through the sequence of extensions
	while( p < seq_end )
	{
		uint8_t *ext_end = seq_end;

		// Extension ::= SEQUENCE
		if( asn1_get_tag_and_len( &p, ext_end, &len, ASN1_CONST_SEQ) != 0 ) return 30;

		// Adjust our end to this one extension
		ext_end = p + len;
		if( ext_end > seq_end ) break;

		// extnID ::= OBJECT IDENTIFIER
		if( asn1_get_tag_and_len( &p, ext_end, &len, ASN1_OID ) != 0 ) return 31;

		// Process OID -- we only care about subjectAltName for now
		if( len != 3 || p[0] != 0x55 || p[1] != 0x1d || p[2] != 0x11 ){
			// Not SAN; fast forward to end of this extension
			p = ext_end;

			// loop -- will catch if we are at end of sequences
			continue;
		}
		p += len;

		// This is a SAN -- so process the full Extension

		// critical ::= BOOLEAN DEFAULT FALSE
		if( (*p & 0x0f) == ASN1_BOOLEAN ){
			if( asn1_get_tag_and_len( &p, ext_end, &len, ASN1_BOOLEAN) != 0 )
				return 32;
			p += len; // skip over boolean value, we don't use it
		}

		// extnValue ::= OCTET STRING
		if( asn1_get_tag_and_len( &p, ext_end, &len, ASN1_OCTET_STRING) != 0 )
			return 33;

		// The octet string is our new container
		ext_end = p + len;
		if( ext_end > seq_end ) break;

		// The extnValue OCTET STRING is really just DER of a form that is
		// specific to the extnID.  Since we are processing SAN, we can
		// proceed to parse the DER bytes accordingly.

		// SubjectAltName ::= GeneralNames
		// GeneralNames ::= SEQUENCE of GeneralName
		if( asn1_get_tag_and_len( &p, ext_end, &len, ASN1_CONST_SEQ) != 0 )
			return 34;

		// the sequence is our new container
		ext_end = p + len;
		if( ext_end > seq_end ) break;

		while( p < ext_end ){
			// We only process dNSName choices, ignore the rest

			// GeneralName ::= CHOICE { dNSName [2] IA5String }
			if( *p == (ASN1_CONTEXT_SPECIFIC|2) ){
				// We got a dNSName, process it
				if( asn1_get_tag_and_len( &p, ext_end, &len, ASN1_CONTEXT_SPECIFIC|2 ) != 0 )
					return 35;

				// Remaining is IA5String
//printf("PKCS7: SAN dNSName=%.*s\n", len, p);

				if( _hostname_check( hostname_check, p, len ) > 0 ){
					// Hostname check matched; we don't have to go
					// any further
					return TFS_PKCS7_X509_OK;
				}

				// Advance over string
				p += len;

			} else {
				// skip over tag
				p++;

				// get length to skip over
				if( asn1_get_len( &p, ext_end, &len, 0 ) != 0 ) return 36;

				// skip over the indicated length for this GeneralName
				p += len;

				// Loop to process next GeneralName
				continue;
			}
		}

		// RFC indicates only one extension type per cert.  We just processed
		// the SAN, and that's all we were looking for -- so we can be done.
		break;
	}

	// If we get here, it means we didn't match the hostname; we return a
	// result that indicates successful parsing of the cert, but a mismatch in the
	// hostname.  That way the caller can still use subject, spki data as needed.
	return TFS_PKCS7_X509_OK_ERR_HOSTNAME;
}

