#!/usr/bin/perl

$NOM=shift or die("Specify keyfile name (no extension)");
$NOM =~ tr/-a-zA-Z0-9._//cd;

die("Key already exists") if( -e $NOM.'.key.der' );
die("Pub already exists") if( -e $NOM.'.pub.der' );

# Generate the private key, then extract the public key from it
system("openssl ecparam -name prime256v1 -genkey -noout -out $NOM.key.der -outform DER");
system("openssl ec -in $NOM.key.der -inform DER -pubout -out $NOM.pub.der -outform DER");



# OpenSSL writes out the private key in ASN.1 format; now retrive that
# data and strip off the ASN.1
open(IN, '<', $NOM.'.key.der') or die("Unable to open private key");
$/ = undef;
$data = <IN>;
close(IN);

die("Unknown ASN.1 prefix") if(substr($data,0,7) ne "\x30\x77\x02\x01\x01\x04\x20");
$data = substr($data,7,32);

# write out the raw binary privkey
open(OUT,'>',$NOM.'.key.raw');
binmode(OUT);
print OUT $data;
close(OUT);



# OpenSSL writes out the public key in ASN.1 format; now retrive that
# data and strip off the ASN.1
open(IN, '<', $NOM.'.pub.der') or die("Unable to open public key");
$/ = undef;
$data = <IN>;
close(IN);

# We could properly parse the ASN.1, which requires an external module ...
# but it's fairly deterministic so we can just directly extract what we
# need.  If openssl output changes in the future, we can adjust accordingly.
$l = length($data);
if( $l < 90 || substr($data,0,25) ne "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42" ){
	die("Unknown ASN.1 prefix");
}
$data = substr($data,25);
$l = length($data);

if( $l == 65 && substr($data,0,1) eq "\x04" ){
	$data = substr($data,1);
}
elsif( $l == 66 && substr($data,0,2) eq "\x00\x04" ){
	$data = substr($data,2);
}

if( length($data) != 64 ){
	die("Unknown public key format/length " . $l);
}

# write out the raw binary pubkey
open(OUT,'>',$NOM.'.pub.raw');
binmode(OUT);
print OUT $data;
close(OUT);

# write out a C struct of the raw binary pubkey
open(OUT,'>',$NOM.'.pub.raw.c');
binmode(OUT);
print OUT "uint8_t KEY[] = {";
foreach (split(//, $data)){
	print OUT sprintf("0x%x,",ord($_));
}
print OUT "};\n";
close(OUT);
