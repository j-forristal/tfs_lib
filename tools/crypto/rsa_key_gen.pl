#!/usr/bin/perl

$NOM=shift or die("Specify keyfile name (no extension)");
$NOM =~ tr/-a-zA-Z0-9._//cd;

die("Key already exists") if( -e $NOM.'.key.der' );
die("Pub already exists") if( -e $NOM.'.pub.der' );

# Generate the private key, then extract the public key from it
system("openssl genrsa -3 -out $NOM.key.pem 2048");
system("openssl rsa -in $NOM.key.pem -inform PEM -outform DER -out $NOM.key.der");
system("openssl rsa -in $NOM.key.der -inform DER -outform DER -pubout -out $NOM.pub.der");

# read in the pubkey DER
open(IN, '<', "$NOM.pub.der");
$/ = undef;
$data = <IN>;
close(IN);

# write out a C struct of the binary pubkey
open(OUT,'>',$NOM.'.pub.raw.c');
binmode(OUT);
print OUT "uint8_t KEY[] = {";
foreach (split(//, $data)){
	print OUT sprintf("0x%x,",ord($_));
}
print OUT "};\n";
close(OUT);
