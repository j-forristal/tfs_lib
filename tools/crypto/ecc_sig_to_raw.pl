#!/usr/bin/perl

#
# OpenSSL signatures are in ASN.1 format. This will parse ASN.1 and
# extract out the two raw 32-byte signature values.
#

$F=shift or die("Must specify a signature file");

open(IN,'<',$F) || die("Can't open signature file");
$/ = undef;
$data = <IN>;
close(IN);

$l = length($data);

$sig = '';

die("Unknown format 1") if( $l < 64 );
$sig = $data if( $l == 64 );
if( $l > 64 ){
	$pref = substr($data, 0, 3);
	die("Unknown format 2") if($pref ne "\x30\x44\x02" && $pref ne "\x30\x45\x02");
	if( substr($data,3,1) eq "\x20" ){
		$sig .= substr($data, 4, 32);
		$data = substr($data, 36);
	}
	elsif( substr($data,3,2) eq "\x21\x00" ){
		$sig .= substr($data, 5, 32);
		$data = substr($data, 37);
	}
	else {
		die("Unknown format 3");
	}

	$l = length($data);

	die("Unknown format 4") if( substr($data, 0, 1) ne "\x02" );
	if( substr($data,1,1) eq "\x20" && $l >= 34 ){
		$sig .= substr($data, 2, 32);
	}
	else if( substr($data,1,2) eq "\x21\x00" && $l >= 35 ){
		$sig .= substr($data, 3, 32);
	}
	else {
		die("Unknown format 5");
	}
}

die("Unable to extract signature") if( length($sig) != 64 );

# write out a C struct of the raw binary pubkey
open(OUT,'>',$F.'.c');
binmode(OUT);
print OUT "uint8_t SIG[] = {";
foreach (split(//, $sig)){
	print OUT sprintf("%d,",ord($_));
}
print OUT "};\n";
close(OUT);
