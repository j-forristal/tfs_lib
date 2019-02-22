#!/usr/bin/perl

$HEADER_SIZE = 336;
$TYPE_MAX = 16;
%SECTIONS = ();

@lt = localtime();
$v = ($lt[5]+1900) * 1000000;
$v += ($lt[4]+1) * 10000;
$v += ($lt[3]) * 100;
$v += 1;
$VERSION = pack("V", $v);

$SECTION_ENTRY_SIZE = 10; # CCLL

$section_count = 0;

$IDENT = shift @ARGV;
foreach (@ARGV){
	continue if( !m/^(\d+):(\d+):(.+)/ );
	$typ = $1;
	$styp = $2;
	$f = $3;

	die("Duplicate type") if(defined $SECTIONS{$type});
	die("Missing file '$f'") if(!-e $f);
	die("Bad type") if($typ < 0 || $type > $TYPE_MAX);

	$SECTIONS{$typ} = [$styp,$f];
	$section_count++;
}

die("No sections found") if( $section_count == 0 );
die("Too many sections") if( $section_count > $TYPE_MAX);

# Create the section table
$SECTION_TABLE_SIZE = 1 + ( $section_count * $SECTION_ENTRY_SIZE ) + $HEADER_SIZE;

# pad to an 8-byte alignment
$padding = '';
if( ($SECTION_TABLE_SIZE % 8) > 0 ){
	$padding = "\x00" x (8 - ($SECTION_TABLE_SIZE % 8));
}
$off = $SECTION_TABLE_SIZE + length($padding);
$SECTION_TABLE = pack("C", $section_count);

# read in each section, saving the data and updating the table
$DATA = '';
@K = keys %SECTIONS;
foreach (@K){
	$N = $_;
	$a = $SECTIONS{$N};
	$s = $a->[0];
	$f = $a->[1];

	local $/ = undef;
	open(F, '<', $f) or die("Can't open file");
	binmode(F);
	$data = <F>;
	close(F);

	$SECTION_TABLE .= pack("CCLL", $N, $s, $off, length($data));
	$DATA .= $data;
	$off += length($data);
}


# create header w/ empty signature
# NOTE: updated to V2 format
$HEADER = "\x01\x52\x7f\x09" . # MAGIC
	chr(0) x 64 . # signature_ecc
	chr(0) x 256 . # signature_rsa
	"\x01\x52\x7f\x09" . # MAGIC again
	$VERSION . # version
	pack("S",$IDENT) . # ident
	"\x00\x00"; # flags
die("Bad header calc") if( length($HEADER) != $HEADER_SIZE );

# Output the data
print $HEADER, $SECTION_TABLE, $padding, $DATA;
exit(0);

