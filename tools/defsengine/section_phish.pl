#!/usr/bin/perl

use Digest::MD5 qw(md5);
#use Digest::SHA1 qw(sha1);

sub h {
	my $d = shift;
	$d =~ s/([a-f0-9][a-f0-9])/chr(hex($1))/egi;
	return md5("ADDSEC".$d);
}

%DATA = ();

while(<>){
	# skip over the non-item stuff
	tr/\r\n//d;
	next if(m/^[ \t]*#/);
	next if($_ eq '');

	# parse the line into pieces
	@p = split(/\t/, $_);
	if( ~~@p != 2 ){ print("WARN: check $_\n"); next; }
	$pkg = h($p[0]);
	$label = h($p[1]);
	$d = $label . $pkg;
	die("Dupe of $p[1]") if( defined $DATA{$d} );
	$DATA{$d} = $pkg;
}

# sort the records by hash
@k = sort keys %DATA;

# create an empty offset table
@table = ();
for( $i=0; $i<256; $i++){
	push @table, 0;
}

# create linear records array
$EMTPY = chr(0) x 4;
$BIN = '';
$rec = 1;
foreach (@k){
	$i = ord( substr($_, 0, 1) );
	$table[$i] = $rec if( $table[$i] == 0 );
	$BIN .= $_ . $EMPTY;
	$rec += 1;
}

# terminating empty record
$BIN .= "\x00" x 20;

# print the offset table
for( $i=0; $i<256; $i++){
	print pack("S", $table[$i]);
}

# print the records
print $BIN;

