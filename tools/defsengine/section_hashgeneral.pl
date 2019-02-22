#!/usr/bin/perl

use Digest::MD5 qw(md5);

%FL = ();

sub h {
	my $d = shift;
	return md5("ADDSEC".$d);
}

sub shifter {
	my $n = shift;
	my $c = 0;
	while( ($n & 1) == 0 ){
		$n = $n >> 1;
		$c++;
	}
	return $c;
}


%DATA = ();

$DATAFILE = shift;
$FLAGSFILE = shift;

open(INF,'<',$FLAGSFILE) || die("flagsfile");
while(<INF>){
	tr/\r\n//d;
	if( $_ =~ m/^([A-Z0-9_]+)\t(\d+)/ ){
		$FL{$1} = $2;
		# We have to reserve the top flag value
		if( $2 == 0x8000 ){ die("Illegal flag value for $1"); }
	}
}
close(INF);

open(IN,'<',$DATAFILE) || die("datafile");
while(<IN>){
	# skip over the non-item stuff
	tr/\r\n//d;
	next if(m/^[ \t]*#/);
	next if($_ eq '');
	s/#.*$//;

	# parse the line into pieces
	@p = split(/\t/, $_);
	next if( ~~@p < 3 );
	$dat = $p[2];
	$fls = $p[0];
	$id = $p[1];

	# split the flags and calc the int value
	@f = split(/\|/, $fls);
	$fl = 0;
	if( (scalar @f) == 1 ){
		# single flag, encode it as a shifter
		die("Unknown flag $_") if(!defined $FL{$f[0]});
		$fl = 0x8000 + shifter( $FL{$f[0]} );
	} else {
		# combinable flags, encode accordingly
		foreach (@f){
			die("Unknown flag $_") if(!defined $FL{$_});
			die("Combining high-order flags '$fls'") if( $FL{$_} > 0x7FFF );
			$fl += $FL{$_};
		}	
	}

	# hash the data
	$h = h($dat);
	die("Dupe of $dat") if( defined $DATA{$h} );

	# save the record data
	$DATA{$h} = pack("SS", $fl, $id);
}

# sort the records by hash
@k = sort keys %DATA;

# create an empty offset table
@table = ();
for( $i=0; $i<256; $i++){
	push @table, 0;
}

# create linear records array
$BIN = '';
$rec = 1;
foreach (@k){
	$i = ord( substr($_, 0, 1) );
	$table[$i] = $rec if( $table[$i] == 0 );
	$BIN .= $_ . $DATA{$_};
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

