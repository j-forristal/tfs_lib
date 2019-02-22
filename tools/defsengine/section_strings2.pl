#!/usr/bin/perl

%FL = ();

%DATA = ();
$longest = 0;
$FIRST = '';

$DATAFILE = shift;
$FLAGSFILE = shift;


sub shifter {
	my $n = shift;
	my $c = 0;
	while( ($n & 1) == 0 ){
		$n = $n >> 1;
		$c++;
	}
	return $c;
}


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
	$fls = $p[0];
	$id = $p[1];
	$st = $p[2];

	# check for dups
	die("Dupe on $st") if(defined $DATA{$st});

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

	$stl = length($st) + 1; # +1 for NULL
	$longest = $stl if($stl > $longest);

	# save the record data
	$DATA{$st} = pack("SS",$fl,$id);

	# special: if this is the first record, mark it
	$FIRST = $st if($FIRST eq '');
}

$C = 0x5e;
@BASE = ($C) x $longest;

# print metadata table
print pack("SS", $longest, $C);

@k = sort keys %DATA;
# special: make first, well, first
unshift @k, $FIRST;

foreach (@k){
	$st = $_;
	# special: to accomodate first handling, we delete
	# as we go to avoid dupes
	next if(!defined $DATA{$_});
	$d = $DATA{$_};
	delete $DATA{$_};

	# convert the string into array of ordinal values
	@CUR = split(//, $st);
	for($i=0; $i<~~@CUR;$i++){ $CUR[$i] = ord($CUR[$i]); }

	# calculate the difference between this string and last one
	$o = 0;
	$diff = '';
	for($i=0; $i<~~@CUR; $i++){
		$delta = $CUR[$i] ^ $BASE[$i];
		# no leading change, so we just increase the offset
		if( $delta == 0 and $i == $o ){
			$o++;
			next;
		}
		$diff .= chr($delta);
		$BASE[$i] = $CUR[$i];
	}

	# the last char is always a forced null
	$BASE[$i] = 0;

	# we can truncate the length if the trailing bytes didn't change
	#for($i=length($diff);$i>0;$i--){
	#	if( substr($diff,$i-1,1) eq chr(0) ){
	#		substr($diff,$i-1,1) = '';
	#		$l--;		
	#	}
	#}

	# print out offset & length
	$l = length($st) - $o;
	if( $o < 128 and $l < 256 ){
		# compressed form - no highbit flag
		print pack("S", ($o << 8) + $l);
	} else {
		# extended form = has highbit flag
		print pack("SS", (0x8000 + $o), $l);
	}

	# print out the metadata
	print $d;

	# print out the difference
	print $diff;
}

# we have to print out a final record; use compressed form
print pack("SSS",0,0,0);


