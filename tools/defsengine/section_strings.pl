#!/usr/bin/perl

%FL = (
        'AV'=>1,
        'EMM'=>2,
        'SS'=>4,
        'SS2'=>8,
        'EMU'=>16,
        'ATT'=>32,
        'GCT'=>64,
        'HT'=>128,
        'PGA'=>256,
        'APF'=>512,
        'MAL'=>1024,
        'AD'=>2048,
        'TEST'=>4096,
        'NP'=>8192
);

@DATA = ();
$longest = 0;

while(<>){
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

	# split the flags and calc the int value
	@f = split(/\|/, $fls);
	$fl = 0;
	foreach (@f){
		$fl += $FL{$_};
	}

	$stl = length($st) + 1; # +1 for NULL
	$longest = $stl if($stl > $longest);

	# save the record data
	push @DATA, [$st,pack("SS",$fl,$id)];
}

$C = 0x5e;
@BASE = ($C) x $longest;

# print metadata table
print pack("SS", $longest, $C);

foreach (@DATA){
	$st = $_->[0];
	$d = $_->[1];

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


