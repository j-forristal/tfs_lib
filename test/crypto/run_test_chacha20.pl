#!/usr/bin/perl

$EXE = shift;
$VEC = shift;

$CNT = 0;
sub run_vector {
	my $key = shift;
	my $nonce = shift;
	my $stream = shift;

	my $res = `$EXE $key $nonce`;
	$res =~ tr/\r\n//d;
	if( $res ne $stream ){
		my $m = "FAIL k=$key n=$nonce expect=$stream got=$res";
		die($m);
	}
	$CNT += 1;
}

open(IN, '<', $VEC) || die("Can't open vectors '$VEC'");
while(<IN>){
	tr/\r\n//d;
	next if($_ eq '');
	next if($_ =~ m/^#/);
	@p = split(/[ \t]/, $_);
	run_vector( $p[0], $p[1], $p[2] );
}
close(IN);

print "FULL PASS - $CNT vectors\n";
