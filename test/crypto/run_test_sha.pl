#!/usr/bin/perl

$EXE = shift;
$VEC = shift;

$CNT = 0;
sub run_vector {
	my $msg = shift;
	my $digest = shift;

	my $res = `$EXE $msg`;
	$res =~ tr/\r\n//d;
	if( $res ne $digest ){
		my $m = "FAIL m=$msg expect=$digest got=$res";
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
	run_vector( $p[1], $p[0] );
}
close(IN);

print "FULL PASS - $CNT vectors\n";
