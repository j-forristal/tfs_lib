#!/usr/bin/perl

$EXE = shift;
$VEC = shift;

$CNT = 0;
sub run_vector {
	my $key = shift;
	my $plain = shift;
	my $cipher = shift;

	my $res = `$EXE $key $plain`;
	$res =~ tr/\r\n//d;
	if( $res ne $cipher ){
		my $msg = "FAIL k=$key p=$plain expect=$cipher got=$res";
		die($msg);
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
