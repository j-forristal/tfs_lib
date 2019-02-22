#!/usr/bin/perl

$PREFIX = shift;

print "#ifndef _$PREFIX\n";
print "#define _$PREFIX\n";

while(<>){
	tr/\r\n//d;
	next if(/^#/);
	next if($_ eq '');

	if( m/^([a-zA-Z0-9_]+)\t(\d+)/ ){
		print "#define ", $PREFIX, "_", $1, "\t", $2, "\n";
	}
}

print "#endif // _$PREFIX\n";
