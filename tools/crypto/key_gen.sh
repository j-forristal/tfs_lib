#!/bin/sh

#echo NOTE - doesn't work on OSX

openssl ecparam -name prime256v1 -genkey -noout -out ec-key.pem
openssl ec -in ec-key.pem -pubout -out ec-pub.pem

echo 'hello' | openssl dgst -sha256 -sign ec-key.pem > test.sig
echo 'hello' | openssl dgst -sha256 -verify ec-pub.pem -signature test.sig

