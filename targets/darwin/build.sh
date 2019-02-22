#!/bin/sh

RELEASE_DIR=../../build/release/darwin/
INTERNAL_DIR=../../build/internal/darwin/

LIBNOM=libtfs
MODNOM=tfs

ARCH=host


if [ -z "$BUILD_BASE" ]; then
	echo ERROR: need BUILD_BASE
	exit 1
fi


make clean
make build vault_tests netsec_tests crypto_tools tlv_tools tlv_tests

rm -rf ${INTERNAL_DIR}
mkdir -p ${INTERNAL_DIR}/lib/
mkdir -p ${INTERNAL_DIR}/include/

cp build/include/* ${INTERNAL_DIR}/include/

mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/

mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
