#!/bin/sh

RELEASE_DIR=../../build/release/darwin/
INTERNAL_DIR=../../build/internal/darwin/

LIBNOM=libtfs
MODNOM=tfs

ARCH=host

make clean
make build
make netsec_tests
make crypto_tools

rm -rf ${INTERNAL_DIR}
mkdir -p ${INTERNAL_DIR}/lib/
mkdir -p ${INTERNAL_DIR}/include/

cp build/include/* ${INTERNAL_DIR}/include/
#cp build/lib/${LIBNOM}.a ${INTERNAL_DIR}/lib/

mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/

mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
