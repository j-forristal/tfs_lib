#!/bin/sh

RELEASE_DIR=../../build/release/linux/
INTERNAL_DIR=../../build/internal/linux/

LIBNOM=libtfs
MODNOM=tfs

ARCH=host

make clean
make build

rm -rf ${INTERNAL_DIR}
mkdir -p ${INTERNAL_DIR}/lib/
mkdir -p ${INTERNAL_DIR}/include/

cp build/include/* ${INTERNAL_DIR}/include/
#cp build/lib/${LIBNOM}.a ${INTERNAL_DIR}/lib/

mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/

mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
