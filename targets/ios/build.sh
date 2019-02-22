#!/bin/sh

RELEASE_DIR=../../build/release/ios/
INTERNAL_DIR=../../build/internal/ios/

LIBNOM=libtfs
MODNOM=tfs

# ARCH is provided by build2.sh

./build2.sh
[ $? -eq 0 ] || exit $?

rm -rf ${INTERNAL_DIR}
mkdir -p ${INTERNAL_DIR}/lib/
mkdir -p ${INTERNAL_DIR}/include/

cp build/include/* ${INTERNAL_DIR}/include/
cp build/lib/${LIBNOM}.a ${INTERNAL_DIR}/lib/

for ARCH in armv7 armv7s arm64 i386 x86_64
do
        mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
        cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/
        mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
        cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/

done


