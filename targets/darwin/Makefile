
LIBNOM := libtfs
TARGET := darwin

ARCH ?= host

SHAREDLIBEXT := .dylib

#SSLSTACK := tfs
#SSLSTACK := mbedtls
#SSLSTACK := apple
SSLSTACK := boringssl

TFSCAL := tfs
#TFSCAL := mbedtls
#TFSCAL := apple
TFSCAL := boringssl

CFLAGS += 
# -fsanitize=address
# -fprofile-arcs -ftest-coverage
# -fprofile-instr-generate -fcoverage-mapping
# --analyze

EXELIBS += -framework Security -framework CoreFoundation

BUILD_DIR := build/

include ../common/top.mk
