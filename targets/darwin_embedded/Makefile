
LIBNOM := libtfs
TARGET := darwin

ARCH ?= host

SHAREDLIBEXT := .dylib

#SSLSTACK := tfs
SSLSTACK := mbedtls

#TFSCAL := apple
#TFSCAL := tfs
TFSCAL := mbedtls

CFLAGS += -g
# --analyze

EXELIBS += -framework Security -framework CoreFoundation

BUILD_DIR := build/

include ../common/top.mk
