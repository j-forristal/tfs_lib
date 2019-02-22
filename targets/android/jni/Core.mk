
TARGET := android
TFS_LIBC_D := $(BUILD_BASE)/tfs_libc/build/internal/$(TARGET)/

ID := $(LOCAL_PATH)/

MSRC :=
MINCS :=
MDEP :=
MDEFS := -D_FILE_OFFSET_BITS=64 -DMBEDTLS_IS_PATCHED
MHEADERS :=

MCFLAGS += -Wall -Werror -fPIC -O3 -fno-exceptions \
	-ffast-math -fno-unwind-tables -fvisibility=hidden \
	-fomit-frame-pointer -finline-limit=64 \
	-fno-asynchronous-unwind-tables

#TFSCAL ?= mbedtls
TFSCAL ?= tfs
TFSLIBC ?= libc
#SSLSTACK ?= mbedtls
SSLSTACK ?= tfs

###############################################
# TFS Libc

MDEFS += -DPLATFORM_H=\"platform.$(TFSLIBC).h\"
MINCS += -I$(TFS_LIBC_D)/include/


###############################################
# SSL Stack (sslstack.mk)

ifeq ($(SSLSTACK),mbedtls)
  TFS_MBED_D := $(BUILD_BASE)/tfs_mbedtls/build/internal/$(TARGET)/
  MINCS += -I$(TFS_MBED_D)/include/
endif

ifeq ($(SSLSTACK),boringssl)
  TFS_BSSL_D := $(BUILD_BASE)/boringssl/
  MINCS += -I$(TFS_BSSL_D)/include/
endif

ifeq ($(SSLSTACK),tfs)
  MSRC += \
	src/tls/aes.c \
	src/tls/asn1.c \
	src/tls/bigint.c \
	src/tls/crypto_misc.c \
	src/tls/hmac.c \
	src/tls/rsa.c \
	src/tls/tls1.c \
	src/tls/tls1_clnt.c \
	src/tls/x509.c
  MINCS += \
        -I$(ID)src/tls/ 
endif


###############################################
# Crypto (crypto.mk)

MHEADERS += \
        src/crypto/tf_crypto.h

MDEP += \
        src/crypto/tf_crypto.h \
        src/crypto/rotate_bits.h

MSRC += \
        src/crypto/crc32.c \
        src/crypto/utils.c \
        src/crypto/base64.c \
        src/crypto/sha256_hmac.c \
	src/crypto/ecc.c \
	src/crypto/uecc/uECC.c

#	src/crypto/ed25519.c \
#	src/crypto/ed25519v2/ed25519impl.c \

# only compile our crypto if we are using the TF CAL
ifeq ($(TFSCAL),tfs)
 MSRC += \
        src/crypto/md5.c \
        src/crypto/sha1.c \
        src/crypto/sha256.c \
        src/crypto/sha512.c \
        src/crypto/aes128.c \
        src/crypto/chacha20.c \
        src/crypto/random.urandom.c 
endif


MINCS += \
        -I$(ID)src/crypto/ \
	-I$(ID)src/crypto/uecc/
#        -I$(ID)src/crypto/ed25519v2/

MDEFS += \
        -DTFC_INCLUDE_AESKDF


	
###############################################
# Defs Engine (defsengine.mk)

MHEADERS += \
        src/defsengine/tf_defs.h

MDEP += \
        src/defsengine/tf_defs.h

MSRC += \
        src/defsengine/engine.c

MINCS += \
        -I$(ID)src/defsengine/


###############################################
# NetSec (netsec.mk)

MHEADERS += \
        src/netsec/tf_netsec.h

MDEP += \
        src/netsec/tf_netsec.h

MSRC += \
        src/netsec/url.c \
        src/netsec/dns.c \
        src/netsec/web.$(SSLSTACK).c

MINCS += \
        -I$(ID)src/netsec/ 

###############################################
# Persist (persist.mk)

MHEADERS += \
        src/persist/tf_persist.h

MDEP += \
        src/persist/tf_persist.h

MSRC += \
        src/persist/persist.$(TARGET).c

MINCS += \
        -I$(ID)src/persist/


###############################################
# QueueFile (queuefile.mk)

#MHEADERS += \
#        src/queuefile/tf_qf.h
#
#MDEP += \
#        src/queuefile/tf_qf.h
#
#MSRC += \
#        src/queuefile/queuefile.c
#
#MINCS += \
#        -I$(ID)src/queuefile/ \
#
#MDEFS += -DTFQF_INTEGRITY


###############################################
# Pkcs7 (pkcs7.mk)

MHEADERS += \
        src/pkcs7/tf_pkcs7.h

MDEP += \
        src/pkcs7/tf_pkcs7.h

MSRC += \
        src/pkcs7/pkcs7.c

MINCS += \
        -I$(ID)src/pkcs7/


###############################################
# linux (N/A)

MHEADERS += \
        src/linux/tf_linux.h

MDEP += \
        src/linux/tf_linux.h

MSRC += \
        src/linux/linux_maps.c \
        src/linux/linux_ps.c \

MINCS += \
        -I$(ID)src/linux/


###############################################
# cal (N/A)


MDEFS += \
	-DTFCALLL_H=\"tf_cal_ll.$(TFSCAL).h\"

MHEADERS += \
        src/crypto_cl/tf_cal.h

MDEP += \
        src/crypto_cl/tf_cal.h

MSRC += \
	src/crypto_cl/tcl.$(TFSCAL).c

MINCS += \
        -I$(ID)src/crypto_cl/



###############################################
# tlv (tlv.mk)

MHEADERS += \
	src/tlv/tf_tlv.h

MDEP += \
	src/tlv/tf_tlv.h

MSRC += \
	src/tlv/tf_tlv.c

MINCS += \
	-I$(ID)src/tlv/


