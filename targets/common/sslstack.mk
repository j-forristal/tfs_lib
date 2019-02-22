
SSLSTACK ?= mbedtls

ifeq ($(SSLSTACK),mbedtls)
	TFS_MBED_D := $(BUILD_BASE)/tfs_mbedtls/build/internal/$(TARGET)/
	EXELIBS += $(TFS_MBED_D)/lib/$(ARCH)/libmbedtls_$(ARCH).a
	INCS += -I$(TFS_MBED_D)/include/
	DEFS += -DMBEDTLS_IS_PATCHED
endif

ifeq ($(SSLSTACK),mbedtls2)
	TFS_MBED_D := $(BUILD_BASE)/tfs_mbedtls/build/internal/$(TARGET)/
	EXELIBS += $(TFS_MBED_D)/lib/$(ARCH)/libmbedtls_$(ARCH).a
	INCS += -I$(TFS_MBED_D)/include/
endif

ifeq ($(SSLSTACK),tfs)
	include ../common/tls.mk
endif

ifeq ($(SSLSTACK),boringssl)
	TFS_BSSL_D := $(BUILD_BASE)/boringssl/build/$(TARGET)/
	EXELIBS += $(TFS_BSSL_D)/libssl.a $(TFS_BSSL_D)/libcrypto.a
	INCS += -I$(BUILD_BASE)/boringssl/include/
endif


ifeq ($(SSLSTACK),openssl)
endif

ifeq ($(SSLSTACK),apple)
endif

ifeq ($(SSLSTACK),esp8266)
endif
