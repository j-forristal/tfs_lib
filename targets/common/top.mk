
TFS_LIBC_D := $(BUILD_BASE)/tfs_libc/build/internal/$(TARGET)/

##############################################
# Source files & definitions

TFSLIBC ?= libc
TFSCAL ?= tfs
SSLSTACK ?= mbedtls

# starting/defaults
HEADERS +=
DEFS += -DPLATFORM_H=\"platform.$(TFSLIBC).h\"
DEP +=
SRC +=
INCS += -I$(TFS_LIBC_D)/include/
EXELIBS += $(TFS_LIBC_D)/lib/$(ARCH)/libtfs_libc_$(ARCH).a

CFLAGS += -Wall -fPIC -O3 -fno-exceptions \
        -ffast-math -fno-unwind-tables -fvisibility=hidden \
        -fomit-frame-pointer \
        -fno-asynchronous-unwind-tables

include ../common/sslstack.mk

# module additions

ifeq ($(TARGET),esp8266)
 include ../common/netsec.mk
 include ../common/pkcs7.mk
 include ../common/cal.mk
 include ../common/crypto.mk
else
 include ../common/defsengine.mk
 include ../common/persist.mk
 include ../common/queuefile.mk
 include ../common/tlv.mk
 include ../common/netsec.mk
 include ../common/pkcs7.mk
 include ../common/crypto.mk
 include ../common/cal.mk
endif

CFLAGS += $(DEFS) $(INCS)

OBJ_DIR = $(BUILD_DIR)/obj_$(ARCH)/
OBJ = $(SRC:%.c=$(OBJ_DIR)/%.o)

################################################
# Compiler/cross-compile support

CROSSCOMPILE ?=
CC ?= $(CROSSCOMPILE)gcc
AR ?= $(CROSSCOMPILE)ar
LD ?= $(CROSSCOMPILE)ld
STRIP ?= $(CROSSCOMPILE)strip

SHAREDLIBEXT ?= .so


##################################################
# RECIPES

.PHONY: build clean 

build: $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/include/
	@cp $(HEADERS) $(BUILD_DIR)/include/
	@echo '' >> $(BUILD_DIR)/build.environment
	@echo $(LIBNOM)_$(ARCH) >> $(BUILD_DIR)/build.environment
	@$(CC) $(CFLAGS) --version >> $(BUILD_DIR)/build.environment
	@echo $(CFLAGS) >> $(BUILD_DIR)/build.environment

$(OBJ): $(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	@echo - CC $<
	@$(CC) $(CFLAGS) -c -o $@ $<

$(LIBNOM)_$(ARCH).a: $(OBJ)
	@mkdir -p $(BUILD_DIR)/lib/
	@$(AR) rcs $(BUILD_DIR)/lib/$@ $(OBJ)
	@$(LD) -r $(OBJ) -o $(BUILD_DIR)/lib/$@.o

$(LIBNOM)_$(ARCH).$(SHAREDLIBEXT): $(OBJ)
	@mkdir -p $(BUILD_DIR)/lib/
	@$(CC) -shared -o $(BUILD_DIR)/lib/$@ $(CFLAGS) $(OBJ)
	@$(STRIP) $(BUILD_DIR)/lib/$@
    
clean:
	rm -rf $(BUILD_DIR)/


