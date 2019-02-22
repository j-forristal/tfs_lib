

##############################################
# Source files

PK_HEADERS := \
	src/pkcs7/tf_pkcs7.h

PK_DEP := \
	src/pkcs7/tf_pkcs7.h 

PK_SRC := \
	src/pkcs7/pkcs7.c

PK_INCS := \
	-Isrc/pkcs7/ \
	
PK_DEFS := 


################################################
# Add to global build target

HEADERS += $(PK_HEADERS)
DEFS += $(PK_DEFS)
DEP += $(PK_DEP)
SRC += $(PK_SRC)
INCS += $(PK_INCS)


##################################################
# RECIPES

pkcs7_tools: $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/tools/
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/pkcs7_dump -I$(BUILD_DIR)/include/ \
		test/pkcs7/pkcs7_dump.c test/test_common.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/x509_dump -I$(BUILD_DIR)/include/ \
		test/pkcs7/x509_dump.c test/test_common.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/x509_fuzz -I$(BUILD_DIR)/include/ \
		test/pkcs7/x509_fuzz.c test/test_common.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a

pkcs7_tests: $(LIBNOM)_$(ARCH).a 
	@mkdir -p $(BUILD_DIR)/test/

pkcs7_runtests: pkcs7_tests
	@echo '-- PKCS7 TESTS -----------------------------'

