
##############################################
# Source files

CRYPTO_HEADERS := \
	src/crypto/tf_crypto.h

CRYPTO_DEP := \
	src/crypto/tf_crypto.h \
	src/crypto/rotate_bits.h

CRYPTO_SRC := \
	src/crypto/crc32.c \
	src/crypto/base64.c \
	src/crypto/utils.c \
	src/crypto/sha256_hmac.c \
	src/crypto/ecc.c \
	src/crypto/uecc/uECC.c
#	src/crypto/ed25519.c \
#	src/crypto/ed25519v2/ed25519impl.c \

ifeq ($(TARGET),esp8266)
  # override it to just crc
  CRYPTO_SRC := \
	src/crypto/crc32.c 
endif

# only compile our crypto if we are using the TF CAL
ifeq ($(TFSCAL),tfs)
  CRYPTO_SRC += \
	src/crypto/md5.c \
	src/crypto/sha1.c \
	src/crypto/sha256.c \
	src/crypto/sha512.c \
	src/crypto/aes128.c \
	src/crypto/chacha20.c \
	src/crypto/random.urandom.c 
endif

CRYPTO_INCS := \
	-Isrc/crypto/ \
	-Isrc/crypto/uecc/ 
#	-Isrc/crypto/ed25519v2/

CRYPTO_DEFS := \
	-DTFC_INCLUDE_AESKDF



################################################
# Add to global build target

HEADERS += $(CRYPTO_HEADERS)
DEFS += $(CRYPTO_DEFS)
DEP += $(CRYPTO_DEP)
SRC += $(CRYPTO_SRC) 
DIS := $(ED25519_SRC)
INCS += $(CRYPTO_INCS)


################################################
# Tests
CRYPTO_TESTS := \
	test/crypto/test_aes128_ecb.c \
	test/crypto/test_aes128_cbc.c \
	test/crypto/test_sha1.c \
	test/crypto/test_sha256.c \
	test/crypto/test_sha512.c \
	test/crypto/test_chacha20.c \
	test/crypto/test_random.c \

CRYPTO_DISABLED := \
	test/test_ecc.c \
	test/test_ecc_gen.c \
	test/test_ecc_size.c \
	test/test_ecc_perf.c 

##################################################
# RECIPES

$(CRYPTO_TESTS_BASIC): $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/test/
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$(basename $@) -I$(BUILD_DIR)/include/ \
		$@ test/crypto/test_common.c $(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a

crypto_tools: $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/tools/
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_dual_sign -I$(BUILD_DIR)/include/ \
		test/crypto/tool_dual_sign.c test/crypto/test_common.c \
		$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_ecc_sign_aslib -I$(BUILD_DIR)/include/ \
		test/crypto/tool_ecc_sign_aslib.c test/crypto/test_common.c \
		$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_dual_verify -I$(BUILD_DIR)/include/ \
		test/crypto/tool_dual_verify.c test/crypto/test_common.c \
		$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a

disabled:
	#@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_ed25519_genkey -I$(BUILD_DIR)/include/ \
	#	test/crypto/tool_ed25519_genkey.c test/crypto/test_common.c \
	#	$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_ed25519_sign_as -I$(BUILD_DIR)/include/ \
	#	test/crypto/tool_ed25519_sign_as.c test/crypto/test_common.c \
	#	$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_ed25519_sign_aslib -I$(BUILD_DIR)/include/ \
	#	test/crypto/tool_ed25519_sign_aslib.c test/crypto/test_common.c \
	#	$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tool_ed25519_verify_as -I$(BUILD_DIR)/include/ \
	#	test/crypto/tool_ed25519_verify_as.c test/crypto/test_common.c \
	#	$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_rsa_verify -I$(BUILD_DIR)/include/ \
	#	test/crypto/test_rsa_verify.c $(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_ecc -I$(BUILD_DIR)/include/ \
	#	test/crypto/test_ecc.c $(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a

crypto_tests: $(LIBNOM)_$(ARCH).a $(CRYPTO_TESTS_BASIC) 
	@mkdir -p $(BUILD_DIR)/test/
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_ed25519 -I$(BUILD_DIR)/include/ \
		test/crypto/test_ed25519.c test/crypto/test_common.c \
		$(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_ed25519_perf -I$(BUILD_DIR)/include/ \
	#	test/crypto/test_ed25519_perf.c test/crypto/test_common.c \
	#	$(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	#$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_ed25519_size -I$(BUILD_DIR)/include/ \
	#	test/crypto/test_ed25519_size.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_perf -I$(BUILD_DIR)/include/ \
		test/crypto/test_perf.c $(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a -lcrypto
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_sha512 -I$(BUILD_DIR)/include/ \
		test/crypto/test_sha512.c test/crypto/test_common.c $(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_hash_comp -I$(BUILD_DIR)/include/ \
		test/crypto/test_hash_comp.c test/crypto/test_common.c $(EXELIBS) $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a -lcrypto
	#@$(STRIP) $(BUILD_DIR)/test/*

crypto_runtests: crypto_tests
	@echo '-- TESTS -----------------------------'
	#perl test/crypto/run_test_chacha20.pl $(BUILD_DIR)/test/test_chacha20 test/crypto/vectors_chacha20.txt
	#perl test/crypto/run_test_aes128_ecb.pl $(BUILD_DIR)/test/test_aes128_ecb test/crypto/vectors_aes128_ecb.txt
	#perl test/crypto/run_test_aes128_cbc.pl $(BUILD_DIR)/test/test_aes128_cbc test/crypto/vectors_aes128_cbc.txt
	#perl test/crypto/run_test_sha.pl $(BUILD_DIR)/test/test_sha1 test/crypto/vectors_sha1.txt
	#perl test/crypto/run_test_sha.pl $(BUILD_DIR)/test/test_sha256 test/crypto/vectors_sha256.txt
	perl test/crypto/run_test_sha.pl $(BUILD_DIR)/test/test_sha512 test/crypto/vectors_sha512.txt
	#$(BUILD_DIR)/test/test_random

