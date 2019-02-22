

##############################################
# Source files

NETSEC_HEADERS := \
	src/netsec/tf_netsec.h

NETSEC_DEP := \
	src/netsec/tf_netsec.h 

NETSEC_SRC := \
	src/netsec/url.c \
	src/netsec/web.$(SSLSTACK).c

ifeq ($(TARGET),esp8266)
 NETSEC_SRC += src/netsec/dns.lwip.c 
else
 NETSEC_SRC += src/netsec/dns.c 
endif

NETSEC_INCS := \
	-Isrc/netsec/ \
	
NETSEC_DEFS := 


################################################
# Add to global build target

HEADERS += $(NETSEC_HEADERS)
DEFS += $(NETSEC_DEFS)
DEP += $(NETSEC_DEP)
SRC += $(NETSEC_SRC)
INCS += $(NETSEC_INCS)


##################################################
# RECIPES

netsec_tools: $(LIBNOM)_$(ARCH).a
	
netsec_tests: $(LIBNOM)_$(ARCH).a 
	@mkdir -p $(BUILD_DIR)/test/
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_web.${SSLSTACK} -I$(BUILD_DIR)/include/ \
		test/netsec/test_web.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_url -I$(BUILD_DIR)/include/ \
		test/netsec/test_url.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/web_requestor.${SSLSTACK} -I$(BUILD_DIR)/include/ \
		test/netsec/web_requestor.c test/test_common.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/msg_poster.${SSLSTACK} -I$(BUILD_DIR)/include/ \
		test/netsec/msg_poster.c test/test_common.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/web_test_harness.${SSLSTACK} -I$(BUILD_DIR)/include/ \
		test/netsec/web_test_harness.c test/test_common.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)

netsec_runtests: netsec_tests
	@echo '-- NETSEC TESTS -----------------------------'

