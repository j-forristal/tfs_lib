

##############################################
# Source files

TLV_HEADERS := \
	src/tlv/tf_tlv.h

TLV_DEP := \
	src/tlv/tf_tlv.h 

TLV_SRC := \
	src/tlv/tf_tlv.c

TLV_INCS := \
	-Isrc/tlv/ \
	
TLV_DEFS := 


################################################
# Add to global build target

HEADERS += $(TLV_HEADERS)
DEFS += $(TLV_DEFS)
DEP += $(TLV_DEP)
SRC += $(TLV_SRC)
INCS += $(TLV_INCS)


##################################################
# RECIPES

tlv_tools: $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/tools/
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/tlv_dump -I$(BUILD_DIR)/include/ \
                tools/tlv/dump.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)

tlv_tests: $(LIBNOM)_$(ARCH).a 
	@mkdir -p $(BUILD_DIR)/test/
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/test/test_tlv -I$(BUILD_DIR)/include/ \
                test/tlv/test_tlv.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a $(EXELIBS)

tlv_runtests: tlv_tests
	@echo '-- TLV TESTS -----------------------------'

