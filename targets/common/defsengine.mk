
##############################################
# Source files

DEFSENGINE_HEADERS := \
	src/defsengine/tf_defs.h

DEFSENGINE_DEP := \
	src/defsengine/tf_defs.h 

DEFSENGINE_SRC := \
	src/defsengine/engine.c

DEFSENGINE_INCS := \
	-Isrc/defsengine/
	
DEFSENGINE_DEFS := 


################################################
# Add to global build target

HEADERS += $(DEFSENGINE_HEADERS)
DEFS += $(DEFSENGINE_DEFS)
DEP += $(DEFSENGINE_DEP)
SRC += $(DEFSENGINE_SRC) 
INCS += $(DEFSENGINE_INCS)


##################################################
# RECIPES

defsengine_tools: $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/tools/
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/tools/defsdump -I$(BUILD_DIR)/include/ \
                test/defsengine/main.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a 

defsengine_tests: $(LIBNOM)_$(ARCH).a 
	@mkdir -p $(BUILD_DIR)/test/

defsengine_runtests: defsengine_tests
	@echo '-- DEFSENGINE TESTS -----------------------------'
