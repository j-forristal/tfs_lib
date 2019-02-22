

##############################################
# Source files

PERSIST_HEADERS := \
	src/persist/tf_persist.h

PERSIST_DEP := \
	src/persist/tf_persist.h 

PERSIST_SRC := \
	src/persist/persist.$(TARGET).c

PERSIST_INCS := \
	-Isrc/persist/ \
	
PERSIST_DEFS := 


################################################
# Add to global build target

HEADERS += $(PERSIST_HEADERS)
DEFS += $(PERSIST_DEFS)
DEP += $(PERSIST_DEP)
SRC += $(PERSIST_SRC)
INCS += $(PERSIST_INCS)


##################################################
# RECIPES

persist_tools: $(LIBNOM)_$(ARCH).a

persist_tests: $(LIBNOM)_$(ARCH).a 
	@mkdir -p $(BUILD_DIR)/test/

persist_runtests: persist_tests
	@echo '-- PERSIST TESTS -----------------------------'

