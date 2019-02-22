

##############################################
# Source files

QF_HEADERS := \
	src/queuefile/tf_qf.h

QF_DEP := \
	src/queuefile/tf_qf.h 

QF_SRC := \
	src/queuefile/queuefile.c

QF_INCS := \
	-Isrc/queuefile/ \
	
QF_DEFS := -DTFQF_INTEGRITY


################################################
# Add to global build target

HEADERS += $(QF_HEADERS)
DEFS += $(QF_DEFS)
DEP += $(QF_DEP)
SRC += $(QF_SRC)
INCS += $(QF_INCS)


##################################################
# RECIPES

queuefile_tools: $(LIBNOM)_$(ARCH).a

queuefile_tests: $(LIBNOM)_$(ARCH).a 
	@mkdir -p $(BUILD_DIR)/test/

queuefile_runtests: queuefile_tests
	@echo '-- QUEUEFILE TESTS -----------------------------'

