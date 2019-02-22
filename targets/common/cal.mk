

##############################################
# Source files

CAL_HEADERS := \
	src/crypto_cl/tf_cal.h

CAL_DEP := \
	src/crypto_cl/tf_cal.h

CAL_SRC := \
	src/crypto_cl/tcl.$(TFSCAL).c

CAL_INCS := \
	-Isrc/crypto_cl/ 

CAL_DEFS := \
	-DTFCALLL_H=\"tf_cal_ll.$(TFSCAL).h\"


################################################
# Add to global build target

HEADERS += $(CAL_HEADERS)
DEFS += $(CAL_DEFS)
DEP += $(CAL_DEP)
SRC += $(CAL_SRC) 
INCS += $(CAL_INCS)


##################################################
# RECIPES
