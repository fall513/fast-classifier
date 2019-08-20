obj-m += fast-classifier.o

ifeq ($(SFE_SUPPORT_IPV6),y)
SFE_SUPPORT_IPV6=y
ccflags-$(SFE_SUPPORT_IPV6) += -DSFE_SUPPORT_IPV6 -Wno-format
else
ccflags-$(SFE_SUPPORT_IPV6) += -Wno-format
endif

ccflags-y += -I$(obj)/../shortcut-fe

obj ?= .
