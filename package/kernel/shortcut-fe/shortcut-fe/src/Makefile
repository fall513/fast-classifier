#
# Makefile for Shortcut FE.
#

obj-m += shortcut-fe.o

ifeq ($(SFE_SUPPORT_IPV6),y)
SFE_SUPPORT_IPV6=y
ccflags-$(SFE_SUPPORT_IPV6) += -DSFE_SUPPORT_IPV6
endif

ifeq ($(SFE_SUPPORT_CM),y)
SFE_SUPPORT_CM=y
ccflags-$(SFE_SUPPORT_CM) += -DSFE_SUPPORT_CM
endif

ifdef SFE_SUPPORT_IPV6
obj-m += shortcut-fe-ipv6.o
endif

ifdef SFE_SUPPORT_CM
obj-m += shortcut-fe-cm.o
endif

shortcut-fe-objs := \
	sfe_ipv4.o

ifdef SFE_SUPPORT_IPV6
shortcut-fe-ipv6-objs := \
	sfe_ipv6.o
endif

ifdef SFE_SUPPORT_CM
shortcut-fe-cm-objs := \
	sfe_cm.o
endif

