#
# Makefile for the IEEE 802.1d ethernet bridging layer.
#

ifneq ($(CONFIG_BRIDGE_EBT_BROUTE),n)
ifneq ($(CONFIG_BRIDGE_EBT_BROUTE),)
export-objs := br.o
endif
endif

obj-$(CONFIG_BRIDGE) += bridge.o

bridge-objs	:= br.o br_device.o br_fdb.o br_forward.o br_if.o br_input.o \
			br_ioctl.o br_notify.o br_stp.o br_stp_bpdu.o \
			br_stp_if.o br_stp_timer.o
obj-$(CONFIG_BRIDGE_EBT) += netfilter/

ifneq ($(CONFIG_BRIDGE_NF),n)
ifneq ($(CONFIG_BRIDGE_NF),)
bridge-objs += br_netfilter.o
endif
endif

include $(TOPDIR)/Rules.make
