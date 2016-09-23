# BUILD libebtc.so

LOCAL_PATH:= $(call my-dir)

cflags := -O2 -g \
    -DPROGNAME=\"ebtables\" \
    -DPROGVERSION=\"2.0.10\" \
    -DPROGDATE=\"December\ 2011\" \
    -Wno-sign-compare -Wno-missing-field-initializers \
    -Wno-ignored-qualifiers -Wno-unused-parameter \
	-Wno-#pragma-messages

extensions_src_files := \
    extensions/ebt_802_3.c \
    extensions/ebt_among.c \
    extensions/ebt_arp.c \
    extensions/ebt_arpreply.c \
    extensions/ebt_ip.c \
    extensions/ebt_ip6.c \
    extensions/ebt_limit.c \
    extensions/ebt_log.c \
    extensions/ebt_mark.c \
    extensions/ebt_mark_m.c \
    extensions/ebt_nat.c \
    extensions/ebt_nflog.c \
    extensions/ebt_pkttype.c \
    extensions/ebt_redirect.c \
    extensions/ebt_standard.c \
    extensions/ebt_stp.c \
    extensions/ebt_ulog.c \
    extensions/ebt_vlan.c \
    extensions/ebtable_broute.c \
    extensions/ebtable_filter.c \
    extensions/ebtable_nat.c

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    getethertype.c \
    communication.c \
    libebtc.c \
    useful_functions.c \
    ebtables.c \
    $(extensions_src_files) \
    ebtables-standalone.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr

LOCAL_CFLAGS := $(cflags)
LOCAL_LDFLAGS := -nostartfiles
LOCAL_MODULE := ebtables

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)


#######dss_test_104##########
include $(CLEAR_VARS)
LOCAL_MODULE:= ethertypes
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := ethertypes
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
include $(BUILD_PREBUILT)

