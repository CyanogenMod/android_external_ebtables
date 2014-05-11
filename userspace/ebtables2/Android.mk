# BUILD libebtc.so

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := getethertype.c
LOCAL_SRC_FILES += communication.c
LOCAL_SRC_FILES += libebtc.c
LOCAL_SRC_FILES += useful_functions.c
LOCAL_SRC_FILES += ebtables.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr

LOCAL_CFLAGS += -DPROGNAME=\"ebtables\" \
        -DPROGVERSION=\"2.0.10\" \
        -DPROGDATE=\"December\ 2011\" \
        -D__THROW=

LOCAL_CFLAGS += -O2 -g -Wno-ignored-qualifiers
LOCAL_CFLAGS += -Wno-sign-compare \
                -Wno-missing-field-initializers \
                -Wno-pointer-arith

LOCAL_MODULE := libebtc

LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)

# sources and intermediate files are separated
include $(CLEAR_VARS)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr

LOCAL_CFLAGS := -O2 -g \
        -DPROGNAME=\"ebtables\" \
        -DPROGVERSION=\"2.0.10\" \
        -DPROGDATE=\"December\ 2011\" \
        -Wno-sign-compare -Wno-missing-field-initializers \
        -Wno-ignored-qualifiers

LOCAL_SRC_FILES := \
	    ebtables-standalone.c \
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

LOCAL_SHARED_LIBRARIES += \
        libebtc \
        libebt_802_3 \
        libebt_among \
        libebt_arp \
        libebt_arpreply \
        libebt_ip \
        libebt_ip6 \
        libebt_limit \
        libebt_log \
        libebt_mark \
        libebt_mark_m \
        libebt_nat \
        libebt_nflog \
        libebt_pkttype \
        libebt_redirect \
        libebt_standard \
        libebt_stp \
        libebt_ulog \
        libebt_vlan \
        libebtable_broute \
        libebtable_filter \
        libebtable_nat

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

