#ifndef __LINUX_BRIDGE_EBT_IP_H
#define __LINUX_BRIDGE_EBT_IP_H

#define EBT_IP_SOURCE 0x01
#define EBT_IP_DEST 0x02
#define EBT_IP_TOS 0x04
#define EBT_IP_PROTO 0x08
#define EBT_IP_MASK (EBT_IP_SOURCE | EBT_IP_DEST | EBT_IP_TOS | EBT_IP_PROTO)
#define EBT_IP_MATCH "ip"

// the same values are used for the invflags
struct ebt_ip_info
{
	__u32 saddr;
	__u32 daddr;
	__u32 smsk;
	__u32 dmsk;
	__u8  tos;
	__u8  protocol;
	__u8  bitmask;
	__u8  invflags;
};

#endif
