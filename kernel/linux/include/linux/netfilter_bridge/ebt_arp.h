#ifndef __LINUX_BRIDGE_EBT_ARP_H
#define __LINUX_BRIDGE_EBT_ARP_H

#define EBT_ARP_OPCODE 0x01
#define EBT_ARP_HTYPE 0x02
#define EBT_ARP_PTYPE 0x04
#define EBT_ARP_SRC_IP 0x08
#define EBT_ARP_DST_IP 0x10
#define EBT_ARP_MASK (EBT_ARP_OPCODE | EBT_ARP_HTYPE | EBT_ARP_PTYPE | \
   EBT_ARP_SRC_IP | EBT_ARP_DST_IP)
#define EBT_ARP_MATCH "arp"

struct ebt_arp_info
{
	__u16 htype;
	__u16 ptype;
	__u16 opcode;
	__u32 saddr;
	__u32 smsk;
	__u32 daddr;
	__u32 dmsk;
	__u8  bitmask;
	__u8  invflags;
};

#endif
