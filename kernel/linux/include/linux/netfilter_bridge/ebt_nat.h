#ifndef __LINUX_BRIDGE_EBT_NAT_H
#define __LINUX_BRIDGE_EBT_NAT_H

struct ebt_nat_info
{
	unsigned char mac[ETH_ALEN];
	// EBT_ACCEPT, EBT_DROP or EBT_CONTINUE
	__u8 target;
};
#define EBT_SNAT_TARGET "snat"
#define EBT_DNAT_TARGET "dnat"

#endif
