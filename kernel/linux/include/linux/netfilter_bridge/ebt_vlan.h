#ifndef __LINUX_BRIDGE_EBT_VLAN_H
#define __LINUX_BRIDGE_EBT_VLAN_H

#define EBT_VLAN_ID	0x01
#define EBT_VLAN_PRIO	0x02
#define EBT_VLAN_MASK (EBT_VLAN_ID | EBT_VLAN_PRIO)
#define EBT_VLAN_MATCH "vlan"

struct ebt_vlan_info {
	__u16 id;		/* VLAN ID {1-4095} */
	__u16 prio;		/* VLAN Priority {0-7} */
	__u8 bitmask;		/* Args bitmask bit 1=1 - ID arg, 
				   bit 2=1 - Pirority arg */
	__u8 invflags;		/* Inverse bitmask  bit 1=1 - inversed ID arg, 
				   bit 2=1 - inversed Pirority arg */
};

#endif
