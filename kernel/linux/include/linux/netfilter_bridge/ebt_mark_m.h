#ifndef __LINUX_BRIDGE_EBT_MARK_M_H
#define __LINUX_BRIDGE_EBT_MARK_M_H

struct ebt_mark_m_info
{
	unsigned long mark, mask;
	__u8 invert;
};
#define EBT_MARK_MATCH "mark_m"

#endif
