#ifndef __LINUX_BRIDGE_EBT_REDIRECT_H
#define __LINUX_BRIDGE_EBT_REDIRECT_H

struct ebt_redirect_info
{
	// EBT_ACCEPT, EBT_DROP or EBT_CONTINUE
	__u8 target;
};
#define EBT_REDIRECT_TARGET "redirect"

#endif
