#ifndef __LINUX_ARP_NETFILTER_H
#define __LINUX_ARP_NETFILTER_H

/* Userspace specific header file since 2.4 only has 2 chains */

/* ARP-specific defines for netfilter.
 * (C)2002 Rusty Russell IBM -- This code is GPL.
 */

#include <linux/config.h>
#include <linux/netfilter.h>

/* There is no PF_ARP. */
#define NF_ARP		0

/* ARP Hooks */
#define NF_ARP_IN	0
#define NF_ARP_OUT	1
#ifndef KERNEL_2_4
#define NF_ARP_FORWARD	2
#define NF_ARP_NUMHOOKS	3
#else
#define NF_ARP_NUMHOOKS	2
#endif

#endif /* __LINUX_ARP_NETFILTER_H */
