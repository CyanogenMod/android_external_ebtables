/*
 *  ebt_arp
 *
 *	Authors:
 *	Bart De Schuymer <bart.de.schuymer@pandora.be>
 *	Tim Gardner <timg@tpi.com>
 *
 *  April, 2002
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_arp.h>
#include <linux/if_arp.h>
#include <linux/module.h>

#define FWINV2(bool,invflg) ((bool) ^ !!(infostuff->invflags & invflg))
static int ebt_filter_arp(const struct sk_buff *skb,
	       const struct net_device *in,
	       const struct net_device *out,
	       const void *data,
	       unsigned int datalen, const struct ebt_counter *c)
{
	struct ebt_arp_info *infostuff = (struct ebt_arp_info *)data;

	if (infostuff->bitmask & EBT_ARP_OPCODE && FWINV2(infostuff->opcode !=
	   ((*skb).nh.arph)->ar_op, EBT_ARP_OPCODE))
		return 1;
	if (infostuff->bitmask & EBT_ARP_HTYPE && FWINV2(infostuff->htype !=
	   ((*skb).nh.arph)->ar_hrd, EBT_ARP_HTYPE))
		return 1;
	if (infostuff->bitmask & EBT_ARP_PTYPE && FWINV2(infostuff->ptype !=
	   ((*skb).nh.arph)->ar_pro, EBT_ARP_PTYPE))
		return 1;

	if (infostuff->bitmask & (EBT_ARP_SRC_IP | EBT_ARP_DST_IP))
	{
		__u32 arp_len = sizeof(struct arphdr) +
		   (2*(((*skb).nh.arph)->ar_hln)) +
		   (2*(((*skb).nh.arph)->ar_pln));
		__u32 dst;
		__u32 src;

 		// Make sure the packet is long enough.
		if ((((*skb).nh.raw) + arp_len) > (*skb).tail)
			return 1;
		// IPV4 addresses are always 4 bytes.
		if (((*skb).nh.arph)->ar_pln != sizeof(__u32))
			return 1;

		if (infostuff->bitmask & EBT_ARP_SRC_IP) {
			memcpy(&src, ((*skb).nh.raw) + sizeof(struct arphdr) +
			   ((*skb).nh.arph)->ar_hln, sizeof(__u32));
			if (FWINV2(infostuff->saddr != (src & infostuff->smsk),
			   EBT_ARP_SRC_IP))
				return 1;
		}

		if (infostuff->bitmask & EBT_ARP_DST_IP) {
			memcpy(&dst, ((*skb).nh.raw)+sizeof(struct arphdr) +
			   (2*(((*skb).nh.arph)->ar_hln)) +
			   (((*skb).nh.arph)->ar_pln), sizeof(__u32));
			if (FWINV2(infostuff->daddr != (dst & infostuff->dmsk),
			   EBT_ARP_DST_IP))
				return 1;
		}
	}
	return 0;
}

static int ebt_arp_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_arp_info *infostuff = (struct ebt_arp_info *) data;

	if (datalen != sizeof(struct ebt_arp_info))
		return -EINVAL;
	if (e->bitmask & (EBT_NOPROTO | EBT_802_3) || 
	   (e->ethproto != __constant_htons(ETH_P_ARP) && 
	    e->ethproto != __constant_htons(ETH_P_RARP)) ||
	   e->invflags & EBT_IPROTO)
		return -EINVAL;
	if (infostuff->bitmask & ~EBT_ARP_MASK)
		return -EINVAL;
	return 0;
}

static struct ebt_match filter_arp =
{
	{NULL, NULL}, EBT_ARP_MATCH, ebt_filter_arp, ebt_arp_check, NULL,
	THIS_MODULE
};

static int __init init(void)
{
	return ebt_register_match(&filter_arp);
}

static void __exit fini(void)
{
	ebt_unregister_match(&filter_arp);
}

module_init(init);
module_exit(fini);
EXPORT_NO_SYMBOLS;
MODULE_LICENSE("GPL");
