/*
 *  ebt_ip
 *
 *	Authors:
 *	Bart De Schuymer <bart.de.schuymer@pandora.be>
 *
 *  April, 2002
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_ip.h>
#include <linux/ip.h>
#include <linux/module.h>

#define FWINV2(bool,invflg) ((bool) ^ !!(infostuff->invflags & invflg))
static int ebt_filter_ip(const struct sk_buff *skb,
	       const struct net_device *in,
	       const struct net_device *out,
	       const void *data,
	       unsigned int datalen, const struct ebt_counter *c)
{
	struct ebt_ip_info *infostuff = (struct ebt_ip_info *) data;

	if (infostuff->bitmask & EBT_IP_TOS &&
	   FWINV2(infostuff->tos != ((*skb).nh.iph)->tos, EBT_IP_TOS))
		return 1;
	if (infostuff->bitmask & EBT_IP_PROTO && FWINV2(infostuff->protocol !=
	   ((*skb).nh.iph)->protocol, EBT_IP_PROTO))
		return 1;
	if (infostuff->bitmask & EBT_IP_SOURCE &&
	   FWINV2((((*skb).nh.iph)->saddr & infostuff->smsk) !=
	   infostuff->saddr, EBT_IP_SOURCE))
		return 1;
	if ((infostuff->bitmask & EBT_IP_DEST) &&
	   FWINV2((((*skb).nh.iph)->daddr & infostuff->dmsk) !=
	   infostuff->daddr, EBT_IP_DEST))
		return 1;
	return 0;
}

static int ebt_ip_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_ip_info *infostuff = (struct ebt_ip_info *) data;

	if (datalen != sizeof(struct ebt_ip_info)) {
		return -EINVAL;
	}
	if (e->bitmask & (EBT_NOPROTO | EBT_802_3) || 
	    e->ethproto != __constant_htons(ETH_P_IP) ||
	    e->invflags & EBT_IPROTO)
	{
		return -EINVAL;
	}
	if (infostuff->bitmask & ~EBT_IP_MASK) {
		return -EINVAL;
	}
	return 0;
}

static struct ebt_match filter_ip =
{
	{NULL, NULL}, EBT_IP_MATCH, ebt_filter_ip, ebt_ip_check, NULL,
	THIS_MODULE
};

static int __init init(void)
{
	return ebt_register_match(&filter_ip);
}

static void __exit fini(void)
{
	ebt_unregister_match(&filter_ip);
}

module_init(init);
module_exit(fini);
EXPORT_NO_SYMBOLS;
MODULE_LICENSE("GPL");
