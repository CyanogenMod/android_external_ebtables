/*
 *  ebt_pkttype
 *
 *	Authors:
 *	Bart De Schuymer <bdschuym@pandora.be>
 *
 *  April, 2003
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_pkttype.h>
#include <linux/module.h>

static int ebt_filter_pkttype(const struct sk_buff *skb,
   const struct net_device *in,
   const struct net_device *out,
   const void *data,
   unsigned int datalen)
{
	struct ebt_pkttype_info *info = (struct ebt_pkttype_info *)data;

	return (skb->pkt_type != info->pkt_type) ^ info->invert;
}

static struct ebt_match filter_pkttype;
static int ebt_pkttype_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen,
   unsigned int version)
{
	struct ebt_pkttype_info *info = (struct ebt_pkttype_info *)data;

	if (datalen != sizeof(struct ebt_pkttype_info))
		return -EINVAL;
	if (ebt_check_version(version, filter_pkttype.version,
			      filter_pkttype.name))
		return -EINVAL;
	if (info->invert != 0 && info->invert != 1)
		return -EINVAL;
	/* Allow any pkt_type value */
	return 0;
}

static struct ebt_match filter_pkttype =
{
	.name		= EBT_PKTTYPE_MATCH,
	.match		= ebt_filter_pkttype,
	.check		= ebt_pkttype_check,
	.me		= THIS_MODULE,
	.version	= VERSIONIZE(1,0),
};

static int __init init(void)
{
	return ebt_register_match(&filter_pkttype);
}

static void __exit fini(void)
{
	ebt_unregister_match(&filter_pkttype);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
