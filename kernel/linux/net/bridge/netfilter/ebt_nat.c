/*
 *  ebt_nat
 *
 *	Authors:
 *	Bart De Schuymer <bart.de.schuymer@pandora.be>
 *
 *  April, 2002
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_nat.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <net/sock.h>

static __u8 ebt_target_snat(struct sk_buff **pskb, unsigned int hooknr,
   const struct net_device *in, const struct net_device *out,
   const void *data, unsigned int datalen)
{
	struct ebt_nat_info *infostuff = (struct ebt_nat_info *) data;

	memcpy(((**pskb).mac.ethernet)->h_source, infostuff->mac,
	   ETH_ALEN * sizeof(unsigned char));
	return infostuff->target;
}

static __u8 ebt_target_dnat(struct sk_buff **pskb, unsigned int hooknr,
   const struct net_device *in, const struct net_device *out,
   const void *data, unsigned int datalen)
{
	struct ebt_nat_info *infostuff = (struct ebt_nat_info *) data;

	memcpy(((**pskb).mac.ethernet)->h_dest, infostuff->mac,
	   ETH_ALEN * sizeof(unsigned char));
	return infostuff->target;
}

static int ebt_target_snat_check(const char *tablename, unsigned int hooknr,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_nat_info *infostuff = (struct ebt_nat_info *) data;

	if (strcmp(tablename, "nat"))
		return -EINVAL;
	if (datalen != sizeof(struct ebt_nat_info))
		return -EINVAL;
	if (hooknr != NF_BR_POST_ROUTING)
		return -EINVAL;
	if (infostuff->target >= NUM_STANDARD_TARGETS)
		return -EINVAL;
	return 0;
}

static int ebt_target_dnat_check(const char *tablename, unsigned int hooknr,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_nat_info *infostuff = (struct ebt_nat_info *) data;

	if ( (strcmp(tablename, "nat") || 
	   (hooknr != NF_BR_PRE_ROUTING && hooknr != NF_BR_LOCAL_OUT)) &&
	   (strcmp(tablename, "broute") || hooknr != NF_BR_BROUTING) )
		return -EINVAL;
	if (datalen != sizeof(struct ebt_nat_info))
		return -EINVAL;
	if (infostuff->target >= NUM_STANDARD_TARGETS)
		return -EINVAL;
	return 0;
}

static struct ebt_target snat =
{
	{NULL, NULL}, EBT_SNAT_TARGET, ebt_target_snat, ebt_target_snat_check,
	NULL, THIS_MODULE
};

static struct ebt_target dnat =
{
	{NULL, NULL}, EBT_DNAT_TARGET, ebt_target_dnat, ebt_target_dnat_check,
	NULL, THIS_MODULE
};

static int __init init(void)
{
	int ret;
	ret = ebt_register_target(&snat);
	if (ret != 0)
		return ret;
	ret = ebt_register_target(&dnat);
	if (ret == 0)
		return 0;
	ebt_unregister_target(&snat);
	return ret;
}

static void __exit fini(void)
{
	ebt_unregister_target(&snat);
	ebt_unregister_target(&dnat);
}

module_init(init);
module_exit(fini);
EXPORT_NO_SYMBOLS;
MODULE_LICENSE("GPL");
