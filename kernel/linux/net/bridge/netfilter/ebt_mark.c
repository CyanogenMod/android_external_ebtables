/*
 *  ebt_mark_t
 *
 *	Authors:
 *	Bart De Schuymer <bart.de.schuymer@pandora.be>
 *
 *  July, 2002
 *
 */

// The mark target can be used in any chain
// I believe adding a mangle table just for marking is total overkill
// Marking a frame doesn't really change anything in the frame anyway
// The target member of the struct ebt_vlan_info provides the same
// functionality as a separate table

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_mark_t.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <net/sock.h>
#include "../br_private.h"

static int ebt_target_mark(struct sk_buff **pskb, unsigned int hooknr,
   const struct net_device *in, const struct net_device *out,
   const void *data, unsigned int datalen)
{
	struct ebt_mark_t_info *infostuff = (struct ebt_mark_t_info *) data;

	if ((*pskb)->nfmark != infostuff->mark) {
		(*pskb)->nfmark = infostuff->mark;
		(*pskb)->nfcache |= NFC_ALTERED;
	}
	return infostuff->target;
}

static int ebt_target_mark_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_mark_t_info *infostuff = (struct ebt_mark_t_info *) data;

	if ((hookmask & (1 << NF_BR_NUMHOOKS)) &&
	   infostuff->target == EBT_RETURN)
		return -EINVAL;
	hookmask &= ~(1 << NF_BR_NUMHOOKS);
	if (datalen != sizeof(struct ebt_mark_t_info))
		return -EINVAL;
	if (infostuff->target < -NUM_STANDARD_TARGETS || infostuff->target >= 0)
		return -EINVAL;
	return 0;
}

static struct ebt_target mark_target =
{
	{NULL, NULL}, EBT_MARK_TARGET, ebt_target_mark,
	ebt_target_mark_check, NULL, THIS_MODULE
};

static int __init init(void)
{
	return ebt_register_target(&mark_target);
}

static void __exit fini(void)
{
	ebt_unregister_target(&mark_target);
}

module_init(init);
module_exit(fini);
EXPORT_NO_SYMBOLS;
MODULE_LICENSE("GPL");
