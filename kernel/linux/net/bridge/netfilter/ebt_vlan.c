/*
 *  ebt_vlan kernelspace
 *
 *      Authors:
 *      Bart De Schuymer <bart.de.schuymer@pandora.be>
 *      Nick Fedchik <nick@fedchik.org.ua>
 *
 *      June, 2002
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_vlan.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/module.h>

static unsigned char debug;
MODULE_PARM (debug, "0-1b");
MODULE_PARM_DESC (debug, "debug=1 is turn on debug messages");

#define MODULE_VERSION "0.2"

static int ebt_filter_vlan (const struct sk_buff *skb,
			    const struct net_device *in,
			    const struct net_device *out,
			    const void *data,
			    unsigned int datalen,
			    const struct ebt_counter *c)
{
	struct ebt_vlan_info *infostuff = (struct ebt_vlan_info *) data;
	struct vlan_ethhdr *vlanethhdr =
	    (struct vlan_ethhdr *) skb->mac.raw;
	unsigned short v_id;
	unsigned short v_prio;
	unsigned short v_TCI;

	/*
	 * Calculate 802.1Q VLAN ID and user_priority from 
	 * Tag Control Information (TCI) field.
	 * Reserved one bit (13) for CFI (Canonical Format Indicator)
	 */
	v_TCI = ntohs (vlanethhdr->h_vlan_TCI);
	v_id = v_TCI & 0xFFF;
	v_prio = v_TCI >> 13;

	/*
	 * Checking VLANs 
	 */
	if (infostuff->bitmask & EBT_VLAN_ID) {	/* Is VLAN ID parsed? */
		if (!((infostuff->id == v_id)
		      ^ !!(infostuff->invflags & EBT_VLAN_ID)))
			return 1;
		if (debug)
			printk (KERN_DEBUG
				"ebt_vlan: matched ID=%s%d (mask=%X)\n",
				(infostuff->
				 invflags & EBT_VLAN_ID) ? "!" : "",
				infostuff->id, infostuff->bitmask);
	}
	/*
	 * Checking User Priority 
	 */
	if (infostuff->bitmask & EBT_VLAN_PRIO) {	/* Is VLAN Prio parsed? */
		if (!((infostuff->prio == v_prio)
		      ^ !!(infostuff->invflags & EBT_VLAN_PRIO)))
			return 1;	/* missed */
		if (debug)
			printk (KERN_DEBUG
				"ebt_vlan: matched Prio=%s%d (mask=%X)\n",
				(infostuff->
				 invflags & EBT_VLAN_PRIO) ? "!" : "",
				infostuff->prio, infostuff->bitmask);
	}
	/*
	 * Checking for Encapsulated proto
	 */
	if (infostuff->bitmask & EBT_VLAN_ENCAP) {	/* Is VLAN Encap parsed? */
		if (!
		    ((infostuff->encap ==
		      vlanethhdr->h_vlan_encapsulated_proto)
		     ^ !!(infostuff->invflags & EBT_VLAN_ENCAP)))
			return 1;	/* missed */
		if (debug)
			printk (KERN_DEBUG
				"ebt_vlan: matched encap=%s%2.4X (mask=%X)\n",
				(infostuff->
				 invflags & EBT_VLAN_ENCAP) ? "!" : "",
				ntohs (infostuff->encap),
				infostuff->bitmask);
	}

	/*
	 * rule matched 
	 */
	return 0;
}

/*
 * ebt_vlan_check() is called when userspace delivers the table to the kernel, 
 * * it is called to check that userspace doesn't give a bad table.
 */
static int ebt_vlan_check (const char *tablename, unsigned int hookmask,
			   const struct ebt_entry *e, void *data,
			   unsigned int datalen)
{
	struct ebt_vlan_info *infostuff = (struct ebt_vlan_info *) data;

	if (datalen != sizeof (struct ebt_vlan_info))
		return -EINVAL;

	if (e->ethproto != __constant_htons (ETH_P_8021Q))
		return -EINVAL;

	if (infostuff->bitmask & ~EBT_VLAN_MASK) {
		return -EINVAL;
	}

	return 0;
}

static struct ebt_match filter_vlan = {
	{NULL, NULL},
	EBT_VLAN_MATCH,
	ebt_filter_vlan,
	ebt_vlan_check,
	NULL,
	THIS_MODULE
};

static int __init init (void)
{
	printk (KERN_INFO
		"ebt_vlan: 802.1Q VLAN matching module for EBTables "
		MODULE_VERSION "\n");
	if (debug)
		printk (KERN_DEBUG
			"ebt_vlan: 802.1Q rule matching debug is on\n");
	return ebt_register_match (&filter_vlan);
}

static void __exit fini (void)
{
	ebt_unregister_match (&filter_vlan);
}

module_init (init);
module_exit (fini);
EXPORT_NO_SYMBOLS;
MODULE_AUTHOR ("Nick Fedchik <nick@fedchik.org.ua>");
MODULE_DESCRIPTION ("802.1Q VLAN matching module for ebtables, v"
		    MODULE_VERSION);
MODULE_LICENSE ("GPL");
