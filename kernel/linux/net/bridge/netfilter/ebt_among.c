/*
 *  ebt_among
 *
 *	Authors:
 *	Grzegorz Borowiak <grzes@gnu.univ.gda.pl>
 *
 *  August, 2003
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_among.h>
#include <linux/module.h>

static int ebt_mac_wormhash_contains(const struct ebt_mac_wormhash *wh, const char *mac)
{
	/* You may be puzzled as to how this code works.
	 * Some tricks were used, refer to include/linux/netfilter_bridge/ebt_among.h
	 * as there you can find a solution of this mystery.
	 */
	const struct ebt_mac_wormhash_tuple *p;
	int offset;
	const char *base = (const char*)wh;
	uint32_t cmp[2] = { 0, 0 };
	int key = (const unsigned char)mac[5];
	memcpy(((char*)cmp)+2, mac, 6);
	offset = wh->table[key];
	while (offset) {
		p = (const struct ebt_mac_wormhash_tuple*)(base + offset);
		if (cmp[1] == p->cmp[1] && cmp[0] == p->cmp[0])
			return 1;
		offset = p->next_ofs;
	}
	return 0;
}

static int ebt_mac_wormhash_check_integrity(const struct ebt_mac_wormhash *wh)
{
	int i, count;
	const struct ebt_mac_wormhash_tuple *p;
	int offset;
	const char *base = (const char*)wh;
	
	count = 0;
	for (i=256; i--;) {
		offset = wh->table[i];
		while (offset) {
			p = (const struct ebt_mac_wormhash_tuple*)(base + offset);
			if (p < wh->pool)
				return -1;
			if (p > wh->pool + 256 - 1)
				return -2;
			count++;
			if (count > 1000)
				return -3;
			offset = p->next_ofs;
		}
	}
	return 0;
}

static int ebt_filter_among(const struct sk_buff *skb,
   const struct net_device *in, const struct net_device *out, const void *data,
   unsigned int datalen)
{
	struct ebt_among_info *info = (struct ebt_among_info *) data;

	const char *dmac, *smac;
	if (info->bitmask & EBT_AMONG_SRC) {
		smac = skb->mac.ethernet->h_source;
		if (!ebt_mac_wormhash_contains(&info->wh_src, smac))
			return EBT_NOMATCH;
	}

	if (info->bitmask & EBT_AMONG_DST) {
		dmac = skb->mac.ethernet->h_dest;
		if (!ebt_mac_wormhash_contains(&info->wh_dst, dmac))
			return EBT_NOMATCH;
	}

	return EBT_MATCH;
}

static int ebt_among_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_among_info *info = (struct ebt_among_info *) data;

	if (datalen != EBT_ALIGN(sizeof(struct ebt_among_info))) {
		printk(KERN_WARNING "ebtables: among: wrong size\n");
		return -EINVAL;
	}
	if ((info->bitmask & EBT_AMONG_DST) && ebt_mac_wormhash_check_integrity(&info->wh_dst)) {
		printk(KERN_WARNING "ebtables: among: dst integrity fail\n");
		return -EINVAL;
	}
	if ((info->bitmask & EBT_AMONG_SRC) && ebt_mac_wormhash_check_integrity(&info->wh_src)) {
		printk(KERN_WARNING "ebtables: among: src integrity fail\n");
		return -EINVAL;
	}
	return 0;
}

static struct ebt_match filter_among =
{
	{NULL, NULL}, EBT_AMONG_MATCH, ebt_filter_among, ebt_among_check, NULL,
	THIS_MODULE
};

static int __init init(void)
{
	return ebt_register_match(&filter_among);
}

static void __exit fini(void)
{
	ebt_unregister_match(&filter_among);
}

module_init(init);
module_exit(fini);
EXPORT_NO_SYMBOLS;
MODULE_LICENSE("GPL");
