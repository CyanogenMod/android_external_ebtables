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
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/module.h>

#define DEBUG

static int ebt_mac_wormhash_contains(const struct ebt_mac_wormhash *wh, const char *mac, uint32_t ip)
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
	if (ip) {
		while (offset) {
			p = (const struct ebt_mac_wormhash_tuple*)(base + offset);
			if (cmp[1] == p->cmp[1] && cmp[0] == p->cmp[0]) {
				if (p->ip == 0 || p->ip == ip) {
					return 1;
				}
			}
			offset = p->next_ofs;
		}
	}
	else {
		while (offset) {
			p = (const struct ebt_mac_wormhash_tuple*)(base + offset);
			if (cmp[1] == p->cmp[1] && cmp[0] == p->cmp[0]) {
				return 1;
			}
			offset = p->next_ofs;
		}
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
			if (p < wh->pool) {
				printk(KERN_WARNING "ebtables: among: integrity: offset too low; 0x%08x\n", offset);
				return -1;
			}
			if (p > wh->pool + wh->poolsize - 1) {
				printk(KERN_WARNING "ebtables: among: integrity: offset too high; 0x%08x\n", offset);
				return -2;
			}
			count++;
			if (count > 1000) {
				printk(KERN_WARNING "ebtables: among: integrity: loop at %d\n", i);
				return -3;
			}
			offset = p->next_ofs;
		}
	}
	return 0;
}

static int get_ip_dst(const struct sk_buff *skb, uint32_t *addr)
{
	if (skb->mac.ethernet->h_proto == __constant_htons(ETH_P_IP)) {
		*addr = skb->nh.iph->daddr;
		return 1;
	}
	if (skb->mac.ethernet->h_proto == __constant_htons(ETH_P_ARP)) {

		uint32_t arp_len = sizeof(struct arphdr) +
		   (2 * (((*skb).nh.arph)->ar_hln)) +
		   (2 * (((*skb).nh.arph)->ar_pln));

		// Make sure the packet is long enough.
		if ((((*skb).nh.raw) + arp_len) > (*skb).tail)
			return 0;
		// IPv4 addresses are always 4 bytes.
		if (((*skb).nh.arph)->ar_pln != sizeof(uint32_t))
			return 0;

		memcpy(addr, ((*skb).nh.raw) + sizeof(struct arphdr) +
		   (2*(((*skb).nh.arph)->ar_hln)) +
		   (((*skb).nh.arph)->ar_pln), sizeof(uint32_t));
		
		return 2;
	}
	return 0;
}

static int get_ip_src(const struct sk_buff *skb, uint32_t *addr)
{
	if (skb->mac.ethernet->h_proto == __constant_htons(ETH_P_IP)) {
		*addr = skb->nh.iph->saddr;
		return 1;
	}
	if (skb->mac.ethernet->h_proto == __constant_htons(ETH_P_ARP)) {

		uint32_t arp_len = sizeof(struct arphdr) +
		   (2 * (((*skb).nh.arph)->ar_hln)) +
		   (2 * (((*skb).nh.arph)->ar_pln));

		// Make sure the packet is long enough.
		if ((((*skb).nh.raw) + arp_len) > (*skb).tail)
			return 0;
		// IPv4 addresses are always 4 bytes.
		if (((*skb).nh.arph)->ar_pln != sizeof(uint32_t))
			return 0;

		memcpy(addr, ((*skb).nh.raw) + sizeof(struct arphdr) +
		   ((((*skb).nh.arph)->ar_hln)), sizeof(uint32_t));
		
		return 2;
	}
	return 0;
}

static int ebt_filter_among(const struct sk_buff *skb,
   const struct net_device *in, const struct net_device *out, const void *data,
   unsigned int datalen)
{
	struct ebt_among_info *info = (struct ebt_among_info *) data;
	const char *dmac, *smac;
	const struct ebt_mac_wormhash *wh_dst, *wh_src;
	uint32_t dip=0, sip=0;

	wh_dst = ebt_among_wh_dst(info);
	wh_src = ebt_among_wh_src(info);
	
	if (wh_src) {
		smac = skb->mac.ethernet->h_source;
		get_ip_src(skb, &sip);
		if (!(info->bitmask & EBT_AMONG_SRC_NEG)) {
			/* we match only if it contains */
			if (!ebt_mac_wormhash_contains(wh_src, smac, sip)) {
				return EBT_NOMATCH;
			}
		}
		else {
			/* we match only if it DOES NOT contain */
			if (ebt_mac_wormhash_contains(wh_src, smac, sip)) {
				return EBT_NOMATCH;
			}
		}
	}

	if (wh_dst) {
		dmac = skb->mac.ethernet->h_dest;
		get_ip_dst(skb, &dip);
		if (!(info->bitmask & EBT_AMONG_DST_NEG)) {
			/* we match only if it contains */
			if (!ebt_mac_wormhash_contains(wh_dst, dmac, dip)) {
				return EBT_NOMATCH;
			}
		}
		else {
			/* we match only if it DOES NOT contain */
			if (ebt_mac_wormhash_contains(wh_dst, dmac, dip)) {
				return EBT_NOMATCH;
			}
		}
	}

	return EBT_MATCH;
}

static int ebt_among_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_among_info *info = (struct ebt_among_info *) data;
	int expected_length = sizeof(struct ebt_among_info);
	const struct ebt_mac_wormhash *wh_dst, *wh_src;
	wh_dst = ebt_among_wh_dst(info);
	wh_src = ebt_among_wh_src(info);
	expected_length += ebt_mac_wormhash_size(wh_dst);
	expected_length += ebt_mac_wormhash_size(wh_src);

	if (datalen < EBT_ALIGN(expected_length)) {
		printk(KERN_WARNING "ebtables: among: wrong size: %d against expected %d, rounded to %d\n", datalen, expected_length, EBT_ALIGN(expected_length));
		return -EINVAL;
	}
	if (wh_dst && ebt_mac_wormhash_check_integrity(wh_dst)) {
		printk(KERN_WARNING "ebtables: among: dst integrity fail\n");
		return -EINVAL;
	}
	if (wh_src && ebt_mac_wormhash_check_integrity(wh_src)) {
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
