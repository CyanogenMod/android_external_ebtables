#ifndef __LINUX_BRIDGE_EBT_AMONG_H
#define __LINUX_BRIDGE_EBT_AMONG_H

#define EBT_AMONG_DST 0x01
#define EBT_AMONG_SRC 0x02

/* Grzegorz Borowiak <grzes@gnu.univ.gda.pl> 2003
 * 
 * Write-once-read-many hash table, used for checking if a given
 * MAC address belongs to a set or not and possibly for checking
 * if it is related with a given IPv4 address.
 *
 * The hash value of an address is its last byte.
 * 
 * In real-world ethernet addresses, values of the last byte are
 * evenly distributed and there is no need to consider other bytes.
 * It would only slow the routines down.
 *
 * For MAC address comparison speedup reasons, we introduce a trick.
 * MAC address is mapped onto an array of two 32-bit integers.
 * This pair of integers is compared with MAC addresses in the
 * hash table, which are stored also in form of pairs of integers
 * (in `cmp' array). This is quick as it requires only two elementary
 * number comparisons in worst case. Further, we take advantage of
 * fact that entropy of 3 last bytes of address is larger than entropy
 * of 3 first bytes. So first we compare 4 last bytes of addresses and
 * if they are the same we compare 2 first.
 *
 * Yes, it is a memory overhead, but in 2003 AD, who cares?
 *
 * `next_ofs' contains a "serialized" pointer to the next tuple in
 * the synonym list. It is a difference between address of the next
 * tuple and address of the entire wormhash structure, in bytes
 * or 0 if there is no next tuple.
 *
 * `table' contains begins of the synonym lists for 
 *
 * This was introduced to make wormhash structure movable. As you may
 * guess, once structure is passed to the kernel, the real pointers
 * would become invalid. Also comparison would not work if they were
 * built of absolute pointers.
 *
 * From the other side, using indices of the `pool' array would be
 * slower. CPU would have to multiply index * size of tuple at each
 * access to a tuple and add this to the address of the beginning
 * of the `pool' array.
 *
 * Summary:
 *
 * The code is damn unreadable and unclear, but - and that's the
 * point - effective.
 */

struct ebt_mac_wormhash_tuple
{
	int next_ofs;
	uint32_t cmp[2];
	uint32_t ip;
};

struct ebt_mac_wormhash
{
	int table[256];
	int poolsize;
	struct ebt_mac_wormhash_tuple pool[0];
};

#define ebt_mac_wormhash_size(x) ((x) ? sizeof(struct ebt_mac_wormhash) + (x)->poolsize * sizeof(struct ebt_mac_wormhash_tuple) : 0)

struct ebt_among_info
{
	int wh_dst_ofs;
	int wh_src_ofs;
	int bitmask;
};

#define EBT_AMONG_DST_NEG 0x1
#define EBT_AMONG_SRC_NEG 0x2

#define ebt_among_wh_dst(x) ((x)->wh_dst_ofs ? (struct ebt_mac_wormhash*)((char*)(x) + (x)->wh_dst_ofs) : NULL)
#define ebt_among_wh_src(x) ((x)->wh_src_ofs ? (struct ebt_mac_wormhash*)((char*)(x) + (x)->wh_src_ofs) : NULL)

#define EBT_AMONG_MATCH "among"

#endif
