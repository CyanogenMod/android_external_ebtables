#ifndef __LINUX_BRIDGE_EBT_AMONG_H
#define __LINUX_BRIDGE_EBT_AMONG_H

#define EBT_AMONG_DST 0x01
#define EBT_AMONG_SRC 0x02

/* Write-once-read-many hash table, used for checking if a given
 * MAC address belongs to a set or not. It remembers up to 256
 * addresses.
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
};

struct ebt_mac_wormhash
{
	int table[256];
	struct ebt_mac_wormhash_tuple pool[256];
};

struct ebt_among_info
{
	uint32_t bitmask;
	struct ebt_mac_wormhash wh_dst;
	struct ebt_mac_wormhash wh_src;
};
#define EBT_AMONG_MATCH "among"

#endif
