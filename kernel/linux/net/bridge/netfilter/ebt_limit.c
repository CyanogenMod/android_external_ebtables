/*
 *  ebt_limit
 *
 *	Authors:
 *	Tom Marshall <tommy@home.tig-grr.com>
 *
 *	Mostly copied from netfilter's ipt_limit.c
 *
 *  September, 2003
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_limit.h>
#include <linux/module.h>

#include <linux/netdevice.h>
#include <linux/spinlock.h>

/* The algorithm used is the Simple Token Bucket Filter (TBF)
 * see net/sched/sch_tbf.c in the linux source tree
 */

static spinlock_t limit_lock = SPIN_LOCK_UNLOCKED;

/* Rusty: This is my (non-mathematically-inclined) understanding of
   this algorithm.  The `average rate' in jiffies becomes your initial
   amount of credit `credit' and the most credit you can ever have
   `credit_cap'.  The `peak rate' becomes the cost of passing the
   test, `cost'.

   `prev' tracks the last packet hit: you gain one credit per jiffy.
   If you get credit balance more than this, the extra credit is
   discarded.  Every time the match passes, you lose `cost' credits;
   if you don't have that many, the test fails.

   See Alexey's formal explanation in net/sched/sch_tbf.c.

   To avoid underflow, we multiply by 128 (ie. you get 128 credits per
   jiffy).  Hence a cost of 2^32-1, means one pass per 32768 seconds
   at 1024HZ (or one every 9 hours).  A cost of 1 means 12800 passes
   per second at 100HZ.  */

#define CREDITS_PER_JIFFY 128

static int ebt_limit_match(const struct sk_buff *skb, const struct net_device *in,
   const struct net_device *out, const void *data, unsigned int datalen)
{
	struct ebt_limit_info *info = (struct ebt_limit_info *)data;
	unsigned long now = jiffies;

	spin_lock_bh(&limit_lock);
	info->credit += (now - xchg(&info->prev, now)) * CREDITS_PER_JIFFY;
	if (info->credit > info->credit_cap)
		info->credit = info->credit_cap;

	if (info->credit >= info->cost) {
		/* We're not limited. */
		info->credit -= info->cost;
		spin_unlock_bh(&limit_lock);
		return EBT_MATCH;
	}

	spin_unlock_bh(&limit_lock);
	return EBT_NOMATCH;
}

/* Precision saver. */
static u_int32_t
user2credits(u_int32_t user)
{
	/* If multiplying would overflow... */
	if (user > 0xFFFFFFFF / (HZ*CREDITS_PER_JIFFY))
		/* Divide first. */
		return (user / EBT_LIMIT_SCALE) * HZ * CREDITS_PER_JIFFY;

	return (user * HZ * CREDITS_PER_JIFFY) / EBT_LIMIT_SCALE;
}

static int ebt_limit_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
	struct ebt_limit_info *info = (struct ebt_limit_info *)data;

	if (datalen != EBT_ALIGN(sizeof(struct ebt_limit_info)))
		return -EINVAL;

	/* Check for overflow. */
	if (info->burst == 0
	    || user2credits(info->avg * info->burst) < user2credits(info->avg)) {
		printk("Overflow in ebt_limit: %u/%u\n",
			info->avg, info->burst);
		return -EINVAL;
	}

	/* User avg in seconds * EBT_LIMIT_SCALE: convert to jiffies * 128. */
	info->prev = jiffies;
	info->credit = user2credits(info->avg * info->burst);
	info->credit_cap = user2credits(info->avg * info->burst);
	info->cost = user2credits(info->avg);
	return 0;
}

static struct ebt_match ebt_limit_reg =
{
	{NULL, NULL}, EBT_LIMIT_MATCH, ebt_limit_match, ebt_limit_check, NULL,
	THIS_MODULE
};

static int __init init(void)
{
	return ebt_register_match(&ebt_limit_reg);
}

static void __exit fini(void)
{
	ebt_unregister_match(&ebt_limit_reg);
}

module_init(init);
module_exit(fini);
EXPORT_NO_SYMBOLS;
MODULE_LICENSE("GPL");
