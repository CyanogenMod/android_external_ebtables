/*
 *  ebtables
 *
 *  Author:
 *  Bart De Schuymer		<bart.de.schuymer@pandora.be>
 *
 *  ebtables.c,v 2.0, April, 2002
 *
 *  This code is stongly inspired on the iptables code which is
 *  Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

// used for print_string
#include <linux/sched.h>
#include <linux/tty.h>

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <linux/smp.h>
#include <net/sock.h>
// needed for logical [in,out]-dev filtering
#include "../br_private.h"

// list_named_find
#define ASSERT_READ_LOCK(x)
#define ASSERT_WRITE_LOCK(x)
#include <linux/netfilter_ipv4/listhelp.h>

#if 0 // use this for remote debugging
#define BUGPRINT(args) print_string(args);
#else
#define BUGPRINT(format, args...) printk("kernel msg: ebtables bug: please "\
                                         "report to author: "format, ## args)
// #define BUGPRINT(format, args...)
#endif
#define MEMPRINT(format, args...) printk("kernel msg: ebtables "\
                                         ": out of memory: "format, ## args)
// #define MEMPRINT(format, args...)

static void print_string(char *str);

static DECLARE_MUTEX(ebt_mutex);
static LIST_HEAD(ebt_tables);
static LIST_HEAD(ebt_targets);
static LIST_HEAD(ebt_matches);
static LIST_HEAD(ebt_watchers);

static struct ebt_target ebt_standard_target =
{ {NULL, NULL}, EBT_STANDARD_TARGET, NULL, NULL, NULL, NULL};

static inline int ebt_do_watcher (struct ebt_entry_watcher *w,
	    const struct sk_buff *skb,
	    const struct net_device *in,
	    const struct net_device *out,
	    const struct ebt_counter *c)
{
	w->u.watcher->watcher(skb, in, out, w->data,
	   w->watcher_size, c);
	// watchers don't give a verdict
	return 0;
}

static inline int ebt_do_match (struct ebt_entry_match *m,
	    const struct sk_buff *skb,
	    const struct net_device *in,
	    const struct net_device *out,
	    const struct ebt_counter *c)
{
	return m->u.match->match(skb, in, out, m->data,
	   m->match_size, c);
}

static inline int ebt_dev_check(char *entry, const struct net_device *device)
{
	if (*entry == '\0')
		return 0;
	if (!device)
		return 1;
	return strncmp(entry, device->name, IFNAMSIZ);
}	

// Do some firewalling
unsigned int ebt_do_table (unsigned int hook, struct sk_buff **pskb,
   const struct net_device *in, const struct net_device *out,
   struct ebt_table *table)
{
	int i, nentries;
	struct ebt_entry *point;
	struct ebt_counter *counter_base;
	struct ebt_entry_target *t;
	__u8 verdict;

	read_lock_bh(&table->lock);
	nentries = table->private->hook_entry[hook]->nentries;
	point = (struct ebt_entry *)(table->private->hook_entry[hook]->data);
	counter_base = table->private->counters +
	   cpu_number_map(smp_processor_id()) * table->private->nentries +
	   table->private->counter_entry[hook];
	#define FWINV(bool,invflg) ((bool) ^ !!(point->invflags & invflg))
 	for (i = 0; i < nentries; i++) {
		if ( ( point->bitmask & EBT_NOPROTO ||
		   FWINV(point->ethproto == ((**pskb).mac.ethernet)->h_proto,
		      EBT_IPROTO)
		   || FWINV(ntohs(((**pskb).mac.ethernet)->h_proto) < 1536 &&
		      (point->bitmask & EBT_802_3), EBT_IPROTO) )
		   && FWINV(!ebt_dev_check((char *)(point->in), in), EBT_IIN)
		   && FWINV(!ebt_dev_check((char *)(point->out), out), EBT_IOUT)
		   && ((!in || !in->br_port) ? 1 : FWINV(!ebt_dev_check((char *)
		      (point->logical_in), &in->br_port->br->dev), EBT_ILOGICALIN))
		   && ((!out || !out->br_port) ? 1 :
		       FWINV(!ebt_dev_check((char *)
		      (point->logical_out), &out->br_port->br->dev), EBT_ILOGICALOUT))

		) {
			char hlpmac[6];
			int j;

			if (point->bitmask & EBT_SOURCEMAC) {
				for (j = 0; j < 6; j++)
					hlpmac[j] = ((**pskb).mac.ethernet)->
					   h_source[j] & point->sourcemsk[j];
				if (FWINV(!!memcmp(point->sourcemac, hlpmac,
				   ETH_ALEN), EBT_ISOURCE) )
					goto letscontinue;
			}

			if (point->bitmask & EBT_DESTMAC) {
				for (j = 0; j < 6; j++)
					hlpmac[j] = ((**pskb).mac.ethernet)->
					   h_dest[j] & point->destmsk[j];
				if (FWINV(!!memcmp(point->destmac, hlpmac,
				   ETH_ALEN), EBT_IDEST) )
					goto letscontinue;
			}

			if (EBT_MATCH_ITERATE(point, ebt_do_match, *pskb, in,
			   out, counter_base + i) != 0)
				goto letscontinue;

			// increase counter
			(*(counter_base + i)).pcnt++;

			// these should only watch: not modify, nor tell us
			// what to do with the packet
			EBT_WATCHER_ITERATE(point, ebt_do_watcher, *pskb, in,
			   out, counter_base + i);

			t = (struct ebt_entry_target *)
			   (((char *)point) + point->target_offset);
			// standard target
			if (!t->u.target->target)
				verdict =
				   ((struct ebt_standard_target *)t)->verdict;
			else
				verdict = t->u.target->target(pskb, hook,
				   in, out, t->data, t->target_size);
			if (verdict == EBT_ACCEPT) {
				read_unlock_bh(&table->lock);
				return NF_ACCEPT;
			}
			if (verdict == EBT_DROP) {
				read_unlock_bh(&table->lock);
				return NF_DROP;
			}
			if (verdict != EBT_CONTINUE) {
				read_unlock_bh(&table->lock);
				BUGPRINT("Illegal target while "
				         "firewalling!!\n");
				// Try not to get oopsen
				return NF_DROP;
			}
		}
letscontinue:
		point = (struct ebt_entry *)
		   (((char *)point) + point->next_offset);
	}

	if ( table->private->hook_entry[hook]->policy == EBT_ACCEPT ) {
		read_unlock_bh(&table->lock);
		return NF_ACCEPT;
	}
	read_unlock_bh(&table->lock);
	return NF_DROP;
}

static inline int
ebt_check_match(struct ebt_entry_match *m, struct ebt_entry *e,
   const char *name, unsigned int hook, unsigned int *cnt)
{
	struct ebt_match *match;
	int ret;

	m->u.name[EBT_FUNCTION_MAXNAMELEN - 1] = '\0';
	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		return -EFAULT;
	if (!(match = (struct ebt_match *)
	   list_named_find(&ebt_matches, m->u.name))) {
		up(&ebt_mutex);
		return -ENOENT;
	}
	m->u.match = match;
	if (match->check &&
	   match->check(name, hook, e, m->data,
	   m->match_size) != 0) {
		BUGPRINT("match->check failed\n");
		up(&ebt_mutex);
		return -EINVAL;
	}
	if (match->me)
		__MOD_INC_USE_COUNT(match->me);
	up(&ebt_mutex);
	(*cnt)++;
	return 0;
}

static inline int
ebt_check_watcher(struct ebt_entry_watcher *w, struct ebt_entry *e,
   const char *name, unsigned int hook, unsigned int *cnt)
{
	struct ebt_watcher *watcher;
	int ret;

	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		return -EFAULT;
	w->u.name[EBT_FUNCTION_MAXNAMELEN - 1] = '\0';
	if (!(watcher = (struct ebt_watcher *)
	   list_named_find(&ebt_watchers, w->u.name))) {
		up(&ebt_mutex);
		return -ENOENT;
	}
	w->u.watcher = watcher;
	if (watcher->check &&
	   watcher->check(name, hook, e, w->data,
	   w->watcher_size) != 0) {
		BUGPRINT("watcher->check failed\n");
		up(&ebt_mutex);
		return -EINVAL;
	}
	if (watcher->me)
		__MOD_INC_USE_COUNT(watcher->me);
	up(&ebt_mutex);
	(*cnt)++;
	return 0;
}

// this one is very careful, as it is the first function
// to parse the userspace data
static inline int
ebt_check_entry_size_and_hooks(struct ebt_entry *e,
   struct ebt_table_info *newinfo, char *base, char *limit,
   struct ebt_entries **hook_entries, unsigned int *n, unsigned int *cnt,
   unsigned int *totalcnt, unsigned int valid_hooks)
{
	int i;

	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if ((valid_hooks & (1 << i)) == 0)
			continue;
		if ( (char *)hook_entries[i] - base ==
		   (char *)e - newinfo->entries)
			break;
	}
	// beginning of a new chain
	if (i != NF_BR_NUMHOOKS) {
		if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) != 0) {
			// we make userspace set this right,
			// so there is no misunderstanding
			BUGPRINT("EBT_ENTRY_OR_ENTRIES shouldn't be set "
			         "in distinguisher\n");
			return -EINVAL;
		}
		// this checks if the previous chain has as many entries
		// as it said it has
		if (*n != *cnt) {
			BUGPRINT("nentries does not equal the nr of entries "
		                 "in the chain\n");
			return -EINVAL;
		}
		// before we look at the struct, be sure it is not too big
		if ((char *)hook_entries[i] + sizeof(struct ebt_entries)
		   > limit) {
			BUGPRINT("entries_size too small\n");
			return -EINVAL;
		}
		if (((struct ebt_entries *)e)->policy != EBT_DROP &&
		   ((struct ebt_entries *)e)->policy != EBT_ACCEPT) {
			BUGPRINT("bad policy\n");
			return -EINVAL;
		}
		*n = ((struct ebt_entries *)e)->nentries;
		*cnt = 0;
		newinfo->hook_entry[i] = (struct ebt_entries *)e;
		newinfo->counter_entry[i] = *totalcnt;
		return 0;
	}
	// a plain old entry, heh
	if (sizeof(struct ebt_entry) > e->watchers_offset ||
	   e->watchers_offset > e->target_offset ||
	   e->target_offset > e->next_offset) {
		BUGPRINT("entry offsets not in right order\n");
		return -EINVAL;
	}
	if (((char *)e) + e->next_offset - newinfo->entries > limit - base) {
		BUGPRINT("entry offsets point too far\n");
		return -EINVAL;
	}

	if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) == 0) {
		BUGPRINT("EBT_ENTRY_OR_ENTRIES should be set in "
		         "bitmask for an entry\n");
		return -EINVAL;
	}
	(*cnt)++;
	(*totalcnt)++;
	return 0;
}

static inline int
ebt_cleanup_match(struct ebt_entry_match *m, unsigned int *i)
{
	if (i && (*i)-- == 0)
		return 1;
	if (m->u.match->destroy)
		m->u.match->destroy(m->data, m->match_size);
	if (m->u.match->me)
		__MOD_DEC_USE_COUNT(m->u.match->me);

	return 0;
}

static inline int
ebt_cleanup_watcher(struct ebt_entry_watcher *w, unsigned int *i)
{
	if (i && (*i)-- == 0)
		return 1;
	if (w->u.watcher->destroy)
		w->u.watcher->destroy(w->data, w->watcher_size);
	if (w->u.watcher->me)
		__MOD_DEC_USE_COUNT(w->u.watcher->me);

	return 0;
}

static inline int
ebt_check_entry(struct ebt_entry *e, struct ebt_table_info *newinfo,
   const char *name, unsigned int *cnt, unsigned int valid_hooks)
{
	struct ebt_entry_target *t;
	struct ebt_target *target;
	unsigned int i, j, hook = 0;
	int ret;

	// Don't mess with the struct ebt_entries
	if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) == 0)
		return 0;

	if (e->bitmask & ~EBT_F_MASK) {
		BUGPRINT("Unknown flag for bitmask\n");
		return -EINVAL;
	}
	if (e->invflags & ~EBT_INV_MASK) {
		BUGPRINT("Unknown flag for inv bitmask\n");
		return -EINVAL;
	}
	if ( (e->bitmask & EBT_NOPROTO) && (e->bitmask & EBT_802_3) ) {
		BUGPRINT("NOPROTO & 802_3 not allowed\n");
		return -EINVAL;
	}
	e->in[IFNAMSIZ - 1] = '\0';
	e->out[IFNAMSIZ - 1] = '\0';
	e->logical_in[IFNAMSIZ - 1] = '\0';
	e->logical_out[IFNAMSIZ - 1] = '\0';
	// what hook do we belong to?
	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if ((valid_hooks & (1 << i)) == 0)
			continue;
		if ((char *)newinfo->hook_entry[i] < (char *)e)
			hook = i;
		else
			break;
	}
	i = 0;
	ret = EBT_MATCH_ITERATE(e, ebt_check_match, e, name, hook, &i);
	if (ret != 0)
		goto cleanup_matches;
	j = 0;
	ret = EBT_WATCHER_ITERATE(e, ebt_check_watcher, e, name, hook, &j);
	if (ret != 0)
		goto cleanup_watchers;
	t = (struct ebt_entry_target *)(((char *)e) + e->target_offset);
	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		goto cleanup_watchers;
	t->u.name[EBT_FUNCTION_MAXNAMELEN - 1] = '\0';
	if (!(target = (struct ebt_target *)
	   list_named_find(&ebt_targets, t->u.name))) {
		ret = -ENOENT;
		up(&ebt_mutex);
		goto cleanup_watchers;
	}
	if (target->me)
		__MOD_INC_USE_COUNT(target->me);
	up(&ebt_mutex);

	t->u.target = target;
	if (t->u.target == &ebt_standard_target) {
		if (e->target_offset + sizeof(struct ebt_standard_target) >
		   e->next_offset) {
			BUGPRINT("Standard target size too big\n");
			ret = -EFAULT;
			goto cleanup_watchers;
		}
		if (((struct ebt_standard_target *)t)->verdict >=
		   NUM_STANDARD_TARGETS) {
			BUGPRINT("Invalid standard target\n");
			ret = -EFAULT;
			goto cleanup_watchers;
		}
	} else if (t->u.target->check &&
	   t->u.target->check(name, hook, e, t->data,
	   t->target_size) != 0) {
		if (t->u.target->me)
			__MOD_DEC_USE_COUNT(t->u.target->me);
		ret = -EFAULT;
		goto cleanup_watchers;
	}
	(*cnt)++;
	return 0;
cleanup_watchers:
	EBT_WATCHER_ITERATE(e, ebt_cleanup_watcher, &j);
cleanup_matches:
	EBT_MATCH_ITERATE(e, ebt_cleanup_match, &i);
	return ret;
}

static inline int
ebt_cleanup_entry(struct ebt_entry *e, unsigned int *cnt)
{
	struct ebt_entry_target *t;

	if (e->bitmask == 0)
		return 0;
	// we're done
	if (cnt && (*cnt)-- == 0)
		return 1;
	EBT_WATCHER_ITERATE(e, ebt_cleanup_watcher, NULL);
	EBT_MATCH_ITERATE(e, ebt_cleanup_match, NULL);
	t = (struct ebt_entry_target *)(((char *)e) + e->target_offset);
	if (t->u.target->destroy)
		t->u.target->destroy(t->data, t->target_size);
	if (t->u.target->me)
		__MOD_DEC_USE_COUNT(t->u.target->me);

	return 0;
}

// do the parsing of the table/chains/entries/matches/watchers/targets, heh
static int translate_table(struct ebt_replace *repl,
   struct ebt_table_info *newinfo)
{
	unsigned int i, j, k;
	int ret;

	i = 0;
	while (i < NF_BR_NUMHOOKS && !(repl->valid_hooks & (1 << i)))
		i++;
	if (i == NF_BR_NUMHOOKS) {
		BUGPRINT("No valid hooks specified\n");
		return -EINVAL;
	}
	if (repl->hook_entry[i] != (struct ebt_entries *)repl->entries) {
		BUGPRINT("Chains don't start at beginning\n");
		return -EINVAL;
	}
	// make sure chains are ordered after each other in same order
	// as their corresponding hooks
	for (j = i + 1; j < NF_BR_NUMHOOKS; j++) {
		if (!(repl->valid_hooks & (1 << j)))
			continue;
		if ( repl->hook_entry[j] <= repl->hook_entry[i] ) {
			BUGPRINT("Hook order must be followed\n");
			return -EINVAL;
		}
		i = j;
	}

	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		newinfo->hook_entry[i] = NULL;
		newinfo->counter_entry[i] = 0;
	}

	newinfo->entries_size = repl->entries_size;
	newinfo->nentries = repl->nentries;

	// do some early checkings and initialize some things
	i = 0; // holds the expected nr. of entries for the chain
	j = 0; // holds the up to now counted entries for the chain
	k = 0; // holds the total nr. of entries, should equal
	       // newinfo->nentries afterwards
	ret = EBT_ENTRY_ITERATE(newinfo->entries, newinfo->entries_size,
	   ebt_check_entry_size_and_hooks, newinfo, repl->entries,
	   repl->entries + repl->entries_size, repl->hook_entry, &i, &j, &k,
	   repl->valid_hooks);

	if (ret != 0)
		return ret;

	if (i != j) {
		BUGPRINT("nentries does not equal the nr of entries in the "
		         "(last) chain\n");
		return -EINVAL;
	}
	if (k != newinfo->nentries) {
		BUGPRINT("Total nentries is wrong\n");
		return -EINVAL;
	}

	// check if all valid hooks have a chain
	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if (newinfo->hook_entry[i] == NULL &&
		   (repl->valid_hooks & (1 << i))){
			BUGPRINT("Valid hook without chain\n");
			return -EINVAL;
		}
	}

	// we just don't trust anything
	repl->name[EBT_TABLE_MAXNAMELEN - 1] = '\0';
	// used to know what we need to clean up if something goes wrong
	i = 0;
	ret = EBT_ENTRY_ITERATE(newinfo->entries, newinfo->entries_size,
	   ebt_check_entry, newinfo, repl->name, &i, repl->valid_hooks);
	if (ret != 0) {
		BUGPRINT("ebt_check_entry gave fault back\n");
		EBT_ENTRY_ITERATE(newinfo->entries, newinfo->entries_size, ebt_cleanup_entry, &i);
	}
	return ret;
}

// called under write_lock
static inline void get_counters(struct ebt_table_info *info,
   struct ebt_counter *counters)
{
	int i, cpu, counter_base;

	// counters of cpu 0
	memcpy(counters, info->counters,
	   sizeof(struct ebt_counter) * info->nentries);
	// add other counters to those of cpu 0
	for (cpu = 1; cpu < smp_num_cpus; cpu++) {
		counter_base = cpu * info->nentries;
		for (i = 0; i < info->nentries; i++)
			counters[i].pcnt +=
			   info->counters[counter_base + i].pcnt;
	}
}

// replace the table
static int do_replace(void *user, unsigned int len)
{
	int ret;
	struct ebt_table_info *newinfo;
	struct ebt_replace tmp;
	struct ebt_table *t;
	struct ebt_counter *counterstmp = NULL;
	// used to be able to unlock earlier
	struct ebt_table_info *table;

 	if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
		return -EFAULT;

	if (len != sizeof(tmp) + tmp.entries_size) {
		BUGPRINT("Wrong len argument\n");
		return -EINVAL;
	}

	if (tmp.entries_size == 0) {
		BUGPRINT("Entries_size never zero\n");
		return -EINVAL;
	}
	newinfo = (struct ebt_table_info *)
	   vmalloc(sizeof(struct ebt_table_info));
	if (!newinfo)
		return -ENOMEM;

	if (tmp.nentries) {
		newinfo->counters = (struct ebt_counter *)vmalloc(
		   sizeof(struct ebt_counter) * tmp.nentries * smp_num_cpus);
		if (!newinfo->counters) {
			ret = -ENOMEM;
			goto free_newinfo;
		}
		memset(newinfo->counters, 0,
		   sizeof(struct ebt_counter) * tmp.nentries * smp_num_cpus);
	}
	else
		newinfo->counters = NULL;

	newinfo->entries = (char *)vmalloc(tmp.entries_size);
	if (!newinfo->entries) {
		ret = -ENOMEM;
		goto free_counters;
	}
	if (copy_from_user(
	   newinfo->entries, tmp.entries, tmp.entries_size) != 0) {
		BUGPRINT("Couldn't copy entries from userspace\n");
		ret = -EFAULT;
		goto free_entries;
	}

	// the user wants counters back
	// the check on the size is done later, when we have the lock
	if (tmp.num_counters) {
		counterstmp = (struct ebt_counter *)
		   vmalloc(tmp.num_counters * sizeof(struct ebt_counter));
		if (!counterstmp) {
			ret = -ENOMEM;
			goto free_entries;
		}
	}
	else
		counterstmp = NULL;

	ret = translate_table(&tmp, newinfo);

	if (ret != 0)
		goto free_counterstmp;

	ret = down_interruptible(&ebt_mutex);

	if (ret != 0)
		goto free_cleanup;

	if (!(t = (struct ebt_table *)list_named_find(&ebt_tables, tmp.name))) {
		ret = -ENOENT;
		// give some help to the poor user
		print_string("The table is not present, try insmod\n");
		goto free_unlock;
	}

	// the table doesn't like it
	if (t->check && (ret = t->check(newinfo, tmp.valid_hooks)))
		goto free_unlock;
		
	if (tmp.num_counters && tmp.num_counters != t->private->nentries) {
		BUGPRINT("Wrong nr. of counters requested\n");
		ret = -EINVAL;
		goto free_unlock;
	}

	// we have the mutex lock, so no danger in reading this pointer
	table = t->private;
	// we need an atomic snapshot of the counters
	write_lock_bh(&t->lock);
	if (tmp.num_counters)
		get_counters(t->private, counterstmp);

	t->private = newinfo;
	write_unlock_bh(&t->lock);
	up(&ebt_mutex);
	// So, a user can change the chains while having messed up his counter
	// allocation. Only reason why I do this is because this way the lock
	// is held only once, while this doesn't bring the kernel into a
	// dangerous state.
	if (tmp.num_counters &&
	   copy_to_user(tmp.counters, counterstmp,
	   tmp.num_counters * sizeof(struct ebt_counter))) {
		BUGPRINT("Couldn't copy counters to userspace\n");
		ret = -EFAULT;
	}
	else
		ret = 0;

	// decrease module count and free resources
	EBT_ENTRY_ITERATE(table->entries, table->entries_size,
	   ebt_cleanup_entry, NULL);

	vfree(table->entries);
	if (table->counters)
		vfree(table->counters);
	vfree(table);

	if (counterstmp)
		vfree(counterstmp);
	return ret;

free_unlock:
	up(&ebt_mutex);
free_cleanup:
	EBT_ENTRY_ITERATE(newinfo->entries, newinfo->entries_size,
	   ebt_cleanup_entry, NULL);
free_counterstmp:
	if (counterstmp)
		vfree(counterstmp);
free_entries:
	if (newinfo->entries)
		vfree(newinfo->entries);
free_counters:
	if (newinfo->counters)
		vfree(newinfo->counters);
free_newinfo:
	if (newinfo)
		vfree(newinfo);
	return ret;
}

int ebt_register_target(struct ebt_target *target)
{
	int ret;

	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		return ret;
	if (!list_named_insert(&ebt_targets, target)) {
		up(&ebt_mutex);
		return -EEXIST;
	}
	up(&ebt_mutex);
	MOD_INC_USE_COUNT;

	return 0;
}

void ebt_unregister_target(struct ebt_target *target)
{
	down(&ebt_mutex);
	LIST_DELETE(&ebt_targets, target);
	up(&ebt_mutex);
	MOD_DEC_USE_COUNT;
}

int ebt_register_match(struct ebt_match *match)
{
	int ret;

	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		return ret;
	if (!list_named_insert(&ebt_matches, match)) {
		up(&ebt_mutex);
		return -EEXIST;
	}
	up(&ebt_mutex);
	MOD_INC_USE_COUNT;

	return 0;
}

void ebt_unregister_match(struct ebt_match *match)
{
	down(&ebt_mutex);
	LIST_DELETE(&ebt_matches, match);
	up(&ebt_mutex);
	MOD_DEC_USE_COUNT;
}

int ebt_register_watcher(struct ebt_watcher *watcher)
{
	int ret;

	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		return ret;
	if (!list_named_insert(&ebt_watchers, watcher)) {
		up(&ebt_mutex);
		return -EEXIST;
	}
	up(&ebt_mutex);
	MOD_INC_USE_COUNT;

	return 0;
}

void ebt_unregister_watcher(struct ebt_watcher *watcher)
{
	down(&ebt_mutex);
	LIST_DELETE(&ebt_watchers, watcher);
	up(&ebt_mutex);
	MOD_DEC_USE_COUNT;
}

int ebt_register_table(struct ebt_table *table)
{
	struct ebt_table_info *newinfo;
	int ret;

	if (!table || !table->table ||!table->table->entries ||
	    table->table->entries_size == 0 ||
	    table->table->counters || table->private) {
		BUGPRINT("Bad table data for ebt_register_table!!!\n");
		return -EINVAL;
	}

	newinfo = (struct ebt_table_info *)
	   vmalloc(sizeof(struct ebt_table_info));
	ret = -ENOMEM;
	if (!newinfo)
		return -ENOMEM;

	newinfo->entries = (char *)vmalloc(table->table->entries_size);
	if (!(newinfo->entries))
		goto free_newinfo;

	memcpy(newinfo->entries, table->table->entries,
	   table->table->entries_size);

	if (table->table->nentries) {
		newinfo->counters = (struct ebt_counter *)
		   vmalloc(table->table->nentries *
		   sizeof(struct ebt_counter) * smp_num_cpus);
		if (!newinfo->counters)
			goto free_entries;
		memset(newinfo->counters, 0, table->table->nentries *
		   sizeof(struct ebt_counter) * smp_num_cpus);
	}
	else
		newinfo->counters = NULL;

	// fill in newinfo and parse the entries
	ret = translate_table(table->table, newinfo);
	if (ret != 0) {
		BUGPRINT("Translate_table failed\n");
		goto free_counters;
	}

	if (table->check && table->check(newinfo, table->valid_hooks)) {
		BUGPRINT("The table doesn't like its own initial data, lol\n");
		return -EINVAL;
	}

	table->private = newinfo;
	table->lock = RW_LOCK_UNLOCKED;
	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		goto free_counters;

	if (list_named_find(&ebt_tables, table->name)) {
		ret = -EEXIST;
		BUGPRINT("Table name already exists\n");
		goto free_unlock;
	}

	list_prepend(&ebt_tables, table);
	up(&ebt_mutex);
	MOD_INC_USE_COUNT;
	return 0;
free_unlock:
	up(&ebt_mutex);
free_counters:
	if (newinfo->counters)
		vfree(newinfo->counters);
free_entries:
	vfree(newinfo->entries);
free_newinfo:
	vfree(newinfo);
	return ret;
}

void ebt_unregister_table(struct ebt_table *table)
{
	if (!table) {
		BUGPRINT("Request to unregister NULL table!!!\n");
		return;
	}
	down(&ebt_mutex);
	LIST_DELETE(&ebt_tables, table);
	up(&ebt_mutex);
	EBT_ENTRY_ITERATE(table->private->entries,
	   table->private->entries_size, ebt_cleanup_entry, NULL);
	if (table->private->counters)
		vfree(table->private->counters);
	if (table->private->entries)
		vfree(table->private->entries);
	vfree(table->private);
	MOD_DEC_USE_COUNT;
}

// userspace just supplied us with counters
static int update_counters(void *user, unsigned int len)
{
	int i, ret;
	struct ebt_counter *tmp;
	struct ebt_replace hlp;
	struct ebt_table *t;

	if (copy_from_user(&hlp, user, sizeof(hlp)))
		return -EFAULT;

	if (len != sizeof(hlp) + hlp.num_counters * sizeof(struct ebt_counter))
		return -EINVAL;
	if (hlp.num_counters == 0)
		return -EINVAL;

	if ( !(tmp = (struct ebt_counter *)
	   vmalloc(hlp.num_counters * sizeof(struct ebt_counter))) ){
		MEMPRINT("Updata_counters && nomemory\n");
		return -ENOMEM;
	}

	hlp.name[EBT_TABLE_MAXNAMELEN - 1] = '\0';
	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		goto free_tmp;

	if (!(t = (struct ebt_table *)list_named_find(&ebt_tables, hlp.name))) {
		ret = -EINVAL;
		goto unlock_mutex;
	}

	if (hlp.num_counters != t->private->nentries) {
		BUGPRINT("Wrong nr of counters\n");
		ret = -EINVAL;
		goto unlock_mutex;
	}

	if ( copy_from_user(tmp, hlp.counters,
	   hlp.num_counters * sizeof(struct ebt_counter)) ) {
		BUGPRINT("Updata_counters && !cfu\n");
		ret = -EFAULT;
		goto unlock_mutex;
	}

	// we want an atomic add of the counters
	write_lock_bh(&t->lock);

	// we add to the counters of the first cpu
	for (i = 0; i < hlp.num_counters; i++)
		t->private->counters[i].pcnt += tmp[i].pcnt;

	write_unlock_bh(&t->lock);
	ret = 0;
unlock_mutex:
	up(&ebt_mutex);
free_tmp:
	vfree(tmp);
	return ret;
}

static inline int ebt_make_matchname(struct ebt_entry_match *m,
   char *base, char *ubase)
{
	char *hlp = ubase - base + (char *)m;
	if (copy_to_user(hlp, m->u.match->name, EBT_FUNCTION_MAXNAMELEN))
		return -EFAULT;
	return 0;
}

static inline int ebt_make_watchername(struct ebt_entry_watcher *w,
   char *base, char *ubase)
{
	char *hlp = ubase - base + (char *)w;
	if (copy_to_user(hlp , w->u.watcher->name, EBT_FUNCTION_MAXNAMELEN))
		return -EFAULT;
	return 0;
}

static inline int ebt_make_names(struct ebt_entry *e, char *base, char *ubase)
{
	int ret;
	char *hlp = ubase - base + (char *)e + e->target_offset;
	struct ebt_entry_target *t;

	if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) == 0)
		return 0;

	t = (struct ebt_entry_target *)(((char *)e) + e->target_offset);
	
	ret = EBT_MATCH_ITERATE(e, ebt_make_matchname, base, ubase);
	if (ret != 0)
		return ret;
	ret = EBT_WATCHER_ITERATE(e, ebt_make_watchername, base, ubase);
	if (ret != 0)
		return ret;
	if (copy_to_user(hlp, t->u.target->name, EBT_FUNCTION_MAXNAMELEN))
		return -EFAULT;
	return 0;
}

// called with ebt_mutex down
static int copy_everything_to_user(struct ebt_table *t, void *user, int *len)
{
	struct ebt_replace tmp;
	struct ebt_table_info *info = t->private;
	struct ebt_counter *counterstmp;
	int i;

	if (copy_from_user(&tmp, user, sizeof(tmp))) {
		BUGPRINT("Cfu didn't work\n");
		return -EFAULT;
	}

	if (*len != sizeof(struct ebt_replace) + info->entries_size +
	   (tmp.num_counters? info->nentries * sizeof(struct ebt_counter): 0)) {
		BUGPRINT("Wrong size\n");
		return -EINVAL;
	}

	if (tmp.nentries != info->nentries) {
		BUGPRINT("Nentries wrong\n");
		return -EINVAL;
	}

	if (tmp.entries_size != info->entries_size) {
		BUGPRINT("Wrong size\n");
		return -EINVAL;
	}

	// userspace might not need the counters
	if (tmp.num_counters) {
		if (tmp.num_counters != info->nentries) {
			BUGPRINT("Num_counters wrong\n");
			return -EINVAL;
		}
		counterstmp = (struct ebt_counter *)
		   vmalloc(info->nentries * sizeof(struct ebt_counter));
		if (!counterstmp) {
			BUGPRINT("Couldn't copy counters, out of memory\n");
			return -ENOMEM;
		}
		write_lock_bh(&t->lock);
		get_counters(info, counterstmp);
		write_unlock_bh(&t->lock);

		if (copy_to_user(tmp.counters, counterstmp,
		   info->nentries * sizeof(struct ebt_counter))) {
			BUGPRINT("Couldn't copy counters to userspace\n");
			vfree(counterstmp);
			return -EFAULT;
		}
		vfree(counterstmp);
	}

	if (copy_to_user(tmp.entries, info->entries, info->entries_size)) {
		BUGPRINT("Couldn't copy entries to userspace\n");
		return -EFAULT;
	}
	// make userspace's life easier
	memcpy(tmp.counter_entry, info->counter_entry,
	   NF_BR_NUMHOOKS * sizeof(int));
	memcpy(tmp.hook_entry, info->hook_entry,
	   NF_BR_NUMHOOKS * sizeof(struct ebt_entries *));
	for (i = 0; i < NF_BR_NUMHOOKS; i++)
		tmp.hook_entry[i] = (struct ebt_entries *)(((char *)
		   (info->hook_entry[i])) - info->entries + tmp.entries);
	if (copy_to_user(user, &tmp, sizeof(struct ebt_replace))) {
		BUGPRINT("Couldn't copy ebt_replace to userspace\n");
		return -EFAULT;
	}
	// set the match/watcher/target names right
	return EBT_ENTRY_ITERATE(info->entries, info->entries_size,
	   ebt_make_names, info->entries, tmp.entries);
}

static int do_ebt_set_ctl(struct sock *sk,
	int cmd, void *user, unsigned int len)
{
	int ret;

	switch(cmd) {
	case EBT_SO_SET_ENTRIES:
		ret = do_replace(user, len);
		break;
	case EBT_SO_SET_COUNTERS:
		ret = update_counters(user, len);
		break;
	default:
		ret = -EINVAL;
  }
	return ret;
}

static int do_ebt_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	int ret;
	struct ebt_replace tmp;
	struct ebt_table *t;

	if (copy_from_user(&tmp, user, sizeof(tmp)))
		return -EFAULT;

	ret = down_interruptible(&ebt_mutex);
	if (ret != 0)
		return ret;

	if (!(t = (struct ebt_table *)list_named_find(&ebt_tables, tmp.name))) {
		print_string("Table not found, try insmod\n");
		up(&ebt_mutex);
		return -EINVAL;
	}

	switch(cmd) {
	case EBT_SO_GET_INFO:
		if (*len != sizeof(struct ebt_replace)){
			ret = -EINVAL;
			up(&ebt_mutex);
			break;
		}
		tmp.nentries = t->private->nentries;
		tmp.entries_size = t->private->entries_size;
		// userspace needs this to check the chain names
		tmp.valid_hooks = t->valid_hooks;
		up(&ebt_mutex);
		if (copy_to_user(user, &tmp, *len) != 0){
			BUGPRINT("c2u Didn't work\n");
			ret = -EFAULT;
			break;
		}
		ret = 0;
		break;

	case EBT_SO_GET_ENTRIES:
		ret = copy_everything_to_user(t, user, len);
		up(&ebt_mutex);
		break;			

	default:
		up(&ebt_mutex);
		ret = -EINVAL;
	}

	return ret;
}

static struct nf_sockopt_ops ebt_sockopts =
{ { NULL, NULL }, PF_INET, EBT_BASE_CTL, EBT_SO_SET_MAX + 1, do_ebt_set_ctl,
    EBT_BASE_CTL, EBT_SO_GET_MAX + 1, do_ebt_get_ctl, 0, NULL
};

// Copyright (C) 1998 by Ori Pomerantz
// Print the string to the appropriate tty, the one
// the current task uses
static void print_string(char *str)
{
	struct tty_struct *my_tty;

	/* The tty for the current task */
	my_tty = current->tty;
	if (my_tty != NULL) {
		(*(my_tty->driver).write)(my_tty, 0, str, strlen(str));  
		(*(my_tty->driver).write)(my_tty, 0, "\015\012", 2);
	}
}

static int __init init(void)
{
	int ret;

	down(&ebt_mutex);
	list_named_insert(&ebt_targets, &ebt_standard_target);
	up(&ebt_mutex);
	if ((ret = nf_register_sockopt(&ebt_sockopts)) < 0)
		return ret;

	print_string("Ebtables v2.0 registered");
	return 0;
}

static void __exit fini(void)
{
	nf_unregister_sockopt(&ebt_sockopts);
	print_string("Ebtables v2.0 unregistered");
}

EXPORT_SYMBOL(ebt_register_table);
EXPORT_SYMBOL(ebt_unregister_table);
EXPORT_SYMBOL(ebt_register_match);
EXPORT_SYMBOL(ebt_unregister_match);
EXPORT_SYMBOL(ebt_register_watcher);
EXPORT_SYMBOL(ebt_unregister_watcher);
EXPORT_SYMBOL(ebt_register_target);
EXPORT_SYMBOL(ebt_unregister_target);
EXPORT_SYMBOL(ebt_do_table);
module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
