/*
 * communication.c, v2.0 April 2002
 *
 * Author: Bart De Schuymer
 *
 */

// All the userspace/kernel communication is in this file.
// The other code should not have to know anything about the way the
// kernel likes the structure of the table data.
// The other code works with linked lists, lots of linked lists.
// So, the translation is done here.

#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/br_db.h> // the database
#include <netinet/in.h> // IPPROTO_IP
#include <asm/types.h>
#include "include/ebtables_u.h"

extern char* hooknames[NF_BR_NUMHOOKS];

int sockfd = -1;

void get_sockfd()
{
	if (sockfd == -1) {
		sockfd = socket(AF_INET, SOCK_RAW, PF_INET);
		if (sockfd < 0)
			print_error("Problem getting a socket");
	}
}

static struct ebt_replace * translate_user2kernel(struct ebt_u_replace *u_repl)
{
	struct ebt_replace *new;
	struct ebt_u_entry *e;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	char *p, *base;
	int i, j;
	unsigned int entries_size = 0;

	new = (struct ebt_replace *)malloc(sizeof(struct ebt_replace));
	if (!new)
		print_memory();
	new->valid_hooks = u_repl->valid_hooks;
	memcpy(new->name, u_repl->name, sizeof(new->name));
	new->nentries = u_repl->nentries;
	new->num_counters = u_repl->num_counters;
	new->counters = u_repl->counters;
	memcpy(new->counter_entry, u_repl->counter_entry,
	   sizeof(new->counter_entry));
	// determine size
	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if (!(new->valid_hooks & (1 << i)))
			continue;
		entries_size += sizeof(struct ebt_entries);
		j = 0;
		e = u_repl->hook_entry[i]->entries;
		while (e) {
			j++;
			entries_size += sizeof(struct ebt_entry);
			m_l = e->m_list;
			while (m_l) {
				entries_size += m_l->m->match_size +
				   sizeof(struct ebt_entry_match);
				m_l = m_l->next;
			}
			w_l = e->w_list;
			while (w_l) {
				entries_size += w_l->w->watcher_size +
				   sizeof(struct ebt_entry_watcher);
				w_l = w_l->next;
			}
			entries_size += e->t->target_size +
			   sizeof(struct ebt_entry_target);
			e = e->next;
		}
		// a little sanity check
		if (j != u_repl->hook_entry[i]->nentries)
			print_bug("Wrong nentries: %d != %d, hook = %s", j,
			   u_repl->hook_entry[i]->nentries, hooknames[i]);
	}

	new->entries_size = entries_size;
	new->entries = (char *)malloc(entries_size);
	if (!new->entries)
		print_memory();

	// put everything in one block
	p = new->entries;
	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		struct ebt_entries *hlp;

		if (!(new->valid_hooks & (1 << i)))
			continue;
		hlp = (struct ebt_entries *)p;
		new->hook_entry[i] = hlp;
		hlp->nentries = u_repl->hook_entry[i]->nentries;
		hlp->policy = u_repl->hook_entry[i]->policy;
		hlp->distinguisher = 0; // make the kernel see the light
		p += sizeof(struct ebt_entries);
		e = u_repl->hook_entry[i]->entries;
		while (e) {
			struct ebt_entry *tmp = (struct ebt_entry *)p;

			tmp->bitmask = e->bitmask | EBT_ENTRY_OR_ENTRIES;
			tmp->invflags = e->invflags;
			tmp->ethproto = e->ethproto;
			memcpy(tmp->in, e->in, sizeof(tmp->in));
			memcpy(tmp->out, e->out, sizeof(tmp->out));
			memcpy(tmp->logical_in, e->logical_in,
			   sizeof(tmp->logical_in));
			memcpy(tmp->logical_out, e->logical_out,
			   sizeof(tmp->logical_out));
			memcpy(tmp->sourcemac, e->sourcemac,
			   sizeof(tmp->sourcemac));
			memcpy(tmp->sourcemsk, e->sourcemsk,
			   sizeof(tmp->sourcemsk));
			memcpy(tmp->destmac, e->destmac, sizeof(tmp->destmac));
			memcpy(tmp->destmsk, e->destmsk, sizeof(tmp->destmsk));

			base = p;
			p += sizeof(struct ebt_entry);
			m_l = e->m_list;
			while (m_l) {
				memcpy(p, m_l->m, m_l->m->match_size +
				   sizeof(struct ebt_entry_match));
				p += m_l->m->match_size +
				   sizeof(struct ebt_entry_match);
				m_l = m_l->next;
			}
			tmp->watchers_offset = p - base;
			w_l = e->w_list;
			while (w_l) {
				memcpy(p, w_l->w, w_l->w->watcher_size +
				   sizeof(struct ebt_entry_watcher));
				p += w_l->w->watcher_size +
				   sizeof(struct ebt_entry_watcher);
				w_l = w_l->next;
			}
			tmp->target_offset = p - base;
			memcpy(p, e->t, e->t->target_size +
			   sizeof(struct ebt_entry_target));
			p += e->t->target_size +
			   sizeof(struct ebt_entry_target);
			tmp->next_offset = p - base;
			e = e->next;
		}
	}

	// sanity check
	if (p - new->entries != new->entries_size)
		print_bug("Entries_size bug");
	return new;
}

void deliver_table(struct ebt_u_replace *u_repl)
{
	socklen_t optlen;
	struct ebt_replace *repl;

	// translate the struct ebt_u_replace to a struct ebt_replace
	repl = translate_user2kernel(u_repl);
	get_sockfd();
	// give the data to the kernel
	optlen = sizeof(struct ebt_replace) + repl->entries_size;
	if (setsockopt(sockfd, IPPROTO_IP, EBT_SO_SET_ENTRIES, repl, optlen))
		print_error("The kernel doesn't support a certain ebtables"
		  " extension, consider recompiling your kernel or insmod"
		  " the extension");	
}

// gets executed after deliver_table
void
deliver_counters(struct ebt_u_replace *u_repl, unsigned short *counterchanges)
{
	unsigned short *point;
	struct ebt_counter *old, *new, *newcounters;
	socklen_t optlen;
	struct ebt_replace repl;

	if (u_repl->nentries == 0)
		return;

	newcounters = (struct ebt_counter *)
	   malloc(u_repl->nentries * sizeof(struct ebt_counter));
	if (!newcounters)
		print_memory();
	memset(newcounters, 0, u_repl->nentries * sizeof(struct ebt_counter));
	old = u_repl->counters;
	new = newcounters;
	point = counterchanges;
	while (*point != CNT_END) {
		if (*point == CNT_NORM) {
			// 'normal' rule, meaning we didn't do anything to it
			// So, we just copy
			new->pcnt = old->pcnt;
			// we've used an old counter
			old++;
			// we've set a new counter
			new++;
		} else
		if (*point == CNT_DEL) {
			// don't use this old counter
			old++;
		} else if (*point == CNT_ADD) {
			// new counter, let it stay 0
			new++;
		} else {
			// zero it
			new->pcnt = 0;
			old++;
			new++;
		}
		point++;
	}

	free(u_repl->counters);
	u_repl->counters = newcounters;
	u_repl->num_counters = u_repl->nentries;
	optlen = u_repl->nentries * sizeof(struct ebt_counter) +
	   sizeof(struct ebt_replace);
	// now put the stuff in the kernel's struct ebt_replace
	repl.counters = u_repl->counters;
	repl.num_counters = u_repl->num_counters;
	memcpy(repl.name, u_repl->name, sizeof(repl.name));

	get_sockfd();
	if (setsockopt(sockfd, IPPROTO_IP, EBT_SO_SET_COUNTERS, &repl, optlen))
		print_bug("couldn't update kernel counters");
}

static int
ebt_translate_match(struct ebt_entry_match *m, struct ebt_u_match_list ***l)
{
	struct ebt_u_match_list *new;

	new = (struct ebt_u_match_list *)
	   malloc(sizeof(struct ebt_u_match_list));
	if (!new)
		print_memory();
	new->m = (struct ebt_entry_match *)
	   malloc(m->match_size + sizeof(struct ebt_entry_match));
	if (!new->m)
		print_memory();
	memcpy(new->m, m, m->match_size + sizeof(struct ebt_entry_match));
	new->next = NULL;
	**l = new;
	*l = &new->next;
	if (find_match(new->m->u.name) == NULL)
		print_error("Kernel match %s unsupported by userspace tool",
		   new->m->u.name);
	return 0;
}

static int
ebt_translate_watcher(struct ebt_entry_watcher *w,
   struct ebt_u_watcher_list ***l)
{
	struct ebt_u_watcher_list *new;

	new = (struct ebt_u_watcher_list *)
	   malloc(sizeof(struct ebt_u_watcher_list));
	if (!new)
		print_memory();
	new->w = (struct ebt_entry_watcher *)
	   malloc(w->watcher_size + sizeof(struct ebt_entry_watcher));
	if (!new->w)
		print_memory();
	memcpy(new->w, w, w->watcher_size + sizeof(struct ebt_entry_watcher));
	new->next = NULL;
	**l = new;
	*l = &new->next;
	if (find_watcher(new->w->u.name) == NULL)
		print_error("Kernel watcher %s unsupported by userspace tool",
		   new->w->u.name);
	return 0;
}

static int
ebt_translate_entry(struct ebt_entry *e, unsigned int *hook, int *n, int *cnt,
   int *totalcnt, struct ebt_u_entry ***u_e, struct ebt_u_replace *u_repl,
   unsigned int valid_hooks)
{
	// an entry
	if (e->bitmask & EBT_ENTRY_OR_ENTRIES) {
		struct ebt_u_entry *new;
		struct ebt_u_match_list **m_l;
		struct ebt_u_watcher_list **w_l;
		struct ebt_entry_target *t;

		new = (struct ebt_u_entry *)malloc(sizeof(struct ebt_u_entry));
		if (!new)
			print_memory();
		new->bitmask = e->bitmask;
		// plain userspace code doesn't know about EBT_ENTRY_OR_ENTRIES
		new->bitmask &= ~EBT_ENTRY_OR_ENTRIES;
		new->invflags = e->invflags;
		new->ethproto = e->ethproto;
		memcpy(new->in, e->in, sizeof(new->in));
		memcpy(new->out, e->out, sizeof(new->out));
		memcpy(new->logical_in, e->logical_in,
		   sizeof(new->logical_in));
		memcpy(new->logical_out, e->logical_out,
		   sizeof(new->logical_out));
		memcpy(new->sourcemac, e->sourcemac, sizeof(new->sourcemac));
		memcpy(new->sourcemsk, e->sourcemsk, sizeof(new->sourcemsk));
		memcpy(new->destmac, e->destmac, sizeof(new->destmac));
		memcpy(new->destmsk, e->destmsk, sizeof(new->destmsk));
		new->m_list = NULL;
		new->w_list = NULL;
		new->next = NULL;
		m_l = &new->m_list;
		EBT_MATCH_ITERATE(e, ebt_translate_match, &m_l);
		w_l = &new->w_list;
		EBT_WATCHER_ITERATE(e, ebt_translate_watcher, &w_l);

		t = (struct ebt_entry_target *)(((char *)e) + e->target_offset);
		new->t = (struct ebt_entry_target *)
		   malloc(t->target_size + sizeof(struct ebt_entry_target));
		if (!new->t)
			print_memory();
		if (find_target(t->u.name) == NULL)
			print_error("Kernel target %s unsupported by "
			            "userspace tool", t->u.name);
		memcpy(new->t, t, t->target_size +
		   sizeof(struct ebt_entry_target));

		// I love pointers
		**u_e = new;
		*u_e = &new->next;
		(*cnt)++;
		(*totalcnt)++;
		return 0;
	} else { // a new chain
		int i;
		struct ebt_entries *entries = (struct ebt_entries *)e;
		struct ebt_u_entries *new;

		for (i = *hook + 1; i < NF_BR_NUMHOOKS; i++)
			if (valid_hooks & (1 << i))
				break;
		if (i >= NF_BR_NUMHOOKS)
			print_bug("Not enough valid hooks");
		*hook = i;
		if (*n != *cnt)
			print_bug("Nr of entries in the chain is wrong");
		*n = entries->nentries;
		*cnt = 0;
		new = (struct ebt_u_entries *)
		   malloc(sizeof(struct ebt_u_entries));
		if (!new)
			print_memory();
		new->nentries = entries->nentries;
		new->policy = entries->policy;
		new->entries = NULL;
		u_repl->hook_entry[*hook] = new;
		*u_e = &new->entries;
		return 0;
	}
}

// talk with kernel to receive the kernel's table
void get_table(struct ebt_u_replace *u_repl)
{
	int i, j, k, hook;
	socklen_t optlen;
	struct ebt_replace repl;
	struct ebt_u_entry **u_e;

	get_sockfd();

	optlen = sizeof(struct ebt_replace);
	strcpy(repl.name, u_repl->name);
	if (getsockopt(sockfd, IPPROTO_IP, EBT_SO_GET_INFO, &repl, &optlen))
		print_error("The %s table is not supported by the kernel,"
		  " consider recompiling your kernel or try insmod ebt_%s",
		  repl.name, repl.name);

	if ( !(repl.entries = (char *) malloc(repl.entries_size)) )
		print_memory();
	if (repl.nentries) {
		if (!(repl.counters = (struct ebt_counter *)
		   malloc(repl.nentries * sizeof(struct ebt_counter))) )
			print_memory();
	}
	else
		repl.counters = NULL;

	// we want to receive the counters
	repl.num_counters = repl.nentries;
	optlen += repl.entries_size + repl.num_counters *
	   sizeof(struct ebt_counter);
	if (getsockopt(sockfd, IPPROTO_IP, EBT_SO_GET_ENTRIES, &repl, &optlen))
		print_bug("hmm, what is wrong??? bug#1");

	// translate the struct ebt_replace to a struct ebt_u_replace
	memcpy(u_repl->name, repl.name, sizeof(u_repl->name));
	u_repl->valid_hooks = repl.valid_hooks;
	u_repl->nentries = repl.nentries;
	u_repl->num_counters = repl.num_counters;
	u_repl->counters = repl.counters;
	memcpy(u_repl->counter_entry, repl.counter_entry,
	   sizeof(repl.counter_entry));
	hook = -1;
	i = 0; // holds the expected nr. of entries for the chain
	j = 0; // holds the up to now counted entries for the chain
	k = 0; // holds the total nr. of entries,
	       // should equal u_repl->nentries afterwards
	EBT_ENTRY_ITERATE(repl.entries, repl.entries_size, ebt_translate_entry,
	   &hook, &i, &j, &k, &u_e, u_repl, u_repl->valid_hooks);
	if (k != u_repl->nentries)
		print_bug("Wrong total nentries");
}

void get_dbinfo(struct brdb_dbinfo *nr)
{
	socklen_t optlen = sizeof(struct brdb_dbinfo);

	get_sockfd();
	
	if (getsockopt(sockfd, IPPROTO_IP, BRDB_SO_GET_DBINFO, nr, &optlen))
		print_error("Sorry, br_db code probably not in kernel, "
		            "try insmod br_db");
}

void get_db(int len, struct brdb_dbentry *db)
{
	socklen_t optlen = len;

	get_sockfd();

	if ( getsockopt(sockfd, IPPROTO_IP, BRDB_SO_GET_DB, db, &optlen) ) {
		print_bug("hmm, what is wrong??? bug#2");
	}
}

void deliver_allowdb(__u16 *decision)
{
	socklen_t optlen = sizeof(__u16);

	get_sockfd();

	if (setsockopt(sockfd, IPPROTO_IP, BRDB_SO_SET_ALLOWDB,
	   decision, optlen))
		print_error("Sorry, br_db code probably not in kernel, "
		            "try insmod br_db");
}
