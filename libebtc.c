
/*
 * libebtc.c, January 2004
 *
 * Contains the functions with which to make a table in userspace.
 *
 * Author: Bart De Schuymer
 *
 *  This code is stongly inspired on the iptables code which is
 *  Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netinet/ether.h>
#include "include/ebtables_u.h"
#include "include/ethernetdb.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

static void decrease_chain_jumps(struct ebt_u_replace *replace);
static void remove_udc(struct ebt_u_replace *replace);
static int iterate_entries(struct ebt_u_replace *replace, int type);

/* The standard names */
const char *ebt_hooknames[NF_BR_NUMHOOKS] =
{
	[NF_BR_PRE_ROUTING]"PREROUTING",
	[NF_BR_LOCAL_IN]"INPUT",
	[NF_BR_FORWARD]"FORWARD",
	[NF_BR_LOCAL_OUT]"OUTPUT",
	[NF_BR_POST_ROUTING]"POSTROUTING",
	[NF_BR_BROUTING]"BROUTING"
};

/* The four target names */
const char* ebt_standard_targets[NUM_STANDARD_TARGETS] =
{
	"ACCEPT",
	"DROP",
	"CONTINUE",
	"RETURN",
};

/* The lists of supported tables, matches, watchers and targets */
struct ebt_u_table *ebt_tables;
struct ebt_u_match *ebt_matches;
struct ebt_u_watcher *ebt_watchers;
struct ebt_u_target *ebt_targets;

/* Find the right structure belonging to a name */
struct ebt_u_target *ebt_find_target(const char *name)
{
	struct ebt_u_target *t = ebt_targets;

	while (t && strcmp(t->name, name))
		t = t->next;
	return t;
}

struct ebt_u_match *ebt_find_match(const char *name)
{
	struct ebt_u_match *m = ebt_matches;

	while (m && strcmp(m->name, name))
		m = m->next;
	return m;
}

struct ebt_u_watcher *ebt_find_watcher(const char *name)
{
	struct ebt_u_watcher *w = ebt_watchers;

	while (w && strcmp(w->name, name))
		w = w->next;
	return w;
}

struct ebt_u_table *ebt_find_table(const char *name)
{
	struct ebt_u_table *t = ebt_tables;

	while (t && strcmp(t->name, name))
		t = t->next;
	return t;
}

/* Prints all registered extensions */
void ebt_list_extensions()
{
	struct ebt_u_table *tbl = ebt_tables;
        struct ebt_u_target *t = ebt_targets;
        struct ebt_u_match *m = ebt_matches;
        struct ebt_u_watcher *w = ebt_watchers;

	PRINT_VERSION;
	printf("Supported userspace extensions:\n\nSupported tables:\n");
        while (tbl) {
		printf("%s\n", tbl->name);
                tbl = tbl->next;
	}
	printf("\nSupported targets:\n");
        while (t) {
		printf("%s\n", t->name);
                t = t->next;
	}
	printf("\nSupported matches:\n");
        while (m) {
		printf("%s\n", m->name);
                m = m->next;
	}
	printf("\nSupported watchers:\n");
        while (w) {
		printf("%s\n", w->name);
                w = w->next;
	}
}

/* Get the table from the kernel or from a binary file
 * init: 1 = ask the kernel for the initial contents of a table, i.e. the
 *           way it looks when the table is insmod'ed
 *       0 = get the current data in the table */
int ebt_get_kernel_table(struct ebt_u_replace *replace, int init)
{
	if (!ebt_find_table(replace->name)) {
		ebt_print_error("Bad table name");
		return -1;
	}
	/* Get the kernel's information */
	if (ebt_get_table(replace, init)) {
		if (ebt_errormsg[0] != '\0')
			return -1;
		ebtables_insmod("ebtables");
		if (ebt_get_table(replace, init)) {
			ebt_print_error("The kernel doesn't support the ebtables %s table", replace->name);
			return -1;
		}
	}
	return 0;
}

/* Put sane values into a new entry */
void ebt_initialize_entry(struct ebt_u_entry *e)
{
	e->bitmask = EBT_NOPROTO;
	e->invflags = 0;
	e->ethproto = 0;
	strcpy(e->in, "");
	strcpy(e->out, "");
	strcpy(e->logical_in, "");
	strcpy(e->logical_out, "");
	e->m_list = NULL;
	e->w_list = NULL;
	e->t = (struct ebt_entry_target *)ebt_find_target(EBT_STANDARD_TARGET);
	ebt_find_target(EBT_STANDARD_TARGET)->used = 1;
	e->cnt.pcnt = e->cnt.bcnt = 0;

	if (!e->t)
		ebt_print_bug("Couldn't load standard target");
	((struct ebt_standard_target *)((struct ebt_u_target *)e->t)->t)->verdict = EBT_CONTINUE;
}

/* Free up the memory of the table held in userspace, *replace can be reused */
void ebt_cleanup_replace(struct ebt_u_replace *replace)
{
	int i;
	struct ebt_u_entries *entries;
	struct ebt_u_chain_list *udc1, *udc2;
	struct ebt_cntchanges *cc1, *cc2;
	struct ebt_u_entry *u_e1, *u_e2;

	replace->name[0] = '\0';
	replace->valid_hooks = 0;
	replace->nentries = 0;
	replace->num_counters = 0;
	replace->flags = 0;
	replace->command = 0;
	replace->selected_chain = -1;
	if (replace->filename) {
		free(replace->filename);
		replace->filename = NULL;
	}
	if (replace->counters) {
		free(replace->counters);
		replace->counters = NULL;
	}

	i = -1;
	while (1) {
		i++;
		entries = ebt_nr_to_chain(replace, i);
		if (!entries) {
			if (i < NF_BR_NUMHOOKS)
				continue;
			else
				break;
		}
		entries->nentries = 0;
		entries->counter_offset = 0;
		u_e1 = entries->entries;
		entries->entries = NULL;
		while (u_e1) {
			ebt_free_u_entry(u_e1);
			u_e2 = u_e1->next;
			free(u_e1);
			u_e1 = u_e2;
		}
	}
	udc1 = replace->udc;
	while (udc1) {
		free(udc1->udc);
		udc2 = udc1->next;
		free(udc1);
		udc1 = udc2;
	}
	replace->udc = NULL;
	cc1 = replace->counterchanges;
	while (cc1) {
		cc2 = cc1->next;
		free(cc2);
		cc1 = cc2;
	}
	replace->counterchanges = NULL;
}

/* Should be called, e.g., between 2 rule adds */
void ebt_reinit_extensions()
{
	struct ebt_u_match *m;
	struct ebt_u_watcher *w;
	struct ebt_u_target *t;
	int size;

	/* The init functions should determine by themselves whether they are
	 * called for the first time or not (when necessary). */
	for (m = ebt_matches; m; m = m->next) {
		size = EBT_ALIGN(m->size) + sizeof(struct ebt_entry_match);
		if (m->used) {
			m->m = (struct ebt_entry_match *)malloc(size);
			if (!m->m)
				ebt_print_memory();
			strcpy(m->m->u.name, m->name);
			m->m->match_size = EBT_ALIGN(m->size);
			m->used = 0;
			m->flags = 0;
		}
		m->init(m->m);
	}
	for (w = ebt_watchers; w; w = w->next) {
		size = EBT_ALIGN(w->size) + sizeof(struct ebt_entry_watcher);
		if (w->used) {
			w->w = (struct ebt_entry_watcher *)malloc(size);
			if (!w->w)
				ebt_print_memory();
			strcpy(w->w->u.name, w->name);
			w->w->watcher_size = EBT_ALIGN(w->size);
			w->used = 0;
			w->flags = 0;
		}
		w->init(w->w);
	}
	for (t = ebt_targets; t; t = t->next) {
		size = EBT_ALIGN(t->size) + sizeof(struct ebt_entry_target);
		if (t->used) {
			t->t = (struct ebt_entry_target *)malloc(size);
			if (!t->t)
				ebt_print_memory();
			strcpy(t->t->u.name, t->name);
			t->t->target_size = EBT_ALIGN(t->size);
			t->used = 0;
			t->flags = 0;
		}
		t->init(t->t);
	}
}

/* This doesn't free e, because the calling function might need e->next */
void ebt_free_u_entry(struct ebt_u_entry *e)
{
	struct ebt_u_match_list *m_l, *m_l2;
	struct ebt_u_watcher_list *w_l, *w_l2;

	m_l = e->m_list;
	while (m_l) {
		m_l2 = m_l->next;
		free(m_l->m);
		free(m_l);
		m_l = m_l2;
	}
	w_l = e->w_list;
	while (w_l) {
		w_l2 = w_l->next;
		free(w_l->w);
		free(w_l);
		w_l = w_l2;
	}
	free(e->t);
}

/* Blatently stolen (again) from iptables.c userspace program
 * find out where the modprobe utility is located */
static char *get_modprobe(void)
{
	int procfile;
	char *ret;

	procfile = open(PROC_SYS_MODPROBE, O_RDONLY);
	if (procfile < 0)
		return NULL;

	ret = malloc(1024);
	if (ret) {
		switch (read(procfile, ret, 1024)) {
		case -1: goto fail;
		case 1024: goto fail; /* Partial read.  Wierd */
		}
		if (ret[strlen(ret)-1] == '\n')
			ret[strlen(ret)-1] = 0;
		close(procfile);
		return ret;
	}
 fail:
	free(ret);
	close(procfile);
	return NULL;
}

char *ebt_modprobe;
/* Try to load the kernel module */
int ebtables_insmod(const char *modname)
{
	char *buf = NULL;
	char *argv[3];

	/* If they don't explicitly set it, read out of kernel */
	if (!ebt_modprobe) {
		buf = get_modprobe();
		if (!buf)
			return -1;
		ebt_modprobe = buf;
	}

	switch (fork()) {
	case 0:
		argv[0] = (char *)ebt_modprobe;
		argv[1] = (char *)modname;
		argv[2] = NULL;
		execv(argv[0], argv);

		/* Not usually reached */
		exit(0);
	case -1:
		return -1;

	default: /* Parent */
		wait(NULL);
	}

	free(buf);
	return 0;
}

/* Gives back a pointer to the chain base, based on nr.
 * If nr >= NF_BR_NUMHOOKS you'll get back a user-defined chain.
 * Returns NULL on failure. */
struct ebt_u_entries *ebt_nr_to_chain(const struct ebt_u_replace *replace,
				       int nr)
{
	if (nr == -1)
		return NULL;
	if (nr < NF_BR_NUMHOOKS)
		return replace->hook_entry[nr];
	else {
		int i;
		struct ebt_u_chain_list *cl = replace->udc;

		i = nr - NF_BR_NUMHOOKS;
		while (i > 0 && cl) {
			cl = cl->next;
			i--;
		}
		if (cl)
			return cl->udc;
		else
			return NULL;
	}
}

/* Gives back a pointer to the chain base of selected_chain */
struct ebt_u_entries *ebt_to_chain(const struct ebt_u_replace *replace)
{
	return ebt_nr_to_chain(replace, replace->selected_chain);
}

/* Parse the chain name and return a pointer to the chain base.
 * Returns NULL on failure. */
struct ebt_u_entries *ebt_name_to_chain(const struct ebt_u_replace *replace,
					const char* arg)
{
	int i;
	struct ebt_u_chain_list *cl = replace->udc;

	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if (!(replace->valid_hooks & (1 << i)))
			continue;
		if (!strcmp(arg, replace->hook_entry[i]->name))
			return replace->hook_entry[i];
	}
	while(cl) {
		if (!strcmp(arg, cl->udc->name))
			return cl->udc;
		cl = cl->next;
	}
	return NULL;
}

/* Parse the chain name and return the corresponding chain nr
 * returns -1 on failure */
int ebt_get_chainnr(const struct ebt_u_replace *replace, const char* arg)
{
	int i;
	struct ebt_u_chain_list *cl = replace->udc;

	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if (!(replace->valid_hooks & (1 << i)))
			continue;
		if (!strcmp(arg, replace->hook_entry[i]->name))
			return i;
	}
	while(cl) {
		if (!strcmp(arg, cl->udc->name))
			return i;
		i++;
		cl = cl->next;
	}
	return -1;
}

     /*
************
************
**COMMANDS**
************
************
     */

/* Change the policy of selected_chain.
 * Handing a bad policy to this function is a bug. */
void ebt_change_policy(struct ebt_u_replace *replace, int policy)
{
	struct ebt_u_entries *entries = ebt_to_chain(replace);

	if (policy < -NUM_STANDARD_TARGETS || policy == EBT_CONTINUE)
		ebt_print_bug("Wrong policy: %d", policy);
	entries->policy = policy;
}

/* Flush one chain or the complete table
 * If selected_chain == -1: flush the complete table */
void ebt_flush_chains(struct ebt_u_replace *replace)
{
	int i, j, numdel;
	struct ebt_u_entry *u_e, *tmp;
	struct ebt_u_entries *entries = ebt_to_chain(replace);
	struct ebt_cntchanges *cc = replace->counterchanges;
	struct ebt_cntchanges **prev_cc =  &(replace->counterchanges);

	/* Flush whole table */
	if (!entries) {
		if (replace->nentries == 0)
			return;
		replace->nentries = 0;

		/* Free everything and zero (n)entries */
		i = -1;
		while (1) {
			i++;
			entries = ebt_nr_to_chain(replace, i);
			if (!entries) {
				if (i < NF_BR_NUMHOOKS)
					continue;
				else
					break;
			}
			entries->nentries = 0;
			entries->counter_offset = 0;
			u_e = entries->entries;
			entries->entries = NULL;
			while (u_e) {
				ebt_free_u_entry(u_e);
				tmp = u_e->next;
				free(u_e);
				u_e = tmp;
			}
		}
		/* Update the counters */
		while (cc) {
			if (cc->type == CNT_ADD) {
				*prev_cc = cc->next;
				free(cc);
				cc = *prev_cc;
				continue;
			}
			cc->type = CNT_DEL;
			prev_cc = &(cc->next);
			cc = cc->next;
		}
		return;
	}

	if (entries->nentries == 0)
		return;
	replace->nentries -= entries->nentries;
	numdel = entries->nentries;

	/* Delete the counters belonging to the specified chain,
	 * update counter_offset */
	i = -1;
	while (1) {
		i++;
		entries = ebt_nr_to_chain(replace, i);
		if (!entries) {
			if (i < NF_BR_NUMHOOKS)
				continue;
			else
				break;
		}
		if (i > replace->selected_chain) {
			entries->counter_offset -= numdel;
			continue;
		}
		j = entries->nentries;
		while (j) {
			/* Don't count deleted entries */
			if (cc->type == CNT_DEL)
				goto letscontinue;
			if (i == replace->selected_chain) {
				if (cc->type == CNT_ADD) {
					*prev_cc = cc->next;
					free(cc);
					cc = *prev_cc;
					j--;
					continue;
				}
				cc->type = CNT_DEL;
			}
			j--;
letscontinue:
			prev_cc = &(cc->next);
			cc = cc->next;
		}
	}

	entries = ebt_to_chain(replace);
	entries->nentries = 0;
	u_e = entries->entries;
	while (u_e) {
		ebt_free_u_entry(u_e);
		tmp = u_e->next;
		free(u_e);
		u_e = tmp;
	}
	entries->entries = NULL;
}

/* Returns the rule number on success (starting from 0), -1 on failure
 *
 * This function expects the ebt_{match,watcher,target} members of new_entry
 * to contain pointers to ebt_u_{match,watcher,target} */
int ebt_check_rule_exists(struct ebt_u_replace *replace,
			  struct ebt_u_entry *new_entry)
{
	struct ebt_u_entry *u_e;
	struct ebt_u_match_list *m_l, *m_l2;
	struct ebt_u_match *m;
	struct ebt_u_watcher_list *w_l, *w_l2;
	struct ebt_u_watcher *w;
	struct ebt_u_target *t = (struct ebt_u_target *)new_entry->t;
	struct ebt_u_entries *entries = ebt_to_chain(replace);
	int i, j, k;

	u_e = entries->entries;
	/* Check for an existing rule (if there are duplicate rules,
	 * take the first occurance) */
	for (i = 0; i < entries->nentries; i++, u_e = u_e->next) {
		if (!u_e)
			ebt_print_bug("Hmm, trouble");
		if (u_e->ethproto != new_entry->ethproto)
			continue;
		if (strcmp(u_e->in, new_entry->in))
			continue;
		if (strcmp(u_e->out, new_entry->out))
			continue;
		if (strcmp(u_e->logical_in, new_entry->logical_in))
			continue;
		if (strcmp(u_e->logical_out, new_entry->logical_out))
			continue;
		if (new_entry->bitmask & EBT_SOURCEMAC &&
		    memcmp(u_e->sourcemac, new_entry->sourcemac, ETH_ALEN))
			continue;
		if (new_entry->bitmask & EBT_DESTMAC &&
		    memcmp(u_e->destmac, new_entry->destmac, ETH_ALEN))
			continue;
		if (new_entry->bitmask != u_e->bitmask ||
		    new_entry->invflags != u_e->invflags)
			continue;
		/* Compare all matches */
		m_l = new_entry->m_list;
		j = 0;
		while (m_l) {
			m = (struct ebt_u_match *)(m_l->m);
			m_l2 = u_e->m_list;
			while (m_l2 && strcmp(m_l2->m->u.name, m->m->u.name))
				m_l2 = m_l2->next;
			if (!m_l2 || !m->compare(m->m, m_l2->m))
				goto letscontinue;
			j++;
			m_l = m_l->next;
		}
		/* Now be sure they have the same nr of matches */
		k = 0;
		m_l = u_e->m_list;
		while (m_l) {
			k++;
			m_l = m_l->next;
		}
		if (j != k)
			continue;

		/* Compare all watchers */
		w_l = new_entry->w_list;
		j = 0;
		while (w_l) {
			w = (struct ebt_u_watcher *)(w_l->w);
			w_l2 = u_e->w_list;
			while (w_l2 && strcmp(w_l2->w->u.name, w->w->u.name))
				w_l2 = w_l2->next;
			if (!w_l2 || !w->compare(w->w, w_l2->w))
				goto letscontinue;
			j++;
			w_l = w_l->next;
		}
		k = 0;
		w_l = u_e->w_list;
		while (w_l) {
			k++;
			w_l = w_l->next;
		}
		if (j != k)
			continue;
		if (strcmp(t->t->u.name, u_e->t->u.name))
			continue;
		if (!t->compare(t->t, u_e->t))
			continue;
		return i;
letscontinue:;
	}
	return -1;
}

/* Add a rule, rule_nr is the rule to update
 * rule_nr specifies where the rule should be inserted
 * rule_nr > 0 : insert the rule right before the rule_nr'th rule
 *               (the first rule is rule 1)
 * rule_nr < 0 : insert the rule right before the (n+rule_nr+1)'th rule,
 *               where n denotes the number of rules in the chain
 * rule_nr == 0: add a new rule at the end of the chain
 *
 * This function expects the ebt_{match,watcher,target} members of new_entry
 * to contain pointers to ebt_u_{match,watcher,target} and updates these
 * pointers so that they point to ebt_{match,watcher,target}, before adding
 * the rule to the chain. Don't free() the ebt_{match,watcher,target} after a
 * successful call to ebt_add_rule() */
void ebt_add_rule(struct ebt_u_replace *replace, struct ebt_u_entry *new_entry,
		  int rule_nr)
{
	int i, j;
	struct ebt_u_entry **u_e;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	struct ebt_u_entries *entries = ebt_to_chain(replace);
	struct ebt_cntchanges *cc = replace->counterchanges, *new_cc;
	struct ebt_cntchanges **prev_cc =  &(replace->counterchanges);

	if (rule_nr <= 0)
		rule_nr += entries->nentries;
	else
		rule_nr--;
	if (rule_nr > entries->nentries || rule_nr < 0) {
		ebt_print_error("The specified rule number is incorrect");
		return;
	}
	/* We're adding one rule */
	replace->nentries++;
	entries->nentries++;

	/* Handle counter stuff */
	for (i = 0; i < replace->selected_chain; i++) {
		if (i < NF_BR_NUMHOOKS && !(replace->valid_hooks & (1 << i)))
			continue;
		j = ebt_nr_to_chain(replace, i)->nentries;
		while (j) {
			if (cc->type != CNT_DEL)
				j--;
			prev_cc = &(cc->next);
			cc = cc->next;
		}
	}
	j = rule_nr;
	while (j) {
		if (cc->type != CNT_DEL)
			j--;
		prev_cc = &(cc->next);
		cc = cc->next;
	}
	if (cc && cc->type == CNT_DEL)
		cc->type = CNT_OWRITE;
	else {
		new_cc = (struct ebt_cntchanges *)
			 malloc(sizeof(struct ebt_cntchanges));
		if (!new_cc)
			ebt_print_memory();
		new_cc->type = CNT_ADD;
		new_cc->next = cc;
		*prev_cc = new_cc;
	}
	/* Go to the right position in the chain */
	u_e = &entries->entries;
	for (i = 0; i < rule_nr; i++)
		u_e = &(*u_e)->next;
	/* Insert the rule */
	new_entry->next = *u_e;
	*u_e = new_entry;

	/* Put the ebt_{match, watcher, target} pointers in place */
	m_l = new_entry->m_list;
	while (m_l) {
		m_l->m = ((struct ebt_u_match *)m_l->m)->m;
		m_l = m_l->next;
	}
	w_l = new_entry->w_list;
	while (w_l) {
		w_l->w = ((struct ebt_u_watcher *)w_l->w)->w;
		w_l = w_l->next;
	}
	new_entry->t = ((struct ebt_u_target *)new_entry->t)->t;
	/* Update the counter_offset of chains behind this one */
	i = replace->selected_chain;
	while (1) {
		i++;
		entries = ebt_nr_to_chain(replace, i);
		if (!entries) {
			if (i < NF_BR_NUMHOOKS)
				continue;
			else
				break;
		} else
			entries->counter_offset++;
	}
}

/* Delete a rule or rules
 * begin == end == 0: delete the rule corresponding to new_entry
 *
 * The first rule has rule nr 1, the last rule has rule nr -1, etc.
 * This function expects the ebt_{match,watcher,target} members of new_entry
 * to contain pointers to ebt_u_{match,watcher,target}. */
void ebt_delete_rule(struct ebt_u_replace *replace,
		     struct ebt_u_entry *new_entry, int begin, int end)
{
	int i, j,  nr_deletes;
	struct ebt_u_entry **u_e, *u_e2;
	struct ebt_u_entries *entries = ebt_to_chain(replace);
	struct ebt_cntchanges *cc = replace->counterchanges;
	struct ebt_cntchanges **prev_cc =  &(replace->counterchanges);

	if (begin < 0)
		begin += entries->nentries + 1;
	if (end < 0)
		end += entries->nentries + 1;

	if (begin < 0 || begin > end || end > entries->nentries) {
		ebt_print_error("Sorry, wrong rule numbers");
		return;
	}

	if ((begin * end == 0) && (begin + end != 0))
		ebt_print_bug("begin and end should be either both zero, "
			      "either both non-zero");
	if (begin != 0 && end != 0) {
		begin--;
		end--;
	} else {
		begin = ebt_check_rule_exists(replace, new_entry);
		end = begin;
		if (begin == -1) {
			ebt_print_error("Sorry, rule does not exist");
			return;
		}
	}

	/* We're deleting rules */
	nr_deletes = end - begin + 1;
	replace->nentries -= nr_deletes;
	entries->nentries -= nr_deletes;

	/* Handle counter stuff */
	for (i = 0; i < replace->selected_chain; i++) {
		if (i < NF_BR_NUMHOOKS && !(replace->valid_hooks & (1 << i)))
			continue;
		j = ebt_nr_to_chain(replace, i)->nentries;
		while (j) {
			if (cc->type != CNT_DEL)
				j--;
			prev_cc = &(cc->next);
			cc = cc->next;
		}
	}
	j = begin;
	while (j) {
		if (cc->type != CNT_DEL)
			j--;
		prev_cc = &(cc->next);
		cc = cc->next;
	}
	j = nr_deletes;
	while (j) {
		if (cc->type != CNT_DEL) {
			j--;
			if (cc->type == CNT_ADD) {
				*prev_cc = cc->next;
				free(cc);
				cc = *prev_cc;
				continue;
			}
			cc->type = CNT_DEL;
		}
		prev_cc = &(cc->next);
		cc = cc->next;
	}

	/* Go to the right position in the chain */
	u_e = &entries->entries;
	for (j = 0; j < begin; j++)
		u_e = &(*u_e)->next;
	/* Remove the rules */
	j = nr_deletes;
	while(j--) {
		u_e2 = *u_e;
		*u_e = (*u_e)->next;
		/* Free everything */
		ebt_free_u_entry(u_e2);
		free(u_e2);
	}

	/* Update the counter_offset of chains behind this one */
	j = replace->selected_chain;
	while (1) {
		j++;
		entries = ebt_nr_to_chain(replace, j);
		if (!entries) {
			if (j < NF_BR_NUMHOOKS)
				continue;
			else
				break;
		} else 
			entries->counter_offset -= nr_deletes;
	}
}

/* Selected_chain == -1 : zero all counters
 * Otherwise, zero the counters of selected_chain */
void ebt_zero_counters(struct ebt_u_replace *replace)
{
	struct ebt_u_entries *entries = ebt_to_chain(replace);
	struct ebt_cntchanges *cc = replace->counterchanges;
	struct ebt_u_entry *next;
	int i, j;

	if (!entries) {
		while (cc) {
			if (cc->type == CNT_NORM)
				cc->type = CNT_ZERO;
			cc = cc->next;
		}
		i = -1;
		while (1) {
			i++;
			if (i < NF_BR_NUMHOOKS && !(replace->valid_hooks & (1 << i)))
				continue;
			entries = ebt_nr_to_chain(replace, i);
			if (!entries) {
				if (i < NF_BR_NUMHOOKS)
					ebt_print_bug("i < NF_BR_NUMHOOKS");
				break;
			}
			next = entries->entries;
			while (next) {
				next->cnt.bcnt = next->cnt.pcnt = 0;
				next = next->next;
			}
		}
			
	} else {
		next = entries->entries;
		if (entries->nentries == 0)
			return;

		for (i = 0; i < replace->selected_chain; i++) {
			if (i < NF_BR_NUMHOOKS && !(replace->valid_hooks & (1 << i)))
				continue;
			j = ebt_nr_to_chain(replace, i)->nentries;
			while (j) {
				if (cc->type != CNT_DEL)
					j--;
				cc = cc->next;
			}
		}
		j = entries->nentries;
		while (j) {
			if (cc->type != CNT_DEL) {
				j--;
				if (cc->type == CNT_NORM)
					cc->type = CNT_ZERO;
			}
			cc = cc->next;
		}
		while (next) {
			next->cnt.bcnt = next->cnt.pcnt = 0;
			next = next->next;
		}
	}
}

/* Add a new chain and specify its policy */
void ebt_new_chain(struct ebt_u_replace *replace, const char *name, int policy)
{
	struct ebt_u_chain_list *cl, **cl2;

	if (ebt_get_chainnr(replace, name) != -1) {
		ebt_print_error("Chain %s already exists", optarg);
		return;
	} else if (ebt_find_target(name)) {
		ebt_print_error("Target with name %s exists", optarg);
		return;
	} else if (strlen(optarg) >= EBT_CHAIN_MAXNAMELEN) {
		ebt_print_error("Chain name length can't exceed %d",
				EBT_CHAIN_MAXNAMELEN - 1);
		return;
	}
	cl = (struct ebt_u_chain_list *)
	     malloc(sizeof(struct ebt_u_chain_list));
	if (!cl)
		ebt_print_memory();
	cl->next = NULL;
	cl->udc = (struct ebt_u_entries *)
	   malloc(sizeof(struct ebt_u_entries));
	if (!cl->udc)
		ebt_print_memory();
	cl->udc->nentries = 0;
	cl->udc->policy = policy;
	cl->udc->counter_offset = replace->nentries;
	cl->udc->hook_mask = 0;
	strcpy(cl->udc->name, name);
	cl->udc->entries = NULL;
	cl->kernel_start = NULL;
	/* Put the new chain at the end */
	cl2 = &(replace->udc);
	while (*cl2)
		cl2 = &((*cl2)->next);
	*cl2 = cl;
}

/* Selected_chain == -1: delete all non-referenced udc
 * selected_chain < NF_BR_NUMHOOKS is illegal */
void ebt_delete_chain(struct ebt_u_replace *replace)
{
	int chain_nr = replace->selected_chain, print_error = 1;

	if (chain_nr != -1 && chain_nr < NF_BR_NUMHOOKS)
		ebt_print_bug("You can't remove a standard chain");
	if (chain_nr == -1) {
		print_error = 0;
		replace->selected_chain = NF_BR_NUMHOOKS;
	}
	do {
		if (ebt_to_chain(replace) == NULL) {
			if (chain_nr == -1)
				break;
			ebt_print_bug("udc nr %d doesn't exist", chain_nr);
		}
		/* If the chain is referenced, don't delete it,
		 * also decrement jumps to a chain behind the
		 * one we're deleting */
		if (ebt_check_for_references(replace, print_error)) {
			if (chain_nr != -1) 
				break;
			replace->selected_chain++;
			continue;
		}
		decrease_chain_jumps(replace);
		ebt_flush_chains(replace);
		remove_udc(replace);
	} while (chain_nr == -1);
	replace->selected_chain = chain_nr; /* Put back to -1 */
}

/* Rename an existing chain. */
void ebt_rename_chain(struct ebt_u_replace *replace, const char *name)
{
	struct ebt_u_entries *entries = ebt_to_chain(replace);

	if (!entries)
		ebt_print_bug("ebt_rename_chain: entries == NULL");
	strcpy(entries->name, name);
}


           /*
*************************
*************************
**SPECIALIZED*FUNCTIONS**
*************************
*************************
            */


/* Executes the final_check() function for all extensions used by the rule
 * ebt_check_for_loops should have been executed earlier, to make sure the
 * hook_mask is correct. The time argument to final_check() is set to 1,
 * meaning it's the second time the final_check() function is executed. */
void ebt_do_final_checks(struct ebt_u_replace *replace, struct ebt_u_entry *e,
			 struct ebt_u_entries *entries)
{
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	struct ebt_u_target *t;
	struct ebt_u_match *m;
	struct ebt_u_watcher *w;

	m_l = e->m_list;
	w_l = e->w_list;
	while (m_l) {
		m = ebt_find_match(m_l->m->u.name);
		m->final_check(e, m_l->m, replace->name,
		   entries->hook_mask, 1);
		if (ebt_errormsg[0] != '\0')
			return;
		m_l = m_l->next;
	}
	while (w_l) {
		w = ebt_find_watcher(w_l->w->u.name);
		w->final_check(e, w_l->w, replace->name,
		   entries->hook_mask, 1);
		if (ebt_errormsg[0] != '\0')
			return;
		w_l = w_l->next;
	}
	t = ebt_find_target(e->t->u.name);
	t->final_check(e, e->t, replace->name,
	   entries->hook_mask, 1);
}

/* Returns 1 (if it returns) when the chain is referenced, 0 when it isn't.
 * print_err: 0 (resp. 1) = don't (resp. do) print error when referenced */
int ebt_check_for_references(struct ebt_u_replace *replace, int print_err)
{
	if (print_err)
		return iterate_entries(replace, 1);
	else
		return iterate_entries(replace, 2);
}

/* chain_nr: nr of the udc (>= NF_BR_NUMHOOKS)
 * Returns 1 (if it returns) when the chain is referenced, 0 when it isn't.
 * print_err: 0 (resp. 1) = don't (resp. do) print error when referenced */
int ebt_check_for_references2(struct ebt_u_replace *replace, int chain_nr,
                              int print_err)
{
	int tmp = replace->selected_chain, ret;

	replace->selected_chain = chain_nr;
	if (print_err)
		ret = iterate_entries(replace, 1);
	else
		ret = iterate_entries(replace, 2);
	replace->selected_chain = tmp;
	return ret;
}

struct ebt_u_stack
{
	int chain_nr;
	int n;
	struct ebt_u_entry *e;
	struct ebt_u_entries *entries;
};

/* Checks for loops
 * As a by-product, the hook_mask member of each chain is filled in
 * correctly. The check functions of the extensions need this hook_mask
 * to know from which standard chains they can be called. */
void ebt_check_for_loops(struct ebt_u_replace *replace)
{
	int chain_nr , i, j , k, sp = 0, verdict;
	struct ebt_u_entries *entries, *entries2;
	struct ebt_u_stack *stack = NULL;
	struct ebt_u_entry *e;

	i = -1;
	/* Initialize hook_mask to 0 */
	while (1) {
		i++;
		if (i < NF_BR_NUMHOOKS && !(replace->valid_hooks & (1 << i)))
			continue;
		entries = ebt_nr_to_chain(replace, i);
		if (!entries)
			break;
		entries->hook_mask = 0;
	}
	if (i > NF_BR_NUMHOOKS) {
		stack = (struct ebt_u_stack *)malloc((i - NF_BR_NUMHOOKS) *
		   sizeof(struct ebt_u_stack));
		if (!stack)
			ebt_print_memory();
	}

	/* Check for loops, starting from every base chain */
	for (i = 0; i < NF_BR_NUMHOOKS; i++) {
		if (!(replace->valid_hooks & (1 << i)))
			continue;
		entries = ebt_nr_to_chain(replace, i);
		/* (1 << NF_BR_NUMHOOKS) implies it's a standard chain
		 * (usefull in the final_check() funtions) */
		entries->hook_mask = (1 << i) | (1 << NF_BR_NUMHOOKS);
		chain_nr = i;

		e = entries->entries;
		for (j = 0; j < entries->nentries; j++) {
			if (strcmp(e->t->u.name, EBT_STANDARD_TARGET))
				goto letscontinue;
			verdict = ((struct ebt_standard_target *)(e->t))->verdict;
			if (verdict < 0)
				goto letscontinue;
			entries2 = ebt_nr_to_chain(replace, verdict + NF_BR_NUMHOOKS);
			entries2->hook_mask |= entries->hook_mask;
			/* Now see if we've been here before */
			for (k = 0; k < sp; k++)
				if (stack[k].chain_nr == verdict + NF_BR_NUMHOOKS) {
					ebt_print_error("Loop from chain '%s' to chain '%s'",
					   ebt_nr_to_chain(replace, chain_nr)->name,
					   ebt_nr_to_chain(replace, stack[k].chain_nr)->name);
					goto free_stack;
				}
			/* Jump to the chain, make sure we know how to get back */
			stack[sp].chain_nr = chain_nr;
			stack[sp].n = j;
			stack[sp].entries = entries;
			stack[sp].e = e;
			sp++;
			j = -1;
			e = entries2->entries;
			chain_nr = verdict + NF_BR_NUMHOOKS;
			entries = entries2;
			continue;
letscontinue:
			e = e->next;
		}
		/* We are at the end of a standard chain */
		if (sp == 0)
			continue;
		/* Go back to the chain one level higher */
		sp--;
		j = stack[sp].n;
		chain_nr = stack[sp].chain_nr;
		e = stack[sp].e;
		entries = stack[sp].entries;
		goto letscontinue;
	}
free_stack:
	free(stack);
	return;
}

/* The user will use the match, so put it in new_entry. The ebt_u_match
 * pointer is put in the ebt_entry_match pointer. ebt_add_rule will
 * fill in the final value for new->m. Unless the rule is added to a chain,
 * the pointer will keep pointing to the ebt_u_match (until the new_entry
 * is freed). I know, I should use a union for these 2 pointer types... */
void ebt_add_match(struct ebt_u_entry *new_entry, struct ebt_u_match *m)
{
	struct ebt_u_match_list **m_list, *new;

	for (m_list = &new_entry->m_list; *m_list; m_list = &(*m_list)->next);
	new = (struct ebt_u_match_list *)
	   malloc(sizeof(struct ebt_u_match_list));
	if (!new)
		ebt_print_memory();
	*m_list = new;
	new->next = NULL;
	new->m = (struct ebt_entry_match *)m;
}

void ebt_add_watcher(struct ebt_u_entry *new_entry, struct ebt_u_watcher *w)
{
	struct ebt_u_watcher_list **w_list;
	struct ebt_u_watcher_list *new;

	for (w_list = &new_entry->w_list; *w_list; w_list = &(*w_list)->next);
	new = (struct ebt_u_watcher_list *)
	   malloc(sizeof(struct ebt_u_watcher_list));
	if (!new)
		ebt_print_memory();
	*w_list = new;
	new->next = NULL;
	new->w = (struct ebt_entry_watcher *)w;
}


        /*
*******************
*******************
**OTHER*FUNCTIONS**
*******************
*******************
         */


/* type = 0 => update chain jumps
 * type = 1 => check for reference, print error when referenced
 * type = 2 => check for reference, don't print error when referenced
 *
 * Returns 1 when type == 1 and the chain is referenced
 * returns 0 otherwise */
static int iterate_entries(struct ebt_u_replace *replace, int type)
{
	int i = -1, j, chain_nr = replace->selected_chain - NF_BR_NUMHOOKS;
	struct ebt_u_entries *entries;
	struct ebt_u_entry *e;

	if (chain_nr < 0)
		ebt_print_bug("iterate_entries: udc = %d < 0", chain_nr);
	while (1) {
		i++;
		entries = ebt_nr_to_chain(replace, i);
		if (!entries) {
			if (i < NF_BR_NUMHOOKS)
				continue;
			else
				break;
		}
		e = entries->entries;
		j = 0;
		while (e) {
			int chain_jmp;

			j++;
			if (strcmp(e->t->u.name, EBT_STANDARD_TARGET)) {
				e = e->next;
				continue;
			}
			chain_jmp = ((struct ebt_standard_target *)e->t)->
				    verdict;
			switch (type) {
			case 1:
			case 2:
			if (chain_jmp == chain_nr) {
				if (type == 2)
					return 1;
				ebt_print_error("Can't delete the chain '%s', it's referenced in chain '%s', rule %d",
				                ebt_nr_to_chain(replace, chain_nr + NF_BR_NUMHOOKS)->name, entries->name, j);
				return 1;
			}
			break;
			case 0:
			/* Adjust the chain jumps when necessary */
			if (chain_jmp > chain_nr)
				((struct ebt_standard_target *)e->t)->verdict--;
			break;
			} /* End switch */
			e = e->next;
		}
	}
	return 0;
}

static void decrease_chain_jumps(struct ebt_u_replace *replace)
{
	iterate_entries(replace, 0);
}

/* Selected_chain >= NF_BR_NUMHOOKS */
static void remove_udc(struct ebt_u_replace *replace)
{
	struct ebt_u_chain_list *cl, **cl2;
	struct ebt_u_entries *entries;
	struct ebt_u_entry *u_e, *tmp;
	int chain_nr = replace->selected_chain;

	if (chain_nr < NF_BR_NUMHOOKS)
		ebt_print_bug("remove_udc: chain_nr = %d < %d", chain_nr,
			      NF_BR_NUMHOOKS);
	/* First free the rules */
	entries = ebt_nr_to_chain(replace, chain_nr);
	u_e = entries->entries;
	while (u_e) {
		ebt_free_u_entry(u_e);
		tmp = u_e->next;
		free(u_e);
		u_e = tmp;
	}

	/* next, remove the chain */
	cl2 = &(replace->udc);
	while ((*cl2)->udc != entries)
		cl2 = &((*cl2)->next);
	cl = (*cl2);
	(*cl2) = (*cl2)->next;
	free(cl->udc);
	free(cl);
}

/* Used in initialization code of modules */
void ebt_register_match(struct ebt_u_match *m)
{
	int size = EBT_ALIGN(m->size) + sizeof(struct ebt_entry_match);
	struct ebt_u_match **i;

	m->m = (struct ebt_entry_match *)malloc(size);
	if (!m->m)
		ebt_print_memory();
	strcpy(m->m->u.name, m->name);
	m->m->match_size = EBT_ALIGN(m->size);
	m->init(m->m);

	for (i = &ebt_matches; *i; i = &((*i)->next));
	m->next = NULL;
	*i = m;
}

void ebt_register_watcher(struct ebt_u_watcher *w)
{
	int size = EBT_ALIGN(w->size) + sizeof(struct ebt_entry_watcher);
	struct ebt_u_watcher **i;

	w->w = (struct ebt_entry_watcher *)malloc(size);
	if (!w->w)
		ebt_print_memory();
	strcpy(w->w->u.name, w->name);
	w->w->watcher_size = EBT_ALIGN(w->size);
	w->init(w->w);

	for (i = &ebt_watchers; *i; i = &((*i)->next));
	w->next = NULL;
	*i = w;
}

void ebt_register_target(struct ebt_u_target *t)
{
	int size = EBT_ALIGN(t->size) + sizeof(struct ebt_entry_target);
	struct ebt_u_target **i;

	t->t = (struct ebt_entry_target *)malloc(size);
	if (!t->t)
		ebt_print_memory();
	strcpy(t->t->u.name, t->name);
	t->t->target_size = EBT_ALIGN(t->size);
	t->init(t->t);

	for (i = &ebt_targets; *i; i = &((*i)->next));
	t->next = NULL;
	*i = t;
}

void ebt_register_table(struct ebt_u_table *t)
{
	t->next = ebt_tables;
	ebt_tables = t;
}

void ebt_iterate_matches(void (*f)(struct ebt_u_match *))
{
	struct ebt_u_match *i;

	for (i = ebt_matches; i; i = i->next)
		f(i);
}

void ebt_iterate_watchers(void (*f)(struct ebt_u_watcher *))
{
	struct ebt_u_watcher *i;

	for (i = ebt_watchers; i; i = i->next)
		f(i);
}

void ebt_iterate_targets(void (*f)(struct ebt_u_target *))
{
	struct ebt_u_target *i;

	for (i = ebt_targets; i; i = i->next)
		f(i);
}

/* Don't use this function, use ebt_print_bug() */
void __ebt_print_bug(char *file, int line, char *format, ...)
{
	va_list l;

	va_start(l, format);
	printf(PROGNAME" v"PROGVERSION":%s:%d:--BUG--: \n", file, line);
	vprintf(format, l);
	printf("\n");
	va_end(l);
	exit (-1);
}

/* The error messages are put in here when ebt_silent == 1
 * ebt_errormsg[0] == '\0' implies there was no error */
char ebt_errormsg[ERRORMSG_MAXLEN];
/* When error messages should not be printed on the screen, after which
 * the program exit()s, set ebt_silent to 1. */
int ebt_silent;
/* Don't use this function, use ebt_print_error() */
void __ebt_print_error(char *format, ...)
{
	va_list l;

	va_start(l, format);
	if (ebt_silent && ebt_errormsg[0] == '\0') {
		vsnprintf(ebt_errormsg, ERRORMSG_MAXLEN, format, l);
		va_end(l);
	} else {
		vprintf(format, l);
		printf("\n");
		va_end(l);
		exit (-1);
	}
}
