/*
 * $Id: ebtables.c,v 1.03 2002/01/19
 *
 * Copyright (C) 2001-2002 Bart De Schuymer
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

#ifndef EBTABLES_U_H
#define EBTABLES_U_H
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/br_db.h>

struct ebt_u_entries
{
	int policy;
	__u32 nentries;
	// counter offset for this chain
	unsigned int counter_offset;
	// used for udc
	unsigned int hook_mask;
	char name[EBT_CHAIN_MAXNAMELEN];
	struct ebt_u_entry *entries;
};

struct ebt_u_chain_list
{
	struct ebt_u_entries *udc;
	struct ebt_u_chain_list *next;
	// this is only used internally, in communications.c
	char *kernel_start;
};

struct ebt_u_replace
{
	char name[EBT_TABLE_MAXNAMELEN];
	unsigned int valid_hooks;
	// nr of rules in the table
	unsigned int nentries;
	struct ebt_u_entries *hook_entry[NF_BR_NUMHOOKS];
	// user defined chains (udc) list
	struct ebt_u_chain_list *udc;
	// nr of counters userspace expects back
	unsigned int num_counters;
	// where the kernel will put the old counters
	struct ebt_counter *counters;
	// can be used e.g. to know if a standard option
	// has been specified twice
	unsigned int flags;
	// we stick the specified command (e.g. -A) in here
	char command;
	// here we stick the hook to do our thing on (can be -1 if unspecified)
	int selected_hook;
};

struct ebt_u_table
{
	char name[EBT_TABLE_MAXNAMELEN];
	int (*check)(struct ebt_u_replace *repl);
	void (*help)(char **);
	struct ebt_u_table *next;
};

struct ebt_u_match_list
{
	struct ebt_u_match_list *next;
	struct ebt_entry_match *m;
};

struct ebt_u_watcher_list
{
	struct ebt_u_watcher_list *next;
	struct ebt_entry_watcher *w;
};

struct ebt_u_entry
{
	__u32 bitmask;
	__u32 invflags;
	__u16 ethproto;
	__u8 in[IFNAMSIZ];
	__u8 logical_in[IFNAMSIZ];
	__u8 out[IFNAMSIZ];
	__u8 logical_out[IFNAMSIZ];
	__u8 sourcemac[ETH_ALEN];
	__u8 sourcemsk[ETH_ALEN];
	__u8 destmac[ETH_ALEN];
	__u8 destmsk[ETH_ALEN];
	struct ebt_u_match_list *m_list;
	struct ebt_u_watcher_list *w_list;
	struct ebt_entry_target *t;
	struct ebt_u_entry *next;
};

struct ebt_u_match
{
	char name[EBT_FUNCTION_MAXNAMELEN];
	// size of the real match data + sizeof struct ebt_match
	unsigned int size;
	void (*help)(void);
	void (*init)(struct ebt_entry_match *m);
	int (*parse)(int c, char **argv, int argc,
	        const struct ebt_u_entry *entry, unsigned int *flags,
	        struct ebt_entry_match **match);
	void (*final_check)(const struct ebt_u_entry *entry,
	   const struct ebt_entry_match *match,
	   const char *name, unsigned int hook_mask);
	void (*print)(const struct ebt_u_entry *entry,
	   const struct ebt_entry_match *match);
	int (*compare)(const struct ebt_entry_match *m1,
	   const struct ebt_entry_match *m2);
	const struct option *extra_ops;
	// can be used e.g. to check for multiple occurance of the same option
	unsigned int flags;
	unsigned int option_offset;
	struct ebt_entry_match *m;
	// if used == 1 we no longer have to add it to
	// the match chain of the new entry
	unsigned int used;
	struct ebt_u_match *next;
};

struct ebt_u_watcher
{
	char name[EBT_FUNCTION_MAXNAMELEN];
	unsigned int size;
	void (*help)(void);
	void (*init)(struct ebt_entry_watcher *w);
	int (*parse)(int c, char **argv, int argc,
	   const struct ebt_u_entry *entry, unsigned int *flags,
	   struct ebt_entry_watcher **watcher);
	void (*final_check)(const struct ebt_u_entry *entry,
	   const struct ebt_entry_watcher *watch, const char *name,
	   unsigned int hook_mask);
	void (*print)(const struct ebt_u_entry *entry,
	   const struct ebt_entry_watcher *watcher);
	int (*compare)(const struct ebt_entry_watcher *w1,
	   const struct ebt_entry_watcher *w2);
	const struct option *extra_ops;
	unsigned int flags;
	unsigned int option_offset;
	struct ebt_entry_watcher *w;
	unsigned int used;
	struct ebt_u_watcher *next;
};

struct ebt_u_target
{
	char name[EBT_FUNCTION_MAXNAMELEN];
	unsigned int size;
	void (*help)(void);
	void (*init)(struct ebt_entry_target *t);
	int (*parse)(int c, char **argv, int argc,
	   const struct ebt_u_entry *entry, unsigned int *flags,
	   struct ebt_entry_target **target);
	void (*final_check)(const struct ebt_u_entry *entry,
	   const struct ebt_entry_target *target, const char *name,
	   unsigned int hook_mask);
	void (*print)(const struct ebt_u_entry *entry,
	   const struct ebt_entry_target *target);
	int (*compare)(const struct ebt_entry_target *t1,
	   const struct ebt_entry_target *t2);
	const struct option *extra_ops;
	unsigned int option_offset;
	unsigned int flags;
	struct ebt_entry_target *t;
	unsigned int used;
	struct ebt_u_target *next;
};

void register_table(struct ebt_u_table *);
void register_match(struct ebt_u_match *);
void register_watcher(struct ebt_u_watcher *);
void register_target(struct ebt_u_target *t);
int get_table(struct ebt_u_replace *repl);
struct ebt_u_target *find_target(const char *name);
struct ebt_u_match *find_match(const char *name);
struct ebt_u_watcher *find_watcher(const char *name);
void deliver_counters(struct ebt_u_replace *repl,
   unsigned short * counterchanges);
void deliver_table(struct ebt_u_replace *repl);
void get_dbinfo(struct brdb_dbinfo *nr);
void get_db(int len, struct brdb_dbentry *db);
void deliver_allowdb(__u16 *decision);
int name_to_protocol(char *name);
void check_option(unsigned int *flags, unsigned int mask);
int check_inverse(const char option[]);
#define print_bug(format, args...) \
   {printf("BUG: "format".\n", ##args); exit(-1);}
#define print_error(format, args...) {printf(format".\n", ##args); exit(-1);}
#define print_memory() {printf("Ebtables: " __FILE__ " " __FUNCTION__ \
   " %d :Out of memory.\n", __LINE__); exit(-1);}



// used for keeping the rule counters right during rule adds or deletes
#define CNT_NORM 0
#define CNT_DEL 1
#define CNT_ADD 2
#define CNT_END 3
#define CNT_ZERO 4

#endif /* EBTABLES_U_H */
