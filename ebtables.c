/*
 * ebtables.c, v2.0 April 2002
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/br_db.h> // the database
#include <netinet/in.h>
#include <netinet/ether.h>
#include <asm/types.h>
#include "include/ebtables_u.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

// here are the number-name correspondences kept for the ethernet
// frame type field
#define PROTOCOLFILE "/etc/ethertypes"

#ifndef PROC_SYS_MODPROBE
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"
#endif

#define DATABASEHOOKNR NF_BR_NUMHOOKS
#define DATABASEHOOKNAME "DB"

static char *prog_name = PROGNAME;
static char *prog_version = PROGVERSION;
char* hooknames[NF_BR_NUMHOOKS] = {
	[NF_BR_PRE_ROUTING]"PREROUTING",
	[NF_BR_LOCAL_IN]"INPUT",
	[NF_BR_FORWARD]"FORWARD",
	[NF_BR_LOCAL_OUT]"OUTPUT",
	[NF_BR_POST_ROUTING]"POSTROUTING",
	[NF_BR_BROUTING]"BROUTING"
};

// default command line options
static struct option ebt_original_options[] = {
	{ "append"        , required_argument, 0, 'A' },
	{ "insert"        , required_argument, 0, 'I' },
	{ "delete"        , required_argument, 0, 'D' },
	{ "list"          , optional_argument, 0, 'L' },
	{ "zero"          , optional_argument, 0, 'Z' },
	{ "flush"         , optional_argument, 0, 'F' },
	{ "policy"        , required_argument, 0, 'P' },
	{ "in-interface"  , required_argument, 0, 'i' },
	{ "in-if"         , required_argument, 0, 'i' },
	{ "logical-in"    , required_argument, 0, 2   },
	{ "logical-out"   , required_argument, 0, 3   },
	{ "out-interface" , required_argument, 0, 'o' },
	{ "out-if"        , required_argument, 0, 'o' },
	{ "version"       , no_argument      , 0, 'V' },
	{ "help"          , no_argument      , 0, 'h' },
	{ "jump"          , required_argument, 0, 'j' },
	{ "proto"         , required_argument, 0, 'p' },
	{ "protocol"      , required_argument, 0, 'p' },
	{ "db"            , required_argument, 0, 'b' },
	{ "source"        , required_argument, 0, 's' },
	{ "src"           , required_argument, 0, 's' },
	{ "destination"   , required_argument, 0, 'd' },
	{ "dst"           , required_argument, 0, 'd' },
	{ "table"         , required_argument, 0, 't' },
	{ "modprobe"      , required_argument, 0, 'M' },
	{ 0 }
};

static struct option *ebt_options = ebt_original_options;

// yup, all the possible target names
char* standard_targets[NUM_STANDARD_TARGETS] = {
	"ACCEPT",
	"DROP",
	"CONTINUE",
};

unsigned char mac_type_unicast[ETH_ALEN] = {0,0,0,0,0,0};
unsigned char msk_type_unicast[ETH_ALEN] = {1,0,0,0,0,0};
unsigned char mac_type_multicast[ETH_ALEN] = {1,0,0,0,0,0};
unsigned char msk_type_multicast[ETH_ALEN] = {1,0,0,0,0,0};
unsigned char mac_type_broadcast[ETH_ALEN] = {255,255,255,255,255,255};
unsigned char msk_type_broadcast[ETH_ALEN] = {255,255,255,255,255,255};

// tells what happened to the old rules
static unsigned short *counterchanges;
// holds all the data
static struct ebt_u_replace replace;

// the chosen table
static struct ebt_u_table *table = NULL;
// the lists of supported tables, matches, watchers and targets
static struct ebt_u_table *tables = NULL;
static struct ebt_u_match *matches = NULL;
static struct ebt_u_watcher *watchers = NULL;
static struct ebt_u_target *targets = NULL;

struct ebt_u_target *find_target(const char *name)
{
	struct ebt_u_target *t = targets;

	while(t && strcmp(t->name, name))
		t = t->next;
	return t;
}

struct ebt_u_match *find_match(const char *name)
{
	struct ebt_u_match *m = matches;

	while(m && strcmp(m->name, name))
		m = m->next;
	return m;
}

struct ebt_u_watcher *find_watcher(const char *name)
{
	struct ebt_u_watcher *w = watchers;

	while(w && strcmp(w->name, name))
		w = w->next;
	return w;
}

struct ebt_u_table *find_table(char *name)
{
	struct ebt_u_table *t = tables;

	while (t && strcmp(t->name, name))
		t = t->next;
	return t;
}

// The pointers in here are special:
// The struct ebt_target * pointer is actually a struct ebt_u_target * pointer.
// instead of making yet a few other structs, we just do a cast.
// We need a struct ebt_u_target pointer because we know the address of the data
// they point to won't change. We want to allow that the struct ebt_u_target.t
// member can change.
// Same holds for the struct ebt_match and struct ebt_watcher pointers
struct ebt_u_entry *new_entry;

void initialize_entry(struct ebt_u_entry *e)
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
	// the init function of the standard target should have put the verdict
	// on CONTINUE
	e->t = (struct ebt_entry_target *)find_target(EBT_STANDARD_TARGET);
	if (!e->t)
		print_bug("Couldn't load standard target\n");
}

// this doesn't free e, becoz the calling function might need e->next
void free_u_entry(struct ebt_u_entry *e)
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

// the user will use the match, so put it in new_entry
static void add_match(struct ebt_u_match *m)
{
	struct ebt_u_match_list **m_list, *new;

	m->used = 1;
	for (m_list = &new_entry->m_list;
	*m_list; m_list = &(*m_list)->next);
	new = (struct ebt_u_match_list *)
	   malloc(sizeof(struct ebt_u_match_list));
	if (!new)
		print_memory();
	*m_list = new;
	new->next = NULL;
	new->m = (struct ebt_entry_match *)m;
}

static void add_watcher(struct ebt_u_watcher *w)
{
	struct ebt_u_watcher_list **w_list;
	struct ebt_u_watcher_list *new;

	w->used = 1;
	for (w_list = &new_entry->w_list;
	   *w_list; w_list = &(*w_list)->next);
	new = (struct ebt_u_watcher_list *)
	   malloc(sizeof(struct ebt_u_watcher_list));
	if (!new)
		print_memory();
	*w_list = new;
	new->next = NULL;
	new->w = (struct ebt_entry_watcher *)w;
}

static int global_option_offset = 0;
#define OPTION_OFFSET 256
static struct option *
merge_options(struct option *oldopts, const struct option *newopts,
	    unsigned int *options_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	if (!newopts || !oldopts || !options_offset)
		print_bug("merge wrong");
	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*options_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	if (!merge)
		print_memory();
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *options_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));
	// only free dynamically allocated stuff
	if (oldopts != ebt_original_options)
		free(oldopts);

	return merge;
}

void register_match(struct ebt_u_match *m)
{
	int size = m->size + sizeof(struct ebt_entry_match);
	struct ebt_u_match **i;

	m->m = (struct ebt_entry_match *)malloc(size);
	if (!m->m)
		print_memory();
	strcpy(m->m->u.name, m->name);
	m->m->match_size = m->size;
	ebt_options = merge_options
	   (ebt_options, m->extra_ops, &(m->option_offset));
	m->init(m->m);

	for (i = &matches; *i; i = &((*i)->next));
	m->next = NULL;
	*i = m;
}

void register_watcher(struct ebt_u_watcher *w)
{
	int size = w->size + sizeof(struct ebt_entry_watcher);
	struct ebt_u_watcher **i;

	w->w = (struct ebt_entry_watcher *)malloc(size);
	if (!w->w)
		print_memory();
	strcpy(w->w->u.name, w->name);
	w->w->watcher_size = w->size;
	ebt_options = merge_options
	   (ebt_options, w->extra_ops, &(w->option_offset));
	w->init(w->w);

	for (i = &watchers; *i; i = &((*i)->next));
	w->next = NULL;
	*i = w;
}

void register_target(struct ebt_u_target *t)
{
	int size = t->size + sizeof(struct ebt_entry_target);
	struct ebt_u_target **i;

	t->t = (struct ebt_entry_target *)malloc(size);
	if (!t->t)
		print_memory();
	strcpy(t->t->u.name, t->name);
	t->t->target_size = t->size;
	ebt_options = merge_options
	   (ebt_options, t->extra_ops, &(t->option_offset));
	t->init(t->t);
	for (i = &targets; *i; i = &((*i)->next));
	t->next = NULL;
	*i = t;
}

void register_table(struct ebt_u_table *t)
{
	t->next = tables;
	tables = t;
}

// blatently stolen (again) from iptables.c userspace program
// find out where the modprobe utility is located
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
		if (ret[strlen(ret)-1]=='\n')
			ret[strlen(ret)-1]=0;
		close(procfile);
		return ret;
	}
 fail:
	free(ret);
	close(procfile);
	return NULL;
}

// I hate stealing, really... Lets call it a tribute.
int ebtables_insmod(const char *modname, const char *modprobe)
{
	char *buf = NULL;
	char *argv[3];

	/* If they don't explicitly set it, read out of kernel */
	if (!modprobe) {
		buf = get_modprobe();
		if (!buf)
			return -1;
		modprobe = buf;
	}

	switch (fork()) {
	case 0:
		argv[0] = (char *)modprobe;
		argv[1] = (char *)modname;
		argv[2] = NULL;
		execv(argv[0], argv);

		/* not usually reached */
		exit(0);
	case -1:
		return -1;

	default: /* parent */
		wait(NULL);
	}

	free(buf);
	return 0;
}


// used to parse /etc/etherproto
int disregard_whitespace(char *buffer, FILE *ifp)
{
	int hlp;
	buffer[0] = '\t';
	while (buffer[0] == '\t' || buffer[0] == '\n' || buffer[0] == ' ') {
		hlp = fscanf(ifp, "%c", buffer);
		if (hlp == EOF || hlp == 0) return -1;
	}
	return 0;
}

// used to parse /etc/etherproto
int disregard_tabspace(char *buffer, FILE *ifp)
{
	int hlp;
	buffer[0] = '\t';
	while (buffer[0] == '\t' || buffer[0] == ' ') {
		hlp = fscanf(ifp, "%c", buffer);
		if (hlp == EOF || hlp == 0) return -1;
	}
	return 0;
}

// helper function: processes a line of data from the file /etc/ethertypes
int get_a_line(char *buffer, char *value, FILE *ifp)
{
	int i, hlp;
	char anotherhlp;

	/* discard comment lines && whitespace*/
	while (1) {
		if (disregard_whitespace(buffer, ifp)) return -1;
		if (buffer[0] == '#')
			while (1) {
				hlp = fscanf(ifp, "%c", &anotherhlp);
				if (!hlp || hlp == EOF)
					return -1;
				if (anotherhlp == '\n')
					break;
			}
		else break;
	}

	// buffer[0] already contains the first letter
	for (i = 1; i < 21; i++) {
		hlp = fscanf(ifp, "%c", buffer + i);
		if (hlp == EOF || hlp == 0) return -1;
		if (buffer[i] == '\t' || buffer[i] == ' ')
			break;
	}
	if (i == 21) return -1;
	buffer[i] = '\0';
	if (disregard_tabspace(value, ifp))
		return -1;
	// maybe I should allow 0x0800 instead of 0800, but I'm feeling lazy
	// buffer[0] already contains the first letter
	for (i = 1; i < 5; i++) {
		hlp = fscanf(ifp, "%c", value+i);
		if (value[i] == '\n' || value[i] == '\t' ||
		   value[i] == ' ' || hlp == EOF)
			break;
	}
	if (i == 5) return -1;
	// discard comments at the end of a line
	if (value[i] == '\t' || value[i] == ' ')
		while (1) {
			hlp = fscanf(ifp, "%c", &anotherhlp);
			if (!hlp || hlp == EOF || anotherhlp == '\n')
				break;
		}
	value[i] = '\0';
	return 0;
}

// helper function for list_em()
int number_to_name(unsigned short proto, char *name)
{
	FILE *ifp;
	char buffer[21], value[5], *bfr;
	unsigned short i;

	if ( !(ifp = fopen(PROTOCOLFILE, "r")) )
		return -1;
	while (1) {
		if (get_a_line(buffer, value, ifp)) {
			fclose(ifp);
			return -1;
		}
		i = (unsigned short) strtol(value, &bfr, 16);
		if (*bfr != '\0' || i != proto)
			continue;
		strcpy(name, buffer);
		fclose(ifp);
		return 0;
	}
}

// helper function for list_rules()
static void list_em(int hooknr)
{
	int i, j, space = 0, digits;
	struct ebt_u_entry *hlp;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	struct ebt_u_match *m;
	struct ebt_u_watcher *w;
	struct ebt_u_target *t;
	char name[21];

	hlp = replace.hook_entry[hooknr]->entries;
	printf("\nBridge chain: %s\nPolicy: %s\n", hooknames[hooknr],
	   standard_targets[replace.hook_entry[hooknr]->policy]);
	printf("nr. of entries: %d \n", replace.hook_entry[hooknr]->nentries);

	i = replace.hook_entry[hooknr]->nentries;
	while (i >9) {
		space++;
		i /= 10;
	}

	for (i = 0; i < replace.hook_entry[hooknr]->nentries; i++) {
		digits = 0;
		// A little work to get nice rule numbers.
		while (j > 9) {
			digits++;
			j /= 10;
		}
		for (j = 0; j < space - digits; j++)
			printf(" ");
		printf("%d. ", i + 1);

		// Don't print anything about the protocol if no protocol was
		// specified, obviously this means any protocol will do.
		if (!(hlp->bitmask & EBT_NOPROTO)) {
			printf("eth proto: ");
			if (hlp->invflags & EBT_IPROTO)
				printf("! ");
			if (hlp->bitmask & EBT_802_3)
				printf("Length, ");
			else {
				if (number_to_name(ntohs(hlp->ethproto), name))
					printf("0x%x, ", ntohs(hlp->ethproto));
				else
					printf("%s, ", name);
			}
		}
		if (hlp->bitmask & EBT_SOURCEMAC) {
			char hlpmsk[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

			printf("source mac: ");
			if (hlp->invflags & EBT_ISOURCE)
				printf("! ");
			if (!memcmp(hlp->sourcemac, mac_type_unicast, 6) &&
			    !memcmp(hlp->sourcemsk, msk_type_unicast, 6)) {
				printf("Unicast");
				goto endsrc;
			}
			if (!memcmp(hlp->sourcemac, mac_type_multicast, 6) &&
			    !memcmp(hlp->sourcemsk, msk_type_multicast, 6)) {
				printf("Multicast");
				goto endsrc;
			}
			if (!memcmp(hlp->sourcemac, mac_type_broadcast, 6) &&
			    !memcmp(hlp->sourcemsk, msk_type_broadcast, 6)) {
				printf("Broadcast");
				goto endsrc;
			}
			printf("%s", ether_ntoa((struct ether_addr *)
			   hlp->sourcemac));
			if (memcmp(hlp->sourcemsk, hlpmsk, 6)) {
				printf("/");
				printf("%s", ether_ntoa((struct ether_addr *)
				   hlp->sourcemsk));
			}
endsrc:
			printf(", ");
		}
		if (hlp->bitmask & EBT_DESTMAC) {
			char hlpmsk[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

			printf("dest mac: ");
			if (hlp->invflags & EBT_IDEST)
				printf("! ");
			if (!memcmp(hlp->destmac, mac_type_unicast, 6) &&
			    !memcmp(hlp->destmsk, msk_type_unicast, 6)) {
				printf("Unicast");
				goto enddst;
			}
			if (!memcmp(hlp->destmac, mac_type_multicast, 6) &&
			    !memcmp(hlp->destmsk, msk_type_multicast, 6)) {
				printf("Multicast");
				goto enddst;
			}
			if (!memcmp(hlp->destmac, mac_type_broadcast, 6) &&
			    !memcmp(hlp->destmsk, msk_type_broadcast, 6)) {
				printf("Broadcast");
				goto enddst;
			}
			printf("%s", ether_ntoa((struct ether_addr *)
			   hlp->destmac));
			if (memcmp(hlp->destmsk, hlpmsk, 6)) {
				printf("/");
				printf("%s", ether_ntoa((struct ether_addr *)
				   hlp->destmsk));
			}
enddst:
			printf(", ");
		}
		if (hlp->in[0] != '\0') {
			if (hlp->invflags & EBT_IIN)
				printf("! ");
			printf("in-if: %s, ", hlp->in);
		}
		if (hlp->logical_in[0] != '\0') {
			if (hlp->invflags & EBT_ILOGICALIN)
				printf("! ");
			printf("logical in-if: %s, ", hlp->logical_in);
		}
		if (hlp->logical_out[0] != '\0') {
			if (hlp->invflags & EBT_ILOGICALOUT)
				printf("! ");
			printf("logical out-if: %s, ", hlp->logical_out);
		}
		if (hlp->out[0] != '\0') {
			if (hlp->invflags & EBT_IOUT)
				printf("! ");
			printf("out-if: %s, ", hlp->out);
		}

		m_l = hlp->m_list;
		while (m_l) {
			m = find_match(m_l->m->u.name);
			if (!m)
				print_bug("Match not found");
			m->print(hlp, m_l->m);
			m_l = m_l->next;
		}
		w_l = hlp->w_list;
		while (w_l) {
			w = find_watcher(w_l->w->u.name);
			if (!w)
				print_bug("Watcher not found");
			w->print(hlp, w_l->w);
			w_l = w_l->next;
		}

		printf("target: ");
		t = find_target(hlp->t->u.name);
		if (!t)
			print_bug("Target not found");
		t->print(hlp, hlp->t);
		printf(", count = %llu",
		   replace.counters[replace.counter_entry[hooknr] + i].pcnt);
		printf("\n");
		hlp = hlp->next;
	}
}

// parse the chain name and return the corresponding nr
int get_hooknr(char* arg)
{
	int i;

	// database is special case (not really a chain)
	if (!strcmp(arg, DATABASEHOOKNAME))
		return DATABASEHOOKNR;

	for (i = 0; i < NF_BR_NUMHOOKS; i++)
		if (!strcmp(arg, hooknames[i]))
			return i;
	return -1;
}

// yup, print out help
void print_help()
{
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;

	printf(
"%s v%s\n"
"Usage:\n"
"ebtables -[ADI] chain rule-specification [options]\n"
"ebtables -P chain target\n"
"ebtables -[LFZ] [chain]\n"
"ebtables -[b] [y,n]\n"
"Commands:\n"
"--append -A chain             : Append to chain\n"
"--delete -D chain             : Delete matching rule from chain\n"
"--delete -D chain rulenum     : Delete rule at position rulenum from chain\n"
"--insert -I chain rulenum     : insert rule at position rulenum in chain\n"
"--list   -L [chain]           : List the rules in a chain or in all chains\n"
"--list   -L "DATABASEHOOKNAME"                : List the database (if present)\n"
"--flush  -F [chain]           : Delete all rules in chain or in all chains\n"
"--zero   -Z [chain]           : Put counters on zero in chain or in all chains\n"
"--policy -P chain target      : Change policy on chain to target\n"
"Options:\n"
"--proto  -p [!] proto         : protocol hexadecimal, by name or LENGTH\n"
"--src    -s [!] address[/mask]: source mac address\n"
"--dst    -d [!] address[/mask]: destination mac address\n"
"--in-if  -i [!] name          : network input interface name\n"
"--out-if -o [!] name          : network output interface name\n"
"--logical-in  [!] name        : logical bridge input interface name\n"
"--logical-out [!] name        : logical bridge output interface name\n"
"--modprobe -M                 : try to insert modules using this command\n"
"--version -V                  : print package version\n"
"\n" ,
	prog_name,
	prog_version);

	m_l = new_entry->m_list;
	while (m_l) {
		((struct ebt_u_match *)m_l->m)->help();
		printf("\n");
		m_l = m_l->next;
	}
	w_l = new_entry->w_list;
	while (w_l) {
		((struct ebt_u_watcher *)w_l->w)->help();
		printf("\n");
		w_l = w_l->next;
	}
	((struct ebt_u_target *)new_entry->t)->help();
	printf("\n");
	if (table->help)
		table->help(hooknames);
	exit(0);
}

// execute command L
static void list_rules()
{
	int i;

	printf("Bridge table: %s\n", table->name);
	if (replace.selected_hook != -1) list_em(replace.selected_hook);
	else
		for (i = 0; i < NF_BR_NUMHOOKS; i++)
			if (replace.valid_hooks & (1 << i))
				list_em(i);
	return;
}

// execute command P
static void change_policy(int policy)
{
	int i;

	// don't do anything if the policy is the same
	if (replace.hook_entry[replace.selected_hook]->policy != policy) {
		replace.hook_entry[replace.selected_hook]->policy = policy;
		replace.num_counters = replace.nentries;
		if (replace.nentries) {
			// '+ 1' for the CNT_END
			if (!(counterchanges = (unsigned short *) malloc(
			   (replace.nentries + 1) * sizeof(unsigned short))))
				print_memory();
			// done nothing special to the rules
			for (i = 0; i < replace.nentries; i++)
				counterchanges[i] = CNT_NORM;
			counterchanges[replace.nentries] = CNT_END;
		}
		else
			counterchanges = NULL;
	}
	else
		exit(0);
}

// flush one chain or the complete table
static void flush_chains()
{
	int i, j, oldnentries;
	unsigned short *cnt;
	struct ebt_u_entry *u_e, *tmp;

	// flush whole table
	if (replace.selected_hook == -1) {
		if (replace.nentries == 0)
			exit(0);
		replace.nentries = 0;
		// no need for the kernel to give us counters back
		replace.num_counters = 0;
		// free everything and zero (n)entries
		for (i = 0; i < NF_BR_NUMHOOKS; i++) {
			if (!(replace.valid_hooks & (1 << i)))
				continue;
			replace.hook_entry[i]->nentries = 0;
			u_e = replace.hook_entry[i]->entries;
			while (u_e) {
				free_u_entry(u_e);
				tmp = u_e->next;
				free(u_e);
				u_e = tmp;
			}
			replace.hook_entry[i]->entries = NULL;
		}
		return;
	}

	if (replace.hook_entry[replace.selected_hook]->nentries == 0)
		exit(0);
	oldnentries = replace.nentries;
	replace.nentries = replace.nentries -
	   replace.hook_entry[replace.selected_hook]->nentries;

	// delete the counters belonging to the specified chain
	if (replace.nentries) {
		// +1 for CNT_END
		if ( !(counterchanges = (unsigned short *)
		   malloc((oldnentries + 1) * sizeof(unsigned short))) )
			print_memory();
		cnt = counterchanges;
		for (i = 0; i < NF_BR_NUMHOOKS; i++) {
			if (!(replace.valid_hooks & (1 << i)))
				continue;
			for (j = 0; j < replace.hook_entry[i]->nentries; j++) {
				if (i != replace.selected_hook)
					*cnt = CNT_NORM;
				else
					*cnt = CNT_DEL;
				cnt++;
			}
		}
		*cnt = CNT_END;
		replace.num_counters = oldnentries;
	}
	else
		replace.num_counters = 0;

	replace.hook_entry[replace.selected_hook]->nentries = 0;
	u_e = replace.hook_entry[replace.selected_hook]->entries;
	while (u_e) {
		free_u_entry(u_e);
		tmp = u_e->next;
		free(u_e);
		u_e = tmp;
	}
	replace.hook_entry[replace.selected_hook]->entries = NULL;
}	

// -1 == no match
static int check_rule_exists(int rule_nr)
{
	struct ebt_u_entry *u_e;
	struct ebt_u_match_list *m_l, *m_l2;
	struct ebt_u_match *m;
	struct ebt_u_watcher_list *w_l, *w_l2;
	struct ebt_u_watcher *w;
	struct ebt_u_target *t = (struct ebt_u_target *)new_entry->t;
	int i, j, k;

	// handle '-D chain rulenr' command
	if (rule_nr != -1) {
		if (rule_nr >
		   replace.hook_entry[replace.selected_hook]->nentries)
			return 0;
		// user starts counting from 1
		return rule_nr - 1;
	}
	u_e = replace.hook_entry[replace.selected_hook]->entries;
	// check for an existing rule (if there are duplicate rules,
	// take the first occurance)
	for (i = 0; i < replace.hook_entry[replace.selected_hook]->nentries;
	   i++, u_e = u_e->next) {
		if (!u_e)
			print_bug("Hmm, trouble");
		if ( u_e->ethproto == new_entry->ethproto
		   && !strcmp(u_e->in, new_entry->in)
		   && !strcmp(u_e->out, new_entry->out)
		   && u_e->bitmask == new_entry->bitmask) {
			if (new_entry->bitmask & EBT_SOURCEMAC &&
			   strcmp(u_e->sourcemac, new_entry->sourcemac))
				continue;
			if (new_entry->bitmask & EBT_DESTMAC &&
			   strcmp(u_e->destmac, new_entry->destmac))
				continue;
			if (new_entry->bitmask != u_e->bitmask ||
			   new_entry->invflags != u_e->invflags)
				continue;
			// compare all matches
			m_l = new_entry->m_list;
			j = 0;
			while (m_l) {
				m = (struct ebt_u_match *)(m_l->m);
				m_l2 = u_e->m_list;
				while (m_l2 &&
				   strcmp(m_l2->m->u.name, m->m->u.name))
					m_l2 = m_l2->next;
				if (!m_l2 || !m->compare(m->m, m_l2->m))
					goto letscontinue;
				j++;
				m_l = m_l->next;
			}
			// now be sure they have the same nr of matches
			k = 0;
			m_l = u_e->m_list;
			while (m_l) {
				k++;
				m_l = m_l->next;
			}
			if (j != k)
				continue;

			// compare all watchers
			w_l = new_entry->w_list;
			j = 0;
			while (w_l) {
				w = (struct ebt_u_watcher *)(w_l->w);
				w_l2 = u_e->w_list;
				while (w_l2 &&
				   strcmp(w_l2->w->u.name, w->w->u.name))
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
		}
letscontinue:
	}
	return -1;
}

// execute command A
static void add_rule(int rule_nr)
{
	int i, j;
	struct ebt_u_entry *u_e, *u_e2;
	unsigned short *cnt;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;

	if (rule_nr != -1) { // command -I
		if (--rule_nr >
		   replace.hook_entry[replace.selected_hook]->nentries)
			print_error("rule nr too high: %d > %d", rule_nr,
			   replace.hook_entry[replace.selected_hook]->nentries);
	} else
		rule_nr = replace.hook_entry[replace.selected_hook]->nentries;
	// we're adding one rule
	replace.num_counters = replace.nentries;
	replace.nentries++;
	replace.hook_entry[replace.selected_hook]->nentries++;

	// handle counter stuff
	// +1 for CNT_END
	if ( !(counterchanges = (unsigned short *)
	   malloc((replace.nentries + 1) * sizeof(unsigned short))) )
		print_memory();
	cnt = counterchanges;
	for (i = 0; i < replace.selected_hook; i++) {
		if (!(replace.valid_hooks & (1 << i)))
			continue;
		for (j = 0; j < replace.hook_entry[i]->nentries; j++) {
			*cnt = CNT_NORM;
			cnt++;
		}
	}
	for (i = 0; i < rule_nr; i++) {
		*cnt = CNT_NORM;
		cnt++;
	}
	*cnt = CNT_ADD;
	cnt++;
	while (cnt != counterchanges + replace.nentries) {
		*cnt = CNT_NORM;
		cnt++;
	}
	*cnt = CNT_END;

	// go to the right position in the chain
	u_e2 = NULL;
	u_e = replace.hook_entry[replace.selected_hook]->entries;
	for (i = 0; i < rule_nr; i++) {
		u_e2 = u_e;
		u_e = u_e->next;
	}
	// insert the rule
	if (u_e2)
		u_e2->next = new_entry;
	else
		replace.hook_entry[replace.selected_hook]->entries = new_entry;
	new_entry->next = u_e;

	// put the ebt_[match, watcher, target] pointers in place
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
}

// execute command D
static void delete_rule(int rule_nr)
{
	int i, j, lentmp = 0;
	unsigned short *cnt;
	struct ebt_u_entry *u_e, *u_e2;

	if ( (i = check_rule_exists(rule_nr)) == -1 )
		print_error("Sorry, rule does not exists");

	// we're deleting a rule
	replace.num_counters = replace.nentries;
	replace.nentries--;

	if (replace.nentries) {
		for (j = 0; j < replace.selected_hook; j++) {
			if (!(replace.valid_hooks & (1 << j)))
				continue;
			lentmp += replace.hook_entry[j]->nentries;
		}
		lentmp += i;
		// +1 for CNT_END
		if ( !(counterchanges = (unsigned short *)malloc(
		   (replace.num_counters + 1) * sizeof(unsigned short))) )
			print_memory();
		cnt = counterchanges;
		for (j = 0; j < lentmp; j++) {
			*cnt = CNT_NORM;
			cnt++;
		}
		*cnt = CNT_DEL;
		cnt++;
		for (j = 0; j < replace.num_counters - lentmp; j++) {
			*cnt = CNT_NORM;
			cnt++;
		}
		*cnt = CNT_END;
	}
	else
		replace.num_counters = 0;

	// go to the right position in the chain
	u_e2 = NULL;
	u_e = replace.hook_entry[replace.selected_hook]->entries;
	for (j = 0; j < i; j++) {
		u_e2 = u_e;
		u_e = u_e->next;
	}

	// remove from the chain
	if (u_e2)
		u_e2->next = u_e->next;
	else
		replace.hook_entry[replace.selected_hook]->entries = u_e->next;

	replace.hook_entry[replace.selected_hook]->nentries--;
	// free everything
	free_u_entry(u_e);
	free(u_e);
}

// execute command Z
void zero_counters(int zerochain)
{

	if (zerochain == -1) {
		// tell main() we don't update the counters
		// this results in tricking the kernel to zero his counters,
		// naively expecting userspace to update its counters. Muahahaha
		counterchanges = NULL;
		replace.num_counters = 0;
	} else {
		int i, j;
		unsigned short *cnt;

		if (replace.hook_entry[zerochain]->nentries == 0)
			exit(0);
		counterchanges = (unsigned short *)
		   malloc((replace.nentries + 1) * sizeof(unsigned short));
		if (!counterchanges)
			print_memory();
		cnt = counterchanges;
		for (i = 0; i < zerochain; i++) {
			if (!(replace.valid_hooks & (1 << i)))
				continue;
			for (j = 0; j < replace.hook_entry[i]->nentries; j++) {
				*cnt = CNT_NORM;
				cnt++;
			}
		}
		for (i = 0; i < replace.hook_entry[zerochain]->nentries; i++) {
			*cnt = CNT_ZERO;
			cnt++;
		}
		while (cnt != counterchanges + replace.nentries) {
			*cnt = CNT_NORM;
			cnt++;
		}
		*cnt = CNT_END;
	}
}

// list the database (optionally compiled into the kernel)
static void list_db()
{
	struct brdb_dbinfo nr;
	struct brdb_dbentry *db;
	char name[21];
	int i;

	get_dbinfo(&nr);

	// 0 : database disabled (-db n)
	if (!(nr.nentries))
		print_error("Database not present"
		            " (disabled), try ebtables --db y");
	nr.nentries--;
	if (!nr.nentries) print_error("Database empty");
	if ( !(db = (struct brdb_dbentry *)
	   malloc(nr.nentries * sizeof(struct brdb_dbentry))) )
		print_memory();

	get_db(nr.nentries, db);
	printf("number of entries: %d\n", nr.nentries);
	for (i = 0; i < nr.nentries; i++) {
		printf(
		"%d:\n"
		"hook    : %s\n"
		"in-if   : %s\n"
		"out-if  : %s\n"
		"protocol: ", i + 1, hooknames[db->hook], db->in, db->out);
		if (db->ethproto == IDENTIFY802_3)
			printf("802.2/802.3 STYLE LENGTH FIELD\n");
		else {
			if (number_to_name(ntohs(db->ethproto), name))
				printf("%x\n",ntohs(db->ethproto));
			else
				printf("%s\n", name);
		}
		db++;
	}
	exit(0);
}

// handle db [dis,en]abling
static void allowdb(char yorn)
{
	__u16 decision;

	if (yorn != 'y' && yorn != 'n')
		print_error("Option [y] or [n] needed");

	if (yorn == 'y')
		decision = BRDB_DB;
	else
		decision = BRDB_NODB;

	deliver_allowdb(&decision);

	exit(0);
}

// set ethproto
int name_to_protocol(char *name)
{
	FILE *ifp;
	char buffer[21], value[5], *bfr;
	unsigned short i;

	if (!strcasecmp("LENGTH", name)) {
		new_entry->ethproto = 0;
		new_entry->bitmask |= EBT_802_3;
		return 1;
	}
	if ( !(ifp = fopen(PROTOCOLFILE, "r")) )
		return -1;
	while (1) {
		if (get_a_line(buffer, value, ifp)) return -1;
		if (strcasecmp(buffer, name))
			continue;
		i = (unsigned short) strtol(value, &bfr, 16);
		if (*bfr != '\0')
			return -1;
		new_entry->ethproto = i;
		fclose(ifp);
		return 0;
	}
	return -1;
}

// put the mac address into 6 (ETH_ALEN) bytes
int getmac_and_mask(char *from, char *to, char *mask)
{
	char *p;
	int i;
	struct ether_addr *addr;

	if (strcasecmp(from, "Unicast") == 0) {
		memcpy(to, mac_type_unicast, ETH_ALEN);
		memcpy(mask, msk_type_unicast, ETH_ALEN);
		return 0;
	}
	if (strcasecmp(from, "Multicast") == 0) {
		memcpy(to, mac_type_multicast, ETH_ALEN);
		memcpy(mask, msk_type_multicast, ETH_ALEN);
		return 0;
	}
	if (strcasecmp(from, "Broadcast") == 0) {
		memcpy(to, mac_type_broadcast, ETH_ALEN);
		memcpy(mask, msk_type_broadcast, ETH_ALEN);
		return 0;
	}
	if ( (p = strrchr(from, '/')) != NULL) {
		*p = '\0';
		if (!(addr = ether_aton(p + 1)))
			return -1;
		memcpy(mask, addr, ETH_ALEN);
	} else
		memset(mask, 0xff, ETH_ALEN);
	if (!(addr = ether_aton(from)))
		return -1;
	memcpy(to, addr, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		to[i] &= mask[i];
	return 0;
}

int check_inverse(const char option[])
{
	if (strcmp(option, "!") == 0) {
		optind++;
		return 1;
	}
	return 0;
}

void check_option(unsigned int *flags, unsigned int mask)
{
	if (*flags & mask)
		print_error("Multiple use of same option not allowed");
	*flags |= mask;
}

#define OPT_COMMAND    0x01
#define OPT_TABLE      0x02
#define OPT_IN         0x04
#define OPT_OUT        0x08
#define OPT_JUMP       0x10
#define OPT_PROTOCOL   0x20
#define OPT_SOURCE     0x40
#define OPT_DEST       0x80
#define OPT_ZERO       0x100
#define OPT_LOGICALIN  0x200
#define OPT_LOGICALOUT 0x400
// the main thing
int main(int argc, char *argv[])
{
	char *buffer, allowbc = 'n';
	int c, i;
	// this special one for the -Z option (we can have -Z <this> -L <that>)
	int zerochain = -1;
	int policy = -1;
	int rule_nr = -1;// used for -D chain number
	struct ebt_u_target *t;
	struct ebt_u_match *m;
	struct ebt_u_watcher *w;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	const char *modprobe = NULL;

	// initialize the table name, OPT_ flags, selected hook and command
	strcpy(replace.name, "filter");
	replace.flags = 0;
	replace.selected_hook = -1;
	replace.command = 'h';

	new_entry = (struct ebt_u_entry *)malloc(sizeof(struct ebt_u_entry));
	if (!new_entry)
		print_memory();
	// put some sane values in our new entry
	initialize_entry(new_entry);

	// getopt saves the day
	while ((c = getopt_long(argc, argv,
	   "-A:D:I:L::Z::F::P:Vhi:o:j:p:b:s:d:t:M:", ebt_options, NULL)) != -1) {
		switch (c) {

		case 'A': // add a rule
		case 'D': // delete a rule
		case 'P': // define policy
		case 'I': // insert a rule
			replace.command = c;
			if (replace.flags & OPT_COMMAND)
				print_error("Multiple commands not allowed");
			replace.flags |= OPT_COMMAND;
			if ((replace.selected_hook = get_hooknr(optarg)) == -1)
				print_error("Bad chain");
			if (c == 'D' && optind < argc &&
			   argv[optind][0] != '-') {
				rule_nr = strtol(argv[optind], &buffer, 10);
				if (*buffer != '\0' || rule_nr < 0)
					print_error("Problem with the "
					            "specified rule number");
				optind++;
			}
			if (c == 'P') {
				if (optind >= argc)
					print_error("No policy specified");
				for (i = 0; i < 2; i++)
					if (!strcmp(argv[optind],
					   standard_targets[i])) {
						policy = i;
						break;
					}
				if (policy == -1)
					print_error("Wrong policy");
				optind++;
			}
			if (c == 'I') {
				if (optind >= argc)
					print_error("No rulenr for -I"
					            " specified");
				rule_nr = strtol(argv[optind], &buffer, 10);
				if (*buffer != '\0' || rule_nr < 0)
					print_error("Problem with the specified"
					            " rule number");
				optind++;
			}
			break;

		case 'L': // list
		case 'F': // flush
		case 'Z': // zero counters
			if (c == 'Z') {
				if (replace.flags & OPT_ZERO)
					print_error("Multiple commands"
					            " not allowed");
				if ( (replace.flags & OPT_COMMAND &&
				   replace.command != 'L'))
					print_error("command -Z only allowed "
					            "together with command -L");
				replace.flags |= OPT_ZERO;
			} else {
				replace.command = c;
				if (replace.flags & OPT_COMMAND)
					print_error("Multiple commands"
					            " not allowed");
				replace.flags |= OPT_COMMAND;
			}
			i = -1;
			if (optarg) {
				if ( (i = get_hooknr(optarg)) == -1 )
					print_error("Bad chain");
			} else
				if (optind < argc && argv[optind][0] != '-') {
					if ((i = get_hooknr(argv[optind]))
					   == -1)
						print_error("Bad chain");
					optind++;
				}
			if (i != -1) {
				if (c == 'Z')
					zerochain = i;
				else
					replace.selected_hook = i;
			}
			break;

		case 'V': // version
			replace.command = 'V';
			if (replace.flags & OPT_COMMAND)
				print_error("Multiple commands not allowed");
			printf("%s, %s\n", prog_name, prog_version);
			exit(0);

		case 'M': // modprobe
			modprobe = optarg;
			break;

		case 'h': // help
			if (replace.flags & OPT_COMMAND)
				print_error("Multiple commands not allowed");
			replace.command = 'h';
			// All other arguments should be extension names
			while (optind < argc) {
				struct ebt_u_match *m;
				struct ebt_u_watcher *w;

				if ((m = find_match(argv[optind])))
					add_match(m);
				else if ((w = find_watcher(argv[optind])))
					add_watcher(w);
				else {
					if (!(t = find_target(argv[optind])))
						print_error("Extension %s "
						   "not found", argv[optind]);
					if (replace.flags & OPT_JUMP)
						print_error("Sorry, you can "
						 "only see help for one "
						 "target extension each time");
					replace.flags |= OPT_JUMP;
					new_entry->t =
					   (struct ebt_entry_target *)t;
				}
				optind++;
			}
			break;

		case 't': // table
			check_option(&replace.flags, OPT_TABLE);
			if (strlen(optarg) > EBT_TABLE_MAXNAMELEN)
				print_error("Table name too long");
			strcpy(replace.name, optarg);
			break;

		case 'i': // input interface
		case 2  : // logical input interface
		case 'o': // output interface
		case 3  : // logical output interface
		case 'j': // target
		case 'p': // net family protocol
		case 's': // source mac
		case 'd': // destination mac
			if ((replace.flags & OPT_COMMAND) == 0)
				print_error("No command specified");
			if ( replace.command != 'A' &&
			   replace.command != 'D' && replace.command != 'I')
				print_error("Command and option do not match");
			if (c == 'i') {
				check_option(&replace.flags, OPT_IN);
				if (replace.selected_hook > 2 &&
				   replace.selected_hook < NF_BR_BROUTING)
					print_error("Use in-interface only in "
					   "INPUT, FORWARD, PREROUTING and"
					   "BROUTING chains");
				if (check_inverse(optarg))
					new_entry->invflags |= EBT_IIN;

				if (optind > argc)
					print_error("No in-interface "
					            "specified");
				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_error("Illegal interfacelength");
				strcpy(new_entry->in, argv[optind - 1]);
				break;
			}
			if (c == 2) {
				check_option(&replace.flags, OPT_LOGICALIN);
				if (replace.selected_hook > 2 &&
				   replace.selected_hook < NF_BR_BROUTING)
					print_error("Use logical in-interface "
					   "only in INPUT, FORWARD, "
					   "PREROUTING and BROUTING chains");
				if (check_inverse(optarg))
					new_entry->invflags |= EBT_ILOGICALIN;

				if (optind > argc)
					print_error("No logical in-interface "
					            "specified");
				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_error("Illegal interfacelength");
				strcpy(new_entry->logical_in, argv[optind - 1]);
				break;
			}
			if (c == 'o') {
				check_option(&replace.flags, OPT_OUT);
				if (replace.selected_hook < 2)
					print_error("Use out-interface only"
					   " in OUTPUT, FORWARD and "
					   "POSTROUTING chains");
				if (check_inverse(optarg))
					new_entry->invflags |= EBT_IOUT;

				if (optind > argc)
					print_error("No out-interface "
					            "specified");

				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_error("Illegal interface "
					            "length");
				strcpy(new_entry->out, argv[optind - 1]);
				break;
			}
			if (c == 3) {
				check_option(&replace.flags, OPT_LOGICALOUT);
				if (replace.selected_hook < 2)
					print_error("Use logical out-interface "
					   "only in OUTPUT, FORWARD and "
					   "POSTROUTING chains");
				if (check_inverse(optarg))
					new_entry->invflags |= EBT_ILOGICALOUT;

				if (optind > argc)
					print_error("No logical out-interface "
					            "specified");

				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_error("Illegal interface "
					            "length");
				strcpy(new_entry->logical_out,
				   argv[optind - 1]);
				break;
			}
			if (c == 'j') {

				check_option(&replace.flags, OPT_JUMP);
				for (i = 0; i < NUM_STANDARD_TARGETS; i++)
					if (!strcmp(optarg,
					   standard_targets[i])) {
						t = find_target(
						   EBT_STANDARD_TARGET);
						((struct ebt_standard_target *)
						   t->t)->verdict = i;
						break;
					}
				// must be an extension then
				if (i == NUM_STANDARD_TARGETS) {
					struct ebt_u_target *t;
					t = find_target(optarg);
					// -j standard not allowed either
					if (!t || t ==
					   (struct ebt_u_target *)new_entry->t)
						print_error("Illegal target "
						            "name");
					new_entry->t =
					   (struct ebt_entry_target *)t;
				}
				break;
			}
			if (c == 's') {
				check_option(&replace.flags, OPT_SOURCE);
				if (check_inverse(optarg))
					new_entry->invflags |= EBT_ISOURCE;

				if (optind > argc)
					print_error("No source mac "
					            "specified");
				if (getmac_and_mask(argv[optind - 1],
				   new_entry->sourcemac, new_entry->sourcemsk))
					print_error("Problem with specified "
					            "source mac");
				new_entry->bitmask |= EBT_SOURCEMAC;
				break;
			}
			if (c == 'd') {
				check_option(&replace.flags, OPT_DEST);
				if (check_inverse(optarg))
					new_entry->invflags |= EBT_IDEST;

				if (optind > argc)
					print_error("No destination mac "
					            "specified");
				if (getmac_and_mask(argv[optind - 1],
				   new_entry->destmac, new_entry->destmsk))
					print_error("Problem with specified "
					            "destination mac");
				new_entry->bitmask |= EBT_DESTMAC;
				break;
			}
			check_option(&replace.flags, OPT_PROTOCOL);
			if (check_inverse(optarg))
				new_entry->invflags |= EBT_IPROTO;

			if (optind > argc)
				print_error("No protocol specified");
			new_entry->bitmask &= ~((unsigned int)EBT_NOPROTO);
			i = strtol(argv[optind - 1], &buffer, 16);
			if (*buffer == '\0' && (i < 0 || i > 0xFFFF))
				print_error("Problem with the specified "
				            "protocol");
			new_entry->ethproto = i;
			if (*buffer != '\0')
				if (name_to_protocol(argv[optind - 1]) == -1)
					print_error("Problem with the specified"
					            " protocol");
			if (new_entry->ethproto < 1536 &&
			   !(new_entry->bitmask & EBT_802_3))
				print_error("Sorry, protocols have values above"
				            " or equal to 1536 (0x0600)");
			break;

		case 'b': // allow database?
			if (replace.flags & OPT_COMMAND)
				print_error("Multiple commands not allowed");
			replace.command = c;
			allowbc = *optarg;
			break;

		default:

			// is it a target option?
			t = (struct ebt_u_target *)new_entry->t;
			if ((t->parse(c - t->option_offset, argv, argc,
			   new_entry, &t->flags, &t->t)))
				continue;

			// is it a match_option?
			for (m = matches; m; m = m->next)
				if (m->parse(c - m->option_offset, argv,
				   argc, new_entry, &m->flags, &m->m))
					break;

			if (m != NULL) {
				if (m->used == 0)
					add_match(m);
				continue;
			}

			// is it a watcher option?
			for (w = watchers; w; w = w->next)
				if (w->parse(c-w->option_offset, argv,
				   argc, new_entry, &w->flags, &w->w))
					break;

			if (w == NULL)
				print_error("Unknown argument");
			if (w->used == 0)
				add_watcher(w);
		}
	}

	// database stuff before ebtables stuff
	if (replace.command == 'b')
		allowdb(allowbc);
	if (replace.command == 'L' && replace.selected_hook == DATABASEHOOKNR)
		list_db();

	if ( (replace.flags & OPT_COMMAND) && replace.command != 'L' &&
	   replace.flags & OPT_ZERO )
		print_error("Command -Z only allowed together with command -L");

	if (replace.command == 'A' || replace.command == 'I' ||
	   replace.command == 'D') {
		if (replace.selected_hook == -1)
			print_error("Not enough information");
	}

	if ( !(table = find_table(replace.name)) )
		print_error("Bad table name");

	// do this after parsing everything, so we can print specific info
	if (replace.command == 'h' && !(replace.flags & OPT_ZERO))
		print_help();

	// do the final checks
	m_l = new_entry->m_list;
	w_l = new_entry->w_list;
	t = (struct ebt_u_target *)new_entry->t;
	while (m_l) {
		m = (struct ebt_u_match *)(m_l->m);
		m->final_check(new_entry, m->m, replace.name,
		   replace.selected_hook);
		m_l = m_l->next;
	}
	while (w_l) {
		w = (struct ebt_u_watcher *)(w_l->w);
		w->final_check(new_entry, w->w, replace.name,
		   replace.selected_hook);
		w_l = w_l->next;
	}
	t->final_check(new_entry, t->t, replace.name, replace.selected_hook);
	
	// so, the extensions can work with the host endian
	// the kernel does not have to do this ofcourse
	new_entry->ethproto = htons(new_entry->ethproto);

	// get the kernel's information
	if (get_table(&replace)) {
		ebtables_insmod("ebtables", modprobe);
		if (get_table(&replace))
			print_error("can't initialize ebtables table %s",
			replace.name);
	}
	// check if selected_hook is a valid_hook
	if (replace.selected_hook >= 0 &&
	   !(replace.valid_hooks & (1 << replace.selected_hook)))
		print_error("Bad chain name");
	if (replace.command == 'P')
		change_policy(policy);
	else if (replace.command == 'L') {
		list_rules();
		if (replace.flags & OPT_ZERO)
			zero_counters(zerochain);
		else
			exit(0);
	}
	if (replace.flags & OPT_ZERO)
		zero_counters(zerochain);
	else if (replace.command == 'F')
		flush_chains();
	else if (replace.command == 'A' || replace.command == 'I')
		add_rule(rule_nr);
	else if (replace.command == 'D')
		delete_rule(rule_nr);

	if (table->check)
		table->check(&replace);

	deliver_table(&replace);

	if (counterchanges)
		deliver_counters(&replace, counterchanges);
	return 0;
}
