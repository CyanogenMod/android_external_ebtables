/*
 * ebtables.c, v2.0 July 2002
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

/*
 * default command line options
 * do not mess around with the already assigned numbers unless
 * you know what you are doing
 */
static struct option ebt_original_options[] =
{
	{ "append"        , required_argument, 0, 'A' },
	{ "insert"        , required_argument, 0, 'I' },
	{ "delete"        , required_argument, 0, 'D' },
	{ "list"          , optional_argument, 0, 'L' },
	{ "Lc"            , no_argument      , 0, 4   },
	{ "Ln"            , no_argument      , 0, 5   },
	{ "Lx"            , no_argument      , 0, 6   },
	{ "Lmac2"         , no_argument      , 0, 12  },
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
	{ "new-chain"     , required_argument, 0, 'N' },
	{ "rename-chain"  , required_argument, 0, 'E' },
	{ "delete-chain"  , optional_argument, 0, 'X' },
	{ "atomic-init"   , no_argument      , 0, 7   },
	{ "atomic-commit" , no_argument      , 0, 8   },
	{ "atomic-file"   , required_argument, 0, 9   },
	{ "atomic-save"   , no_argument      , 0, 10  },
	{ "init-table"    , no_argument      , 0, 11  },
	{ 0 }
};

static struct option *ebt_options = ebt_original_options;

/*
 * holds all the data
 */
static struct ebt_u_replace replace;

/*
 * the chosen table
 */
static struct ebt_u_table *table = NULL;

/*
 * The pointers in here are special:
 * The struct ebt_target * pointer is actually a struct ebt_u_target * pointer.
 * instead of making yet a few other structs, we just do a cast.
 * We need a struct ebt_u_target pointer because we know the address of the data
 * they point to won't change. We want to allow that the struct ebt_u_target.t
 * member can change.
 * Same holds for the struct ebt_match and struct ebt_watcher pointers
 */
struct ebt_u_entry *new_entry;


static int global_option_offset = 0;
#define OPTION_OFFSET 256
static struct option *
merge_options(struct option *oldopts, const struct option *newopts,
	    unsigned int *options_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	if (!newopts || !oldopts || !options_offset)
		ebt_print_bug("merge wrong");
	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*options_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	if (!merge)
		ebt_print_memory();
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *options_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));
	/* only free dynamically allocated stuff */
	if (oldopts != ebt_original_options)
		free(oldopts);

	return merge;
}

static void merge_match(struct ebt_u_match *m)
{
	ebt_options = merge_options
	   (ebt_options, m->extra_ops, &(m->option_offset));
}

static void merge_watcher(struct ebt_u_watcher *w)
{
	ebt_options = merge_options
	   (ebt_options, w->extra_ops, &(w->option_offset));
}

static void merge_target(struct ebt_u_target *t)
{
	ebt_options = merge_options
	   (ebt_options, t->extra_ops, &(t->option_offset));
}

/* be backwards compatible, so don't use '+' in kernel */
#define IF_WILDCARD 1
static void print_iface(const char *iface)
{
	char *c;

	if ((c = strchr(iface, IF_WILDCARD)))
		*c = '+';
	printf("%s ", iface);
	if (c)
		*c = IF_WILDCARD;
}

/*
 * we use replace.flags, so we can't use the following values:
 * 0x01 == OPT_COMMAND, 0x02 == OPT_TABLE, 0x100 == OPT_ZERO
 */
#define LIST_N    0x04
#define LIST_C    0x08
#define LIST_X    0x10
#define LIST_MAC2 0x20

/*
 * helper function for list_rules()
 */
static void list_em(struct ebt_u_entries *entries)
{
	int i, j, space = 0, digits;
	struct ebt_u_entry *hlp;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	struct ebt_u_match *m;
	struct ebt_u_watcher *w;
	struct ebt_u_target *t;

	if (replace.flags & LIST_MAC2)
		ebt_printstyle_mac = 2;
	hlp = entries->entries;
	if (replace.flags & LIST_X && entries->policy != EBT_ACCEPT) {
		printf("ebtables -t %s -P %s %s\n", replace.name,
		   entries->name, ebt_standard_targets[-entries->policy - 1]);
	} else if (!(replace.flags & LIST_X)) {
		printf("\nBridge chain: %s, entries: %d, policy: %s\n",
		   entries->name, entries->nentries,
		   ebt_standard_targets[-entries->policy - 1]);
	}

	i = entries->nentries;
	while (i > 9) {
		space++;
		i /= 10;
	}

	for (i = 0; i < entries->nentries; i++) {
		if (replace.flags & LIST_N) {
			digits = 0;
			/* A little work to get nice rule numbers. */
			j = i + 1;
			while (j > 9) {
				digits++;
				j /= 10;
			}
			for (j = 0; j < space - digits; j++)
				printf(" ");
			printf("%d. ", i + 1);
		}
		if (replace.flags & LIST_X)
			printf("ebtables -t %s -A %s ",
			   replace.name, entries->name);

		/* The standard target's print() uses this to find out
		 * the name of a udc */
		hlp->replace = &replace;

		/*
		 * Don't print anything about the protocol if no protocol was
		 * specified, obviously this means any protocol will do.
		 */
		if (!(hlp->bitmask & EBT_NOPROTO)) {
			printf("-p ");
			if (hlp->invflags & EBT_IPROTO)
				printf("! ");
			if (hlp->bitmask & EBT_802_3)
				printf("Length ");
			else {
				struct ethertypeent *ent;

				ent = getethertypebynumber
				      (ntohs(hlp->ethproto));
				if (!ent)
					printf("0x%x ", ntohs(hlp->ethproto));
				else
					printf("%s ", ent->e_name);
			}
		}
		if (hlp->bitmask & EBT_SOURCEMAC) {
			printf("-s ");
			if (hlp->invflags & EBT_ISOURCE)
				printf("! ");
			ebt_print_mac_and_mask(hlp->sourcemac, hlp->sourcemsk);
			printf(" ");
		}
		if (hlp->bitmask & EBT_DESTMAC) {
			printf("-d ");
			if (hlp->invflags & EBT_IDEST)
				printf("! ");
			ebt_print_mac_and_mask(hlp->destmac, hlp->destmsk);
			printf(" ");
		}
		if (hlp->in[0] != '\0') {
			printf("-i ");
			if (hlp->invflags & EBT_IIN)
				printf("! ");
			print_iface(hlp->in);
		}
		if (hlp->logical_in[0] != '\0') {
			printf("--logical-in ");
			if (hlp->invflags & EBT_ILOGICALIN)
				printf("! ");
			print_iface(hlp->logical_in);
		}
		if (hlp->logical_out[0] != '\0') {
			printf("--logical-out ");
			if (hlp->invflags & EBT_ILOGICALOUT)
				printf("! ");
			print_iface(hlp->logical_out);
		}
		if (hlp->out[0] != '\0') {
			printf("-o ");
			if (hlp->invflags & EBT_IOUT)
				printf("! ");
			print_iface(hlp->out);
		}

		m_l = hlp->m_list;
		while (m_l) {
			m = ebt_find_match(m_l->m->u.name);
			if (!m)
				ebt_print_bug("Match not found");
			m->print(hlp, m_l->m);
			m_l = m_l->next;
		}
		w_l = hlp->w_list;
		while (w_l) {
			w = ebt_find_watcher(w_l->w->u.name);
			if (!w)
				ebt_print_bug("Watcher not found");
			w->print(hlp, w_l->w);
			w_l = w_l->next;
		}

		printf("-j ");
		if (strcmp(hlp->t->u.name, EBT_STANDARD_TARGET))
			printf("%s ", hlp->t->u.name);
		t = ebt_find_target(hlp->t->u.name);
		if (!t)
			ebt_print_bug("Target not found");
		t->print(hlp, hlp->t);
		if (replace.flags & LIST_C)
			printf(", pcnt = %llu -- bcnt = %llu",
			   replace.counters[entries->counter_offset + i].pcnt,
			   replace.counters[entries->counter_offset + i].bcnt);
		printf("\n");
		hlp = hlp->next;
	}
}

static void print_help()
{
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;

	PRINT_VERSION;
	printf(
"Usage:\n"
"ebtables -[ADI] chain rule-specification [options]\n"
"ebtables -P chain target\n"
"ebtables -[LFZ] [chain]\n"
"ebtables -[NX] [chain]\n"
"ebtables -E old-chain-name new-chain-name\n\n"
"Commands:\n"
"--append -A chain             : append to chain\n"
"--delete -D chain             : delete matching rule from chain\n"
"--delete -D chain rulenum     : delete rule at position rulenum from chain\n"
"--insert -I chain rulenum     : insert rule at position rulenum in chain\n"
"--list   -L [chain]           : list the rules in a chain or in all chains\n"
"--flush  -F [chain]           : delete all rules in chain or in all chains\n"
"--init-table                  : replace the kernel table with the initial table\n"
"--zero   -Z [chain]           : put counters on zero in chain or in all chains\n"
"--policy -P chain target      : change policy on chain to target\n"
"--new-chain -N chain          : create a user defined chain\n"
"--rename-chain -E old new     : rename a chain\n"
"--delete-chain -X [chain]     : delete a user defined chain\n"
"--atomic-commit               : update the kernel w/t table contained in <FILE>\n"
"--atomic-init                 : put the initial kernel table into <FILE>\n"
"--atomic-save                 : put the current kernel table into <FILE>\n"
"--atomic-file file            : set <FILE> to file\n\n"
"Options:\n"
"--proto  -p [!] proto         : protocol hexadecimal, by name or LENGTH\n"
"--src    -s [!] address[/mask]: source mac address\n"
"--dst    -d [!] address[/mask]: destination mac address\n"
"--in-if  -i [!] name          : network input interface name\n"
"--out-if -o [!] name          : network output interface name\n"
"--logical-in  [!] name        : logical bridge input interface name\n"
"--logical-out [!] name        : logical bridge output interface name\n"
"--modprobe -M program         : try to insert modules using this program\n"
"--version -V                  : print package version\n\n"
"Environment variable:\n"
ATOMIC_ENV_VARIABLE "          : if set <FILE> (see above) will equal its value"
"\n\n");
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
		table->help(ebt_hooknames);
	exit(0);
}

/*
 * execute command L
 */
static void list_rules()
{
	int i;

	if (!(replace.flags & LIST_X))
		printf("Bridge table: %s\n", table->name);
	if (replace.selected_chain != -1) {
		list_em(ebt_to_chain(&replace));
	} else {
		struct ebt_u_chain_list *cl = replace.udc;

		/*
		 * create new chains and rename standard chains when necessary
		 */
		if (replace.flags & LIST_X) {
			while (cl) {
				printf("ebtables -t %s -N %s\n", replace.name,
				   cl->udc->name);
				cl = cl->next;
			}
			cl = replace.udc;
			for (i = 0; i < NF_BR_NUMHOOKS; i++)
				if (replace.valid_hooks & (1 << i) &&
				   strcmp(replace.hook_entry[i]->name,
					  ebt_hooknames[i]))
					printf("ebtables -t %s -E %s %s\n",
					   replace.name, ebt_hooknames[i],
					   replace.hook_entry[i]->name);
		}
		i = 0;
		while (1) {
			if (i < NF_BR_NUMHOOKS) {
				if (replace.valid_hooks & (1 << i))
					list_em(replace.hook_entry[i]);
				i++;
				continue;
			} else {
				if (!cl)
					break;
				list_em(cl->udc);
				cl = cl->next;
			}
		}
	}
}

static int parse_delete_rule(const char *argv, int *rule_nr, int *rule_nr_end)
{
	char *colon = strchr(argv, ':'), *buffer;

	if (colon) {
		*colon = '\0';
		if (*(colon + 1) == '\0')
			*rule_nr_end = -1; /* until the last rule */
		else {
			*rule_nr_end = strtol(colon + 1, &buffer, 10);
			if (*buffer != '\0' || *rule_nr_end == 0)
				return -1;
		}
	}
	if (colon == argv)
		*rule_nr = 1; /* beginning with the first rule */
	else {
		*rule_nr = strtol(argv, &buffer, 10);
		if (*buffer != '\0' || *rule_nr == 0)
			return -1;
	}
	if (!colon)
		*rule_nr_end = *rule_nr;
	return 0;
}

static void parse_iface(char *iface, char *option)
{
	char *c;

	if ((c = strchr(iface, '+'))) {
		if (*(c + 1) != '\0') {
			ebt_print_error("Spurious characters after '+' "
			                "wildcard for %s", option);
		} else
			*c = IF_WILDCARD;
	}
}

#define print_if_l_error ebt_print_error("Interface name length must be less " \
   "than %d", IFNAMSIZ)
#define print_epoto_error(__proto) ebt_print_error("Problem with the specified"\
   " Ethernet protocol (%s), perhaps "_PATH_ETHERTYPES " is missing", __proto);
#define OPT_COMMAND	0x01
#define OPT_TABLE	0x02
#define OPT_IN		0x04
#define OPT_OUT		0x08
#define OPT_JUMP	0x10
#define OPT_PROTOCOL	0x20
#define OPT_SOURCE	0x40
#define OPT_DEST	0x80
#define OPT_ZERO	0x100
#define OPT_LOGICALIN	0x200
#define OPT_LOGICALOUT	0x400
#define OPT_KERNELDATA	0x800 /* if set, we already have loaded the table
			       * in userspace */
/* the main thing */
int main(int argc, char *argv[])
{
	char *buffer;
	int c, i;
	/*
	 * this special one for the -Z option (we can have -Z <this> -L <that>)
	 */
	int zerochain = -1;
	int policy = 0;
	int rule_nr = 0; /* used for -[D,I] */
	int rule_nr_end = 0; /* used for -I */
	struct ebt_u_target *t;
	struct ebt_u_match *m;
	struct ebt_u_watcher *w;
	struct ebt_u_match_list *m_l;
	struct ebt_u_watcher_list *w_l;
	struct ebt_u_entries *entries;

	opterr = 0;

	ebt_iterate_matches(merge_match);
	ebt_iterate_watchers(merge_watcher);
	ebt_iterate_targets(merge_target);

	buffer = getenv(ATOMIC_ENV_VARIABLE);
	if (buffer) {
		replace.filename = malloc(strlen(buffer)+1);
		if (!replace.filename)
			ebt_print_memory();
		memcpy(replace.filename, buffer, strlen(buffer)+1);
		buffer = NULL;
	}
	/*
	 * initialize the table name, OPT_ flags, selected hook and command
	 */
	strcpy(replace.name, "filter");
	replace.flags = 0;
	replace.selected_chain = -1;
	replace.command = 'h';
	replace.counterchanges = NULL;

	new_entry = (struct ebt_u_entry *)malloc(sizeof(struct ebt_u_entry));
	if (!new_entry)
		ebt_print_memory();
	/*
	 * put some sane values in our new entry
	 */
	ebt_initialize_entry(new_entry);
	new_entry->replace = &replace;

	/*
	 * The scenario induced by this loop makes that:
	 * '-t'  ,'-M' and --atomic (if specified) have to come
	 * before '-A' and the like
	 */

	/*
	 * getopt saves the day
	 */
	while ((c = getopt_long(argc, argv,
	   "-A:D:I:N:E:X::L::Z::F::P:Vhi:o:j:p:s:d:t:M:", ebt_options, NULL)) != -1) {
		switch (c) {

		case 'A': /* add a rule */
		case 'D': /* delete a rule */
		case 'P': /* define policy */
		case 'I': /* insert a rule */
		case 'N': /* make a user defined chain */
		case 'E': /* rename chain */
		case 'X': /* delete chain */
			/* We allow -N chainname -P policy */
			if (replace.command == 'N' && c == 'P') {
				replace.command = c;
				optind--;
				goto handle_P;
			}
			replace.command = c;
			replace.flags |= OPT_COMMAND;
			if (!(replace.flags & OPT_KERNELDATA)) {
				ebt_get_kernel_table(&replace, table, 0);
				replace.flags |= OPT_KERNELDATA;
			}
			if (optarg && (optarg[0] == '-' ||
			    !strcmp(optarg, "!")))
				ebt_print_error("No chain name specified");
			if (c == 'N') {
				ebt_new_chain(&replace, optarg, EBT_ACCEPT);
				/* This is needed to get -N x -P y working */
				replace.selected_chain =
				ebt_get_chainnr(&replace, optarg);
				break;
			}
			if (c == 'X') {
				char *opt;

				if (!optarg && (optind >= argc ||
				   (argv[optind][0] == '-'
				    && strcmp(argv[optind], "!")))) {
					replace.selected_chain = -1;
					ebt_delete_chain(&replace);
					break;
				}
				if (optarg)
					opt = optarg;
				else {
					opt = argv[optind];
					optind++;
				}
				if ((replace.selected_chain =
				     ebt_get_chainnr(&replace, opt)) == -1)
					ebt_print_error("Chain %s doesn't "
							"exist", opt);
				ebt_delete_chain(&replace);
				break;
			}

			if ((replace.selected_chain =
			    ebt_get_chainnr(&replace, optarg)) == -1)
				ebt_print_error("Chain %s doesn't exist",
						optarg);
			if (c == 'E') {
				if (optind >= argc || argv[optind][0] == '-' ||
				   !strcmp(argv[optind], "!"))
					ebt_print_error("No new chain name "
						    "specified");
				if (strlen(argv[optind])>=EBT_CHAIN_MAXNAMELEN)
					ebt_print_error("Chain name len can't "
						    "exceed %d",
						    EBT_CHAIN_MAXNAMELEN - 1);
				if (ebt_get_chainnr(&replace, argv[optind]) !=
				    -1)
					ebt_print_error("Chain %s already "
							"exists", argv[optind]);
				if (ebt_find_target(argv[optind]))
					ebt_print_error("Target with name %s "
							"exists", argv[optind]);
				ebt_rename_chain(&replace, argv[optind]);
				optind++;
				break;
			}

			if (c == 'D' && optind < argc &&
			    (argv[optind][0] != '-' ||
			    (argv[optind][1] >= '0' &&
			     argv[optind][1] <= '9'))) {
				if (parse_delete_rule(argv[optind],
				    &rule_nr, &rule_nr_end))
					ebt_print_error("Problem with the "
					            "specified rule number(s)");
				optind++;
			}
			if (c == 'I') {
				if (optind >= argc ||
				    (argv[optind][0] == '-' &&
				    (argv[optind][1] < '0' ||
				    argv[optind][1] > '9')))
					ebt_print_error("No rulenr for -I"
					            " specified");
				rule_nr = strtol(argv[optind], &buffer, 10);
				if (*buffer != '\0')
					ebt_print_error("Problem with the "
					            "specified rule number");
				optind++;
			}
			if (c == 'P') {
handle_P:
				if (optind >= argc)
					ebt_print_error("No policy specified");
				policy = 0;
				for (i = 0; i < NUM_STANDARD_TARGETS; i++)
					if (!strcmp(argv[optind],
					   ebt_standard_targets[i])) {
						policy = -i -1;
						if (policy == EBT_CONTINUE)
							policy = 0;
						break;
					}
				if (policy == 0)
					ebt_print_error("Wrong policy");
				optind++;
			}
			break;

		case 'L': /* list */
		case 'F': /* flush */
		case 'Z': /* zero counters */
			if (c == 'Z') {
				if (replace.flags & OPT_ZERO)
					ebt_print_error("Multiple commands"
					            " not allowed");
				if ( (replace.flags & OPT_COMMAND &&
				   replace.command != 'L'))
					ebt_print_error("command -Z only "
					   "allowed together with command -L");
				replace.flags |= OPT_ZERO;
			} else {
				replace.command = c;
				if (replace.flags & OPT_COMMAND)
					ebt_print_error("Multiple commands"
					            " not allowed");
				replace.flags |= OPT_COMMAND;
			}
			ebt_get_kernel_table(&replace, table, 0);
			i = -1;
			if (optarg) {
				if ( (i = ebt_get_chainnr(&replace, optarg)) ==
				      -1 )
					ebt_print_error("Bad chain");
			} else
				if (optind < argc && argv[optind][0] != '-') {
					if ((i = ebt_get_chainnr(&replace,
					    argv[optind])) == -1)
						ebt_print_error("Bad chain");
					optind++;
				}
			if (i != -1) {
				if (c == 'Z')
					zerochain = i;
				else
					replace.selected_chain = i;
			}
			break;

		case 'V': /* version */
			replace.command = 'V';
			if (replace.flags & OPT_COMMAND)
				ebt_print_error("Multiple commands not "
						"allowed");
			PRINT_VERSION;
			exit(0);

		case 'M': /* modprobe */
			if (replace.command != 'h')
				ebt_print_error("Please put the -M option "
						"earlier");
			ebt_modprobe = optarg;
			break;

		case 'h': /* help */
			if (replace.flags & OPT_COMMAND)
				ebt_print_error("Multiple commands not "
						"allowed");
			replace.command = 'h';
			/*
			 * All other arguments should be extension names
			 */
			while (optind < argc) {
				struct ebt_u_match *m;
				struct ebt_u_watcher *w;

				if (!strcasecmp("list_extensions",
				   argv[optind]))
					ebt_list_extensions();
					
				if ((m = ebt_find_match(argv[optind])))
					ebt_add_match(new_entry, m);
				else if ((w = ebt_find_watcher(argv[optind])))
					ebt_add_watcher(new_entry, w);
				else {
					if (!(t = ebt_find_target(argv[optind])))
						ebt_print_error("Extension %s "
						   "not found", argv[optind]);
					if (replace.flags & OPT_JUMP)
						ebt_print_error("Sorry, you "
						 "can only see help for one "
						 "target extension each time");
					replace.flags |= OPT_JUMP;
					new_entry->t =
					   (struct ebt_entry_target *)t;
				}
				optind++;
			}
			break;

		case 't': /* table */
			if (replace.command != 'h')
				ebt_print_error("Please put the -t option "
						"first");
			ebt_check_option(&replace.flags, OPT_TABLE);
			if (strlen(optarg) > EBT_TABLE_MAXNAMELEN - 1)
				ebt_print_error("Table name too long");
			strcpy(replace.name, optarg);
			break;

		case 'i': /* input interface */
		case 2  : /* logical input interface */
		case 'o': /* output interface */
		case 3  : /* logical output interface */
		case 'j': /* target */
		case 'p': /* net family protocol */
		case 's': /* source mac */
		case 'd': /* destination mac */
			if ((replace.flags & OPT_COMMAND) == 0)
				ebt_print_error("No command specified");
			if ( replace.command != 'A' &&
			   replace.command != 'D' && replace.command != 'I')
				ebt_print_error("Command and option do not "
						"match");
			if (c == 'i') {
				ebt_check_option(&replace.flags, OPT_IN);
				if (replace.selected_chain > 2 &&
				   replace.selected_chain < NF_BR_BROUTING)
					ebt_print_error("Use in-interface "
					   "only in "
					   "INPUT, FORWARD, PREROUTING and"
					   "BROUTING chains");
				if (ebt_check_inverse(optarg))
					new_entry->invflags |= EBT_IIN;

				if (optind > argc)
					ebt_print_error("No in-interface "
					            "specified");
				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_if_l_error;
				strcpy(new_entry->in, argv[optind - 1]);
				parse_iface(new_entry->in, "-i");
				break;
			}
			if (c == 2) {
				ebt_check_option(&replace.flags, OPT_LOGICALIN);
				if (replace.selected_chain > 2 &&
				   replace.selected_chain < NF_BR_BROUTING)
					ebt_print_error("Use logical "
					   "in-interface "
					   "only in INPUT, FORWARD, "
					   "PREROUTING and BROUTING chains");
				if (ebt_check_inverse(optarg))
					new_entry->invflags |= EBT_ILOGICALIN;

				if (optind > argc)
					ebt_print_error("No logical "
					   "in-interface specified");
				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_if_l_error;
				strcpy(new_entry->logical_in, argv[optind - 1]);
				parse_iface(new_entry->logical_in,
				            "--logical-in");
				break;
			}
			if (c == 'o') {
				ebt_check_option(&replace.flags, OPT_OUT);
				if (replace.selected_chain < 2)
					ebt_print_error("Use out-interface "
					   "only in OUTPUT, FORWARD and "
					   "POSTROUTING chains");
				if (ebt_check_inverse(optarg))
					new_entry->invflags |= EBT_IOUT;

				if (optind > argc)
					ebt_print_error("No out-interface "
					            "specified");

				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_if_l_error;
				strcpy(new_entry->out, argv[optind - 1]);
				parse_iface(new_entry->out, "-o");
				break;
			}
			if (c == 3) {
				ebt_check_option(&replace.flags,
						 OPT_LOGICALOUT);
				if (replace.selected_chain < 2)
					ebt_print_error("Use logical "
					   "out-interface "
					   "only in OUTPUT, FORWARD and "
					   "POSTROUTING chains");
				if (ebt_check_inverse(optarg))
					new_entry->invflags |= EBT_ILOGICALOUT;

				if (optind > argc)
					ebt_print_error("No logical "
					   "out-interface specified");

				if (strlen(argv[optind - 1]) >= IFNAMSIZ)
					print_if_l_error;
				strcpy(new_entry->logical_out,
				   argv[optind - 1]);
				parse_iface(new_entry->logical_out,
				         "--logical-out");
				break;
			}
			if (c == 'j') {
				ebt_check_option(&replace.flags, OPT_JUMP);
				for (i = 0; i < NUM_STANDARD_TARGETS; i++)
					if (!strcmp(optarg,
					   ebt_standard_targets[i])) {
						t = ebt_find_target(
						   EBT_STANDARD_TARGET);
						((struct ebt_standard_target *)
						   t->t)->verdict = -i - 1;
						break;
					}
				if (-i - 1 == EBT_RETURN) {
					if (replace.selected_chain <
					    NF_BR_NUMHOOKS)
						ebt_print_error("Return target"
						" only for user defined "
						"chains");
				}
				if (i != NUM_STANDARD_TARGETS)
					break;
				if ((i = ebt_get_chainnr(&replace, optarg)) !=
				     -1) {
					if (i < NF_BR_NUMHOOKS)
						ebt_print_error("don't jump"
						  " to a standard chain");
					t = ebt_find_target(EBT_STANDARD_TARGET);
					((struct ebt_standard_target *)
					   t->t)->verdict = i - NF_BR_NUMHOOKS;
					break;
				} else {
					/*
					 * must be an extension then
					 */
					struct ebt_u_target *t;

					t = ebt_find_target(optarg);
					/*
					 * -j standard not allowed either
					 */
					if (!t || t ==
					   (struct ebt_u_target *)new_entry->t)
						ebt_print_error("Illegal "
						   "target name");
					new_entry->t =
					   (struct ebt_entry_target *)t;
				}
				break;
			}
			if (c == 's') {
				ebt_check_option(&replace.flags, OPT_SOURCE);
				if (ebt_check_inverse(optarg))
					new_entry->invflags |= EBT_ISOURCE;

				if (optind > argc)
					ebt_print_error("No source mac "
					            "specified");
				if (ebt_get_mac_and_mask(argv[optind - 1],
				   new_entry->sourcemac, new_entry->sourcemsk))
					ebt_print_error("Problem with "
					   "specified source mac");
				new_entry->bitmask |= EBT_SOURCEMAC;
				break;
			}
			if (c == 'd') {
				ebt_check_option(&replace.flags, OPT_DEST);
				if (ebt_check_inverse(optarg))
					new_entry->invflags |= EBT_IDEST;

				if (optind > argc)
					ebt_print_error("No destination mac "
					            "specified");
				if (ebt_get_mac_and_mask(argv[optind - 1],
				   new_entry->destmac, new_entry->destmsk))
					ebt_print_error("Problem with "
					   "specified destination mac");
				new_entry->bitmask |= EBT_DESTMAC;
				break;
			}
			ebt_check_option(&replace.flags, OPT_PROTOCOL);
			if (ebt_check_inverse(optarg))
				new_entry->invflags |= EBT_IPROTO;

			if (optind > argc)
				ebt_print_error("No protocol specified");
			new_entry->bitmask &= ~((unsigned int)EBT_NOPROTO);
			i = strtol(argv[optind - 1], &buffer, 16);
			if (*buffer == '\0' && (i < 0 || i > 0xFFFF))
				ebt_print_error("Problem with the specified "
				            "protocol");
			new_entry->ethproto = i;
			if (*buffer != '\0') {
				struct ethertypeent *ent;

				if (!strcasecmp(argv[optind - 1], "LENGTH")) {
					new_entry->bitmask |= EBT_802_3;
					break;
				}
				ent = getethertypebyname(argv[optind - 1]);
				if (!ent)
					print_epoto_error(argv[optind - 1]);
				new_entry->ethproto = ent->e_ethertype;
			}
			if (new_entry->ethproto < 1536 &&
			   !(new_entry->bitmask & EBT_802_3))
				ebt_print_error("Sorry, protocols have values "
						"above or equal to 0x0600");
			break;

		case 4  : /* Lc */
			ebt_check_option(&replace.flags, LIST_C);
			if (replace.command != 'L')
				ebt_print_error("Use --Lc with -L");
			if (replace.flags & LIST_X)
				ebt_print_error("--Lx not compatible with "
						"--Lc");
			replace.flags |= LIST_C;
			break;
		case 5  : /* Ln */
			ebt_check_option(&replace.flags, LIST_N);
			if (replace.command != 'L')
				ebt_print_error("Use --Ln with -L");
			if (replace.flags & LIST_X)
				ebt_print_error("--Lx not compatible with "
						"--Ln");
			replace.flags |= LIST_N;
			break;
		case 6  : /* Lx */
			ebt_check_option(&replace.flags, LIST_X);
			if (replace.command != 'L')
				ebt_print_error("Use --Lx with -L");
			if (replace.flags & LIST_C)
				ebt_print_error("--Lx not compatible with "
						"--Lc");
			if (replace.flags & LIST_N)
				ebt_print_error("--Lx not compatible with "
						"--Ln");
			replace.flags |= LIST_X;
			break;
		case 12 : /* Lmac2 */
			ebt_check_option(&replace.flags, LIST_MAC2);
			if (replace.command != 'L')
				ebt_print_error("Use --Lmac2 with -L");
			replace.flags |= LIST_MAC2;
			break;
		case 8 : /* atomic-commit */
			replace.command = c;
			if (replace.flags & OPT_COMMAND)
				ebt_print_error("Multiple commands not "
						"allowed");
			replace.flags |= OPT_COMMAND;
			if (!replace.filename)
				ebt_print_error("No atomic file specified");
			/*
			 * get the information from the file
			 */
			ebt_get_table(&replace, 0);
			/*
			 * we don't want the kernel giving us its counters,
			 * they would overwrite the counters extracted from
			 * the file
			 */
			replace.num_counters = 0;
			/*
			 * make sure the table will be written to the kernel
			 */
			free(replace.filename);
			replace.filename = NULL;
			break;
		case 7 : /* atomic-init */
		case 10: /* atomic-save */
		case 11: /* init-table */
			replace.command = c;
			if (replace.flags & OPT_COMMAND)
				ebt_print_error("Multiple commands not "
						"allowed");
			if (c != 11 && !replace.filename)
				ebt_print_error("No atomic file specified");
			replace.flags |= OPT_COMMAND;
			{
				char *tmp = replace.filename;
				int init = 1;

				if (c == 10)
					init = 0;
				tmp = replace.filename;
				/* get the kernel table */
				replace.filename = NULL;
				ebt_get_kernel_table(&replace, table, init);
				replace.filename = tmp;
			}
			break;
		case 9 : /* atomic */
			if (replace.flags & OPT_COMMAND)
				ebt_print_error("--atomic has to come before"
						" the command");
			/* another possible memory leak here */
			replace.filename = (char *)malloc(strlen(optarg) + 1);
			strcpy(replace.filename, optarg);
			break;
		case 1 :
			if (!strcmp(optarg, "!"))
				ebt_check_inverse(optarg);
			else
				ebt_print_error("Bad argument : %s", optarg);
			/*
			 * ebt_check_inverse() did optind++
			 */
			optind--;
			continue;
		default:
			/*
			 * is it a target option?
			 */
			t = (struct ebt_u_target *)new_entry->t;
			if ((t->parse(c - t->option_offset, argv, argc,
			   new_entry, &t->flags, &t->t)))
				goto check_extension;

			/*
			 * is it a match_option?
			 */
			for (m = ebt_matches; m; m = m->next)
				if (m->parse(c - m->option_offset, argv,
				   argc, new_entry, &m->flags, &m->m))
					break;

			if (m != NULL) {
				if (m->used == 0) {
					ebt_add_match(new_entry, m);
					m->used = 1;
				}
				goto check_extension;
			}

			/*
			 * is it a watcher option?
			 */
			for (w = ebt_watchers; w; w = w->next)
				if (w->parse(c-w->option_offset, argv,
				   argc, new_entry, &w->flags, &w->w))
					break;

			if (w == NULL)
				ebt_print_error("Unknown argument");
			if (w->used == 0) {
				ebt_add_watcher(new_entry, w);
				w->used = 1;
			}
check_extension:
			if (replace.command != 'A' && replace.command != 'I' &&
			   replace.command != 'D')
				ebt_print_error("Extensions only for -A, "
						"-I and -D");
		}
		ebt_invert = 0;
	}

	if ( !table && !(table = ebt_find_table(replace.name)) )
		ebt_print_error("Bad table name");

	if ( (replace.flags & OPT_COMMAND) && replace.command != 'L' &&
	   replace.flags & OPT_ZERO )
		ebt_print_error("Command -Z only allowed together with "
				"command -L");

	/*
	 * do this after parsing everything, so we can print specific info
	 */
	if (replace.command == 'h' && !(replace.flags & OPT_ZERO))
		print_help();

	/*
	 * do the final checks
	 */
	if (replace.command == 'A' || replace.command == 'I' ||
	   replace.command == 'D') {
		/*
		 * this will put the hook_mask right for the chains
		 */
		ebt_check_for_loops(&replace);
		entries = ebt_to_chain(&replace);
		m_l = new_entry->m_list;
		w_l = new_entry->w_list;
		t = (struct ebt_u_target *)new_entry->t;
		while (m_l) {
			m = (struct ebt_u_match *)(m_l->m);
			m->final_check(new_entry, m->m, replace.name,
			   entries->hook_mask, 0);
			m_l = m_l->next;
		}
		while (w_l) {
			w = (struct ebt_u_watcher *)(w_l->w);
			w->final_check(new_entry, w->w, replace.name,
			   entries->hook_mask, 0);
			w_l = w_l->next;
		}
		t->final_check(new_entry, t->t, replace.name,
		   entries->hook_mask, 0);
	}
	/*
	 * so, the extensions can work with the host endian
	 * the kernel does not have to do this of course
	 */
	new_entry->ethproto = htons(new_entry->ethproto);

	if (replace.command == 'P') {
		if (replace.selected_chain < NF_BR_NUMHOOKS &&
		   policy == EBT_RETURN)
			ebt_print_error("Policy RETURN only allowed for user "
					"defined chains");
		ebt_change_policy(&replace, policy);
	} else if (replace.command == 'L') {
		list_rules();
		if (replace.flags & OPT_ZERO) {
			replace.selected_chain = zerochain;
			ebt_zero_counters(&replace);
		} else
			exit(0);
	}
	if (replace.flags & OPT_ZERO) {
		replace.selected_chain = zerochain;
		ebt_zero_counters(&replace);
	} else if (replace.command == 'F')
		ebt_flush_chains(&replace);
	else if (replace.command == 'A' || replace.command == 'I') {
		ebt_add_rule(&replace, new_entry, rule_nr);
		ebt_check_for_loops(&replace);
		/*
		 * do the final_check(), for all entries
		 * needed when adding a rule that has a chain target
		 */
		i = -1;
		while (1) {
			struct ebt_u_entry *e;

			i++;
			entries = ebt_nr_to_chain(&replace, i);
			if (!entries) {
				if (i < NF_BR_NUMHOOKS)
					continue;
				else
					break;
			}
			e = entries->entries;
			while (e) {
				/*
				 * userspace extensions use host endian
				 */
				e->ethproto = ntohs(e->ethproto);
				ebt_do_final_checks(&replace, e, entries);
				e->ethproto = htons(e->ethproto);
				e = e->next;
			}
		}
	} else if (replace.command == 'D')
		ebt_delete_rule(&replace, new_entry, rule_nr, rule_nr_end);
	/*
	 * commands -N, -E, -X, --atomic-commit, --atomic-commit, --atomic-save,
	 * --init-table fall through
	 */

	if (table->check)
		table->check(&replace);

	ebt_deliver_table(&replace);

	if (replace.counterchanges)
		ebt_deliver_counters(&replace);
	return 0;
}
