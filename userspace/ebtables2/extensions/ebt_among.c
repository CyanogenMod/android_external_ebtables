#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <netinet/ether.h>
#include "../include/ebtables_u.h"
#include "../include/ethernetdb.h"
#include <linux/if_ether.h>
#include <linux/netfilter_bridge/ebt_among.h>

/*
#define DEBUG
*/

#define AMONG_DST '1'
#define AMONG_SRC '2'

static struct option opts[] =
{
	{ "among-dst"     , required_argument, 0, AMONG_DST },
	{ "among-src"     , required_argument, 0, AMONG_SRC },
	{ 0 }
};

#ifdef DEBUG
static void hexdump(const void *mem, int howmany)
{
	printf("\n");
	const unsigned char *p = mem;
	int i;
	for (i = 0; i < howmany; i++) {
		if (i % 32 == 0) {
			printf("\n%04x: ", i);
		}
		printf("%2.2x ", p[i]);
	}
	printf("\n");
}
#endif /* DEBUG */

static void print_help()
{
	printf(
"`among' options:\n"
"--among-dst list                : matches if ether dst is in list\n"
"--among-src list                : matches if ether src is in list\n"
"list has form:\n"
"\txx:xx:xx:xx:xx:xx,yy:yy:yy:yy:yy:yy,...,zz:zz:zz:zz:zz:zz\n"
"i.e. MAC addresses separated by commas, without spaces.\n"
"Optional comma can be included after the last MAC address, i.e.:\n"
"\txx:xx:xx:xx:xx:xx,yy:yy:yy:yy:yy:yy,...,zz:zz:zz:zz:zz:zz,\n"
"Each list can contain up to 256 addresses.\n"
	);
}

static void init(struct ebt_entry_match *match)
{
	struct ebt_among_info *amonginfo = (struct ebt_among_info *)match->data;

	memset(amonginfo, 0, sizeof(struct ebt_among_info));
}

static int fill_mac(char *mac, const char *string)
{
	char xnum[3];
	const char *p = string;
	int i = 0;
	int j = 0;
	while (1) {
		if (isxdigit(*p)) {
			xnum[j] = *p;
			j++;
			if (j >= 3) {
				/* 3 or more hex digits for a single byte */
				return -3;
			}
		}
		else {
			xnum[j] = 0;
			j = 0;
			mac[i] = strtol(xnum, 0, 16);
			i++;
			if (i >= 6) {
				if (*p == ':') {
					/* MAC address too long */
					return -2;
				}
				else {
					return 0;
				}
			}
			else {
				if (*p != ':') {
					/* MAC address too short */
					return -1;
				}
			}
		}
		p++;
	}
		
}

static void fill_wormhash(struct ebt_mac_wormhash *wh, const char *arg)
{
	const char *pc = arg;
	const char *anchor;
	char mac[6];
	int index;
	int nmacs = 0;
	char *base = (char*)wh;
	memset(wh, 0, sizeof(struct ebt_mac_wormhash));
	while (1) {
		anchor = pc;
		while (*pc && *pc != ',') pc++;
		while (*pc && *pc == ',') pc++;
		if (fill_mac(mac, anchor)) {
			print_error("problem with MAC %20s...", anchor);
		}
		index = (unsigned char)mac[5];
		memcpy(((char*)wh->pool[nmacs].cmp)+2, mac, 6);
		wh->pool[nmacs].next_ofs = wh->table[index];
		wh->table[index] = ((const char*)&wh->pool[nmacs]) - base;
		nmacs++;
		if (*pc && nmacs >= 256) {
			print_error("--among-src/--among-dst list can contain no more than 256 addresses\n");
		}
		if (!*pc) {
			break;
		}
	}
}

#define OPT_DST 0x01
#define OPT_SRC 0x02
static int parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
   unsigned int *flags, struct ebt_entry_match **match)
{
	struct ebt_among_info *amonginfo = (struct ebt_among_info *)(*match)->data;
	struct ebt_mac_wormhash *wh;

	switch (c) {
	case AMONG_DST:
	case AMONG_SRC:
		if (c == AMONG_DST) {
			check_option(flags, OPT_DST);
			wh = &amonginfo->wh_dst;
			amonginfo->bitmask |= EBT_AMONG_DST;
		} else {
			check_option(flags, OPT_SRC);
			wh = &amonginfo->wh_src;
			amonginfo->bitmask |= EBT_AMONG_SRC;
		}
		if (optind > argc)
			print_error("No MAC list specified\n");
		fill_wormhash(wh, argv[optind - 1]);
		break;
	default:
		return 0;
	}
	return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_match *match, const char *name,
   unsigned int hookmask, unsigned int time)
{
}

static void wormhash_printout(const struct ebt_mac_wormhash *wh)
{
	int i;
	int offset;
	for (i = 0; i < 256; i++) {
		const struct ebt_mac_wormhash_tuple *p;
		offset = wh->table[i];
		while (offset) {
			p = (const struct ebt_mac_wormhash_tuple*)((const char*)wh + offset);
			printf("%s,", ether_ntoa((const struct ether_addr *)(((const char*)&p->cmp[0]) + 2)));
			offset = p->next_ofs;
		}
	}				
	printf(" ");
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_match *match)
{
	struct ebt_among_info *amonginfo = (struct ebt_among_info *)match->data;

	if (amonginfo->bitmask & EBT_AMONG_DST) {
		printf("--among-dst ");
		wormhash_printout(&amonginfo->wh_dst);
	}
	if (amonginfo->bitmask & EBT_AMONG_SRC) {
		printf("--among-src ");
		wormhash_printout(&amonginfo->wh_src);
	}
}

static int compare(const struct ebt_entry_match *m1,
   const struct ebt_entry_match *m2)
{
	struct ebt_among_info *amonginfo1 = (struct ebt_among_info *)m1->data;
	struct ebt_among_info *amonginfo2 = (struct ebt_among_info *)m2->data;

#ifdef DEBUG	
//	hexdump(amonginfo1, sizeof(struct ebt_among_info));
//	hexdump(amonginfo2, sizeof(struct ebt_among_info));
#endif /* DEBUG */

	return memcmp(amonginfo1, amonginfo2, sizeof(struct ebt_among_info)) == 0;
}

static struct ebt_u_match among_match =
{
	EBT_AMONG_MATCH,
	sizeof(struct ebt_among_info),
	print_help,
	init,
	parse,
	final_check,
	print,
	compare,
	opts
};

static void _init(void) __attribute__ ((constructor));
static void _init(void)
{
	register_match(&among_match);
}
