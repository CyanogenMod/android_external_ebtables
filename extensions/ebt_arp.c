#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_arp.h>

#define ARP_OPCODE '1'
#define ARP_HTYPE  '2'
#define ARP_PTYPE  '3'
#define ARP_IP_S   '4'
#define ARP_IP_D   '5'
static struct option opts[] =
{
	{ "arp-opcode"    , required_argument, 0, ARP_OPCODE },
	{ "arp-op"        , required_argument, 0, ARP_OPCODE },
	{ "arp-htype"     , required_argument, 0, ARP_HTYPE  },
	{ "arp-ptype"     , required_argument, 0, ARP_PTYPE  },
	{ "arp-ip-src"    , required_argument, 0, ARP_IP_S   },
	{ "arp-ip-dst"    , required_argument, 0, ARP_IP_D   },
	{ 0 }
};

#define NUMOPCODES 9
// a few names
static char *opcodes[] =
{
	"Request",
	"Reply",
	"Request_Reverse",
	"Reply_Reverse",
	"DRARP_Request",
	"DRARP_Reply",
	"DRARP_Error",
	"InARP_Request",
	"ARP_NAK",
};

static void print_help()
{
	int i;

	printf(
"arp options:\n"
"--arp-opcode opcode            : ARP opcode (integer or string)\n"
"--arp-htype type               : ARP hardware type (integer or string)\n"
"--arp-ptype type               : ARP protocol type (hexadecimal or string)\n"
"--arp-ip-src [!] address[/mask]: ARP IP source specification\n"
"--arp-ip-dst [!] address[/mask]: ARP IP target specification\n"
" opcode strings: \n");
	for (i = 0; i < NUMOPCODES; i++)
		printf("%d = %s\n", i + 1, opcodes[i]);
	printf(
" hardware type string: 1 = Ethernet\n"
" protocol type string: see /etc/ethertypes\n");
}

static void init(struct ebt_entry_match *match)
{
	struct ebt_arp_info *arpinfo = (struct ebt_arp_info *)match->data;

	arpinfo->invflags = 0;
	arpinfo->bitmask = 0;
}

// defined in ebt_ip.c
void parse_ip_address(char *address, uint32_t *addr, uint32_t *msk);

#define OPT_OPCODE 0x01
#define OPT_HTYPE  0x02
#define OPT_PTYPE  0x04
#define OPT_IP_S   0x08
#define OPT_IP_D   0x10
static int parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
   unsigned int *flags, struct ebt_entry_match **match)
{
	struct ebt_arp_info *arpinfo = (struct ebt_arp_info *)(*match)->data;
	long int i;
	char *end;
	uint32_t *addr;
	uint32_t *mask;

	switch (c) {
	case ARP_OPCODE:
		check_option(flags, OPT_OPCODE);
		if (check_inverse(optarg))
			arpinfo->invflags |= EBT_ARP_OPCODE;

		if (optind > argc)
			print_error("Missing ARP opcode argument");
		i = strtol(argv[optind - 1], &end, 10);
		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
			for (i = 0; i < NUMOPCODES; i++)
				if (!strcasecmp(opcodes[i], optarg))
					break;
			if (i == NUMOPCODES)
				print_error("Problem with specified "
				            "ARP opcode");
			i++;
		}
		arpinfo->opcode = htons(i);
		arpinfo->bitmask |= EBT_ARP_OPCODE;
		break;

	case ARP_HTYPE:
		check_option(flags, OPT_HTYPE);
		if (check_inverse(optarg))
			arpinfo->invflags |= EBT_ARP_HTYPE;

		if (optind > argc)
			print_error("Missing ARP hardware type argument");
		i = strtol(argv[optind - 1], &end, 10);
		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
			if (!strcasecmp("Ethernet", argv[optind - 1]))
				i = 1;
			else
				print_error("Problem with specified ARP "
				            "hardware type");
		}
		arpinfo->htype = htons(i);
		arpinfo->bitmask |= EBT_ARP_HTYPE;
		break;

	case ARP_PTYPE:
	{
		uint16_t proto;

		check_option(flags, OPT_PTYPE);
		if (check_inverse(optarg))
			arpinfo->invflags |= EBT_ARP_PTYPE;

		if (optind > argc)
			print_error("Missing ARP protocol type argument");
		i = strtol(argv[optind - 1], &end, 16);
		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
			if (name_to_number (argv[optind - 1], &proto) == -1)
				print_error("Problem with specified ARP "
				            "protocol type");
		} else
			proto = i;
		arpinfo->ptype = htons(proto);
		arpinfo->bitmask |= EBT_ARP_PTYPE;
		break;
	}

	case ARP_IP_S:
	case ARP_IP_D:
		if (c == ARP_IP_S) {
			check_option(flags, OPT_IP_S);
			addr = &arpinfo->saddr;
			mask = &arpinfo->smsk;
			arpinfo->bitmask |= EBT_ARP_SRC_IP;
		} else {
			check_option(flags, OPT_IP_D);
			addr = &arpinfo->daddr;
			mask = &arpinfo->dmsk;
			arpinfo->bitmask |= EBT_ARP_DST_IP;
		}
		if (check_inverse(optarg)) {
			if (c == ARP_IP_S)
				arpinfo->invflags |= EBT_ARP_SRC_IP;
			else
				arpinfo->invflags |= EBT_ARP_DST_IP;
		}
		if (optind > argc)
			print_error("Missing ARP IP address argument");
		parse_ip_address(argv[optind - 1], addr, mask);
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
	if ((entry->ethproto != ETH_P_ARP && entry->ethproto != ETH_P_RARP) ||
	    entry->invflags & EBT_IPROTO)
		print_error("For (R)ARP filtering the protocol must be "
		            "specified as ARP or RARP");
}

// defined in the ebt_ip.c
char *mask_to_dotted(uint32_t mask);

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_match *match)
{
	struct ebt_arp_info *arpinfo = (struct ebt_arp_info *)match->data;
	int i;
	char name[21];

	if (arpinfo->bitmask & EBT_ARP_OPCODE) {
		int opcode = ntohs(arpinfo->opcode);
		printf("--arp-op ");
		if (arpinfo->invflags & EBT_ARP_OPCODE)
			printf("! ");
		if (opcode > 0 && opcode <= NUMOPCODES)
			printf("%s ", opcodes[opcode - 1]);
		else
			printf("%d ", opcode);
	}
	if (arpinfo->bitmask & EBT_ARP_HTYPE) {
		printf("--arp-htype ");
		if (arpinfo->invflags & EBT_ARP_HTYPE)
			printf("! ");
		printf("%d ", ntohs(arpinfo->htype));
	}
	if (arpinfo->bitmask & EBT_ARP_PTYPE) {
		printf("--arp-ptype ");
		if (arpinfo->invflags & EBT_ARP_PTYPE)
			printf("! ");
		if (number_to_name(ntohs(arpinfo->ptype), name))
			printf("0x%x ", ntohs(arpinfo->ptype));
		else
			printf("%s ", name);
	}
	if (arpinfo->bitmask & EBT_ARP_SRC_IP) {
		printf("--arp-ip-src ");
		if (arpinfo->invflags & EBT_ARP_SRC_IP)
			printf("! ");
		for (i = 0; i < 4; i++)
			printf("%d%s", ((unsigned char *)&arpinfo->saddr)[i],
			   (i == 3) ? "" : ".");
		printf("%s ", mask_to_dotted(arpinfo->smsk));
	}
	if (arpinfo->bitmask & EBT_ARP_DST_IP) {
		printf("--arp-ip-dst ");
		if (arpinfo->invflags & EBT_ARP_DST_IP)
			printf("! ");
		for (i = 0; i < 4; i++)
			printf("%d%s", ((unsigned char *)&arpinfo->daddr)[i],
			   (i == 3) ? "" : ".");
		printf("%s ", mask_to_dotted(arpinfo->dmsk));
	}
}

static int compare(const struct ebt_entry_match *m1,
   const struct ebt_entry_match *m2)
{
	struct ebt_arp_info *arpinfo1 = (struct ebt_arp_info *)m1->data;
	struct ebt_arp_info *arpinfo2 = (struct ebt_arp_info *)m2->data;

	if (arpinfo1->bitmask != arpinfo2->bitmask)
		return 0;
	if (arpinfo1->invflags != arpinfo2->invflags)
		return 0;
	if (arpinfo1->bitmask & EBT_ARP_OPCODE) {
		if (arpinfo1->opcode != arpinfo2->opcode)
			return 0;
	}
	if (arpinfo1->bitmask & EBT_ARP_HTYPE) {
		if (arpinfo1->htype != arpinfo2->htype)
			return 0;
	}
	if (arpinfo1->bitmask & EBT_ARP_PTYPE) {
		if (arpinfo1->ptype != arpinfo2->ptype)
			return 0;
	}
	if (arpinfo1->bitmask & EBT_ARP_SRC_IP) {
		if (arpinfo1->saddr != arpinfo2->saddr)
			return 0;
		if (arpinfo1->smsk != arpinfo2->smsk)
			return 0;
	}
	if (arpinfo1->bitmask & EBT_ARP_DST_IP) {
		if (arpinfo1->daddr != arpinfo2->daddr)
			return 0;
		if (arpinfo1->dmsk != arpinfo2->dmsk)
			return 0;
	}
	return 1;
}

static struct ebt_u_match arp_match =
{
	EBT_ARP_MATCH,
	sizeof(struct ebt_arp_info),
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
	register_match(&arp_match);
}
