#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_ip.h>

#define IP_SOURCE '1'
#define IP_DEST   '2'
#define IP_myTOS  '3' // include/bits/in.h seems to already define IP_TOS
#define IP_PROTO  '4'

static struct option opts[] =
{
	{ "ip-source"     , required_argument, 0, IP_SOURCE },
	{ "ip-src"        , required_argument, 0, IP_SOURCE },
	{ "ip-destination", required_argument, 0, IP_DEST   },
	{ "ip-dst"        , required_argument, 0, IP_DEST   },
	{ "ip-tos"        , required_argument, 0, IP_myTOS  },
	{ "ip-protocol"   , required_argument, 0, IP_PROTO  },
	{ "ip-proto"      , required_argument, 0, IP_PROTO  },
	{ 0 }
};

// put the ip string into 4 bytes
static int undot_ip(char *ip, unsigned char *ip2)
{
	char *p, *q, *end;
	int onebyte, i;
	char buf[20];

	strncpy(buf, ip, sizeof(buf) - 1);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return -1;
		*q = '\0';
		onebyte = strtol(p, &end, 10);
		if (*end != '\0' || onebyte > 255 || onebyte < 0)
			return -1;
		ip2[i] = (unsigned char)onebyte;
		p = q + 1;
	}

	onebyte = strtol(p, &end, 10);
	if (*end != '\0' || onebyte >255 || onebyte < 0)
		return -1;
	ip2[3] = (unsigned char)onebyte;

	return 0;
}

// put the mask into 4 bytes
static int ip_mask(char *mask, unsigned char *mask2)
{
	char *end;
	int bits;
	__u32 mask22;

	if (undot_ip(mask, mask2)) {
		// not the /a.b.c.e format, maybe the /x format
		bits = strtol(mask, &end, 10);
		if (*end != '\0' || bits > 32 || bits < 0)
			return -1;
		if (bits != 0) {
			mask22 = htonl(0xFFFFFFFF << (32 - bits));
			memcpy(mask2, &mask22, 4);
		} else {
			mask22 = 0xFFFFFFFF;
			memcpy(mask2, &mask22, 4);
		}
	}
	return 0;
}

// set the ip mask and ip address
void parse_ip_address(char *address, __u32 *addr, __u32 *msk)
{
	char *p;
	int i;

	// first the mask
	if ((p = strrchr(address, '/')) != NULL) {
		*p = '\0';
		i = ip_mask(p + 1, (unsigned char *)msk);
		if (i)
			print_error("Problem with the ip mask");
	}
	else
		*msk = 0xFFFFFFFF;

	i = undot_ip(address, (unsigned char *)addr);
	if (i)
		print_error("Problem with the ip address");
	*addr = *addr & *msk;
}

// transform the ip mask into a string ready for output
char *mask_to_dotted(__u32 mask)
{
	int i;
	static char buf[20];
	__u32 maskaddr, bits;

	maskaddr = ntohl(mask);

	// don't print /32
	if (mask == 0xFFFFFFFFL)
		return "";

	i = 32;
	bits = 0xFFFFFFFEL; // case 0xFFFFFFFF has just been dealt with
	while (--i >= 0 && maskaddr != bits)
		bits <<= 1;

	if (i > 0)
		sprintf(buf, "/%d", i);
	else if (!i)
		*buf = '\0';
	else
		// mask was not a decent combination of 1's and 0's
		sprintf(buf, "/%d.%d.%d.%d", ((unsigned char *)&mask)[0],
		   ((unsigned char *)&mask)[1], ((unsigned char *)&mask)[2],
		   ((unsigned char *)&mask)[3]);

	return buf;
}

static void print_help()
{
	printf(
"ip options:\n"
"--ip-src    [!] address[/mask]: ip source specification\n"
"--ip-dst    [!] address[/mask]: ip destination specification\n"
"--ip-tos    [!] tos           : ip tos specification\n"
"--ip-proto  [!] protocol      : ip protocol specification\n");
}

static void init(struct ebt_entry_match *match)
{
	struct ebt_ip_info *ipinfo = (struct ebt_ip_info *)match->data;

	ipinfo->invflags = 0;
	ipinfo->bitmask = 0;
}

#define OPT_SOURCE 0x01
#define OPT_DEST   0x02
#define OPT_TOS    0x04
#define OPT_PROTO  0x08
static int parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
   unsigned int *flags, struct ebt_entry_match **match)
{
	struct ebt_ip_info *ipinfo = (struct ebt_ip_info *)(*match)->data;
	char *end, *buffer;
	int i;

	switch (c) {
	case IP_SOURCE:
		check_option(flags, OPT_SOURCE);
		ipinfo->bitmask |= EBT_IP_SOURCE;

	case IP_DEST:
		if (c == IP_DEST) {
			check_option(flags, OPT_DEST);
			ipinfo->bitmask |= EBT_IP_DEST;
		}
		if (check_inverse(optarg)) {
			if (c == IP_SOURCE)
				ipinfo->invflags |= EBT_IP_SOURCE;
			else
				ipinfo->invflags |= EBT_IP_DEST;
		}

		if (optind > argc)
			print_error("Missing ip address argument");
		if (c == IP_SOURCE)
			parse_ip_address(argv[optind - 1], &ipinfo->saddr,
			   &ipinfo->smsk);
		else
			parse_ip_address(argv[optind - 1], &ipinfo->daddr,
			   &ipinfo->dmsk);
		break;

	case IP_myTOS:
		check_option(flags, OPT_TOS);
		if (check_inverse(optarg))
			ipinfo->invflags |= EBT_IP_TOS;

		if (optind > argc)
			print_error("Missing ip tos argument");
		i = strtol(argv[optind - 1], &end, 16);
		if (i < 0 || i > 255 || *buffer != '\0')
			print_error("Problem with specified ip tos");
		ipinfo->tos = i;
		ipinfo->bitmask |= EBT_IP_TOS;
		break;

	case IP_PROTO:
		check_option(flags, OPT_PROTO);
		if (check_inverse(optarg))
			ipinfo->invflags |= EBT_IP_PROTO;
		if (optind > argc)
			print_error("Missing ip protocol argument");
		i = strtol(argv[optind - 1], &end, 10);
		if (i < 0 || i > 255 || *end != '\0')
			print_error("Problem with specified ip protocol");
		ipinfo->protocol = i;
		ipinfo->bitmask |= EBT_IP_PROTO;
		break;
	default:
		return 0;
	}
	return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_match *match, const char *name, unsigned int hook)
{
	if (entry->bitmask & EBT_NOPROTO || entry->bitmask & EBT_802_3 ||
	   entry->ethproto != ETH_P_IP)
		print_error("For IP filtering the protocol must be "
		            "specified as IPv4");
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_match *match)
{
	struct ebt_ip_info *ipinfo = (struct ebt_ip_info *)match->data;
	int j;

	if (ipinfo->bitmask & EBT_IP_SOURCE) {
		printf("source ip: ");
		if (ipinfo->invflags & EBT_IP_SOURCE)
			printf("! ");
		for (j = 0; j < 4; j++)
			printf("%d%s",((unsigned char *)&ipinfo->saddr)[j],
			   (j == 3) ? "" : ".");
		printf("%s, ", mask_to_dotted(ipinfo->smsk));
	}
	if (ipinfo->bitmask & EBT_IP_DEST) {
		printf("dest ip: ");
		if (ipinfo->invflags & EBT_IP_DEST)
			printf("! ");
		for (j = 0; j < 4; j++)
			printf("%d%s", ((unsigned char *)&ipinfo->daddr)[j],
			   (j == 3) ? "" : ".");
		printf("%s, ", mask_to_dotted(ipinfo->dmsk));
	}
	if (ipinfo->bitmask & EBT_IP_TOS) {
		printf("ip TOS: ");
		if (ipinfo->invflags & EBT_IP_TOS)
			printf("! ");
		printf("0x%02X, ", ipinfo->tos);
	}
	if (ipinfo->bitmask & EBT_IP_PROTO) {
		printf("ip proto: ");
		if (ipinfo->invflags & EBT_IP_DEST)
			printf("! ");
		printf("%d, ", ipinfo->protocol);
	}
}

static int compare(const struct ebt_entry_match *m1,
   const struct ebt_entry_match *m2)
{
	struct ebt_ip_info *ipinfo1 = (struct ebt_ip_info *)m1->data;
	struct ebt_ip_info *ipinfo2 = (struct ebt_ip_info *)m2->data;

	if (ipinfo1->bitmask != ipinfo2->bitmask)
		return 0;
	if (ipinfo1->invflags != ipinfo2->invflags)
		return 0;
	if (ipinfo1->bitmask & EBT_IP_SOURCE) {
		if (ipinfo1->saddr != ipinfo2->saddr)
			return 0;
		if (ipinfo1->smsk != ipinfo2->smsk)
			return 0;
	}
	if (ipinfo1->bitmask & EBT_IP_DEST) {
		if (ipinfo1->daddr != ipinfo2->daddr)
			return 0;
		if (ipinfo1->dmsk != ipinfo2->dmsk)
			return 0;
	}
	if (ipinfo1->bitmask & EBT_IP_TOS) {
		if (ipinfo1->tos != ipinfo2->tos)
			return 0;
	}
	if (ipinfo1->bitmask & EBT_IP_PROTO) {
		if (ipinfo1->protocol != ipinfo2->protocol)
			return 0;
	}
	return 1;
}

static struct ebt_u_match ip_match =
{
	EBT_IP_MATCH,
	sizeof(struct ebt_ip_info),
	print_help,
	init,
	parse,
	final_check,
	print,
	compare,
	opts,
};

static void _init(void) __attribute((constructor));
static void _init(void)
{
	register_match(&ip_match);
}
