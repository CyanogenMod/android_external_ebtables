#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_nat.h>

extern char *standard_targets[NUM_STANDARD_TARGETS];

int to_source_supplied, to_dest_supplied;

#define NAT_S '1'
#define NAT_D '1'
#define NAT_S_TARGET '2'
#define NAT_D_TARGET '2'
static struct option opts_s[] =
{
	{ "to-source"     , required_argument, 0, NAT_S },
	{ "to-src"        , required_argument, 0, NAT_S },
	{ "snat-target"    , required_argument, 0, NAT_S_TARGET },
	{ 0 }
};

static struct option opts_d[] =
{
	{ "to-destination", required_argument, 0, NAT_D },
	{ "to-dst"        , required_argument, 0, NAT_D },
	{ "dnat-target"    , required_argument, 0, NAT_D_TARGET },
	{ 0 }
};

static void print_help_s()
{
	printf(
	"snat options:\n"
	" --to-src address       : MAC address to map source to\n"
	" --snat-target target   : ACCEPT, DROP or CONTINUE\n");
}

static void print_help_d()
{
	printf(
	"dnat options:\n"
	" --to-dst address       : MAC address to map destination to\n"
	" --dnat-target target   : ACCEPT, DROP or CONTINUE\n");
}

static void init_s(struct ebt_entry_target *target)
{
	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)target->data;

	to_source_supplied = 0;
	natinfo->target = EBT_ACCEPT;
	return;
}

static void init_d(struct ebt_entry_target *target)
{
	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)target->data;

	to_dest_supplied = 0;
	natinfo->target = EBT_ACCEPT;
	return;
}

#define OPT_SNAT         0x01
#define OPT_SNAT_TARGET  0x02
static int parse_s(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	int i;
	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)(*target)->data;

	switch (c) {
	case NAT_S:
		check_option(flags, OPT_SNAT);
		to_source_supplied = 1;
		if (getmac(optarg, natinfo->mac))
			print_error("Problem with specified to-source mac");
		break;
	case NAT_S_TARGET:
		check_option(flags, OPT_SNAT_TARGET);
		for (i = 0; i < NUM_STANDARD_TARGETS; i++)
			if (!strcmp(optarg, standard_targets[i])) {
				natinfo->target = i;
				break;
			}
		if (i == NUM_STANDARD_TARGETS)
			print_error("Illegal --snat-target target");
		break;
	default:
		return 0;
	}
	return 1;
}

#define OPT_DNAT        0x01
#define OPT_DNAT_TARGET 0x02
static int parse_d(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	int i;
	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)(*target)->data;

	switch (c) {
	case NAT_D:
		check_option(flags, OPT_DNAT);
		to_dest_supplied = 1;
		if (getmac(optarg, natinfo->mac))
			print_error("Problem with specified "
			            "to-destination mac");
		break;
	case NAT_D_TARGET:
		check_option(flags, OPT_DNAT_TARGET);
		for (i = 0; i < NUM_STANDARD_TARGETS; i++)
			if (!strcmp(optarg, standard_targets[i])) {
				natinfo->target = i;
				break;
			}
		if (i == NUM_STANDARD_TARGETS)
			print_error("Illegal --dnat-target target");
		break;
	default:
		return 0;
	}
	return 1;
}

static void final_check_s(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name, unsigned int hook)
{
	if (hook != NF_BR_POST_ROUTING || strcmp(name, "nat"))
		print_error("Wrong chain for snat");
	if (to_source_supplied == 0)
		print_error("No snat address supplied");
}

static void final_check_d(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name, unsigned int hook)
{
	if ( ((hook != NF_BR_PRE_ROUTING && hook != NF_BR_LOCAL_OUT) ||
	   strcmp(name, "nat")) &&
	   (hook != NF_BR_BROUTING || strcmp(name, "broute")) )
		print_error("Wrong chain for dnat");
	if (to_dest_supplied == 0)
		print_error("No dnat address supplied");
}

static void print_s(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)target->data;
	int i;

	printf("snat - to: ");
	for (i = 0; i < ETH_ALEN; i++)
		printf("%02x%s",
		   natinfo->mac[i], (i == ETH_ALEN - 1) ? "" : ":");
	printf(" --snat-target %s", standard_targets[natinfo->target]);
}

static void print_d(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)target->data;
	int i;

	printf("dnat - to: ");
	for (i = 0; i < ETH_ALEN; i++)
		printf("%02x%s",
		   natinfo->mac[i], (i == ETH_ALEN - 1) ? "" : ":");
	printf(" --dnat-target %s", standard_targets[natinfo->target]);
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	struct ebt_nat_info *natinfo1 = (struct ebt_nat_info *)t1->data;
	struct ebt_nat_info *natinfo2 = (struct ebt_nat_info *)t2->data;


	return !memcmp(natinfo1->mac, natinfo2->mac, sizeof(natinfo1->mac)) &&
	   natinfo1->target == natinfo2->target;
}

static struct ebt_u_target snat_target =
{
	EBT_SNAT_TARGET,
	sizeof(struct ebt_nat_info),
	print_help_s,
	init_s,
	parse_s,
	final_check_s,
	print_s,
	compare,
	opts_s,
};

static struct ebt_u_target dnat_target =
{
	EBT_DNAT_TARGET,
	sizeof(struct ebt_nat_info),
	print_help_d,
	init_d,
	parse_d,
	final_check_d,
	print_d,
	compare,
	opts_d,
};

static void _init(void) __attribute__ ((constructor));
static void _init(void)
{
	register_target(&snat_target);
	register_target(&dnat_target);
}
