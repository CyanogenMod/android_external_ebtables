#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_redirect.h>

extern char *standard_targets[NUM_STANDARD_TARGETS];

#define REDIRECT_TARGET '1'
static struct option opts[] =
{
	{ "redirect-target"    , required_argument, 0, REDIRECT_TARGET },
	{ 0 }
};

static void print_help()
{
	printf(
	"redirect option:\n"
	" --redirect-target target   : ACCEPT, DROP or CONTINUE\n");
}

static void init(struct ebt_entry_target *target)
{
	struct ebt_redirect_info *redirectinfo =
	   (struct ebt_redirect_info *)target->data;

	redirectinfo->target = EBT_ACCEPT;
	return;
}

#define OPT_REDIRECT_TARGET  0x01
static int parse(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	int i;
	struct ebt_redirect_info *redirectinfo =
	   (struct ebt_redirect_info *)(*target)->data;

	switch (c) {
	case REDIRECT_TARGET:
		check_option(flags, OPT_REDIRECT_TARGET);
		for (i = 0; i < NUM_STANDARD_TARGETS; i++)
			if (!strcmp(optarg, standard_targets[i])) {
				redirectinfo->target = -i - 1;
				break;
			}
		if (i == NUM_STANDARD_TARGETS)
			print_error("Illegal --redirect-target target");
		break;
	default:
		return 0;
	}
	return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name,
   unsigned int hook_mask, unsigned int time)
{
	if ( ((hook_mask & ~(1 << NF_BR_PRE_ROUTING)) || strcmp(name, "nat")) &&
	   ((hook_mask & ~(1 << NF_BR_BROUTING)) || strcmp(name, "broute")) )
		print_error("Wrong chain for redirect");
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	struct ebt_redirect_info *redirectinfo =
	   (struct ebt_redirect_info *)target->data;

	if (redirectinfo->target == EBT_ACCEPT)
		return;
	printf(" --redirect-target %s",
	   standard_targets[-redirectinfo->target - 1]);
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	struct ebt_redirect_info *redirectinfo1 =
	   (struct ebt_redirect_info *)t1->data;
	struct ebt_redirect_info *redirectinfo2 =
	   (struct ebt_redirect_info *)t2->data;

	return redirectinfo1->target == redirectinfo2->target;
}

static struct ebt_u_target redirect_target =
{
	EBT_REDIRECT_TARGET,
	sizeof(struct ebt_redirect_info),
	print_help,
	init,
	parse,
	final_check,
	print,
	compare,
	opts,
};

static void _init(void) __attribute__ ((constructor));
static void _init(void)
{
	register_target(&redirect_target);
}
