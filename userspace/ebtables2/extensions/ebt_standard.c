#include <stdio.h>
#include <sys/socket.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <getopt.h>
#include "../include/ebtables_u.h"

static struct option opts[] =
{
	{0}
};

static void print_help()
{
	printf("Standard targets: DROP, ACCEPT and CONTINUE\n");
}

static void init(struct ebt_entry_target *t)
{
	((struct ebt_standard_target *)t)->verdict = EBT_CONTINUE;
}

static int parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
   unsigned int *flags, struct ebt_entry_target **target)
{
	return 0;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name, unsigned int hook)
{
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	__u8 verdict = ((struct ebt_standard_target *)target)->verdict;

	if (verdict == EBT_CONTINUE)
		printf("Continue ");
	else if (verdict ==  EBT_ACCEPT)
		printf("Accept ");
	else
		printf("Drop ");
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	return ((struct ebt_standard_target *)t1)->verdict ==
	   ((struct ebt_standard_target *)t2)->verdict;
}

static struct ebt_u_target standard =
{
	EBT_STANDARD_TARGET,
	sizeof(struct ebt_standard_target) - sizeof(struct ebt_entry_target),
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
	register_target(&standard);
}
