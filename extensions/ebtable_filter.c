#include <stdio.h>
#include <sys/socket.h>
#include <linux/netfilter_bridge/ebtables.h>
#include "../include/ebtables_u.h"

#define FILTER_VALID_HOOKS ((1 << NF_BR_LOCAL_IN) | (1 << NF_BR_FORWARD) | \
   (1 << NF_BR_LOCAL_OUT))

static void print_help(char **hn)
{
	int i;

	printf("Supported chains for the filter table:\n");
	for (i = 0; i < NF_BR_NUMHOOKS; i++)
		if (FILTER_VALID_HOOKS & (1 << i))
			printf("%s ", hn[i]);
	printf("\n");
}

static struct ebt_u_table table =
{
	"filter",
	NULL,
	print_help,
	NULL
};

static void _init(void) __attribute__ ((constructor));
static void _init(void)
{
	register_table(&table);
}
