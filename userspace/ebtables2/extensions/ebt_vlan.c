/*
 * Summary: ebt_vlan userspace module
 * 
 * Description: 802.1Q Virtual LAN match support module for ebtables project.
 * Enable to match 802.1Q VLAN tagged frames by VLAN numeric 
 * identifier (12-bites field) and frame priority (3-bites field)
 * 
 * Authors:
 * Bart De Schuymer <bart.de.schuymer@pandora.be>
 * Nick Fedchik <nick@fedchik.org.ua>
 *  
 *  May, 2002
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_vlan.h>

#define VLAN_ID    '1'
#define VLAN_PRIO  '2'

static struct option opts[] = {
	{"vlan-id", required_argument, 0, VLAN_ID},
	{"vlan-prio", required_argument, 0, VLAN_PRIO},
	{0}
};

/*
 * Print out help for ebtables -h vlan 
 */
static void print_help ()
{
	printf ("802.1Q VLAN options:\n"
		"--vlan-id [!] id        : VLAN ID 1-4095 (integer)\n"
		"--vlan-prio [!] prio    : VLAN Priority 0-7 (integer)\n");
}

/*
 * Initialization function 
 */
static void init (struct ebt_entry_match *match)
{
	struct ebt_vlan_info *vlaninfo =
	    (struct ebt_vlan_info *) match->data;
	/*
	 * Just clean initial values 
	 */
	vlaninfo->id = 0;
	vlaninfo->prio = 0;
	vlaninfo->invflags = 0;
	vlaninfo->bitmask = 0;
}

#define OPT_VLAN_ID     0x01
#define OPT_VLAN_PRIO   0x02
static int
parse (int c, char **argv, int argc,
       const struct ebt_u_entry *entry, unsigned int *flags,
       struct ebt_entry_match **match)
{
	struct ebt_vlan_info *vlaninfo =
	    (struct ebt_vlan_info *) (*match)->data;
	unsigned short i;
	char *end;

	switch (c) {
	case VLAN_ID:
		check_option (flags, OPT_VLAN_ID);
		/*
		 * Check If we got inversed arg for VID,
		 * otherwise unset inversion flag 
		 */
		if (check_inverse (optarg))
			vlaninfo->invflags |= EBT_VLAN_ID;
		/*
		 * Check arg value presense 
		 */
		if (optind > argc)
			print_error ("Missing VLAN ID argument\n");
		/*
		 * Convert argv to long int,
		 * set *end to end of argv string, 
		 * base set 10 for decimal only 
		 */
		(unsigned short) i = strtol (argv[optind - 1], &end, 10);
		/*
		 * Check arg val range 
		 */
		if (i < 1 || i >= 4096 || *end != '\0') {
			i = 0;
			print_error
			    ("Problem with specified VLAN ID range\n");
		}
		vlaninfo->id = i;
		vlaninfo->bitmask|=EBT_VLAN_ID;
		break;

	case VLAN_PRIO:
		check_option (flags, OPT_VLAN_PRIO);
		if (check_inverse (optarg))
			vlaninfo->invflags |= EBT_VLAN_PRIO;
		if (optind > argc)
			print_error
			    ("Missing VLAN Priority level argument\n");
		/*
		 * Convert argv to long int,
		 * set *end to end of argv string, 
		 * base set 10 for decimal only 
		 */
		(unsigned short) i = strtol (argv[optind - 1], &end, 10);
		/*
		 * Check arg val range 
		 */
		if (i >= 8 || *end != '\0') {
			i = 0;
			print_error
			    ("Problem with specified VLAN Priority range\n");
		}
		vlaninfo->prio = i;
		vlaninfo->bitmask|=EBT_VLAN_PRIO;
		break;

	default:
		return 0;
	}
	return 1;
}

/*
 * Final check 
 */
static void
final_check (const struct ebt_u_entry *entry,
	     const struct ebt_entry_match *match,
	     const char *name, unsigned int hook)
{
	/*
	 * Is any proto supplied there? Or specified proto isn't 802.1Q?
	 */
	if (entry->bitmask & EBT_NOPROTO || entry->ethproto != ETH_P_8021Q)
		print_error
		    ("For matching 802.1Q VLAN the protocol must be specified as 802_1Q\n");
}

/*
 * Print line when listing rules by ebtables -L 
 */
static void
print (const struct ebt_u_entry *entry,
       const struct ebt_entry_match *match)
{
	struct ebt_vlan_info *vlaninfo =
	    (struct ebt_vlan_info *) match->data;

	/*
	 * Print VLAN ID if they are specified 
	 */
	if (vlaninfo->bitmask & EBT_VLAN_ID) {
		printf ("vlan id: %s%d, ",
			vlaninfo->invflags & EBT_VLAN_ID ? "!" : "",
			vlaninfo->id);
	}
	/*
	 * Print VLAN priority if they are specified 
	 */
	if (vlaninfo->bitmask & EBT_VLAN_PRIO) {
		printf ("vlan prio: %s%d, ",
			vlaninfo->invflags & EBT_VLAN_PRIO ? "!" : "",
			vlaninfo->prio);
	}
}


static int
compare (const struct ebt_entry_match *vlan1,
	 const struct ebt_entry_match *vlan2)
{
	struct ebt_vlan_info *vlaninfo1 =
	    (struct ebt_vlan_info *) vlan1->data;
	struct ebt_vlan_info *vlaninfo2 =
	    (struct ebt_vlan_info *) vlan2->data;
	/*
	 * Compare argc 
	 */
	if (vlaninfo1->bitmask != vlaninfo2->bitmask)
		return 0;
	/*
	 * Compare inv flags  
	 */
	if (vlaninfo1->invflags != vlaninfo2->invflags)
		return 0;
	/*
	 * Compare VLAN ID if they are present 
	 */
	if (vlaninfo1->bitmask & EBT_VLAN_ID) {
		if (vlaninfo1->id != vlaninfo2->id)
			return 0;
	};
	/*
	 * Compare VLAN Prio if they are present 
	 */
	if (vlaninfo1->bitmask & EBT_VLAN_PRIO) {
		if (vlaninfo1->prio != vlaninfo2->prio)
			return 0;
	};
	return 1;
}

static struct ebt_u_match vlan_match = {
	EBT_VLAN_MATCH,
	sizeof (struct ebt_vlan_info),
	print_help,
	init,
	parse,
	final_check,
	print,
	compare,
	opts,
};

static void _init (void) __attribute__ ((constructor));
static void _init (void)
{
	register_match (&vlan_match);
}
