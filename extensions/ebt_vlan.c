/*
 * Summary: ebt_vlan - IEEE 802.1Q extension module for userspace
 *
 * Description: 802.1Q Virtual LAN match support module for ebtables project. 
 * Enables to match 802.1Q:
 * 1) VLAN-tagged frames by VLAN numeric identifier (12 - bits field)
 * 2) Priority-tagged frames by user_priority (3 bits field)
 * 3) Encapsulated Frame by ethernet protocol type/length
 * 
 * Authors:
 * Bart De Schuymer <bart.de.schuymer@pandora.be>
 * Nick Fedchik <nick@fedchik.org.ua> 
 * June, 2002
 *
 * License: GNU GPL 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include "../include/ethernetdb.h"
#include <linux/netfilter_bridge/ebt_vlan.h>

#define GET_BITMASK(_MASK_) vlaninfo->bitmask & _MASK_
#define SET_BITMASK(_MASK_) vlaninfo->bitmask |= _MASK_
#define INV_FLAG(_inv_flag_) (vlaninfo->invflags & _inv_flag_) ? "! " : ""

#define VLAN_ID    0
#define VLAN_PRIO  1
#define VLAN_ENCAP 2
static struct option opts[] = {
	{"vlan-id", required_argument, NULL, VLAN_ID},
	{"vlan-prio", required_argument, NULL, VLAN_PRIO},
	{"vlan-encap", required_argument, NULL, VLAN_ENCAP},
	{NULL}
};


/*
 * Print out local help by "ebtables -h vlan" 
 */
static void print_help ()
{
	printf ("802.1Q VLAN extension options:\n"
		"--vlan-id [!] id        : VLAN-tagged frame identifier, 0,1-4094 (integer)\n"
		"--vlan-prio [!] prio    : Priority-tagged frame user_priority, 0-7 (integer)\n"
		"--vlan-encap [!] proto  : Encapsulated protocol (hexadecimal)\n");
}

/*
 * Initialization function 
 */
static void init (struct ebt_entry_match *match)
{
	struct ebt_vlan_info *vlaninfo =
	    (struct ebt_vlan_info *) match->data;
	/*
	 * Set initial values 
	 */
	vlaninfo->id = 1;	/* Default VID for VLAN-tagged 802.1Q frames */
	vlaninfo->prio = 0;
	vlaninfo->encap = 0;
	vlaninfo->invflags = 0;
	vlaninfo->bitmask = 0;
}

/*
 * option flags definition 
 */
#define OPT_VLAN_ID     0x01
#define OPT_VLAN_PRIO   0x02
#define OPT_VLAN_ENCAP  0x04

/*
 * Parse passed arguments values (ranges, flags, etc...)
 * int c - parameter number from static struct option opts[]
 * int argc - total amout of arguments (std argc value)
 * 
 */
static int
parse (int c,
       char **argv,
       int argc,
       const struct ebt_u_entry *entry,
       unsigned int *flags, struct ebt_entry_match **match)
{
	struct ebt_vlan_info *vlaninfo =
	    (struct ebt_vlan_info *) (*match)->data;
	unsigned long i;
	char *end;
	uint16_t encap;
	switch (c) {
	case VLAN_ID:
		/*
		 * ebtables.c:check_option(unsigned int *flags, unsigned int mask)
		 * checking for multiple usage of same option 
		 */
		check_option (flags, OPT_VLAN_ID);
		/*
		 * Check If we got inversed arg for vlan-id option,
		 * otherwise unset inversion flag 
		 */
		if (check_inverse (optarg))
			vlaninfo->invflags |= EBT_VLAN_ID;
		/*
		 * Check arg value presence
		 */
		if (optind > argc)
			print_error ("Missing VLAN ID argument value");
		/*
		 * Convert argv to long int,
		 * set *end to end of argv string, 
		 * base set 10 for decimal only
		 */
		(unsigned short) i = strtol (argv[optind - 1], &end, 10);
		/*
		 * Check arg val range
		 */
		if (i > 4094 || *end != '\0')
			print_error
			    ("Specified VLAN ID is out of range (0-4094)");
		/*
		 * Set up parameter value
		 */
		vlaninfo->id = i;
		/*
		 * Set up parameter presence flag 
		 */
		SET_BITMASK (EBT_VLAN_ID);
		break;

	case VLAN_PRIO:
		check_option (flags, OPT_VLAN_PRIO);
		if (check_inverse (optarg))
			vlaninfo->invflags |= EBT_VLAN_PRIO;
		if (optind > argc)
			print_error
			    ("Missing user_priority argument value");
		/*
		 * Convert argv to long int,
		 * set *end to end of argv string, 
		 * base set 10 for decimal only 
		 */
		(unsigned char) i = strtol (argv[optind - 1], &end, 10);
		/*
		 * Check arg val range 
		 */
		if (i >= 8 || *end != '\0')
			print_error
			    ("Specified user_priority is out of range (0-7)");
		/*
		 * Set up parameter value 
		 */
		vlaninfo->prio = i;
		/*
		 * Set up parameter presence flag 
		 */
		SET_BITMASK (EBT_VLAN_PRIO);
		break;

	case VLAN_ENCAP:
		check_option (flags, OPT_VLAN_ENCAP);
		if (check_inverse (optarg))
			vlaninfo->invflags |= EBT_VLAN_ENCAP;
		if (optind > argc)
			print_error
			    ("Missing encapsulated frame type argument value");
		/*
		 * Parameter can be decimal, hexadecimal, or string.
		 * Check arg val range (still raw area)
		 */
		(unsigned short) encap = strtol (argv[optind - 1], &end, 16);
		if (*end == '\0' && (encap < ETH_ZLEN || encap > 0xFFFF))
			print_error
			    ("Specified encapsulated frame type is out of range");
		if (*end != '\0') {
			struct ethertypeent *ent;

			ent = getethertypebyname(argv[optind - 1]);
			if (!ent)
				print_error
				    ("Problem with the specified encapsulated"
				     "protocol");
			encap = ent->e_ethertype;
		}
		/*
		 * Set up parameter value (network notation)
		 */
		vlaninfo->encap = htons (encap);
		/*
		 * Set up parameter presence flag
		 */
		SET_BITMASK (EBT_VLAN_ENCAP);
		break;
	default:
		return 0;
	}
	return 1;
}

/*
 * Final check - logical conditions
 */
static void
final_check (const struct ebt_u_entry *entry,
	     const struct ebt_entry_match *match,
	     const char *name, unsigned int hookmask, unsigned int time)
{

	struct ebt_vlan_info *vlaninfo =
	    (struct ebt_vlan_info *) match->data;
	/*
	 * Specified proto isn't 802.1Q?
	 */
	if (entry->ethproto != ETH_P_8021Q ||
	    entry->invflags & EBT_IPROTO)
		print_error
		    ("For use 802.1Q extension the protocol must be specified as 802_1Q");
	/*
	 * Check if specified vlan-encap=0x8100 (802.1Q Frame) 
	 * when vlan-encap specified.
	 */
	if (GET_BITMASK (EBT_VLAN_ENCAP)) {
		if (vlaninfo->encap==htons(0x8100))
			print_error
			    ("Encapsulated frame type can not be 802.1Q (0x8100)");
	}

	/*
	 * Check if specified vlan-id=0 (priority-tagged frame condition) 
	 * when vlan-prio was specified.
	 */
	if (GET_BITMASK (EBT_VLAN_PRIO)) {
		if (vlaninfo->id && GET_BITMASK (EBT_VLAN_ID))
			print_error
			    ("For use user_priority the specified vlan-id must be 0");
	}
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
	if (GET_BITMASK (EBT_VLAN_ID)) {
		printf ("--%s %s%d ",
			opts[VLAN_ID].name,
			INV_FLAG (EBT_VLAN_ID), vlaninfo->id);
	}
	/*
	 * Print user priority if they are specified 
	 */
	if (GET_BITMASK (EBT_VLAN_PRIO)) {
		printf ("--%s %s%d ",
			opts[VLAN_PRIO].name,
			INV_FLAG (EBT_VLAN_PRIO), vlaninfo->prio);
	}
	/*
	 * Print encapsulated frame type if they are specified 
	 */
	if (GET_BITMASK (EBT_VLAN_ENCAP)) {
		struct ethertypeent *ent;

		printf ("--%s %s",
			opts[VLAN_ENCAP].name, INV_FLAG (EBT_VLAN_ENCAP));
		ent = getethertypebynumber(ntohs(vlaninfo->encap));
		if (!ent)
			printf ("%2.4X ", ntohs (vlaninfo->encap));
		else
			printf ("%s ", ent->e_name);
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
	/*
	 * Compare VLAN Encap if they are present 
	 */
	if (vlaninfo1->bitmask & EBT_VLAN_ENCAP) {
		if (vlaninfo1->encap != vlaninfo2->encap)
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
	opts
};

static void _init (void) __attribute__ ((constructor));
static void _init (void)
{
	register_match (&vlan_match);
}
