/*
 *  bridge ethernet protocol filter
 *
 *	Authors:
 *	Bart De Schuymer		<bart.de.schuymer@pandora.be>
 *
 *	br_db.h,v 1.1 2001/04/16
 *
 *  This code is stongly inspired on the iptables code which is
 *  Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef __LINUX_BRIDGE_DB_H
#define __LINUX_BRIDGE_DB_H
#include <linux/if.h> /* IFNAMSIZ */
#ifdef __KERNEL__
#include <linux/if_bridge.h>
#include <linux/netfilter_bridge.h>
#else
#include <linux/netfilter_bridge.h>
#endif
#define BRDB_BASE_CTL            135

#define BRDB_SO_SET_ALLOWDB      (BRDB_BASE_CTL)
#define BRDB_SO_SET_MAX          (BRDB_SO_SET_ALLOWDB+1)

#define BRDB_SO_GET_DBINFO       (BRDB_BASE_CTL)
#define BRDB_SO_GET_DB           (BRDB_SO_GET_DBINFO+1)
#define BRDB_SO_GET_MAX          (BRDB_SO_GET_DB+1)

#define BRDB_NODB 0
#define BRDB_DB   1

#define INITIAL_DBSIZE 10
#define IDENTIFY802_3 46

struct brdb_dbinfo {
	__u32 nentries;
};

struct brdb_dbentry {
	__u8 in[IFNAMSIZ];
	__u8 out[IFNAMSIZ];
	__u16 ethproto;
	__u32 hook;
};

#endif
