/*
 *  bridge ethernet protocol database
 *
 *	Authors:
 *	Bart De Schuymer		<bart.de.schuymer@pandora.be>
 *
 *  br_db.c, April, 2002
 *
 *  This code is stongly inspired on the iptables code which is
 *  Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netfilter_bridge.h>
#include <linux/br_db.h>
#include <linux/socket.h> /* PF_BRIDGE */
#include <linux/spinlock.h> /* rwlock_t */
#include <asm/errno.h>
#include <asm/uaccess.h> /* copy_[to,from]_user */
#include <linux/smp.h> /* multiprocessors */

#define BUGPRINT(format, args...) printk("kernel msg: brdb bug: please report to author: "format, ## args)
/*#define BUGPRINT(format, args...)*/
#define MEMPRINT(format, args...) printk("kernel msg: brdb : out of memory: "format, ## args)
/*#define MEMPRINT(format, args...)*/

/* database variables */
static __u16 allowdb = BRDB_NODB;
static struct brdb_dbentry **flowdb = NULL;
static unsigned int *dbsize;
static unsigned int *dbnum;
/* database lock */
static rwlock_t brdb_dblock;

static inline int brdb_dev_check(char *entry, const struct net_device *device){
	if (*entry == '\0') return 0;
	if (!device) return 1;
	return strncmp(entry, device->name, IFNAMSIZ);
}	

static inline int brdb_proto_check(unsigned int a, unsigned int b){
	if (a == b || ( a == IDENTIFY802_3 && ntohs(b) < 1536 )) return 0;
	return 1;
}

static unsigned int maintaindb (unsigned int hook, struct sk_buff **pskb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct brdb_dbentry *hlp;
	int i, cpunr;
	unsigned short ethproto = ((**pskb).mac.ethernet)->h_proto;

	cpunr = cpu_number_map(smp_processor_id());

	read_lock_bh(&brdb_dblock);

	if (allowdb == BRDB_NODB) {// must be after readlock
		read_unlock_bh(&brdb_dblock);
		return NF_ACCEPT;
	}
	hlp = flowdb[cpunr];
	/* search for existing entry */
	for (i = 0; i < dbnum[cpunr]; i++) {
		if (hlp->hook == hook && !brdb_proto_check(hlp->ethproto, ethproto) &&
			  !brdb_dev_check(hlp->in, in) && !brdb_dev_check(hlp->out, out)) {
			read_unlock_bh(&brdb_dblock);
			return NF_ACCEPT;
		}
		hlp++;
	}
	/* add new entry to database */
	if (dbnum[cpunr] == dbsize[cpunr]) {
		dbsize[cpunr] *= 2;
		if ( !( hlp = (struct brdb_dbentry *) vmalloc(dbsize[cpunr] * sizeof(struct brdb_dbentry)) ) ) {
			dbsize[cpunr] /= 2;
			MEMPRINT("maintaindb && nomemory\n");
			read_unlock_bh(&brdb_dblock);
			return NF_ACCEPT;
		}
		memcpy(hlp, flowdb[cpunr], dbnum[cpunr] * sizeof(struct brdb_dbentry));
		vfree(flowdb[cpunr]);
		flowdb[cpunr] = hlp;
	}

	hlp = flowdb[cpunr] + dbnum[cpunr];
	hlp->hook = hook;
	if (in)
		strncpy(hlp->in, in->name, IFNAMSIZ);
	else
		hlp->in[0] = '\0';
	if (out)
		strncpy(hlp->out, out->name, IFNAMSIZ);
	else
		hlp->out[0] = '\0';
	if (ntohs(ethproto) < 1536)
		hlp->ethproto = IDENTIFY802_3;
	else
		hlp->ethproto = ethproto;
	dbnum[cpunr]++;

	read_unlock_bh(&brdb_dblock);

	return NF_ACCEPT;
}

static int copy_db(void *user, int *len)
{
	int i, j, nentries = 0, ret;
	struct brdb_dbentry *begin, *end1, *end2, *point, *point2;

	write_lock_bh(&brdb_dblock);
	for (i = 0; i < smp_num_cpus; i++)
		nentries += dbnum[i];
	if (*len > nentries)
		return -EINVAL;

	if ( !(begin = (struct brdb_dbentry *) vmalloc((*len) * sizeof(struct brdb_dbentry))) )
		return -ENOMEM;
	memcpy(begin, flowdb[0], dbnum[0] * sizeof(struct brdb_dbentry));
	end1 = begin + dbnum[0];
	for (i = 1; i < smp_num_cpus; i++) {/* cycle databases per cpu */
		point2 = flowdb[i];
		end2 = end1;
		for (j = 0; j < dbnum[i]; j++) {/* cycle entries of a cpu's database (point2) */
			for (point = begin; point != end2; point++)/* cycle different entries we found so far */
				if (point->hook == point2->hook && !strncmp(point->in, point2->in, IFNAMSIZ) &&
				    !strncmp(point->out, point2->out, IFNAMSIZ) && point->ethproto == point2->ethproto)
					goto out;/* already exists in a database of another cpu */

			memcpy(end1, point2, sizeof(struct brdb_dbentry));
			end1++;
out:
			point2++;
		}
	}
	write_unlock_bh(&brdb_dblock);
	i = (int)( (char *)end1 - (char *)begin);
	*len = i < *len ? i : *len;
	if (copy_to_user(user, begin, *len * sizeof(struct brdb_dbentry)) != 0)
		ret = -EFAULT;
	else
		ret = 0;
	vfree(begin);
	return ret;
}

static int switch_nodb(void){
	int i;

	if (!flowdb)
		BUGPRINT("switch_nodb && !flowdb\n");
	for (i = 0; i < smp_num_cpus; i++)
		vfree(flowdb[i]);
	vfree(flowdb);
	if (!dbsize)
		BUGPRINT("switch_nodb && !dbsize\n");
	vfree(dbsize);
	if (!dbnum)
		BUGPRINT("switch_nodb && !dbnum\n");
	vfree(dbnum);
	flowdb = NULL;
	allowdb = BRDB_NODB;
	return 0;
}

static int switch_db(void)
{
	int i, j;

	if (flowdb) BUGPRINT("switch_db && flowdb\n");
	if ( !(flowdb = (struct brdb_dbentry **) vmalloc(smp_num_cpus * sizeof(struct brdb_dbentry *))) ) {
		MEMPRINT("switch_db && nomemory\n");
		return -ENOMEM;
	}

	for (i = 0; i < smp_num_cpus; i++)
		if ( !(flowdb[i] = (struct brdb_dbentry *) vmalloc(INITIAL_DBSIZE * sizeof(struct brdb_dbentry))) )
			goto sw_free1;
		else
			memset(flowdb[i], 0, INITIAL_DBSIZE * sizeof(struct brdb_dbentry));

	if ( !(dbnum = (int*) vmalloc(smp_num_cpus * sizeof(int))) )
		goto sw_free2;

	if ( !(dbsize = (int*) vmalloc(smp_num_cpus * sizeof(int))) )
		goto sw_free3;

	for (i = 0; i < smp_num_cpus; i++) {
		dbnum[i] = 0;
		dbsize[i] = INITIAL_DBSIZE;
	}
	allowdb = BRDB_DB;
	return 0;

sw_free3:
	MEMPRINT("switch_db && nomemory2\n");
	vfree(dbnum);
	dbnum = NULL;
sw_free2:
	MEMPRINT("switch_db && nomemory3\n");
sw_free1:
	MEMPRINT("switch_db && nomemory4\n");
	for (j = 0; j<i; j++)
		vfree(flowdb[j]);
	vfree(flowdb);
	allowdb = BRDB_NODB;
	return -ENOMEM;
}

static int
do_brdb_set_ctl(struct sock *sk, int cmd, void *user, unsigned int len)
{
	int ret;
	__u16 adb;
	switch(cmd) {
	case BRDB_SO_SET_ALLOWDB:
		if (len != sizeof(__u16)) {
			ret = -EINVAL;
			break;
		}
	 	if (copy_from_user(&adb, user, len) != 0) {
			ret = -EFAULT;
	 		break;
		}
		if (adb != BRDB_DB && adb != BRDB_NODB) {
			ret = -EINVAL;
			break;
		}
		write_lock_bh(&brdb_dblock);
		if (adb == allowdb) {
			ret = 0;
			write_unlock_bh(&brdb_dblock);
			break;
		}
		if (allowdb == BRDB_DB)
			ret = switch_nodb();
		else
			ret = switch_db();
		write_unlock_bh(&brdb_dblock);
		break;

	default:
		ret = -EINVAL;
	}
	return ret;
}

static int
do_brdb_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	struct brdb_dbinfo help2;
	int i, ret;
	switch(cmd) {
	case BRDB_SO_GET_DBINFO:
		if (sizeof(struct brdb_dbinfo) != *len)
			return -EINVAL;
		write_lock_bh(&brdb_dblock);
		/* 0 == no database
		 * i-1 == number of entries (if database)
		 */
		if (allowdb == BRDB_NODB)
			help2.nentries = 0;
		else {
			help2.nentries = 1;
			for (i = 0; i < smp_num_cpus; i++)
				help2.nentries += dbnum[i];
		}
		write_unlock_bh(&brdb_dblock);
		if (copy_to_user(user, &help2, sizeof(help2)) != 0)
			ret = -EFAULT;
		else
			ret = 0;
		break;

	case BRDB_SO_GET_DB:
		if (*len == 0 || allowdb == BRDB_NODB)
			return -EINVAL;
		ret = copy_db(user, len);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static struct nf_sockopt_ops brdb_sockopts
= { { NULL, NULL }, PF_INET, BRDB_BASE_CTL, BRDB_SO_SET_MAX+1, do_brdb_set_ctl,
    BRDB_BASE_CTL, BRDB_SO_GET_MAX+1, do_brdb_get_ctl, 0, NULL  };


static struct nf_hook_ops brdb_br_ops[] = {
	{ { NULL, NULL }, maintaindb, PF_BRIDGE, NF_BR_PRE_ROUTING, -250},
	{ { NULL, NULL }, maintaindb, PF_BRIDGE, NF_BR_LOCAL_IN, -250},
	{ { NULL, NULL }, maintaindb, PF_BRIDGE, NF_BR_FORWARD, -250},
	{ { NULL, NULL }, maintaindb, PF_BRIDGE, NF_BR_LOCAL_OUT, -250},
	{ { NULL, NULL }, maintaindb, PF_BRIDGE, NF_BR_POST_ROUTING, -250}
};

static int __init init(void)
{
	int ret;

	if ((ret = nf_register_hook(&brdb_br_ops[0])) < 0)
		return ret;

	if ((ret = nf_register_hook(&brdb_br_ops[1])) < 0)
		goto clean0;

	if ((ret = nf_register_hook(&brdb_br_ops[2])) < 0)
		goto clean1;

	if ((ret = nf_register_hook(&brdb_br_ops[3])) < 0)
		goto clean2;

	if ((ret = nf_register_hook(&brdb_br_ops[4])) < 0)
		goto clean3;

	/* Register setsockopt */
	if ((ret = nf_register_sockopt(&brdb_sockopts)) < 0)
		goto clean4;
	
	rwlock_init(&brdb_dblock);
	printk("Bridge ethernet database registered\n");
	return ret;

clean4:		nf_unregister_hook(&brdb_br_ops[4]);
clean3:		nf_unregister_hook(&brdb_br_ops[3]);
clean2:		nf_unregister_hook(&brdb_br_ops[2]);
clean1:		nf_unregister_hook(&brdb_br_ops[1]);
clean0:		nf_unregister_hook(&brdb_br_ops[0]);

	return ret;
}

static void __exit fini(void)
{
	nf_unregister_hook(&brdb_br_ops[4]);
	nf_unregister_hook(&brdb_br_ops[3]);
	nf_unregister_hook(&brdb_br_ops[2]);
	nf_unregister_hook(&brdb_br_ops[1]);
	nf_unregister_hook(&brdb_br_ops[0]);
	nf_unregister_sockopt(&brdb_sockopts);
}

module_init(init);
module_exit(fini);
