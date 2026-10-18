// SPDX-License-Identifier: GPL-2.0-only
/*
 * NAT support for the ARINC 615A connection tracking helper.
 *
 * Every connection expected by nf_conntrack_arinc615a flows from the peer
 * that received a request back to the requester, so it simply mirrors the
 * NAT mapping of its master, delivered to the requester's own port.
 */

#include <linux/module.h>
#include <linux/udp.h>

#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_nat_helper.h>

#include "nf_conntrack_arinc615a.h"

#define NAT_HELPER_NAME "arinc615a"

MODULE_DESCRIPTION("ARINC 615A NAT helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NF_NAT_HELPER(NAT_HELPER_NAME);

static struct nf_conntrack_nat_helper nat_helper_arinc615a =
	NF_CT_NAT_HELPER_INIT(NAT_HELPER_NAME);

static void nf_nat_arinc615a(struct nf_conntrack_expect *exp, __be16 port)
{
	exp->saved_proto.udp.port = port;
	exp->dir = IP_CT_DIR_REPLY;
	exp->expectfn = nf_nat_follow_master;
}

static void __exit nf_nat_arinc615a_fini(void)
{
	nf_nat_helper_unregister(&nat_helper_arinc615a);
	RCU_INIT_POINTER(nf_nat_arinc615a_hook, NULL);
	synchronize_rcu();
}

static int __init nf_nat_arinc615a_init(void)
{
	if (WARN_ON(rcu_access_pointer(nf_nat_arinc615a_hook)))
		return -EBUSY;

	nf_nat_helper_register(&nat_helper_arinc615a);
	RCU_INIT_POINTER(nf_nat_arinc615a_hook, nf_nat_arinc615a);
	return 0;
}

module_init(nf_nat_arinc615a_init);
module_exit(nf_nat_arinc615a_fini);
