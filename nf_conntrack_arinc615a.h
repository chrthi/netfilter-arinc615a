/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NF_CONNTRACK_ARINC615A_H
#define _NF_CONNTRACK_ARINC615A_H

#include <linux/types.h>
#include <net/netfilter/nf_conntrack_expect.h>

#define ARINC615A_PORT		59
#define ARINC615A_TIMEOUT	14	/* seconds */

/* TFTP opcodes used by ARINC 615A */
#define ARINC615A_OP_RRQ	1
#define ARINC615A_OP_WRQ	2

/* RFC 2347: a request including options must not exceed 512 octets */
#define ARINC615A_MAX_REQ_LEN	512

/*
 * Set by nf_nat_arinc615a. Prepares @exp so that the connection it creates
 * follows the NAT mapping of its master; @port is the port, in the
 * requester's own (untranslated) address space, the new connection must be
 * delivered to.
 */
extern void (__rcu *nf_nat_arinc615a_hook)(struct nf_conntrack_expect *exp,
					   __be16 port);

#endif /* _NF_CONNTRACK_ARINC615A_H */
