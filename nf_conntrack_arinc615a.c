// SPDX-License-Identifier: GPL-2.0-only
/*
 * Connection tracking helper for ARINC 615A data loading.
 *
 * ARINC 615A runs on top of TFTP, but unlike plain TFTP both peers act as
 * TFTP server during one operation:
 *
 *  - The Data Loader (DL) starts every operation with a RRQ/WRQ to the
 *    Target's UDP port 59 (the "root" connection). The Target answers from a
 *    new port, as in plain TFTP.
 *  - During the operation the Target sends its own RRQ/WRQs (status files,
 *    data files) to the DL's TFTP server. That is UDP port 59 as well,
 *    unless the DL's request carries a "port" option (ASCII decimal) naming
 *    another one. The DL answers those from a new port again.
 *
 * Every connection created from an expectation gets this helper as well, so
 * all flows of one operation form a tree below the root connection. Each
 * packet seen anywhere in that tree restarts the timeout of every connection
 * from that flow up to the root, and of their pending expectations. An
 * operation is therefore removed once no packet of it has been seen for
 * "timeout" seconds.
 *
 * The helper only uses addresses and ports from the conntrack tuples, so it
 * works on the Target, on the Data Loader and on any router in between.
 * nf_nat_arinc615a adds NAT support.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/moduleparam.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/version.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>

#include "nf_conntrack_arinc615a.h"

#define HELPER_NAME "arinc615a"

MODULE_DESCRIPTION("ARINC 615A connection tracking helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NFCT_HELPER(HELPER_NAME);

#define MAX_PORTS 8
static unsigned short ports[MAX_PORTS];
static unsigned int ports_c;
module_param_array(ports, ushort, &ports_c, 0400);
MODULE_PARM_DESC(ports, "Target ARINC 615A ports (default 59)");

static unsigned int arinc615a_timeout __read_mostly = ARINC615A_TIMEOUT;

void (__rcu *nf_nat_arinc615a_hook)(struct nf_conntrack_expect *exp,
				    __be16 port) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_arinc615a_hook);

/* Per-connection helper data, lives in nf_conn_help->data. */
struct nf_ct_arinc615a {
	unsigned long exp_refreshed;	/* jiffies of last expectation refresh */
};

/* Expectation timers are refreshed at most this often per operation. */
#define ARINC615A_EXP_REFRESH_INTERVAL	(HZ / 2)

static struct nf_conntrack_expect_policy arinc615a_exp_policy __read_mostly = {
	/* reply port, DL server port, retries with another "port" option */
	.max_expected	= 8,
	.timeout	= ARINC615A_TIMEOUT,
	.name		= HELPER_NAME,
};

static struct nf_conntrack_helper arinc615a[MAX_PORTS * 2] __read_mostly;

static int arinc615a_set_timeout(const char *val, const struct kernel_param *kp)
{
	unsigned int t;
	int ret;

	ret = kstrtouint(val, 10, &t);
	if (ret)
		return ret;
	/* nf_ct_refresh() takes u32 jiffies */
	if (t == 0 || t > U32_MAX / HZ / 2)
		return -EINVAL;

	WRITE_ONCE(arinc615a_timeout, t);
	WRITE_ONCE(arinc615a_exp_policy.timeout, t);
	return 0;
}

static const struct kernel_param_ops arinc615a_timeout_ops = {
	.set	= arinc615a_set_timeout,
	.get	= param_get_uint,
};
module_param_cb(timeout, &arinc615a_timeout_ops, &arinc615a_timeout, 0644);
MODULE_PARM_DESC(timeout,
		 "Seconds without any packet after which an operation is dropped (default 14)");

/*
 * nf_ct_refresh() lost its skb argument in v6.14. Kbuild detects the variant
 * from the kernel headers (vendor kernels may backport it); fall back to the
 * version number otherwise.
 */
#if defined(ARINC615A_REFRESH_HAS_SKB) || \
	(!defined(ARINC615A_REFRESH_NO_SKB) && \
	 LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0))
#define arinc615a_ct_refresh(ct, j)	nf_ct_refresh(ct, NULL, j)
#else
#define arinc615a_ct_refresh(ct, j)	nf_ct_refresh(ct, j)
#endif

static int arinc615a_help(struct sk_buff *skb, unsigned int protoff,
			  struct nf_conn *ct, enum ip_conntrack_info ctinfo);

/* Return @ct's helper if it is one of ours, NULL otherwise. */
static struct nf_conntrack_helper *arinc615a_helper(const struct nf_conn *ct)
{
	struct nf_conntrack_helper *helper;
	struct nf_conn_help *help;

	if (!ct)
		return NULL;
	help = nfct_help(ct);
	if (!help)
		return NULL;
	helper = rcu_dereference(help->helper);
	if (!helper || helper->help != arinc615a_help)
		return NULL;
	return helper;
}

/*
 * Restart the timeout of @ct, of all its ancestors that belong to the same
 * operation and of the expectations they own.
 */
static void arinc615a_refresh(struct nf_conn *ct)
{
	u32 tmo = READ_ONCE(arinc615a_timeout) * HZ;
	struct nf_conntrack_expect *exp;
	struct nf_ct_arinc615a *info;
	struct nf_conn *node, *root;
	unsigned long last;

	root = ct;
	arinc615a_ct_refresh(ct, tmo);
	while (arinc615a_helper(root->master)) {
		root = root->master;
		arinc615a_ct_refresh(root, tmo);
	}

	/*
	 * Expectations live in a global, lock protected hash. Data transfers
	 * run at line rate, so don't take the lock for every packet; the
	 * timeout is in seconds anyway.
	 */
	info = nfct_help_data(root);
	last = READ_ONCE(info->exp_refreshed);
	if (last && time_in_range(jiffies, last,
				  last + ARINC615A_EXP_REFRESH_INTERVAL))
		return;
	WRITE_ONCE(info->exp_refreshed, jiffies);

	spin_lock_bh(&nf_conntrack_expect_lock);
	for (node = ct; node; node = node->master) {
		struct nf_conn_help *help = nfct_help(node);

		/*
		 * mod_timer_pending() leaves expectations alone whose timer
		 * already fired; they are being removed.
		 */
		hlist_for_each_entry(exp, &help->expectations, lnode)
			mod_timer_pending(&exp->timeout, jiffies + tmo);

		if (node == root)
			break;
	}
	spin_unlock_bh(&nf_conntrack_expect_lock);
}

/*
 * Find a "port" option in a RRQ/WRQ:
 *   opcode | filename \0 | mode \0 | [ option \0 | value \0 ]*
 * Option names are case insensitive (RFC 2347).
 *
 * Return: true and the port in *@port if a valid option was found.
 */
static bool arinc615a_parse_port(const char *buf, unsigned int len, u16 *port)
{
	const char *p = buf + 2, *end = buf + len, *name = NULL, *nul;
	unsigned int field = 0;

	for (; p < end; p = nul + 1, field++) {
		unsigned int val = 0;
		const char *c;

		nul = memchr(p, '\0', end - p);
		if (!nul)
			break;		/* truncated or malformed */

		/* fields 0 and 1 are filename and mode, then name/value pairs */
		if (field < 2)
			continue;
		if (field % 2 == 0) {
			name = p;
			continue;
		}
		if (strcasecmp(name, "port"))
			continue;

		/* strictly 1..5 decimal digits, 1..65535 */
		if (nul == p || nul - p > 5)
			return false;
		for (c = p; c < nul; c++) {
			if (!isdigit(*c))
				return false;
			val = val * 10 + (*c - '0');
		}
		if (val == 0 || val > 65535)
			return false;

		*port = val;
		return true;
	}
	return false;
}

/*
 * Expect a connection from the peer that received the request on @ct (any
 * source port) to the requester's port @port. @saved_port is the same port as
 * the requester itself knows it, which differs from @port only if NAT
 * remapped the requester's source port.
 */
static int arinc615a_expect(struct sk_buff *skb, struct nf_conn *ct,
			    struct nf_conntrack_helper *helper,
			    __be16 port, __be16 saved_port, unsigned int flags)
{
	const struct nf_conntrack_tuple *tuple =
		&ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	void (*nat_hook)(struct nf_conntrack_expect *exp, __be16 port);
	struct nf_conntrack_expect *exp;
	int err;

	exp = nf_ct_expect_alloc(ct);
	if (!exp) {
		nf_ct_helper_log(skb, ct, "cannot alloc expectation");
		return NF_DROP;
	}

	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, nf_ct_l3num(ct),
			  &tuple->src.u3, &tuple->dst.u3,
			  IPPROTO_UDP, NULL, &port);
	exp->flags |= flags;
	/* the new connection is part of this operation, track it too */
	exp->helper = helper;

	nat_hook = rcu_dereference(nf_nat_arinc615a_hook);
	if (nat_hook && (ct->status & IPS_NAT_MASK))
		nat_hook(exp, saved_port);

	pr_debug("expect: ");
	nf_ct_dump_tuple(&exp->tuple);

	err = nf_ct_expect_related(exp, 0);
	nf_ct_expect_put(exp);

	/*
	 * -EALREADY: another connection already expects exactly this, e.g. a
	 * DL that reuses its server port for a new operation before the old
	 * one timed out. The new flow will be tracked by that one.
	 */
	if (err && err != -EALREADY) {
		nf_ct_helper_log(skb, ct, "cannot add expectation: %d", err);
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static DEFINE_SPINLOCK(arinc615a_buf_lock);
static char arinc615a_buf[ARINC615A_MAX_REQ_LEN];

static int arinc615a_request(struct sk_buff *skb, unsigned int dataoff,
			     struct nf_conn *ct,
			     struct nf_conntrack_helper *helper)
{
	const struct nf_conntrack_tuple *orig =
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	const struct nf_conntrack_tuple *reply =
		&ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	/* The requester's port, as the peer sees it and as it knows it. */
	__be16 req_port = reply->dst.u.udp.port;
	__be16 req_saved = orig->src.u.udp.port;
	__be16 srv_port;
	unsigned int len;
	bool has_opt;
	u16 opt = 0;
	int ret;

	nf_ct_dump_tuple(orig);
	nf_ct_dump_tuple(reply);

	/*
	 * A request on a connection created by one of our expectations: the
	 * Target asking the DL's server, or the DL asking a Target port it
	 * was told about. Plain TFTP: the peer answers from a new port.
	 */
	if (arinc615a_helper(ct->master))
		return arinc615a_expect(skb, ct, helper, req_port, req_saved, 0);

	/*
	 * A request to the Target's ARINC 615A port starts or continues an
	 * operation. The Target will send its own requests to the DL's server
	 * port, repeatedly and from changing source ports, for as long as the
	 * operation lasts, so that expectation is permanent.
	 */
	len = min_t(unsigned int, skb->len - dataoff, sizeof(arinc615a_buf));
	spin_lock_bh(&arinc615a_buf_lock);
	if (skb_copy_bits(skb, dataoff, arinc615a_buf, len) == 0)
		has_opt = arinc615a_parse_port(arinc615a_buf, len, &opt);
	else
		has_opt = false;
	spin_unlock_bh(&arinc615a_buf_lock);

	/*
	 * The Target uses this port as is, on whatever address it sees the DL
	 * at. With NAT the DL therefore has to be reachable on the same port
	 * of the translated address.
	 */
	srv_port = htons(has_opt ? opt : ARINC615A_PORT);
	pr_debug("DL server port %u%s\n", ntohs(srv_port),
		 has_opt ? " (port option)" : "");

	if (srv_port != req_port) {
		/* answer to this request from the Target, one shot */
		ret = arinc615a_expect(skb, ct, helper, req_port, req_saved, 0);
		if (ret != NF_ACCEPT)
			return ret;
	}
	/* covers the answer to this request too if the ports are equal */
	return arinc615a_expect(skb, ct, helper, srv_port, srv_port,
				NF_CT_EXPECT_PERMANENT);
}

static int arinc615a_help(struct sk_buff *skb, unsigned int protoff,
			  struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	struct nf_conntrack_helper *helper = arinc615a_helper(ct);
	unsigned int dataoff = protoff + sizeof(struct udphdr);
	__be16 _opcode;
	const __be16 *opcode;

	if (WARN_ON_ONCE(!helper))
		return NF_ACCEPT;

	arinc615a_refresh(ct);

	/* Requests only ever start a flow, i.e. travel in original direction. */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	opcode = skb_header_pointer(skb, dataoff, sizeof(_opcode), &_opcode);
	if (!opcode)
		return NF_ACCEPT;

	switch (ntohs(*opcode)) {
	case ARINC615A_OP_RRQ:
	case ARINC615A_OP_WRQ:
		return arinc615a_request(skb, dataoff, ct, helper);
	default:
		return NF_ACCEPT;
	}
}

static void __exit nf_conntrack_arinc615a_fini(void)
{
	nf_conntrack_helpers_unregister(arinc615a, ports_c * 2);
}

static int __init nf_conntrack_arinc615a_init(void)
{
	int i, ret;

	NF_CT_HELPER_BUILD_BUG_ON(sizeof(struct nf_ct_arinc615a));

	if (ports_c == 0)
		ports[ports_c++] = ARINC615A_PORT;

	for (i = 0; i < ports_c; i++) {
		nf_ct_helper_init(&arinc615a[2 * i], AF_INET, IPPROTO_UDP,
				  HELPER_NAME, ARINC615A_PORT, ports[i], i,
				  &arinc615a_exp_policy, 0, arinc615a_help,
				  NULL, THIS_MODULE);
		nf_ct_helper_init(&arinc615a[2 * i + 1], AF_INET6, IPPROTO_UDP,
				  HELPER_NAME, ARINC615A_PORT, ports[i], i,
				  &arinc615a_exp_policy, 0, arinc615a_help,
				  NULL, THIS_MODULE);
		arinc615a[2 * i].data_len = sizeof(struct nf_ct_arinc615a);
		arinc615a[2 * i + 1].data_len = sizeof(struct nf_ct_arinc615a);
	}

	ret = nf_conntrack_helpers_register(arinc615a, ports_c * 2);
	if (ret < 0) {
		pr_err("failed to register helpers\n");
		return ret;
	}
	return 0;
}

module_init(nf_conntrack_arinc615a_init);
module_exit(nf_conntrack_arinc615a_fini);
