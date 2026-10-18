# SPDX-License-Identifier: GPL-2.0-only

obj-m += nf_conntrack_arinc615a.o
ifneq ($(CONFIG_NF_NAT),)
obj-m += nf_nat_arinc615a.o
endif

ccflags-y += -I$(src)

# nf_ct_refresh() dropped its skb argument in v6.14. Detect which variant the
# target kernel has, so vendor backports build too.
arinc615a_refresh_proto := $(shell grep -A2 'static inline void nf_ct_refresh.struct nf_conn' \
	$(srctree)/include/net/netfilter/nf_conntrack.h 2>/dev/null)
ifneq ($(arinc615a_refresh_proto),)
ifneq ($(findstring sk_buff,$(arinc615a_refresh_proto)),)
ccflags-y += -DARINC615A_REFRESH_HAS_SKB
else
ccflags-y += -DARINC615A_REFRESH_NO_SKB
endif
endif
