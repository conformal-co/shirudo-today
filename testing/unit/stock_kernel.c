// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include <bpf/btf.h>

#include <shirudo/upatch.h>

#include "stock_kernel.h"
#include "unit.h"

#define LIST(s)		s, sizeof(s) - 1
#define NETFILTER	UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING

static void lsm_list_names_bpf_anywhere(void)
{
	EXPECT_TRUE(stock_lsm_list_has_bpf(LIST("lockdown,capability,bpf\n")));
	EXPECT_TRUE(stock_lsm_list_has_bpf(LIST("bpf,landlock")));
	EXPECT_TRUE(stock_lsm_list_has_bpf(LIST("bpf")));
}

static void lsm_list_without_bpf_is_refused(void)
{
	EXPECT_FALSE(stock_lsm_list_has_bpf(LIST("lockdown,capability,landlock,yama,apparmor\n")));
	EXPECT_FALSE(stock_lsm_list_has_bpf(LIST("bpfx,xbpf")));
	EXPECT_FALSE(stock_lsm_list_has_bpf(LIST("")));
}

static void a_missing_kind_is_refused_with_its_remedy(void)
{
	struct stock_kernel k = {};

	EXPECT_TRUE(stock_kernel_refusal(&k, UPATCH_ATTACH_UPROBE_MULTI));
	EXPECT_TRUE(stock_kernel_refusal(&k, UPATCH_ATTACH_KRETPROBE_MULTI));
	EXPECT_TRUE(stock_kernel_refusal(&k, UPATCH_ATTACH_CGROUP_SKB_EGRESS));
	EXPECT_TRUE(stock_kernel_refusal(&k, NETFILTER));
	EXPECT_TRUE(strstr(stock_kernel_lsm_refusal(&k), "lsm=...,bpf"));
	k = (struct stock_kernel){
		.uprobe_multi	= true,
		.kprobe_multi	= true,
		.cgroup_bpf	= true,
		.netfilter	= true,
		.bpf_lsm	= true,
	};
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_UPROBE_MULTI));
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_KRETPROBE_MULTI));
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_CGROUP_SKB_EGRESS));
	EXPECT_FALSE(stock_kernel_lsm_refusal(&k));
}

static void kinds_every_kernel_has_are_never_refused(void)
{
	struct stock_kernel k = {};

	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_RAW_TRACEPOINT));
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_KPROBE));
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_UPROBE));
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_XDP));
	EXPECT_FALSE(stock_kernel_refusal(&k, UPATCH_ATTACH_FMOD_RET));
}

/* A BTF with a kprobe.multi link only. */
static void btf_says_which_kinds_the_kernel_has(void)
{
	struct stock_kernel k = {};
	struct btf *btf;

	btf = btf__new_empty();
	ASSERT_TRUE(btf);
	ASSERT_TRUE(btf__add_struct(btf, "bpf_kprobe_multi_link", 0) > 0);
	stock_kernel_probe_btf(btf, &k);
	EXPECT_TRUE(k.kprobe_multi);
	EXPECT_FALSE(k.uprobe_multi);
	EXPECT_FALSE(k.netfilter);
	btf__free(btf);
}

static const struct unit_case cases[] = {
	UNIT_CASE(lsm_list_names_bpf_anywhere),
	UNIT_CASE(lsm_list_without_bpf_is_refused),
	UNIT_CASE(a_missing_kind_is_refused_with_its_remedy),
	UNIT_CASE(kinds_every_kernel_has_are_never_refused),
	UNIT_CASE(btf_says_which_kinds_the_kernel_has),
	{}
};

UNIT_SUITE(stock_kernel, cases);
