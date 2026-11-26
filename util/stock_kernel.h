/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a stock distribution kernel offers the stock-kernel profile: the
 * BPF LSM and the attach kinds a upatch may use. Every answer comes from
 * a probe of the running kernel, never from its release, which enterprise
 * kernels backport past.
 */

#ifndef SHIRUDO_STOCK_KERNEL_H
#define SHIRUDO_STOCK_KERNEL_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

struct btf;

struct stock_kernel {
	bool	bpf_lsm;	/* "bpf" in the active LSM list */
	bool	cgroup_bpf;	/* cgroup v2 at /sys/fs/cgroup */
	bool	kprobe_multi;
	bool	uprobe_multi;
	bool	netfilter;
};

/* The running kernel; what cannot be probed counts as missing. */
void stock_kernel_probe(struct stock_kernel *k);

/* The attach kinds a vmlinux BTF has, for a test. */
void stock_kernel_probe_btf(const struct btf *btf, struct stock_kernel *k);

/* Whether the text of /sys/kernel/security/lsm, len bytes, names bpf. */
bool stock_lsm_list_has_bpf(const char *text, size_t len);

/*
 * NULL when the kernel can attach a program of the upatch attach kind
 * (enum upatch_attach_kind), else the reason and the remedy.
 */
const char *stock_kernel_refusal(const struct stock_kernel *k, __u32 kind);

/* The reason an lsm program cannot take effect, NULL when it can. */
const char *stock_kernel_lsm_refusal(const struct stock_kernel *k);

#endif /* SHIRUDO_STOCK_KERNEL_H */
