// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The stock-kernel profile's view of the running kernel: its pre-flight
 * and kernel_abi_check(), in place of util/preflight.c and
 * util/kernel_abi.c, which check the patched kernel, and the attach
 * kinds a load may use.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/magic.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "kernel_abi.h"
#include "keys.h"
#include "malloc.h"
#include "paths.h"
#include "preflight.h"
#include "stock_kernel.h"

void stock_kernel_probe_btf(const struct btf *btf, struct stock_kernel *k)
{
	k->kprobe_multi = btf__find_by_name_kind(btf, "bpf_kprobe_multi_link",
						 BTF_KIND_STRUCT) > 0;
	k->uprobe_multi = btf__find_by_name_kind(btf, "bpf_uprobe_multi_link",
						 BTF_KIND_STRUCT) > 0;
	k->netfilter = btf__find_by_name_kind(btf, "bpf_nf_link",
					      BTF_KIND_STRUCT) > 0;
}

bool stock_lsm_list_has_bpf(const char *text, size_t len)
{
	const char *name;
	size_t n;

	for_each_token(name, n, text, len, ",\n") {
		if (span_equals(name, n, "bpf"))
			return true;
	}
	return false;
}

/* securityfs reports a size of zero: read what the file gives. */
static bool bpf_lsm_active(void)
{
	char text[4096];
	ssize_t n;
	int fd;

	fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	n = read(fd, text, sizeof(text));
	close(fd);
	return n > 0 && stock_lsm_list_has_bpf(text, (size_t)n);
}

void stock_kernel_probe(struct stock_kernel *k)
{
	struct btf *btf = btf__load_vmlinux_btf();
	struct statfs st;

	memset(k, 0, sizeof(*k));
	if (btf)
		stock_kernel_probe_btf(btf, k);
	btf__free(btf);
	k->bpf_lsm = bpf_lsm_active();
	k->cgroup_bpf = !statfs("/sys/fs/cgroup", &st) &&
			st.f_type == CGROUP2_SUPER_MAGIC;
}

const char *stock_kernel_lsm_refusal(const struct stock_kernel *k)
{
	return k->bpf_lsm ? NULL :
	       "lsm attach requires 'bpf' in the kernel lsm= list; "
	       "add lsm=...,bpf to the kernel command line and reboot";
}

const char *stock_kernel_refusal(const struct stock_kernel *k, __u32 kind)
{
	switch (kind) {
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return k->cgroup_bpf ? NULL :
		       "cgroup_skb attach requires the unified cgroup v2 "
		       "hierarchy at /sys/fs/cgroup";
	case UPATCH_ATTACH_KPROBE_MULTI:
	case UPATCH_ATTACH_KRETPROBE_MULTI:
		return k->kprobe_multi ? NULL :
		       "kprobe.multi attach requires a kernel with "
		       "bpf_kprobe_multi_link and CONFIG_FPROBE";
	case UPATCH_ATTACH_UPROBE_MULTI:
	case UPATCH_ATTACH_URETPROBE_MULTI:
		return k->uprobe_multi ? NULL :
		       "uprobe.multi attach requires a kernel with bpf_uprobe_multi_link";
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return k->netfilter ? NULL :
		       "netfilter attach requires a kernel with bpf_nf_link";
	default:
		return NULL;
	}
}

/*
 * Every payload BPF_PROG_LOAD of libbpf's gen_loader passes the
 * attribute up to core_relo_rec_size, which a kernel without in-kernel
 * CO-RE refuses as bytes past the end of its own bpf_attr.
 */
static bool core_relo_attr(void)
{
	const struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	union bpf_attr attr = {};
	int fd;

	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insns = ptr_to_u64(insns);
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.license = ptr_to_u64("GPL");
	attr.core_relo_rec_size = sizeof(struct bpf_core_relo);
	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr,
		     offsetofend(union bpf_attr, core_relo_rec_size));
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

/* A payload's BTF carries the type tags of vmlinux.h's __rcu and kin. */
static bool btf_type_tag(void)
{
	struct btf *btf = btf__new_empty();
	const void *raw = NULL;
	__u32 size;
	int id, fd = -1;

	id = btf ? btf__add_int(btf, "int", sizeof(int), BTF_INT_SIGNED) : -1;
	if (id > 0)
		id = btf__add_type_tag(btf, "tag", id);
	if (id > 0 && btf__add_ptr(btf, id) > 0)
		raw = btf__raw_data(btf, &size);
	if (raw)
		fd = bpf_btf_load(raw, size, NULL);
	if (fd >= 0)
		close(fd);
	btf__free(btf);
	return fd >= 0;
}

static bool syscall_helper(enum bpf_func_id helper)
{
	return libbpf_probe_bpf_helper(BPF_PROG_TYPE_SYSCALL, helper, NULL) > 0;
}

/*
 * The BPF the signed loader and its payloads use, which Linux 5.17 has.
 * The probes load programs and BTF, so they need CAP_BPF.
 */
int kernel_abi_check(char *detail, size_t detail_sz)
{
	static const char *const lacks[] = {
		"kernel BTF",
		"bpf_sys_bpf() in a sleepable BPF_PROG_TYPE_SYSCALL program",
		"bpf_kallsyms_lookup_name() in a BPF_PROG_TYPE_SYSCALL program",
		"BTF type tags",
		"in-kernel CO-RE relocation",
	};
	struct btf *vmlinux = btf__load_vmlinux_btf();
	const bool has[ARRAY_SIZE(lacks)] = {
		vmlinux,
		syscall_helper(BPF_FUNC_sys_bpf),
		syscall_helper(BPF_FUNC_kallsyms_lookup_name),
		btf_type_tag(),
		core_relo_attr(),
	};
	size_t i, len = 0;
	int n;

	btf__free(vmlinux);
	detail[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(lacks); i++) {
		n = has[i] ? 0 : strsprintf(detail + len, detail_sz - len,
					    "%s%s", len ? ", " :
					    "the kernel lacks ", lacks[i]);
		len += n > 0 ? (size_t)n : 0;
	}
	if (!len)
		return 0;
	if (strsprintf(detail + len, detail_sz - len,
		       "; the stock-kernel profile needs the BPF of Linux 5.17") < 0)
		detail[len] = '\0';
	return -EOPNOTSUPP;
}

static bool trusted_certs_present(void)
{
	struct trusted_set *set = xcalloc(1, sizeof(*set));
	bool present;

	present = set && !keys_load_dir(STOCK_KEYS_DIR, STOCK_REVOKED_DIR,
					set) && set->n;
	xfree(set, sizeof(*set));
	return present;
}

/*
 * What init and every load need. The BPF LSM and the attach kinds are
 * not checked here: a load refuses only what its upatch uses.
 */
void preflight_run(struct preflight_result *r)
{
	struct preflight_check *c = r->checks;
	int i;

	memset(r, 0, sizeof(*r));
	c[0] = (struct preflight_check){ .id = PRE_ROOT, .name = "root",
					 .ok = !geteuid() };
	if (!c[0].ok)
		strscpy_literal(c[0].detail, "must run as root");
	c[1] = (struct preflight_check){ .id = PRE_SIGNED_LOADER_ABI,
					 .name = "signed_loader_kernel_abi" };
	c[1].ok = !kernel_abi_check(c[1].detail, sizeof(c[1].detail));
	c[2] = (struct preflight_check){ .id = PRE_CERT_ON_DISK,
					 .name = "trusted_certs",
					 .ok = trusted_certs_present() };
	if (!c[2].ok)
		strscpy_literal(c[2].detail, "no usable certificate (*.der) in "
				STOCK_KEYS_DIR);
	for (r->n = 3, i = 0; i < r->n; i++)
		r->n_failed += !c[i].ok;
}
