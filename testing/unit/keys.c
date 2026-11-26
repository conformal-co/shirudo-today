// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#ifdef CONFIG_STOCK_KERNEL
#include "testkey.h"
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <shirudo/string.h>

#include "hex.h"
#include "keys.h"
#ifdef CONFIG_STOCK_KERNEL
#include "sign.h"
#endif
#include "unit.h"

static struct trusted_set set;

static void member_is_found_by_fingerprint(void)
{
	__u8 absent[32];

	memset(&set, 0, sizeof(set));
	set.n = 2;
	memset(set.certs[0].fingerprint, 0x11, 32);
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(absent, 0x33, sizeof(absent));

	EXPECT_TRUE(keys_member(&set, set.certs[1].fingerprint) ==
		    &set.certs[1]);
	EXPECT_TRUE(!keys_member(&set, absent));
}

/* Entries past n are a stale tail, not members. */
static void member_past_the_count_is_none(void)
{
	__u8 stale[32];

	memset(&set, 0, sizeof(set));
	set.n = 1;
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(stale, 0x22, sizeof(stale));

	EXPECT_TRUE(!keys_member(&set, stale));
}

#ifdef CONFIG_STOCK_KERNEL
#define DIR_TEMPLATE	"/tmp/shirudo-unit-keys-XXXXXX"

static char dir[sizeof(DIR_TEMPLATE)];

static void path_in(char *out, size_t cap, const char *name)
{
	ASSERT_TRUE(strsprintf(out, cap, "%s/%s", dir, name) >= 0);
}

static void copy_file(const char *from, const char *to)
{
	char buf[16384];
	size_t n;
	FILE *in, *out;

	in = fopen(from, "r");
	out = fopen(to, "w");
	ASSERT_TRUE(in && out);
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		ASSERT_EQ(fwrite(buf, 1, n, out), n);
	fclose(in);
	ASSERT_EQ(fclose(out), 0);
}

/* operator.der, vendor.der, a note and revoked/ in a fresh directory. */
static void stock_dir_make(void)
{
	char path[PATH_MAX];
	FILE *f;

	memcpy(dir, DIR_TEMPLATE, sizeof(dir));
	ASSERT_TRUE(mkdtemp(dir));
	path_in(path, sizeof(path), "operator.der");
	testkey_make("operator", NULL, path);
	path_in(path, sizeof(path), "vendor.der");
	testkey_make("vendor", NULL, path);
	path_in(path, sizeof(path), "README");
	f = fopen(path, "w");
	ASSERT_TRUE(f);
	fputs("not a certificate\n", f);
	ASSERT_EQ(fclose(f), 0);
	path_in(path, sizeof(path), "revoked");
	ASSERT_EQ(mkdir(path, 0700), 0);
}

static void stock_dir_load(struct trusted_set *out)
{
	char revoked[PATH_MAX];

	path_in(revoked, sizeof(revoked), "revoked");
	ASSERT_EQ(keys_load_dir(dir, revoked, out), 0);
}

static void stock_dir_trusts_every_certificate(void)
{
	stock_dir_make();
	stock_dir_load(&set);
	EXPECT_EQ(set.n, 2);
	EXPECT_EQ(set.n_unvouched, 0);
	EXPECT_EQ(set.n_revoked, 0);
}

static void stock_dir_holds_a_key_once(void)
{
	char from[PATH_MAX], to[PATH_MAX];

	stock_dir_make();
	path_in(from, sizeof(from), "vendor.der");
	path_in(to, sizeof(to), "vendor-copy.der");
	copy_file(from, to);
	stock_dir_load(&set);
	EXPECT_EQ(set.n, 2);
}

static void stock_dir_leaves_out_a_revoked_key(void)
{
	char from[PATH_MAX], to[PATH_MAX], hex[65];
	struct trusted_set all;
	size_t i;

	stock_dir_make();
	stock_dir_load(&all);
	ASSERT_EQ(all.n, 2);
	path_in(from, sizeof(from), "vendor.der");
	i = strcmp(all.certs[0].path, from) ? 1 : 0;
	ASSERT_STREQ(all.certs[i].path, from);
	hex_encode(all.certs[i].fingerprint, 32, hex);
	ASSERT_TRUE(strsprintf(to, sizeof(to), "%s/revoked/%s.der", dir,
			       hex) >= 0);
	copy_file(from, to);
	stock_dir_load(&set);
	EXPECT_EQ(set.n, 1);
	EXPECT_EQ(set.n_revoked, 1);
	EXPECT_TRUE(!keys_member(&set, all.certs[i].fingerprint));
	path_in(from, sizeof(from), "operator.der");
	EXPECT_STREQ(set.certs[0].path, from);
}

static void stock_dir_missing_is_an_error(void)
{
	EXPECT_EQ(keys_load_dir("/nonexistent/shirudo-keys", NULL, &set),
		  -ENOENT);
}

/*
 * bpm tree sync checks a publication's detached signature against the
 * set of the keys dir, as a load checks a upatch: a member's verifies,
 * a revoked member's no longer does.
 */
static void stock_dir_verifies_a_tree_publication(void)
{
	static const char doc[] = "{\"schema\":1,\"tree_id\":\"t\"}";
	char key[PATH_MAX], cert[PATH_MAX], revoked[PATH_MAX];
	__u8 sig[16384], signer[32], sha[32], want[32];
	struct sign_io io = {
		.insns = doc, .insns_sz = sizeof(doc) - 1,
		.signature = sig, .signature_sz = sizeof(sig),
	};
	char hex[65];

	stock_dir_make();
	path_in(key, sizeof(key), "vendor.pem");
	path_in(cert, sizeof(cert), "vendor.der");
	testkey_make("vendor", key, cert);
	ASSERT_EQ(cms_sign(&io, key, cert), 0);
	stock_dir_load(&set);
	EXPECT_EQ(keys_verify_signature(&set, (const __u8 *)doc,
					sizeof(doc) - 1, sig, io.signature_sz,
					signer), 0);
	ASSERT_EQ(keys_digest_file(cert, sha, want), 0);
	EXPECT_MEMEQ(signer, want, sizeof(want));
	hex_encode(want, 32, hex);
	ASSERT_TRUE(strsprintf(revoked, sizeof(revoked), "%s/revoked/%s.der",
			       dir, hex) >= 0);
	copy_file(cert, revoked);
	stock_dir_load(&set);
	EXPECT_EQ(keys_verify_signature(&set, (const __u8 *)doc,
					sizeof(doc) - 1, sig, io.signature_sz,
					NULL), -EKEYREJECTED);
}
#endif

static const struct unit_case cases[] = {
	UNIT_CASE(member_is_found_by_fingerprint),
	UNIT_CASE(member_past_the_count_is_none),
#ifdef CONFIG_STOCK_KERNEL
	UNIT_CASE(stock_dir_trusts_every_certificate),
	UNIT_CASE(stock_dir_holds_a_key_once),
	UNIT_CASE(stock_dir_leaves_out_a_revoked_key),
	UNIT_CASE(stock_dir_missing_is_an_error),
	UNIT_CASE(stock_dir_verifies_a_tree_publication),
#endif
	{}
};

UNIT_SUITE(keys, cases);
