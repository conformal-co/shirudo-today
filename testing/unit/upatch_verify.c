// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#ifdef CONFIG_STOCK_KERNEL
#include "testkey.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#ifdef CONFIG_STOCK_KERNEL
#include <limits.h>
#include <string.h>

#include <shirudo/string.h>

#include "keys.h"
#include "sign.h"
#endif
#include "paths.h"
#include "unit.h"
#include "upatch.h"
#include "upatch_verify.h"

#define FIXTURE "fuzz/corpus/upatch/xdp-virtual"

/* make -C testing runs from testing/, and by hand from the top of the tree. */
static __u8 *read_fixture(size_t *len)
{
	static __u8 buf[1 << 16];
	FILE *f = fopen(FIXTURE, "r");

	if (!f)
		f = fopen("testing/" FIXTURE, "r");
	ASSERT_TRUE(f);
	*len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return buf;
}

static int memfd_of(const __u8 *buf, size_t len)
{
	char path[] = "/tmp/shirudo-unit-verify-XXXXXX";
	int fd = mkstemp(path);

	ASSERT_TRUE(fd >= 0);
	unlink(path);
	ASSERT_EQ(write(fd, buf, len), (ssize_t)len);
	return fd;
}

static void payload_of_fixture(const __u8 *buf, size_t len,
			       __u8 payload[UPATCH_PAYLOAD_HASH_LEN])
{
	int fd = memfd_of(buf, len);
	struct upatch u;

	ASSERT_EQ(upatch_open_fd(fd, &u), 0);
	close(fd);
	memcpy(payload, u.hdr.payload_sha256, UPATCH_PAYLOAD_HASH_LEN);
	upatch_close(&u);
}

static void open_fixture(struct upatch *u)
{
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	int fd = memfd_of(buf, len);

	ASSERT_EQ(upatch_open_fd(fd, u), 0);
	close(fd);
}

static void the_payload_digest_hashes_the_loader_then_the_data(void)
{
	__u8 want[UPATCH_PAYLOAD_HASH_LEN], got[UPATCH_PAYLOAD_HASH_LEN];
	static __u8 cat[1 << 16];
	size_t loader_len;
	struct upatch u;

	open_fixture(&u);
	loader_len = u.hdr.loader_insns_len;
	ASSERT_TRUE(u.hdr.data_len > 0);
	ASSERT_TRUE(loader_len + u.hdr.data_len <= sizeof(cat));
	memcpy(cat, upatch_loader(&u), loader_len);
	memcpy(cat + loader_len, upatch_data(&u), u.hdr.data_len);
	ASSERT_EQ(sha256_buffer(cat, loader_len + u.hdr.data_len, want), 0);
	ASSERT_EQ(upatch_payload_digest(&u, got), 0);
	EXPECT_MEMEQ(got, want, sizeof(got));
	EXPECT_MEMEQ(got, u.hdr.payload_sha256, sizeof(got));
	upatch_close(&u);
}

static void a_payload_without_data_hashes_the_loader_alone(void)
{
	__u8 want[UPATCH_PAYLOAD_HASH_LEN], got[UPATCH_PAYLOAD_HASH_LEN];
	struct upatch u;

	open_fixture(&u);
	u.hdr.data_len = 0;
	ASSERT_TRUE(!upatch_data(&u));
	ASSERT_EQ(sha256_buffer(upatch_loader(&u), u.hdr.loader_insns_len,
				want), 0);
	ASSERT_EQ(upatch_payload_digest(&u, got), 0);
	EXPECT_MEMEQ(got, want, sizeof(got));
	upatch_close(&u);
}

static void the_loaded_bytes_verify(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	payload_of_fixture(buf, len, payload);
	fd = memfd_of(buf, len);
	ASSERT_EQ(upatch_verify_fd(fd, payload, &u), 0);
	close(fd);
	upatch_close(&u);
}

static void another_payload_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	payload_of_fixture(buf, len, payload);
	payload[0] ^= 1;
	fd = memfd_of(buf, len);
	EXPECT_EQ(upatch_verify_fd(fd, payload, &u), -ESTALE);
	close(fd);
}

static void changed_data_under_an_intact_header_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN], copy[1 << 16];
	size_t len = 0, off;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	payload_of_fixture(buf, len, payload);
	fd = memfd_of(buf, len);
	ASSERT_EQ(upatch_open_fd(fd, &u), 0);
	close(fd);
	off = u.hdr.data_off;
	ASSERT_TRUE(u.hdr.data_len > 0);
	upatch_close(&u);
	memcpy(copy, buf, len);
	copy[off] ^= 1;
	fd = memfd_of(copy, len);
	EXPECT_EQ(upatch_verify_fd(fd, payload, &u), -ESTALE);
	close(fd);
}

static void a_truncated_file_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	size_t len = 0;
	const __u8 *buf = read_fixture(&len);
	struct upatch u;
	int fd;

	fd = memfd_of(buf, 64);
	EXPECT_EQ(upatch_verify_fd(fd, payload, &u), -ESTALE);
	close(fd);
}

static void a_missing_archive_is_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	struct upatch u;

	EXPECT_EQ(upatch_archive_verify("shirudo-unit-no-such-upatch",
					payload, &u), -ESTALE);
}

static void links_of_a_missing_archive_are_stale(void)
{
	EXPECT_EQ(upatch_links_complete("shirudo-unit-no-such-upatch",
					"/nonexistent/shirudo-unit.upatch"),
		  -ESTALE);
}

static void specs_of_a_missing_archive_are_stale(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	struct prog_spec *specs = NULL;
	struct upatch u;

	EXPECT_EQ(upatch_archive_specs("shirudo-unit-no-such-upatch", payload,
				       &u, &specs), -ESTALE);
	EXPECT_TRUE(!specs);
}

static int never(const char *name, void *ctx)
{
	return 1;
}

static void nothing_pinned_checks_clean(void)
{
	struct upatch_checks c = { .changed = never, .lost = never };

	if (access(BPFFS_UPATCHES_DIR, F_OK) == 0)
		unit_skip("upatches are pinned on this host");
	upatch_checks_run(NULL, &c);
	EXPECT_EQ(c.nr_changed + c.nr_lost + c.nr_uncovered, 0);
	EXPECT_EQ(c.check_err, 0);
	EXPECT_EQ(c.coverage_err, 0);
}

#ifdef CONFIG_STOCK_KERNEL
/*
 * The stock-kernel profile verifies a loader's signature in userspace,
 * over the bytes the patched kernel would: insns || data.
 */
#define KEYS_DIR_TEMPLATE	"/tmp/shirudo-unit-sig-XXXXXX"

static char keys_dir[sizeof(KEYS_DIR_TEMPLATE)];
static __u8 sig[16384];
static size_t sig_len;

static void signer_paths(const char *who, char *key, char *cert)
{
	ASSERT_TRUE(strsprintf(key, PATH_MAX, "%s/%s.pem", keys_dir, who) >= 0);
	ASSERT_TRUE(strsprintf(cert, PATH_MAX, "%s/%s.der", keys_dir,
			       who) >= 0);
}

/* operator.der and vendor.der, the loader of u signed by signer. */
static void signed_by(const struct upatch *u, const char *signer)
{
	char key[PATH_MAX], cert[PATH_MAX];
	struct sign_io io = {};

	memcpy(keys_dir, KEYS_DIR_TEMPLATE, sizeof(keys_dir));
	ASSERT_TRUE(mkdtemp(keys_dir));
	signer_paths("operator", key, cert);
	testkey_make("operator", key, cert);
	signer_paths("vendor", key, cert);
	testkey_make("vendor", key, cert);
	signer_paths(signer, key, cert);
	io.insns = upatch_loader(u);
	io.insns_sz = u->hdr.loader_insns_len;
	io.data = upatch_data(u);
	io.data_sz = u->hdr.data_len;
	io.signature = sig;
	io.signature_sz = sizeof(sig);
	ASSERT_EQ(cms_sign(&io, key, cert), 0);
	sig_len = io.signature_sz;
}

static int verify(const struct trusted_set *set, const struct upatch *u,
		  const void *insns, const void *data, __u8 signer[32])
{
	return upatch_content_verify(set, insns, u->hdr.loader_insns_len,
				     data, u->hdr.data_len, sig, sig_len,
				     signer);
}

static void a_member_signature_over_loader_and_data_verifies(void)
{
	static struct trusted_set set;
	__u8 signer[32], want[32], sha[32];
	char cert[PATH_MAX], key[PATH_MAX];
	struct upatch u;

	open_fixture(&u);
	signed_by(&u, "vendor");
	ASSERT_EQ(keys_load_dir(keys_dir, NULL, &set), 0);
	ASSERT_EQ(set.n, 2);
	EXPECT_EQ(verify(&set, &u, upatch_loader(&u), upatch_data(&u),
			 signer), 0);
	signer_paths("vendor", key, cert);
	ASSERT_EQ(keys_digest_file(cert, sha, want), 0);
	EXPECT_MEMEQ(signer, want, sizeof(want));
	upatch_close(&u);
}

static void changed_data_or_loader_is_rejected(void)
{
	static struct trusted_set set;
	static __u8 copy[1 << 16];
	struct upatch u;

	open_fixture(&u);
	signed_by(&u, "operator");
	ASSERT_EQ(keys_load_dir(keys_dir, NULL, &set), 0);
	ASSERT_TRUE(u.hdr.data_len <= sizeof(copy));
	memcpy(copy, upatch_data(&u), u.hdr.data_len);
	copy[u.hdr.data_len / 2] ^= 1;
	EXPECT_EQ(verify(&set, &u, upatch_loader(&u), copy, NULL),
		  -EKEYREJECTED);
	ASSERT_TRUE(u.hdr.loader_insns_len <= sizeof(copy));
	memcpy(copy, upatch_loader(&u), u.hdr.loader_insns_len);
	copy[0] ^= 1;
	EXPECT_EQ(verify(&set, &u, copy, upatch_data(&u), NULL),
		  -EKEYREJECTED);
	upatch_close(&u);
}

static void a_signer_outside_the_set_is_rejected(void)
{
	static struct trusted_set set;
	char key[PATH_MAX], cert[PATH_MAX];
	struct upatch u;

	open_fixture(&u);
	signed_by(&u, "vendor");
	signer_paths("vendor", key, cert);
	ASSERT_EQ(unlink(cert), 0);
	ASSERT_EQ(keys_load_dir(keys_dir, NULL, &set), 0);
	ASSERT_EQ(set.n, 1);
	EXPECT_EQ(verify(&set, &u, upatch_loader(&u), upatch_data(&u), NULL),
		  -EKEYREJECTED);
	upatch_close(&u);
}

/* The fixture's own signature is by a key no test set holds. */
static void a_foreign_signature_is_rejected(void)
{
	static struct trusted_set set;
	struct upatch u;

	open_fixture(&u);
	signed_by(&u, "operator");
	ASSERT_EQ(keys_load_dir(keys_dir, NULL, &set), 0);
	EXPECT_EQ(upatch_content_verify(&set, upatch_loader(&u),
					u.hdr.loader_insns_len,
					upatch_data(&u), u.hdr.data_len,
					upatch_signature(&u),
					u.hdr.signature_len, NULL),
		  -EKEYREJECTED);
	upatch_close(&u);
}

static void nothing_signed_is_invalid(void)
{
	static struct trusted_set set;

	EXPECT_EQ(upatch_content_verify(&set, NULL, 0, NULL, 0, sig, 0, NULL),
		  -EINVAL);
}
#endif

static const struct unit_case cases[] = {
	UNIT_CASE(the_payload_digest_hashes_the_loader_then_the_data),
	UNIT_CASE(a_payload_without_data_hashes_the_loader_alone),
	UNIT_CASE(the_loaded_bytes_verify),
	UNIT_CASE(another_payload_is_stale),
	UNIT_CASE(changed_data_under_an_intact_header_is_stale),
	UNIT_CASE(a_truncated_file_is_stale),
	UNIT_CASE(a_missing_archive_is_stale),
	UNIT_CASE(links_of_a_missing_archive_are_stale),
	UNIT_CASE(specs_of_a_missing_archive_are_stale),
	UNIT_CASE(nothing_pinned_checks_clean),
#ifdef CONFIG_STOCK_KERNEL
	UNIT_CASE(a_member_signature_over_loader_and_data_verifies),
	UNIT_CASE(changed_data_or_loader_is_rejected),
	UNIT_CASE(a_signer_outside_the_set_is_rejected),
	UNIT_CASE(a_foreign_signature_is_rejected),
	UNIT_CASE(nothing_signed_is_invalid),
#endif
	{}
};

UNIT_SUITE(upatch_verify, cases);
