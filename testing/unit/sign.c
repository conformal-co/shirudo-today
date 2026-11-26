// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "testkey.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "sign.h"
#include "unit.h"

#define KEYS_DIR_TEMPLATE	"/tmp/shirudo-unit-sign-XXXXXX"
#define SIGNER			"tools/signers/local-test-signer"
#define SIG_MAX			16384

static const char insns[] = "loader instructions";
static const char data[] = "loader data";
static char keys_dir[sizeof(KEYS_DIR_TEMPLATE)];
static char key[PATH_MAX], cert[PATH_MAX], other_key[PATH_MAX];
static char signer[PATH_MAX];

/* make -C testing runs from testing/, and by hand from the top of the tree. */
static void find_signer(void)
{
	if (!access(SIGNER, X_OK))
		strscpy_literal(signer, SIGNER);
	else
		strscpy_literal(signer, "../" SIGNER);
	ASSERT_EQ(access(signer, X_OK), 0);
}

static void make_keys(void)
{
	char other_cert[PATH_MAX];

	if (keys_dir[0])
		return;
	memcpy(keys_dir, KEYS_DIR_TEMPLATE, sizeof(keys_dir));
	ASSERT_TRUE(mkdtemp(keys_dir));
	ASSERT_TRUE(strsprintf(key, sizeof(key), "%s/key.pem", keys_dir) >= 0);
	ASSERT_TRUE(strsprintf(cert, sizeof(cert), "%s/cert.der",
			       keys_dir) >= 0);
	ASSERT_TRUE(strsprintf(other_key, sizeof(other_key), "%s/other.pem",
			       keys_dir) >= 0);
	ASSERT_TRUE(strsprintf(other_cert, sizeof(other_cert),
			       "%s/other.der", keys_dir) >= 0);
	testkey_make("signer", key, cert);
	testkey_make("other", other_key, other_cert);
	find_signer();
}

/* The test signer holding the key at key_path. */
static void set_signer(const char *key_path)
{
	char command[2 * PATH_MAX + 8];

	ASSERT_TRUE(strsprintf(command, sizeof(command), "%s %s", signer,
			       key_path) >= 0);
	ASSERT_EQ(setenv("SHIRUDO_SIGNER", command, 1), 0);
}

static int sign(__u8 *sig, size_t *sig_len, const char *pkey)
{
	struct sign_io io = {
		.insns = insns,
		.insns_sz = sizeof(insns),
		.data = data,
		.data_sz = sizeof(data),
		.signature = sig,
		.signature_sz = SIG_MAX,
	};
	int ret;

	ret = cms_sign(&io, pkey, cert);
	*sig_len = io.signature_sz;
	return ret;
}

/*
 * ML-DSA signs with fresh randomness each time, so two containers of one
 * content and key differ only in the signature value they end with.
 */
static void a_signer_builds_the_container_a_key_file_does(void)
{
	static __u8 by_file[SIG_MAX], by_signer[SIG_MAX];
	size_t file_len, signer_len, sig_len = 4627;

	make_keys();
	ASSERT_EQ(unsetenv("SHIRUDO_SIGNER"), 0);
	ASSERT_EQ(sign(by_file, &file_len, key), 0);
	set_signer(key);
	ASSERT_EQ(sign(by_signer, &signer_len, "/nonexistent/key.pem"), 0);
	ASSERT_EQ(file_len, signer_len);
	ASSERT_TRUE(file_len > sig_len);
	EXPECT_MEMEQ(by_file, by_signer, file_len - sig_len);
	EXPECT_TRUE(memcmp(by_file + file_len - sig_len,
			   by_signer + file_len - sig_len, sig_len));
	ASSERT_EQ(unsetenv("SHIRUDO_SIGNER"), 0);
}

static void another_keys_signature_is_refused(void)
{
	static __u8 sig[SIG_MAX];
	size_t len;

	make_keys();
	set_signer(other_key);
	EXPECT_EQ(sign(sig, &len, key), -EBADMSG);
	ASSERT_EQ(unsetenv("SHIRUDO_SIGNER"), 0);
}

static void a_failing_or_silent_signer_is_refused(void)
{
	static const char *const commands[] = {
		"exit 3",
		"true",
		"cat >/dev/null",
		"head -c 9000 /dev/zero",
		"kill -9 $$",
	};
	static __u8 sig[SIG_MAX];
	size_t len;

	make_keys();
	for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		ASSERT_EQ(setenv("SHIRUDO_SIGNER", commands[i], 1), 0);
		EXPECT_EQ(sign(sig, &len, key), -EIO);
	}
	ASSERT_EQ(unsetenv("SHIRUDO_SIGNER"), 0);
}

static void a_garbage_signature_is_refused(void)
{
	static __u8 sig[SIG_MAX];
	size_t len;

	make_keys();
	ASSERT_EQ(setenv("SHIRUDO_SIGNER", "head -c 4627 /dev/urandom", 1), 0);
	EXPECT_EQ(sign(sig, &len, key), -EBADMSG);
	ASSERT_EQ(unsetenv("SHIRUDO_SIGNER"), 0);
}

static void an_empty_signer_is_no_signer(void)
{
	make_keys();
	ASSERT_EQ(setenv("SHIRUDO_SIGNER", "", 1), 0);
	EXPECT_TRUE(!signer_command());
	ASSERT_EQ(unsetenv("SHIRUDO_SIGNER"), 0);
	EXPECT_TRUE(!signer_command());
}

static const struct unit_case cases[] = {
	UNIT_CASE(a_signer_builds_the_container_a_key_file_does),
	UNIT_CASE(another_keys_signature_is_refused),
	UNIT_CASE(a_failing_or_silent_signer_is_refused),
	UNIT_CASE(a_garbage_signature_is_refused),
	UNIT_CASE(an_empty_signer_is_no_signer),
	{}
};

UNIT_SUITE(sign, cases);
