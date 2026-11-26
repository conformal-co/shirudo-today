/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A throwaway ML-DSA-87 key and self-signed certificate for the suites
 * that verify signatures: the key as PEM, mode 0600, the certificate as
 * DER, the forms util/sign.c and util/keys.c read.
 */

#ifndef SHIRUDO_TESTING_UNIT_TESTKEY_H
#define SHIRUDO_TESTING_UNIT_TESTKEY_H

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "unit.h"

static void testkey_write_cert(EVP_PKEY *key, const char *cn,
			       const char *cert_path)
{
	__u8 *der = NULL;
	X509_EXTENSION *ski;
	X509V3_CTX ctx;
	X509_NAME *name;
	X509 *x;
	FILE *f;
	int len;

	x = X509_new();
	ASSERT_TRUE(x);
	ASSERT_EQ(X509_set_version(x, 2), 1);
	ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(x), 1), 1);
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(x), 0));
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(x), 86400));
	ASSERT_EQ(X509_set_pubkey(x, key), 1);
	name = X509_get_subject_name(x);
	ASSERT_EQ(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					     (const __u8 *)cn, -1,
					     -1, 0), 1);
	ASSERT_EQ(X509_set_issuer_name(x, name), 1);
	/* CMS names its signer by the subject key identifier. */
	X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
	ski = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier,
				  "hash");
	ASSERT_TRUE(ski);
	ASSERT_EQ(X509_add_ext(x, ski, -1), 1);
	X509_EXTENSION_free(ski);
	ASSERT_TRUE(X509_sign(x, key, NULL) > 0);
	len = i2d_X509(x, &der);
	ASSERT_TRUE(len > 0);
	f = fopen(cert_path, "w");
	ASSERT_TRUE(f);
	ASSERT_EQ(fwrite(der, 1, (size_t)len, f), (size_t)len);
	ASSERT_EQ(fclose(f), 0);
	OPENSSL_free(der);
	X509_free(x);
}

/* A fresh key at key_path (NULL for none) and its certificate at cert_path. */
static void testkey_make(const char *cn, const char *key_path,
			 const char *cert_path)
{
	EVP_PKEY *key;
	FILE *f;
	int fd;

	key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
	ASSERT_TRUE(key);
	testkey_write_cert(key, cn, cert_path);
	if (key_path) {
		fd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			  0600);
		ASSERT_TRUE(fd >= 0);
		f = fdopen(fd, "w");
		ASSERT_TRUE(f);
		ASSERT_EQ(PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL,
					       NULL), 1);
		ASSERT_EQ(fclose(f), 0);
	}
	EVP_PKEY_free(key);
}

#endif /* SHIRUDO_TESTING_UNIT_TESTKEY_H */
