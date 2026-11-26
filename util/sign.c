// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2025 Google LLC.
 * Copyright (c) 2026 Authors of shirudo
 *
 * Vendored from tools/bpf/bpftool/sign.c (dual-licensed
 * (GPL-2.0-only OR BSD-2-Clause); shirudo consumes the BSD branch).
 * Adapted to take pkey/cert paths as arguments, route errors
 * through util/log.h, and present a shirudo-local I/O struct
 * instead of libbpf's bpf_load_and_run_opts (shirudo issues raw
 * BPF_PROG_LOAD; the bpftool struct is incidental). The
 * register_session_key() helper, which adds a cert to the calling
 * task's session keyring, is dropped -- shirudo's operator side
 * doesn't need it; the target side uses util/keyring.c against
 * the named "shirudo" keyring.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <shirudo/overflow.h>

#include "io.h"
#include "log.h"
#include "malloc.h"
#include "sign.h"

#define OPEN_SSL_ERR_BUF_LEN	256
#define SIGNER_ENV		"SHIRUDO_SIGNER"

/*
 * Never a signing time: the kernel refuses a signature whose signing
 * time falls outside the signer's validity period
 * (crypto/asymmetric_keys/pkcs7_verify.c), which would let a
 * certificate's dates decide what loads. Every OpenSSL shirudo builds
 * with has the flag, so it is not guarded.
 */
#define SIGNER_FLAGS	(CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP | \
			 CMS_NO_SIGNING_TIME | CMS_USE_KEYID)

#if !defined(OPENSSL_VERSION_MAJOR) || (OPENSSL_VERSION_MAJOR < 3)
#define ERR_get_error_all(file, line, func, data, flags) \
	ERR_get_error_line_data(file, line, data, flags)
#endif

static void display_openssl_errors(void)
{
	char buf[OPEN_SSL_ERR_BUF_LEN];
	const char *file;
	const char *data;
	unsigned long e;
	int flags;
	int line;

	while ((e = ERR_get_error_all(&file, &line, NULL, &data, &flags))) {
		ERR_error_string_n(e, buf, sizeof(buf));
		if (data && (flags & ERR_TXT_STRING))
			pr_err("OpenSSL %s: %s:%d: %s", buf, file, line, data);
		else
			pr_err("OpenSSL %s: %s:%d", buf, file, line);
	}
}

#define DISPLAY_OSSL_ERR(cond)				\
	do {						\
		bool __cond = (cond);			\
		if (__cond && ERR_peek_error())		\
			display_openssl_errors();	\
	} while (0)

int open_signing_key(const char *pkey_path)
{
	struct stat st;
	int fd, ret;

	/* A FIFO in its place would block open() before fstat() refuses it. */
	fd = open(pkey_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		ret = -errno;
		pr_err("open private key %s: %s", pkey_path, strerror(errno));
		return ret;
	}
	if (fstat(fd, &st)) {
		ret = -errno;
		pr_err("stat private key %s: %s", pkey_path, strerror(errno));
		goto err;
	}
	ret = -EPERM;
	if (!S_ISREG(st.st_mode)) {
		pr_err("signing key %s is not a regular file", pkey_path);
		goto err;
	}
	if ((st.st_mode & 07777) != 0600) {
		pr_err("signing key %s has mode 0%o, must be 0600 "
		       "(run `chmod 0600 %s`)",
		       pkey_path, (__u32)(st.st_mode & 07777), pkey_path);
		goto err;
	}
	return fd;
err:
	close(fd);
	return ret;
}

static EVP_PKEY *read_private_key(const char *pkey_path)
{
	EVP_PKEY *private_key = NULL;
	BIO *b;
	int fd;

	fd = open_signing_key(pkey_path);
	if (fd < 0)
		return NULL;
	b = BIO_new_fd(fd, BIO_CLOSE);
	if (!b) {
		close(fd);
		DISPLAY_OSSL_ERR(1);
		return NULL;
	}
	private_key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
	BIO_free(b);
	DISPLAY_OSSL_ERR(!private_key);
	return private_key;
}

static X509 *read_x509(const char *x509_name)
{
	unsigned char buf[2];
	X509 *x509 = NULL;
	BIO *b;
	int n;

	b = BIO_new_file(x509_name, "rb");
	if (!b)
		goto cleanup;

	/* sniff the first two bytes: 0x30 + length-of-length -> raw DER */
	n = BIO_read(b, buf, 2);
	if (n != 2)
		goto cleanup;
	if (BIO_reset(b) != 0)
		goto cleanup;

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		x509 = d2i_X509_bio(b, NULL);
	else
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

cleanup:
	BIO_free(b);
	DISPLAY_OSSL_ERR(!x509);
	return x509;
}

/*
 * Only ML-DSA-87: the target's trust set refuses the smaller parameter
 * sets, so an artifact signed with one could never load.
 */
static bool pkey_is_mldsa87(const EVP_PKEY *pkey)
{
	return EVP_PKEY_is_a(pkey, "ML-DSA-87");
}

const char *signer_command(void)
{
	const char *command = getenv(SIGNER_ENV);

	return command && *command ? command : NULL;
}

/*
 * The command's ends of the pipes become its standard input and output
 * in the child alone; every other descriptor, the pipes' own included,
 * is close-on-exec and stays here.
 */
static pid_t signer_spawn(const char *command, int *to_signer,
			  int *from_signer)
{
	const char *const argv[] = { "sh", "-c", command, NULL };
	posix_spawn_file_actions_t actions;
	int in[2], out[2], ret;
	pid_t pid;

	if (pipe2(in, O_CLOEXEC))
		return -errno;
	if (pipe2(out, O_CLOEXEC)) {
		ret = -errno;
		goto close_in;
	}
	ret = -posix_spawn_file_actions_init(&actions);
	if (ret)
		goto close_out;
	ret = -posix_spawn_file_actions_adddup2(&actions, in[0], STDIN_FILENO);
	if (!ret)
		ret = -posix_spawn_file_actions_adddup2(&actions, out[1],
							 STDOUT_FILENO);
	if (!ret)
		ret = -posix_spawn(&pid, "/bin/sh", &actions, NULL,
				   (char *const *)argv, environ);
	posix_spawn_file_actions_destroy(&actions);
	if (ret)
		goto close_out;
	close(out[1]);
	*to_signer = in[1];
	*from_signer = out[0];
	close(in[0]);
	return pid;
close_out:
	close(out[0]);
	close(out[1]);
close_in:
	close(in[0]);
	close(in[1]);
	return ret;
}

/* At most cap - 1 bytes: a signature that fills buf is too long. */
static int signer_read(int fd, __u8 *buf, size_t cap, size_t *len)
{
	size_t got = 0;
	ssize_t n;

	while (got < cap) {
		n = read(fd, buf + got, cap - got);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (!n) {
			*len = got;
			return got ? 0 : -ENODATA;
		}
		got += (size_t)n;
	}
	return -EMSGSIZE;
}

/*
 * A signer that exits without reading its input must not kill the
 * process with SIGPIPE: its exit status is the error to report.
 */
static int signer_write(int fd, const __u8 *msg, size_t msg_len)
{
	struct sigaction ignore = { .sa_handler = SIG_IGN }, old;
	int ret;

	if (sigaction(SIGPIPE, &ignore, &old))
		return -errno;
	ret = write_complete(fd, msg, msg_len);
	sigaction(SIGPIPE, &old, NULL);
	return ret;
}

static int signer_run(const char *command, const __u8 *msg, size_t msg_len,
		      __u8 *sig, size_t sig_cap, size_t *sig_len)
{
	int to_signer, from_signer, status, ret;
	pid_t pid;

	pid = signer_spawn(command, &to_signer, &from_signer);
	if (pid < 0) {
		pr_err("cannot run " SIGNER_ENV ": %s", strerror((int)-pid));
		return -EIO;
	}
	ret = signer_write(to_signer, msg, msg_len);
	close(to_signer);
	if (!ret)
		ret = signer_read(from_signer, sig, sig_cap, sig_len);
	close(from_signer);
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -errno;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err(SIGNER_ENV " failed (%s %d)",
		       WIFEXITED(status) ? "exit status" : "signal",
		       WIFEXITED(status) ? WEXITSTATUS(status) :
					   WTERMSIG(status));
		return -EIO;
	}
	if (ret == -ENODATA || ret == -EMSGSIZE)
		pr_err(SIGNER_ENV " wrote %s", ret == -ENODATA ?
		       "no signature" : "more than a signature");
	else if (ret)
		pr_err(SIGNER_ENV ": %s", strerror(-ret));
	return ret ? -EIO : 0;
}

/*
 * The DER of the signed attributes, with the SET OF tag the signature
 * covers (RFC 5652 5.4), in the order DER sorts them into, which is
 * also the order they are written in.
 */
static int signed_attrs_der(CMS_SignerInfo *si, __u8 **der)
{
	struct stack_st_X509_ATTRIBUTE *attrs = sk_X509_ATTRIBUTE_new_null();
	int i, len = -1;

	if (!attrs)
		return -1;
	for (i = 0; i < CMS_signed_get_attr_count(si); i++) {
		if (!sk_X509_ATTRIBUTE_push(attrs, CMS_signed_get_attr(si, i)))
			goto out;
	}
	len = ASN1_item_i2d((ASN1_VALUE *)attrs, der,
			    ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
out:
	sk_X509_ATTRIBUTE_free(attrs);
	return len;
}

static int sign_attrs_external(const char *command, CMS_SignerInfo *si,
			       size_t sig_max)
{
	size_t sig_cap = sig_max + 1, sig_len = 0;
	__u8 *attrs = NULL, *sig;
	int attrs_len, ret;

	attrs_len = signed_attrs_der(si, &attrs);
	if (attrs_len <= 0)
		return -EIO;
	sig = xmalloc(sig_cap);
	if (!sig) {
		ret = -ENOMEM;
		goto out;
	}
	ret = signer_run(command, attrs, (size_t)attrs_len, sig, sig_cap,
			 &sig_len);
	if (!ret && !ASN1_STRING_set(CMS_SignerInfo_get0_signature(si), sig,
				     (int)sig_len))
		ret = -ENOMEM;
	xfree(sig, sig_cap);
out:
	OPENSSL_free(attrs);
	return ret;
}

/*
 * What CMS_add1_signer() and CMS_final() build for a key file under
 * OpenSSL 3.x, signed attributes of content type and SHA-512 message
 * digest, with the certificate's public key in place of the private
 * one, and the signature over the attributes from the command. Signed
 * attributes under OpenSSL 4 as well: the command then signs a few
 * hundred bytes, not the content, and a KMS signs only short messages.
 */
static int cms_sign_external(CMS_ContentInfo *cms, const char *command,
			     X509 *x509, const void *content,
			     size_t content_sz)
{
	__u8 md[SHA512_DIGEST_LENGTH];
	EVP_PKEY *public_key;
	CMS_SignerInfo *si;
	int ret = -EINVAL;

	public_key = X509_get_pubkey(x509);
	if (!public_key)
		return -EINVAL;
	if (!pkey_is_mldsa87(public_key)) {
		pr_err("certificate holds a %s key; shirudo signs with "
		       "ML-DSA-87 only",
		       EVP_PKEY_get0_type_name(public_key) ?: "unknown");
		goto out;
	}
	si = CMS_add1_signer(cms, x509, public_key, EVP_sha512(),
			     SIGNER_FLAGS);
	if (!si)
		goto out;
	ret = -EIO;
	if (EVP_Digest(content, content_sz, md, NULL, EVP_sha512(),
		       NULL) != 1 ||
	    !CMS_signed_add1_attr_by_NID(si, NID_pkcs9_messageDigest,
					 V_ASN1_OCTET_STRING, md, sizeof(md)) ||
	    !CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType,
					 V_ASN1_OBJECT,
					 CMS_get0_eContentType(cms), -1))
		goto out;
	ret = sign_attrs_external(command, si,
				  (size_t)EVP_PKEY_get_size(public_key));
out:
	EVP_PKEY_free(public_key);
	return ret;
}

/*
 * The signature came from outside the process: check the container as
 * written, as a target will, before the caller writes anything.
 */
static int cms_check_external(const void *der, size_t der_len, X509 *x509,
			      const void *content, size_t content_sz)
{
	struct stack_st_X509 *certs = sk_X509_new_null();
	unsigned int flags = CMS_BINARY | CMS_NOINTERN |
			     CMS_NO_SIGNER_CERT_VERIFY;
	BIO *data = BIO_new_mem_buf(content, (int)content_sz);
	const __u8 *p = der;
	CMS_ContentInfo *cms;
	int ret = -EBADMSG;

	cms = d2i_CMS_ContentInfo(NULL, &p, (long)der_len);
	if (data && certs && cms && sk_X509_push(certs, x509) &&
	    CMS_verify(cms, certs, NULL, data, NULL, flags) == 1)
		ret = 0;
	else
		pr_err("the signature " SIGNER_ENV " made does not verify "
		       "against the certificate");
	CMS_ContentInfo_free(cms);
	sk_X509_free(certs);
	BIO_free(data);
	return ret;
}

static int cms_sign_key(CMS_ContentInfo *cms, BIO *bd_in, X509 *x509,
			const char *pkey_path)
{
	unsigned int signer_flags = SIGNER_FLAGS | CMS_NOATTR;
	const EVP_MD *cms_digest = EVP_sha256();
	EVP_PKEY *private_key;
	int err = -EINVAL;

	private_key = read_private_key(pkey_path);
	if (!private_key)
		return -EINVAL;
	if (!pkey_is_mldsa87(private_key)) {
		pr_err("%s: %s key; shirudo signs with ML-DSA-87 only "
		       "(re-key with shirudo genkey)", pkey_path,
		       EVP_PKEY_get0_type_name(private_key) ?: "unknown");
		goto out;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_VERSION_NUMBER < 0x40000000L
	/*
	 * OpenSSL 3.x cannot combine ML-DSA with CMS_NOATTR, so fall back
	 * to signedAttrs, where the kernel accepts only SHA-512 for ML-DSA
	 * (crypto/asymmetric_keys/public_key.c). Same workaround as
	 * bpftool and module signing; OpenSSL 4 signs the content directly.
	 */
	signer_flags &= ~CMS_NOATTR;
	cms_digest = EVP_sha512();
#endif

	if (!CMS_add1_signer(cms, x509, private_key, cms_digest,
			     signer_flags))
		goto out;
	err = -EIO;
	if (CMS_final(cms, bd_in, NULL, CMS_NOCERTS | CMS_BINARY) == 1)
		err = 0;
out:
	EVP_PKEY_free(private_key);
	return err;
}

int cms_sign(struct sign_io *io,
	     const char *pkey_path, const char *cert_path)
{
	const char *command = signer_command();
	unsigned int hash_len = SHA256_LEN;
	BIO *bd_in = NULL, *bd_out = NULL;
	CMS_ContentInfo *cms = NULL;
	long actual_sig_len = 0;
	void *content = NULL;
	X509 *x509 = NULL;
	size_t content_sz = 0;
	int err = 0;

	/*
	 * The signature and the payload hash both span insns || data --
	 * the concatenation the kernel folds and verifies at load. Build
	 * that once and feed it to both CMS_final and the digest.
	 */
	if (check_add_overflow(io->insns_sz, io->data_sz, &content_sz) ||
	    content_sz > INT_MAX) {
		err = -E2BIG;
		goto cleanup;
	}
	content = xmalloc(content_sz);
	if (!content) {
		err = -ENOMEM;
		goto cleanup;
	}
	memcpy(content, io->insns, io->insns_sz);
	if (io->data_sz)
		memcpy((char *)content + io->insns_sz, io->data, io->data_sz);

	bd_in = BIO_new_mem_buf(content, (int)content_sz);
	if (!bd_in) {
		err = -ENOMEM;
		goto cleanup;
	}

	x509 = read_x509(cert_path);
	if (!x509) {
		err = -EINVAL;
		goto cleanup;
	}

	cms = CMS_sign(NULL, NULL, NULL, NULL,
		       CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED |
		       CMS_STREAM);
	if (!cms) {
		err = -EINVAL;
		goto cleanup;
	}

	if (command)
		err = cms_sign_external(cms, command, x509, content,
					content_sz);
	else
		err = cms_sign_key(cms, bd_in, x509, pkey_path);
	if (err)
		goto cleanup;

	if (EVP_Digest(content, content_sz, io->payload_sha256,
		       &hash_len, EVP_sha256(), NULL) != 1) {
		err = -EIO;
		goto cleanup;
	}

	bd_out = BIO_new(BIO_s_mem());
	if (!bd_out) {
		err = -ENOMEM;
		goto cleanup;
	}

	if (!i2d_CMS_bio_stream(bd_out, cms, NULL, 0)) {
		err = -EIO;
		goto cleanup;
	}

	actual_sig_len = BIO_get_mem_data(bd_out, NULL);
	if (actual_sig_len <= 0) {
		err = -EIO;
		goto cleanup;
	}

	if ((size_t)actual_sig_len > io->signature_sz) {
		err = -ENOSPC;
		goto cleanup;
	}

	if (BIO_read(bd_out, io->signature, actual_sig_len) != actual_sig_len) {
		err = -EIO;
		goto cleanup;
	}

	if (command) {
		err = cms_check_external(io->signature, (size_t)actual_sig_len,
					 x509, content, content_sz);
		if (err)
			goto cleanup;
	}

	io->signature_sz = (size_t)actual_sig_len;
cleanup:
	BIO_free(bd_out);
	CMS_ContentInfo_free(cms);
	X509_free(x509);
	BIO_free(bd_in);
	xfree(content, content_sz);
	DISPLAY_OSSL_ERR(err < 0);
	return err;
}
