/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * CMS/PKCS#7 signer. Linked only into shirudo-build.
 */

#ifndef SHIRUDO_SIGN_H
#define SHIRUDO_SIGN_H

#include <stddef.h>

#include <shirudo/misc.h>

#define SHA256_LEN	32

/*
 * The signature and payload_sha256 both span insns || data, the bytes
 * the kernel reconstructs at BPF_PROG_LOAD; data may be empty.
 * signature_sz comes back as the actual size.
 */
struct sign_io {
	const void	*insns;
	size_t		insns_sz;

	const void	*data;
	size_t		data_sz;

	void		*signature;
	size_t		signature_sz;

	__u8		payload_sha256[SHA256_LEN];
};

/*
 * -ENOSPC when the signature buffer is too small, -EINVAL on a parse
 * failure, -EIO on an OpenSSL or signer failure, -EBADMSG when the
 * signer's signature does not verify. With signer_command() set,
 * pkey_path is not read.
 */
int cms_sign(struct sign_io *io,
	     const char *pkey_path, const char *cert_path);

/*
 * Opens the private key and checks, on that descriptor, that it is a
 * regular file of mode 0600. The descriptor, or -errno logged.
 */
int open_signing_key(const char *pkey_path);

/*
 * SHIRUDO_SIGNER, or NULL when it is unset or empty: a command run by
 * /bin/sh that reads the DER of the signed attributes on standard input
 * and writes their raw ML-DSA-87 signature to standard output, so that
 * the private key never has to be a file here.
 */
const char *signer_command(void);

#endif /* SHIRUDO_SIGN_H */
