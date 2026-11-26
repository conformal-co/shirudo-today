// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The measurement register of the stock-kernel profile, which binds no
 * TPM: this boot's eventlog records, replayed, under a name of zeros, as
 * there is no NV index. Root can rewrite the eventlog: a record, not
 * evidence.
 */

#include <errno.h>
#include <string.h>

#include "chain.h"
#include "eventlog.h"

int chain_read(__u8 out[CHAIN_DIGEST_LEN])
{
	int ret = eventlog_replay(out);

	return ret == -ENOENT ? -ENODEV : ret;
}

/* The caller appends the event under the eventlog lock: nothing to write. */
int chain_extend(const __u8 event[CHAIN_DIGEST_LEN],
		 __u8 out_chain[CHAIN_DIGEST_LEN])
{
	__u8 value[CHAIN_DIGEST_LEN];
	int ret;

	ret = chain_read(value);
	if (ret)
		return ret == -ENODEV ? ret : -EACCES;
	ret = chain_fold(value, event);
	if (!ret && out_chain)
		memcpy(out_chain, value, sizeof(value));
	return ret;
}

int chain_live(struct chain_live *out)
{
	memset(out, 0, sizeof(*out));
	return chain_read(out->value);
}

bool chain_bound(void)
{
	__u8 value[CHAIN_DIGEST_LEN];

	return !chain_read(value);
}

int chain_status(struct chain_status *st)
{
	memset(st, 0, sizeof(*st));
	st->logged = !eventlog_boot_init(&st->init);
	st->defined = !chain_read(st->value);
	st->written = st->defined;
	st->anchored = st->defined;
	st->name_len = TPM_NAME_LEN;
	return st->defined ? 0 : -ENODEV;
}

/* The first init of a boot folds its event; a later one finds it on record. */
int chain_init(const __u8 event[CHAIN_DIGEST_LEN],
	       struct chain_init_info *info)
{
	int ret;

	memset(info, 0, sizeof(*info));
	info->name_len = TPM_NAME_LEN;
	ret = chain_read(info->value);
	if (ret != -ENODEV) {
		info->reused = !ret;
		return ret;
	}
	return chain_fold(info->value, event);
}
