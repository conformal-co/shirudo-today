#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-stock-reproducible.sh -- build the stock-kernel
# binary of HEAD again in two other directories and fail unless both are
# the file the checkout built:
#
#   - a worktree that builds its target dependencies from source, as the
#     checkout did, at a path of another length;
#   - a worktree that takes the checkout's dependencies prebuilt
#     (TARGET_DEPS_PREBUILT=1), outside its own tree.
#
#   .github/scripts/check-stock-reproducible.sh [<make argument>...]
#
# Run in a checkout where make STOCK_KERNEL=1, with the same arguments,
# built build/stock/shirudo. The worktrees go under TMPDIR, or /tmp, and
# are removed afterwards.

set -eu

cd "$(git rev-parse --show-toplevel)"
top=$PWD
first=$top/build/stock/shirudo
deps=$top/build/target-deps
[ -f "$first" ] || {
	printf 'check-stock-reproducible: %s not built\n' "$first" >&2
	exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/reproducible.XXXXXX")
cleanup() {
	git worktree remove --force "$work/source" 2>/dev/null || :
	git worktree remove --force "$work/prebuilt/deps/elsewhere" 2>/dev/null || :
	rm -rf "$work"
}
trap cleanup EXIT

git worktree add -q --detach "$work/source" HEAD
make -C "$work/source" -j"$(nproc)" STOCK_KERNEL=1 "$@"

git worktree add -q --detach "$work/prebuilt/deps/elsewhere" HEAD
make -C "$work/prebuilt/deps/elsewhere" -j"$(nproc)" STOCK_KERNEL=1 \
	TARGET_DEPS_PREBUILT=1 TARGET_DEPS_DIR="$deps" "$@"

want=$(sha256sum <"$first" | cut -d' ' -f1)
bad=0
for bin in "$first" "$work/source/build/stock/shirudo" \
	   "$work/prebuilt/deps/elsewhere/build/stock/shirudo"; do
	got=$(sha256sum <"$bin" | cut -d' ' -f1)
	printf '%s  %s\n' "$got" "$bin"
	[ "$got" = "$want" ] || bad=1
done
if [ "$bad" -ne 0 ]; then
	printf 'check-stock-reproducible: the binaries differ\n' >&2
	exit 1
fi
printf 'check-stock-reproducible: build/stock/shirudo %s in three directories\n' \
	"$want"
