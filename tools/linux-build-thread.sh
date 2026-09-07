#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-thread.sh -- build and run the Linux thread-subsystem pilot
# natively. Sibling to tools/linux-build.sh (mman/unistd); see that
# script's own banner for the shared discipline (raw syscall(2), no host
# libc wrapper, -nostdinc against spicule's own generated headers,
# aarch64-host-only syscall numbers).
#
# Builds src/thread/linux/plat_thread.c + src/thread/linux/aarch64/clone.S +
# src/internal/linux/tls_setup.c (the real per-thread CLONE_SETTLS TLS
# block builder plat_thread.c's __plat_thread_spawn() calls -- linked
# here too since this pilot's whole point is exercising real clone()'d
# threads) -- a deliberately narrow slice of src/internal/plat_thread.h
# (semaphores, a manual-reset event, single-handle waiting, and real
# clone(2)-based thread creation; see plat_thread.c's own banner for the
# full list of what this does NOT cover and why) -- and links them against fuzz/
# linux_pilot_test_thread.c, which builds a minimal mutex directly on
# top of the real backend functions and stress-tests it with real,
# clone()-spawned Linux threads hammering a shared counter. Unlike
# tools/linux-build.sh's pilot, this one does NOT link any real spicule
# front-door .c file (no src/thread/pthread_mutex.c) -- see plat_thread.c
# for exactly why that front door cannot be linked against this backend
# without also porting RtlAcquirePebLock()/__pthread_current(), separate
# follow-up work.
#
# Usage: tools/linux-build-thread.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- the
#          width convention for spicule's OWN generated headers this
#          build compiles against; unrelated to the host's real CPU
#          architecture, see tools/linux-build.sh's own comment)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-thread}
TAG=linux-build-thread

cd "$srcdir"

if [ -f config.mak ]; then
	cfg_arch=$(sed -n 's/^ARCH *= *//p' config.mak | head -1)
	if [ -n "$cfg_arch" ] && [ "$cfg_arch" != "$ARCH" ]; then
		echo "$TAG: tree is configured for ARCH=$cfg_arch but this build is $ARCH." >&2
		echo "$TAG: reconfigure (./configure --host=$ARCH-win32 CC=...) or set SPICULE_ARCH=$cfg_arch." >&2
		exit 1
	fi
fi

mkdir -p "$OBJ"
if [ ! -f obj/include/bits/alltypes.h ]; then
	echo "$TAG: obj/include/bits/alltypes.h is missing -- run './configure --host=$ARCH-win32 CC=$ARCH-win32-tcc' and 'make ARCH=$ARCH obj/include/bits/alltypes.h' first (the generated header this build needs, same one 'make'/'make asan' use)." >&2
	exit 1
fi

INC="-Isrc/internal -Iobj/include -Iinclude -Iarch/$ARCH -Iarch/generic"
CFLAGS="-std=c99 -nostdinc -fno-builtin -g -O0 -ffunction-sections -fdata-sections \
$INC -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL -Wall -Wno-unused-function"

FILES="
	src/thread/linux/plat_thread.c
	src/thread/linux/aarch64/clone.S
	src/internal/linux/tls_setup.c
	src/internal/errno.c
	fuzz/linux_pilot_test_thread.c
"

echo "$TAG: compiling ($CC, native ELF)..."
objs=""
for f in $FILES; do
	o="$OBJ/$(basename "$f" | sed 's/\.[cS]$/.o/')"
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -c -o "$o" "$f"; then
		echo "$TAG: FAILED compiling $f" >&2
		exit 1
	fi
	objs="$objs $o"
done

echo "$TAG: linking..."
# shellcheck disable=SC2086
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_thread" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_thread"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
