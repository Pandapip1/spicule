#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-pthread-cond.sh -- build and run the pthread_cond_t
# front-door pilot natively. See tools/linux-build-pthread-mutex.sh for
# the pattern this mirrors; see fuzz/linux_pilot_test_pthread_cond.c's
# own banner for why this exists (a posix-optsrun CI investigation into
# pthread_cond_broadcast/*.c timeouts that turned out to be specific to
# that job's real target, x86_64-win32 under Wine, not this backend --
# kept here afterward as permanent regression coverage for the portable
# half of the algorithm).
#
# Proves a REAL, contended pthread_cond_broadcast() -- multiple real
# pthread_create()'d waiters blocked in a real pthread_cond_wait(),
# woken by one broadcast and pthread_join()'d -- against the REAL
# src/thread/pthread_cond.c/pthread_mutex.c front doors, statically
# linked into one native, runnable ELF binary. No Wine, no emulation,
# on whatever host this script runs on.
#
# `timeout`-wrapped deliberately: this test's own failure mode under
# test is "a waiter never wakes up", i.e. a real missed-wakeup bug here
# hangs pthread_join() forever, not just returns nonzero -- wrapping the
# run keeps a regression in this specific bug from also hanging
# whatever invokes this script (CI's own job timeout-minutes is a much
# blunter, much slower backstop for the exact same failure this script
# already knows how to name precisely).
#
# Usage: tools/linux-build-pthread-cond.sh
# Env:   NTLIBC_CC (default clang), NTLIBC_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${NTLIBC_CC:-clang}
ARCH=${NTLIBC_ARCH:-x86_64}
OBJ=${NTLIBC_LINUX_OBJ:-$srcdir/obj/linux-pilot-pthread-cond}
TAG=linux-build-pthread-cond
TIMEOUT_SECS=${NTLIBC_PILOT_TIMEOUT:-30}

cd "$srcdir"

if [ -f config.mak ]; then
	cfg_arch=$(sed -n 's/^ARCH *= *//p' config.mak | head -1)
	if [ -n "$cfg_arch" ] && [ "$cfg_arch" != "$ARCH" ]; then
		echo "$TAG: tree is configured for ARCH=$cfg_arch but this build is $ARCH." >&2
		echo "$TAG: reconfigure (./configure --host=$ARCH-win32 CC=...) or set NTLIBC_ARCH=$cfg_arch." >&2
		exit 1
	fi
fi

mkdir -p "$OBJ"
if [ ! -f obj/include/bits/alltypes.h ]; then
	echo "$TAG: obj/include/bits/alltypes.h is missing -- run './configure --host=$ARCH-win32 CC=$ARCH-win32-tcc' and 'make ARCH=$ARCH obj/include/bits/alltypes.h' first (the generated header this build needs, same one 'make'/'make asan' use)." >&2
	exit 1
fi

INC="-Isrc/internal -Isrc/thread -Iobj/include -Iinclude -Iarch/$ARCH -Iarch/generic"
CFLAGS="-std=c99 -nostdinc -fno-builtin -g -O0 -ffunction-sections -fdata-sections \
$INC -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_NTLIBC_INTERNAL -Wall -Wno-unused-function"

FILES="
	src/thread/pthread_mutex.c
	src/thread/pthread_cond.c
	src/thread/pthread.c
	src/thread/pthread_cancel.c
	src/thread/linux/plat_thread.c
	src/thread/linux/$ARCH/clone.S
	src/internal/linux/tls_setup.c
	src/unistd/getpid.c
	src/unistd/linux/plat_unistd.c
	src/unistd/linux/plat_fd.c
	src/internal/fd.c
	src/internal/linux/plat_fd_init.c
	src/time/clock_gettime.c
	src/time/linux/plat_time.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_pthread_cond.c
	fuzz/linux_pilot_test_pthread_cond.c
"

echo "$TAG: compiling ($CC, native ELF)..."
objs=""
for f in $FILES; do
	base=$(basename "$f")
	o="$OBJ/${base%.*}.o"
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -c -o "$o" "$f"; then
		echo "$TAG: FAILED compiling $f" >&2
		exit 1
	fi
	objs="$objs $o"
done

echo "$TAG: linking..."
# shellcheck disable=SC2086
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_pthread_cond" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running (timeout ${TIMEOUT_SECS}s)..."
if timeout "$TIMEOUT_SECS" "$OBJ/linux_pilot_test_pthread_cond"; then
	echo "$TAG: PASS"
	exit 0
else
	rc=$?
	if [ "$rc" -eq 124 ]; then
		echo "$TAG: FAILED -- timed out after ${TIMEOUT_SECS}s (a real missed-wakeup would hang here, not just fail)" >&2
	else
		echo "$TAG: FAIL" >&2
	fi
	exit 1
fi
