#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-time.sh -- build and run the Linux platform pilot's time
# extension natively. Sibling of tools/linux-build.sh (the original
# mman/unistd pilot script); see that script's own banner for the
# general discipline this one follows too.
#
# Proves src/internal/plat_time.h's clock-query functions (time(),
# clock(), clock_gettime(), clock_settime(), clock_getres(),
# timespec_get(), stime()) against a real Linux backend
# (src/time/linux/plat_time.c), exercised through the REAL
# src/time/{time,clock,stime,timespec_get,clock_gettime}.c front doors,
# as one native, runnable ELF binary -- no Wine, no emulation, on
# whatever host this script runs on.
#
# Scope, deliberately: the POSIX-interval-timer manager thread
# (timer.c) is NOT built or exercised here -- src/time/linux/
# plat_time.c's own __plat_timer_manager_start() comment explains why
# (real clone(2) thread creation plus a real futex/eventfd-based wake
# primitive is a materially harder, higher-risk piece of work than the
# clock-query functions, so this script's scope stops at the latter
# rather than attempting an unverified implementation of the former).
#
# Usage: tools/linux-build-time.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-time}
TAG=linux-build-time

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
	src/time/time.c
	src/time/clock.c
	src/time/stime.c
	src/time/timespec_get.c
	src/time/clock_gettime.c
	src/time/linux/plat_time.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_time.c
	fuzz/linux_pilot_test_time.c
"

echo "$TAG: compiling ($CC, native ELF)..."
objs=""
for f in $FILES; do
	o="$OBJ/$(basename "$f" .c).o"
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -c -o "$o" "$f"; then
		echo "$TAG: FAILED compiling $f" >&2
		exit 1
	fi
	objs="$objs $o"
done

echo "$TAG: linking..."
# shellcheck disable=SC2086
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_time" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_time"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
