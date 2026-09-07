#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-unistd2.sh -- build and run the "rest of src/unistd" Linux
# platform pilot natively.  tools/linux-build.sh's own twin, for the
# second Linux backend: src/unistd/linux/plat_unistd.c, implementing
# src/internal/plat_unistd.h (sleep's clock/alarm pair, getppid,
# ftruncate, fsync, pipe, sysconf, unlink, chdir, link/readlink/symlink,
# and ids.c's uid/pgrp/session/chown-probe functions) via raw Linux
# syscalls, exactly the same discipline (see that file's own banner).
#
# fuzz/linux_pilot_test_unistd2.c exercises the REAL front doors
# (src/unistd/{close,read,write,lseek,dup,fsync,pipe,ftruncate,sysconf,
# unlink,ids,chdir,link}.c) statically linked, unmodified, against the new
# backend, as one native, runnable ELF binary -- no Wine, no emulation.
# chdir.c and link.c joined this list once their own front doors
# (chdir(), link.c's readlinkat()) stopped calling __vfs_resolve_at()
# (src/internal/vfs.c) themselves -- that NT-only-overlay call moved
# behind __plat_chdir()/__plat_readlink() (src/internal/plat_unistd.h),
# exactly the shape __plat_open() (src/fcntl/nt/plat_fcntl.c) already
# got. A couple of functions still have no plat_unistd.h front door at
# all to test through (__plat_getppid, the sleep.c clock/alarm pair --
# getpid()/gettid() read NT's TEB directly, out of scope for this
# interface) and are exercised directly instead -- see
# fuzz/linux_pilot_test_unistd2.c and src/unistd/linux/plat_unistd.c's
# own banners for the full argument.
#
# Usage: tools/linux-build-unistd2.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own comment on this)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-unistd2}
TAG=linux-build-unistd2

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
	src/unistd/close.c
	src/unistd/read.c
	src/unistd/write.c
	src/unistd/lseek.c
	src/unistd/dup.c
	src/unistd/linux/plat_fd.c
	src/unistd/fsync.c
	src/unistd/pipe.c
	src/unistd/ftruncate.c
	src/unistd/sysconf.c
	src/unistd/unlink.c
	src/unistd/ids.c
	src/unistd/chdir.c
	src/unistd/link.c
	src/unistd/linux/plat_unistd.c
	fuzz/linux_pilot_harness_unistd2.c
	fuzz/linux_pilot_test_unistd2.c
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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_unistd2" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_unistd2"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
