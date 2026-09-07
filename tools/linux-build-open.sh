#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-open.sh -- build and run the open()/openat() front-door
# pilot natively. See tools/linux-build-fs.sh for the pattern this
# mirrors; a separate script because this one adds src/fcntl/open.c
# itself to the link -- the REAL front door, not a raw openat(2)
# stand-in the way every earlier Linux pilot's test used one.
#
# Proves the open()-path-resolution refactor (src/internal/
# plat_fcntl.h's __plat_open(), src/fcntl/nt/plat_fcntl.c's and
# src/fcntl/linux/plat_fcntl.c's implementations of it) against the
# REAL src/fcntl/open.c front door (open()/openat()/creat()),
# statically linked into one native, runnable ELF binary -- no Wine,
# no emulation, on whatever host this script runs on.
#
# Usage: tools/linux-build-open.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-open}
TAG=linux-build-open

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
	src/fcntl/open.c
	src/fcntl/fcntl.c
	src/fcntl/fadvise.c
	src/fcntl/linux/plat_fcntl.c
	src/stat/chmod.c
	src/stat/stat.c
	src/stat/statvfs.c
	src/stat/utimensat.c
	src/stat/linux/plat_stat.c
	src/unistd/close.c
	src/unistd/read.c
	src/unistd/write.c
	src/unistd/lseek.c
	src/unistd/dup.c
	src/unistd/linux/plat_fd.c
	src/string/memcpy.c
	src/internal/errno.c
	src/malloc/crt_alloc.c
	src/malloc/linux/plat_malloc.c
	src/thread/linux/plat_thread.c
	fuzz/linux_pilot_harness_fs.c
	fuzz/linux_pilot_test_open.c
"
# src/malloc/crt_alloc.c, src/malloc/linux/plat_malloc.c and
# src/thread/linux/plat_thread.c -- the identical gap and identical fix
# tools/linux-build-fs.sh's own comment already documents in full
# (src/stat/chmod.c's fchmod() calls __free() on its EACCES retry path;
# __malloc()/__free() need __plat_alloc()/__plat_dealloc()
# (plat_malloc.c); the allocator's own lock needs
# __plat_thread_alertable_yield() (plat_thread.c), and
# __plat_thread_spawn() -- this file's only other function needing an
# unresolved symbol, __spicule_linux_clone() -- is never called here
# either, so --gc-sections drops it before the link needs it). This
# script links fuzz/linux_pilot_harness_fs.c, the SAME harness (and the
# same dead EACCES branch) tools/linux-build-fs.sh already uses -- see
# that file's own comment for why __handle_path()'s NULL stub makes the
# call unreachable at runtime but not at link time. Confirmed by
# reproducing the identical `undefined reference to __free` failure
# here first, then fixing it the same way and verifying with a full
# clean rebuild+run.

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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_open" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_open"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
