#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-fs.sh -- build and run the Linux filesystem-subsystem
# pilot natively. See tools/linux-build.sh (the original mman/unistd
# fd-ops pilot) for the pattern this mirrors; this script is a separate
# copy, not a generalisation of it, matching that file's own "Usage"
# banner and this pilot's distinct fuzz/linux_pilot_{test,harness}_fs.c
# naming.
#
# Proves src/{dirent,fcntl,file,ioctl,stat}/linux/plat_*.c against the
# REAL src/fcntl/{fcntl,fadvise}.c, src/file/flock.c, src/ioctl/ioctl.c,
# and src/stat/{chmod,stat,statvfs,utimensat}.c front doors, statically
# linked into one native, runnable ELF binary -- no Wine, no emulation,
# on whatever host this script runs on.
#
# src/dirent/linux/plat_dirent.c is compiled (so it stays part of the
# ordinary build) but is NOT exercised by this test: it is now a real
# implementation (see that file's own banner), exercised instead by the
# dedicated tools/linux-build-dirent.sh pilot alongside the real
# src/dirent/{opendir,readdir,getdents,closedir,rewinddir}.c front
# doors.
#
# Usage: tools/linux-build-fs.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-fs}
TAG=linux-build-fs

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
	src/fcntl/fcntl.c
	src/fcntl/fadvise.c
	src/fcntl/linux/plat_fcntl.c
	src/file/flock.c
	src/file/linux/plat_flock.c
	src/ioctl/ioctl.c
	src/ioctl/linux/plat_ioctl.c
	src/stat/chmod.c
	src/stat/stat.c
	src/stat/statvfs.c
	src/stat/utimensat.c
	src/stat/linux/plat_stat.c
	src/dirent/linux/plat_dirent.c
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
	fuzz/linux_pilot_test_fs.c
"
# src/malloc/crt_alloc.c + src/malloc/linux/plat_malloc.c were missing
# until this same gap that tools/linux-build-crt.sh already hit
# (__malloc()/__free(), see that script's own comment) surfaced here
# too, for real: src/stat/chmod.c's fchmod() calls __free(path) on its
# EACCES retry path (compiled in unconditionally, even though this
# pilot's harness stub for __handle_path() always returns NULL, so the
# call is never actually reached at runtime -- see fuzz/
# linux_pilot_harness_fs.c's own banner on __handle_path()). Traced by
# reading chmod.c's real call, confirmed there is no other __malloc/
# __free/malloc/realloc reference anywhere else in this FILES list, and
# verified by actually compiling, linking and running. src/malloc/
# malloc.c (the public POSIX allocator, needed elsewhere for realloc())
# is NOT needed here: nothing in this FILES list calls malloc()/
# calloc()/realloc()/free(), only crt_alloc.c's own separate __malloc/
# __free token domain (see that file's own banner on why the two are
# deliberately not the same translation unit).
#
# src/thread/linux/plat_thread.c was the next gap this same chain
# uncovered: src/internal/plat_malloc_generic.h's spicule_malloc_lock(),
# called for real (not a dead branch) by __plat_alloc()/__plat_dealloc()
# on every allocation/free, calls __plat_thread_alertable_yield() to
# spin-wait for the allocator's lock. Only this one function of
# plat_thread.c's many is ever reached here: __plat_thread_spawn() (the
# only other function in this file that references anything else
# unresolved, __spicule_linux_clone() in src/thread/linux/
# aarch64/clone.S) is never called by anything in this FILES list, so
# --gc-sections drops that whole function's own section, and its own
# unresolved reference, before the link ever needs to satisfy it --
# confirmed by linking successfully without aarch64/clone.S at all.

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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_fs" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_fs"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
