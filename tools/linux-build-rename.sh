#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-rename.sh -- build and run the rename()/renameat()
# front-door pilot natively. See tools/linux-build-open.sh for the
# pattern this mirrors; a separate script because this one adds
# src/stdio/misc.c (rename()/renameat()) and src/fcntl/open.c
# (needed by the test to create/verify files) to the link.
#
# Proves the rename()-path-resolution refactor (src/internal/
# plat_stdio.h's __plat_rename(), src/stdio/nt/plat_stdio.c's and
# src/stdio/linux/plat_stdio.c's implementations of it) against the
# REAL src/stdio/misc.c front door, statically linked into one native,
# runnable ELF binary -- no Wine, no emulation, on whatever host this
# script runs on.
#
# Usage: tools/linux-build-rename.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-rename}
TAG=linux-build-rename

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
	src/stdio/misc.c
	src/stdio/linux/plat_stdio.c
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
	fuzz/linux_pilot_test_rename.c
"
# src/malloc/crt_alloc.c, src/malloc/linux/plat_malloc.c and
# src/thread/linux/plat_thread.c -- the identical gap and identical fix
# tools/linux-build-fs.sh's own comment already documents in full
# (src/stat/chmod.c's fchmod() calls __free() on its EACCES retry path;
# this test never calls fchmod() either, but src/stat/chmod.c is linked
# here as a whole object, same shape as src/stdio/misc.c below).
#
# fuzz/linux_pilot_test_rename.c's own __find_program() stub was added
# for the same reason its pre-existing __file_new()/__spawn() stubs
# exist: src/stdio/misc.c's popen() (never called by this test, but
# compiled in unconditionally alongside rename()/renameat()) calls the
# real src/process/find_program.c's __find_program() to locate "sh" --
# a whole PATH-search subsystem (malloc(), access(),
# src/process/linux/plat_process.c's __plat_is_program()) well past
# this pilot's own scope, so it is stubbed locally instead, matching
# the file's own established pattern and comment.

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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_rename" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_rename"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
