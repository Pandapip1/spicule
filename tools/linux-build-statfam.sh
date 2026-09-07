#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-statfam.sh -- build and run the stat-family front-door
# pilot natively. See tools/linux-build-open.sh for the pattern this
# mirrors; a separate script (and separate obj dir/binary name) because
# this one links a different front-door set -- src/stat/{chmod,mkdir,
# stat,statvfs,utimensat}.c -- and must not collide with
# tools/linux-build-open.sh/tools/linux-build-fs.sh's own object trees.
#
# Proves the stat-family path-resolution refactor (src/internal/
# plat_stat.h's __plat_chmodat()/__plat_mkdir()/__plat_fstatat()/
# __plat_statvfs_path()/__plat_set_times_at(), src/stat/nt/plat_stat.c's
# and src/stat/linux/plat_stat.c's implementations of it -- the same
# relocation commit ce4763c already did for open()) against the REAL
# src/stat/{chmod,mkdir,stat,statvfs,utimensat}.c front doors
# (chmod()/fchmod()/fchmodat(), mkdir()/mkdirat(), stat()/lstat()/
# fstat()/fstatat(), statvfs()/fstatvfs(), utimensat()), statically
# linked into one native, runnable ELF binary -- no Wine, no emulation,
# on whatever host this script runs on.
#
# Usage: tools/linux-build-statfam.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-statfam}
TAG=linux-build-statfam

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
	src/stat/chmod.c
	src/stat/mkdir.c
	src/stat/stat.c
	src/stat/statvfs.c
	src/stat/utimensat.c
	src/stat/linux/plat_stat.c
	src/unistd/linux/plat_fd.c
	src/internal/errno.c
	src/malloc/crt_alloc.c
	src/malloc/linux/plat_malloc.c
	src/thread/linux/plat_thread.c
	fuzz/linux_pilot_harness_fs.c
	fuzz/linux_pilot_test_statfam.c
"
# src/malloc/crt_alloc.c, src/malloc/linux/plat_malloc.c and
# src/thread/linux/plat_thread.c -- the identical gap and identical fix
# tools/linux-build-fs.sh's own comment already documents in full
# (src/stat/chmod.c's fchmod() calls __free() on its EACCES retry path;
# this test never calls fchmod() either, but src/stat/chmod.c is linked
# here as a whole object, not pulled from an archive, so its compiled
# body's own reference must resolve regardless).

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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_statfam" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_statfam"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
