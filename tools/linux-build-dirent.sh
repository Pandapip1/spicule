#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-dirent.sh -- build and run the Linux dirent pilot
# natively. See tools/linux-build-open.sh for the pattern this mirrors
# (compile flags, -nostdinc, -ffunction-sections/-Wl,--gc-sections); a
# separate script, not a generalisation of it, matching every other
# tools/linux-build-*.sh script's own precedent.
#
# Proves src/internal/plat_dirent.h's new __plat_dir_decode_one()
# redesign (see that header's own banner) end to end: the real
# src/dirent/{opendir,readdir,getdents,closedir,rewinddir}.c front doors,
# statically linked against the real src/dirent/linux/plat_dirent.c
# backend and the real src/fcntl/open.c/src/fcntl/linux/plat_fcntl.c
# open() path -- running as a real, native aarch64 Linux process on
# whatever host this script runs on, no Wine, no emulation.
#
# Usage: tools/linux-build-dirent.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-dirent}
TAG=linux-build-dirent

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
	src/dirent/opendir.c
	src/dirent/readdir.c
	src/dirent/getdents.c
	src/dirent/closedir.c
	src/dirent/rewinddir.c
	src/dirent/linux/plat_dirent.c
	src/fcntl/open.c
	src/fcntl/linux/plat_fcntl.c
	src/unistd/close.c
	src/unistd/linux/plat_fd.c
	src/string/memcpy.c
	src/string/memset.c
	src/string/strcpy.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_dirent.c
	fuzz/linux_pilot_test_dirent.c
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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_dirent" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_dirent"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
