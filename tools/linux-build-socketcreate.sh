#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-socketcreate.sh -- build and run the Linux socket-CREATION
# pilot natively. Same pattern as tools/linux-build-socket.sh (the
# earlier recv()/send()-only pilot); see that script's own banner for the
# general discipline.
#
# Proves src/internal/plat_socket.h's __plat_socket_{open,bind,connect,
# listen,accept}() (src/socket/linux/plat_socket.c) against the REAL
# src/socket/{socket,bind,connect,listen,accept,sendrecv}.c front doors,
# statically linked here, unmodified, as one native, runnable ELF binary
# -- no Wine, no emulation, on whatever host this script runs on. Named
# distinctly from tools/linux-build-socket.sh/fuzz/linux_pilot_test_socket.c
# (that earlier pilot's send()/recv()-only scope, using a raw
# socketpair(2) in place of connection setup) so the two do not collide.
#
# Syscall numbers are aarch64's, hardcoded directly in
# src/socket/linux/plat_socket.c: confirmed against the build host's own
# <sys/syscall.h> as an oracle, not assumed, but this script and those
# files as they stand only support an aarch64 host.
#
# Usage: tools/linux-build-socketcreate.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- the
#          width convention for spicule's OWN generated headers this
#          build compiles against; unrelated to the host's real CPU
#          architecture, matching tools/linux-build.sh's own choice)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-socketcreate}
TAG=linux-build-socketcreate

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
	src/socket/socket.c
	src/socket/bind.c
	src/socket/connect.c
	src/socket/listen.c
	src/socket/accept.c
	src/socket/sendrecv.c
	src/socket/inet.c
	src/socket/linux/plat_socket.c
	src/unistd/linux/plat_fd.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_socketcreate.c
	fuzz/linux_pilot_test_socketcreate.c
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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_socketcreate" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_socketcreate"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
