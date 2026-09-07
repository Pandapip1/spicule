#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-socket.sh -- build and run the Linux socket-backend pilot
# natively. Same pattern as tools/linux-build.sh (the mman/unistd
# pilot); see that script's own banner for the general discipline.
#
# Proves src/socket/linux/plat_socket.c (__plat_sock_recv()/
# __plat_sock_send(), the only two functions src/internal/plat_socket.h
# declares) against the REAL src/socket/sendrecv.c front door
# (recv()/send()), statically linked here, unmodified, as one native,
# runnable ELF binary -- no Wine, no emulation, on whatever host this
# script runs on.
#
# Scope, deliberately: ONLY recv()/send(). socket()/accept()/bind()/
# connect()/listen() are NOT ported (they call raw NT `\Device\Afd` wire-
# protocol machinery directly, with no portable abstraction at all --
# see src/socket/linux/plat_socket.c's own banner). fuzz/
# linux_pilot_test_socket.c gets a connected socket pair via a raw
# socketpair(2) instead, and registers both ends into spicule's own fd
# table by hand (fuzz/linux_pilot_harness_socket.c supplies the minimal
# fd table, matching fuzz/linux_pilot_harness.c's own precedent and its
# own reason: the real src/internal/fd.c's __handle_type() unconditionally
# needs two NT-only syscalls the compiler cannot prove dead).
#
# Syscall numbers are aarch64's, hardcoded directly in
# src/socket/linux/plat_socket.c and fuzz/linux_pilot_test_socket.c:
# confirmed against the build host's own <sys/syscall.h> as an oracle,
# not assumed, but this script and those files as they stand only
# support an aarch64 host.
#
# Usage: tools/linux-build-socket.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- the
#          width convention for spicule's OWN generated headers this
#          build compiles against; unrelated to the host's real CPU
#          architecture, matching tools/linux-build.sh's own choice)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-socket}
TAG=linux-build-socket

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
	src/socket/sendrecv.c
	src/socket/linux/plat_socket.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_socket.c
	fuzz/linux_pilot_test_socket.c
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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_socket" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_socket"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
