#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build.sh -- build and run the Linux platform pilot natively.
#
# Proves the platform-abstraction seam (src/internal/plat_*.h) against
# a second real backend, not just NT: src/mman/linux/plat_mem.c and
# src/unistd/linux/plat_fd.c implement the mman and unistd-fd-ops
# interfaces via raw Linux syscalls (syscall(2), no host libc wrapper --
# the same discipline the NT side keeps toward ntdll), and
# fuzz/linux_pilot_test.c exercises the REAL src/mman/mman.c and
# src/unistd/{close,read,write,lseek,dup}.c front doors against them as
# one native, runnable ELF binary -- no Wine, no emulation, on whatever
# host this script runs on.
#
# Scope, deliberately: only the two subsystems the original NT pilot
# covered (mman, unistd fd-ops). Every other migrated subsystem (time,
# socket, process, filesystem, misc/select/signal/stdio, thread) has no
# Linux backend yet -- this is a pilot proving the pattern holds for a
# second OS, not a second complete port. open()'s own front door
# (src/fcntl/open.c) still resolves paths through NT-only machinery
# (__ntpath_at) directly and cannot be exercised at all without a
# larger, separate effort (see the report this script's own commit
# message and CONTRIBUTING.md-style notes describe); fuzz/
# linux_pilot_test.c opens its test file with a raw openat(2) instead,
# the same shape of scaffolding fuzz/ntstubs.c already uses to stand in
# for what a native build cannot have.
#
# fuzz/linux_pilot_harness.c supplies three more things this pilot does
# NOT port, each documented at its own definition: __fd_pos_save()/
# __fd_pos_restore() (an NT-only quirk workaround pread/pwrite need,
# meaningless on Linux, where positioned I/O never moves the descriptor
# at all), __mq_fd_closed() (mqueue bookkeeping this pilot's test never
# touches), and a from-scratch minimal fd table (__fds[]/__fd_alloc/
# __fd_install*/__fd_get) rather than linking the real
# src/internal/fd.c, whose __handle_type() unconditionally needs two
# NT-only syscalls that this pilot has no Linux equivalent for yet.
#
# Syscall numbers are aarch64's (arch/arm64/include/uapi/asm/unistd.h),
# hardcoded directly in each plat_*.c file: confirmed against the build
# host's own <sys/syscall.h> as an oracle, not assumed, but this script
# and the backend files as they stand only support an aarch64 host.
# Porting to x86_64 means adding that architecture's own syscall-number
# table to each backend file (see their own comments for why the
# numbers cannot come from a host header: this build is -nostdinc
# against spicule's own generated headers, never glibc's).
#
# Usage: tools/linux-build.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- the
#          width convention for spicule's OWN generated headers this
#          build compiles against; unrelated to the host's real CPU
#          architecture, the same simplification tools/asan-build.sh
#          already makes for its own native build)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot}
TAG=linux-build

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
	src/mman/mman.c
	src/mman/linux/plat_mem.c
	src/unistd/close.c
	src/unistd/read.c
	src/unistd/write.c
	src/unistd/lseek.c
	src/unistd/dup.c
	src/unistd/linux/plat_fd.c
	src/internal/errno.c
	fuzz/linux_pilot_harness.c
	fuzz/linux_pilot_test.c
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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
