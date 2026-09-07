#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-process.sh -- build and run the Linux process/fork/wait
# pilot natively.
#
# Extends tools/linux-build.sh's pattern (mman + unistd fd-ops) to
# process creation: src/process/linux/plat_process.c implements the
# process interface (src/internal/plat_process.h) via raw Linux
# syscalls -- clone(2) standing in for fork(2), which does not exist on
# aarch64 -- and fuzz/linux_pilot_test_process.c exercises the REAL
# src/process/{fork,wait,children}.c front doors against it as one
# native, runnable ELF binary, statically linked alongside the
# already-proven src/unistd/{close,read,write}.c + its own Linux
# backend (src/unistd/linux/plat_fd.c) -- no Wine, no emulation, on
# whatever host this script runs on. src/mman/mman.c is NOT linked
# here: this pilot's own test never calls mmap()/munmap(), and linking
# it would collide with fuzz/linux_pilot_harness_process.c's own stub
# for __mman_reset_after_fork() (see that file's banner) with a second,
# real definition of the same symbol.
#
# Scope, deliberately, same spirit as linux-build.sh's own: fork()/
# waitpid()/__plat_process_resume()/__plat_is_program() are exercised
# for real; posix_spawn()/execve()'s own front doors (spawn.c,
# posix_spawn.c, exec.c, find_program.c's PATH search) are NOT linked
# here, even though __plat_process_spawn() itself is implemented in the
# backend -- see the report for why (every one of those front doors
# pulls in subsystems, PATH/UTF-8/command-line handling and cross-
# subsystem hooks well past this pilot's own scope). pipe(2)'s own
# front door (src/unistd/pipe.c) and _exit() (src/exit/exit.c) are two
# more unported subsystems fuzz/linux_pilot_test_process.c stands in
# for with raw syscalls, the same shape of scaffolding linux-build.sh's
# own test already uses for open().
#
# fuzz/linux_pilot_harness_process.c supplies LOCAL-ONLY stubs for
# every OTHER subsystem's fork()-related hook src/process/{fork,wait,
# children}.c calls out to (thread, signal, mman's own reset, malloc,
# aio, WOW64 detection) -- each one owned by a different, still-Linux-
# unported subsystem some other, isolated session is porting in
# parallel; see that file's own banner for why a stub, not a real
# implementation, is correct here.
#
# Syscall numbers are aarch64's, hardcoded directly in
# src/process/linux/plat_process.c: confirmed against the build host's
# own <sys/syscall.h> as an oracle, not assumed (see the report) -- this
# script and that backend file, like linux-build.sh's own, only support
# an aarch64 host.
#
# Usage: tools/linux-build-process.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          linux-build.sh's own comment on this variable)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-process}
TAG=linux-build-process

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
	src/process/fork.c
	src/process/wait.c
	src/process/children.c
	src/process/linux/plat_process.c
	src/signal/linux/plat_signal.c
	src/thread/linux/plat_thread.c
	src/thread/linux/aarch64/clone.S
	src/internal/linux/tls_setup.c
	src/unistd/close.c
	src/unistd/read.c
	src/unistd/write.c
	src/unistd/linux/plat_fd.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_process.c
	fuzz/linux_pilot_test_process.c
"
# src/thread/linux/plat_thread.c (plus its own aarch64/clone.S trampoline
# -- renamed from clone_aarch64.S when the clone(2) trampoline was ported
# per-arch to x86_64/i386 -- and src/internal/linux/tls_setup.c dependency, the same trio
# tools/linux-build-thread.sh already links) was missing until commit
# 735db9c8 ("pthread_create(): give Linux a real create_suspended
# primitive") moved __plat_thread_resume() out of
# src/process/linux/plat_process.c (which this FILES list already had)
# into plat_thread.c, for the ODR reason that commit's own message
# gives (it needs plat_thread.c's new suspend/resume gate table). This
# pilot's own fork.c calls __plat_thread_resume() directly, unstubbed
# by fuzz/linux_pilot_harness_process.c (that harness only stubs the
# atfork hooks, per its own banner) -- so the link broke the moment the
# real definition moved out from under this list. Verified with a full
# clean rebuild+run.
# src/signal/linux/plat_signal.c was missing until commit d47e081f
# ("Send real SIGHUP to orphaned stopped children on Linux") made
# src/process/children.c's clear_stops() call the real
# __plat_sig_deliverable_to_other_process() -- a real, previously-hidden
# gap CI never reached because tools/linux-build-crt.sh and then
# tools/linux-build-fs.sh always failed to link first. Traced by reading
# children.c's real call and confirming: unlike tools/linux-build-fs.sh/
# tools/linux-build-open.sh's own __free gap, nothing else in this
# FILES list needed the allocator or the fd table plat_signal.c's OTHER
# functions reach (__plat_sigevent_create()'s __fd_install(), see
# tools/linux-build-misc.sh's own comment) -- this pilot's own test
# never calls anything that reaches that code path, so --gc-sections
# drops it, and the build links and runs clean with just this one file
# added. Verified with a full clean rebuild+run.

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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_process" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_process"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
