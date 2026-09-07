#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-misc.sh -- build and run the Linux platform pilot's
# exit/misc/select/signal extension natively.
#
# Extends tools/linux-build.sh (the mman/unistd-fd-ops pilot) with
# Linux backends for four more of the platform-abstraction headers:
# src/exit/linux/plat_exit.c, src/misc/linux/plat_misc.c, src/select/
# linux/plat_select.c and src/signal/linux/plat_signal.c. See each
# file's own banner for what it implements, what it deliberately scopes
# out (plat_signal.h's named-pipe/mutant cross-process transport and
# the named-stop-event namespace -- both genuinely NT-object-manager-
# shaped, not a syscall swap), and the pidfd_open(2)-based process-
# handle redesign src/misc/linux/plat_misc.c's banner works through in
# detail (needed so plat_fd.h's shared __plat_close() -- which every
# process-handle-vending front door here calls -- does the right thing
# on a handle this session hands out).
#
# src/internal/plat_stdio.h (renameat()) has NO Linux backend in this
# tree: its own interface signature is built entirely around
# struct __ntpath, the same already-resolved NT path structure
# src/internal/libc.h's __ntpath_at() produces -- a Linux backend would
# need the front door's own path resolution ported first (someone
# else's, much larger, subsystem), not a mechanical translation of this
# header alone. Scoped out honestly rather than faked with an invented
# struct __ntpath substitute; see the commit message for the full
# reasoning.
#
# Testing strategy, per subsystem (see fuzz/linux_pilot_test_misc.c's
# own banner for the full reasoning on each):
#   - exit:   __plat_terminate() called directly (exit.c's own front
#             door pulls in unrelated, unported subsystems), verified
#             by this SCRIPT checking the real process exit status.
#   - misc:   the REAL src/misc/sched.c and src/misc/resource.c front
#             doors, linked and run genuinely end to end (a small
#             harness standin supplies getpid()/getppid()/getuid(),
#             the only other-subsystem NT-only calls those two files
#             need that this tree has no Linux backend for yet).
#   - select: src/select/linux/plat_select.c's functions called
#             directly against real pipes/sockets/eventfds this test
#             sets up with raw syscalls -- select()/poll()'s own front
#             doors pull in src/signal/'s lock machinery and the real
#             fd table, far beyond plat_select.h's own scope to stand
#             up just for this.
#   - signal: the implemented src/signal/linux/plat_signal.c functions
#             called directly, including against a REAL, independent
#             background `sleep` process this script spawns for exactly
#             that purpose -- see below -- so the test binary never has
#             to SIGSTOP itself.
#
# Usage: tools/linux-build-misc.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own note: this is spicule's own
#          generated-header width convention, unrelated to the host's
#          real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-misc}
TAG=linux-build-misc

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
	src/exit/linux/plat_exit.c
	src/misc/sched.c
	src/misc/resource.c
	src/misc/linux/plat_misc.c
	src/select/linux/plat_select.c
	src/signal/linux/plat_signal.c
	src/unistd/linux/plat_fd.c
	src/unistd/close.c
	src/internal/fd.c
	src/internal/linux/plat_fd_init.c
	src/internal/errno.c
	src/malloc/crt_alloc.c
	src/malloc/linux/plat_malloc.c
	src/thread/linux/plat_thread.c
	fuzz/linux_pilot_harness_misc.c
	fuzz/linux_pilot_test_misc.c
"
# src/unistd/close.c, src/internal/fd.c, src/internal/linux/
# plat_fd_init.c, src/malloc/crt_alloc.c, src/malloc/linux/
# plat_malloc.c and src/thread/linux/plat_thread.c were all missing
# until commit 66367136 ("Install real rt_sigaction(2) hardware-fault
# delivery on Linux/aarch64") made src/signal/linux/plat_signal.c's
# __plat_sigevent_create() register its eventfd through the REAL
# src/internal/fd.c __fd_install(), a call this script's FILES list
# had never needed to satisfy before -- a real, previously-hidden gap
# CI never reached because tools/linux-build-crt.sh and then
# tools/linux-build-fs.sh always failed to link first. Traced by
# reading each new file's own #includes/calls, one real gap at a time,
# exactly like tools/linux-build-crt.sh's own history:
#   - src/internal/fd.c: __fd_install() itself -- plat_signal.c's own
#     call
#   - src/internal/linux/plat_fd_init.c: __handle_type() -- fd.c's own
#     __fd_install_at() calls it whenever a caller (as here) passes
#     type=0
#   - src/malloc/crt_alloc.c + src/malloc/linux/plat_malloc.c:
#     __malloc()/__free() -- fd.c's own __fd_release_dynamic(), called
#     unconditionally by __fd_install_at() (same gap tools/
#     linux-build-fs.sh's own comment already documents)
#   - src/thread/linux/plat_thread.c: __plat_thread_alertable_yield()
#     -- the allocator's own lock (src/internal/plat_malloc_generic.h's
#     spicule_malloc_lock(), reached for real by __malloc()/__free()
#     above); __plat_thread_spawn() (this file's only OTHER function
#     needing anything unresolved, __spicule_linux_clone() in
#     src/thread/linux/aarch64/clone.S) is never called by anything in
#     this FILES list, so --gc-sections drops it before the link ever
#     needs that symbol -- confirmed by linking successfully without
#     aarch64/clone.S at all
#   - src/unistd/close.c: needed so this pilot's own eventfd close()s
#     go through the SAME __fds[] table __fd_install() just registered
#     them in, not a raw syscall that frees the real descriptor while
#     leaving its table slot marked occupied forever (see fuzz/
#     linux_pilot_test_misc.c's own comment on this, and its main()'s
#     __fd_init() comment for the matching table-desync gap that surfaced
#     first)
#
# fuzz/linux_pilot_harness_misc.c's own __fd_limit stub was removed as
# part of the same fix: src/internal/fd.c now supplies the real one,
# and a second definition would collide with it.
#
# fuzz/linux_pilot_test_misc.c itself needed two real fixes once it
# could finally link and run for the first time since that commit:
# __plat_event_peek()'s own contract moved to a different handle domain
# in a later commit in the same chain (1e3d2165, "Fix genuine hang in
# posix-signal-crossproc.c stop-signal job control") that this test's
# eventfd-domain calls to it were never updated to match (replaced with
# __plat_wait_ready()/a direct consuming read(2), the correct
# counterparts for this domain); and main() now calls __fd_init() before
# anything else, the same real fd-table bootstrap crt/linux/crt1.c's
# own startup now performs before __signal_init() (also commit
# 66367136) -- without it this pilot's own __fds[] table starts out of
# sync with the kernel's real fd numbering, and __plat_sigevent_create()
# box()es a table slot that stops matching the real kernel fd every
# other plat_signal.c/plat_select.c function unbox()es directly into a
# raw syscall.

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
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_misc" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running the main check suite (misc/select/signal-events)..."
set +e
"$OBJ/linux_pilot_test_misc"
main_status=$?
set -e
if [ "$main_status" -ne 0 ]; then
	echo "$TAG: FAIL (main suite)" >&2
	exit 1
fi

echo "$TAG: running the exit-code round-trip check (__plat_terminate())..."
set +e
"$OBJ/linux_pilot_test_misc" exit-test
exit_status=$?
set -e
if [ "$exit_status" -ne 42 ]; then
	echo "$TAG: FAIL -- __plat_terminate(42) should have made the real process exit status 42, got $exit_status" >&2
	exit 1
fi
echo "$TAG: ok   - __plat_terminate(42) produced a real process exit status of exactly 42"

echo "$TAG: spawning a background 'sleep' for the cross-process signal checks..."
sleep 300 &
sleeppid=$!
trap 'kill -9 "$sleeppid" 2>/dev/null || true' EXIT INT TERM

set +e
"$OBJ/linux_pilot_test_misc" signal-test "$sleeppid"
signal_status=$?
set -e
wait "$sleeppid" 2>/dev/null || true
if [ "$signal_status" -ne 0 ]; then
	echo "$TAG: FAIL (cross-process signal suite)" >&2
	exit 1
fi

echo "$TAG: PASS"
exit 0
