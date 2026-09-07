#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-crt.sh -- build and run fuzz/linux_pilot_test_crt.c as a
# real, freestanding, statically linked ELF binary through the REAL
# ./configure --platform=linux / Makefile build, not an ad hoc FILES
# list compiled straight from this script the way every earlier
# tools/linux-build-*.sh pilot works.
#
# The difference matters more than it sounds: every earlier Linux pilot
# links with a bare `$CC ... -o binary $objs`, no -nostdlib -- which
# means every one of them silently rides on the HOST's real glibc crt
# (_start, argv/envp/auxv parsing, and -- easy to miss -- real TLS
# setup via the dynamic linker) for everything this script's own
# crt/linux/crt1.c + crt/linux/aarch64/start.S now do from scratch.
# That is *why* errno (a __thread variable) always worked in those
# pilots despite no spicule code anywhere setting up TPIDR_EL0: glibc's
# own crt already had. This script is the first one that does not
# borrow that -- $(CC) links -nostdlib -static -no-pie against nothing
# but this build's own lib/crt1.o, lib/start.o and lib/libc.a-shaped
# object set, so a pass here is a real, first-time proof that this
# project's OWN program-startup code (not the host's) gets argv/
# environ/TLS/errno/fd 0-2/exit status all correct end to end.
#
# -static -no-pie here is scope, not a correctness requirement any
# more: crt1.c's TLS setup used to read a PT_TLS program header's own
# p_vaddr as if it were already an absolute runtime address, which is
# only true for a non-PIE ET_EXEC binary loaded at its link-time-fixed
# addresses -- a real, reproduced bug (a PIE build of this very file,
# minus these two flags, segfaulted in memcpy() at startup reading a
# tiny, unmapped link-time address instead of the real ASLR-random
# runtime one). find_tls_phdr() now also computes the image's real
# load bias (AT_PHDR minus the PT_PHDR program header's own p_vaddr,
# the same technique musl/glibc/FreeBSD's own loaders use) and every
# p_vaddr this file reads out of a program header gets that bias
# added before use, so a PIE build of the very same crt/link inputs
# now works too -- see obj/bin/*.exe's own real build (no -static
# -no-pie at all, see Makefile's obj/bin/%.exe pattern rule) for that
# proof. This script keeps -static -no-pie anyway, unrelated to the
# fix: it is still the simplest, smallest-moving-parts format for a
# from-scratch pilot script whose only job is proving this crt's own
# code (not a PIE build's worth of dynamic-linker/relocation
# interaction, already covered by the real product build) gets argv/
# environ/TLS/errno/fd 0-2/exit status right.
#
# Deliberately NOT `make all`: PLATFORM=linux's `make lib/libc.a`
# builds the WHOLE library, including large swaths (src/math/x87.h's
# x87-specific inline asm, setjmp/longjmp, signal altstack assembly --
# none arch-guarded) that assume x86 unconditionally and do not even
# compile on aarch64. Porting the rest of the library to a second CPU
# architecture is real, separate, disclosed future work -- the crt/
# build-target gap this script proves closed is specifically "can a
# real program start up and run under this platform's own crt", which
# needs only the curated file list below, the same shape every earlier
# linux-build-*.sh pilot already uses.
#
# Usage: tools/linux-build-crt.sh
# Env:   SPICULE_CC (default clang)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
BUILD=${SPICULE_LINUX_CRT_BUILD:-$srcdir/obj/linux-crt-build}
TAG=linux-build-crt

cd "$srcdir"

mkdir -p "$BUILD"

echo "$TAG: configuring (platform=linux, native $CC)..."
(cd "$BUILD" && "$srcdir/configure" --srcdir="$srcdir" --platform=linux CC="$CC" >/dev/null)

cfg_arch=$(sed -n 's/^ARCH *= *//p' "$BUILD/config.mak" | head -1)
if [ "$cfg_arch" != "aarch64" ]; then
	echo "$TAG: this build host configured ARCH=$cfg_arch, but crt/linux/aarch64/start.S is the only arch implemented so far -- see crt/linux/crt1.c's own banner." >&2
	exit 1
fi

echo "$TAG: building lib/crt1.o + lib/start.o + lib/libc.a's needed objects..."
"${MAKE:-make}" -C "$BUILD" -f "$srcdir/Makefile" srcdir="$srcdir" \
	lib/crt1.o lib/start.o >/dev/null

FILES="
	fuzz/linux_pilot_test_crt.c
	src/fcntl/open.c
	src/fcntl/linux/plat_fcntl.c
	src/unistd/linux/plat_fd.c
	src/internal/fd.c
	src/internal/linux/plat_fd_init.c
	src/internal/linux/tls_setup.c
	src/internal/errno.c
	src/internal/ldbl_layout_check.c
	src/exit/linux/plat_exit.c
	src/exit/exit.c
	src/malloc/crt_alloc.c
	src/math/fenv.c
	src/signal/signal.c
	src/signal/linux/plat_signal.c
	src/signal/linux/sigdelivery.c
	src/signal/aarch64/altstack.S
	arch/aarch64/src/sigreturn_trampoline.S
	src/process/children.c
	src/process/linux/plat_process.c
	src/stdio/file.c
	src/stdio/buf.c
	src/thread/linux/plat_thread.c
	src/thread/pthread_cancel.c
	src/thread/pthread.c
	src/thread/pthread_tsd.c
	src/misc/linux/plat_misc.c
	src/unistd/getpid.c
	src/unistd/ids.c
	src/unistd/linux/plat_unistd.c
	src/malloc/linux/plat_malloc.c
	src/malloc/malloc.c
	src/misc/resource.c
	src/socket/sendrecv.c
	src/socket/linux/plat_socket.c
	src/unistd/write.c
	src/unistd/lseek.c
	src/string/memcpy.c
	src/string/memset.c
	src/string/strlen.c
	src/string/strcmp.c
	src/string/strncmp.c
"
# src/internal/ldbl_layout_check.c was missing from this list until this
# same gap surfaced again, for real, while bringing up the x86_64/i386
# CRT ports (tools/linux-build-crt-cross.sh): crt/linux/crt1.c's own
# __linux_start_main() has unconditionally called __verify_ldbl_layout()
# since it was added, and this curated list simply never grew a line for
# it -- a real, pre-existing link failure on THIS arch too
# (`undefined reference to __verify_ldbl_layout`), not something the
# cross port introduced. Confirmed by reproducing it here, natively,
# before fixing it.
#
# The block added above it (exit.c through lseek.c) closes the same kind
# of gap for real, at real depth: crt/linux/crt1.c's own
# __linux_start_main() now calls exit(rc), and exit() -> __exit_internal()
# -> __stdio_exit()/__child_resume_stopped()/__plat_sig_default_terminate()
# reach far more of this library than the four symbols a real CI run ever
# printed (the link stops at the first few unresolved symbols, so later
# ones stay hidden until the earlier ones are fixed). Traced by reading
# each new file's own #includes/calls, then confirmed by actually
# compiling and linking, one real gap at a time, rather than guessed:
#   - src/exit/exit.c: exit(), __exit_internal() -- crt1.c's own call
#   - src/malloc/crt_alloc.c: __malloc()/__free() -- linux_build_environ()
#   - src/math/fenv.c: __fenv_init() -- crt1.c's own call
#   - src/signal/signal.c + src/signal/linux/{plat_signal.c,sigdelivery.c}
#     + src/signal/aarch64/altstack.S + arch/aarch64/src/
#     sigreturn_trampoline.S: __signal_init() -- crt1.c's own call, and
#     its real Linux/aarch64 Tier-2 fault-handler/cross-process-delivery
#     dependency closure (SA_ONSTACK's altstack switch, the rt_sigaction
#     SA_RESTORER trampoline)
#   - src/process/children.c + src/process/linux/plat_process.c:
#     __child_resume_stopped() -- exit()'s own unconditional call
#   - src/stdio/file.c + src/stdio/buf.c: __stdio_exit() -- exit()'s own
#     call, and the fflush()/lseek() it performs
#   - src/thread/pthread.c/pthread_cancel.c/pthread_tsd.c +
#     src/thread/linux/plat_thread.c: sigdelivery.c's own recursive lock
#     (__sig_lock()/__sig_unlock(), built on __pthread_cancel_defer_
#     enter/leave()) and pthread_exit()
#   - src/misc/linux/plat_misc.c: kill()'s job-control primitives and
#     write()'s RLIMIT_FSIZE query (see src/misc/resource.c below)
#   - src/unistd/getpid.c + src/unistd/ids.c +
#     src/unistd/linux/plat_unistd.c: getpid()/getuid()/getpgrp(), used
#     by signal.c's make_siginfo()/stop_self()/kill()
#   - src/malloc/linux/plat_malloc.c + src/malloc/malloc.c: realloc(),
#     used by src/stdio/buf.c's own dynamic buffer growth
#   - src/misc/resource.c: __fsize_limited()/__fsize_clamp(), which
#     write() consults unconditionally before writing
#   - src/socket/sendrecv.c + src/socket/linux/plat_socket.c: send(),
#     write()'s own __FD_SOCKET branch
#   - src/unistd/write.c + src/unistd/lseek.c: __file_write()/
#     __file_seek() in src/stdio/buf.c call the real, public front doors
#
# -mno-outline-atomics (CFLAGS, below) was the one non-FILES fix this
# same chain needed: __plat_event_peek()/__plat_wait_one()/pthread_cancel.c's
# own atomics compiled to calls into __aarch64_cas4_acq and friends
# without it -- see that flag's own comment.
INC="-I$srcdir/src/internal -I$BUILD/obj/include -I$srcdir/include -I$srcdir/arch/aarch64 -I$srcdir/arch/generic"
# -fno-stack-protector: this build has no __stack_chk_guard/_fail (NT
# never needed one under tcc, which does not insert stack-protector
# calls by default) -- without this flag, this host's clang defaults
# to inserting them anyway and the link fails on two symbols nothing
# in this tree defines. Found empirically, not anticipated.
# -mno-outline-atomics: without it, clang emits calls to
# __aarch64_cas4_acq/__aarch64_ldadd4_acq_rel/etc for every atomic RMW op
# (a runtime ifunc dispatch to LSE-vs-LL/SC helpers normally supplied by
# libgcc/compiler-rt) -- this build links against neither, so those calls
# are undefined references at link time. Forcing plain inlined LL/SC
# atomics avoids the outlined helpers entirely. Found empirically, not
# anticipated.
CFLAGS="-std=c99 -nostdinc -fno-builtin -fno-stack-protector -mno-outline-atomics -g -O0 -ffunction-sections -fdata-sections \
$INC -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL -Wall -Wno-unused-function"

echo "$TAG: compiling ($CC, native ELF)..."
objs="$BUILD/lib/crt1.o $BUILD/lib/start.o"
for f in $FILES; do
	o="$BUILD/$(basename "$f" .c).o"
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -c -o "$o" "$srcdir/$f"; then
		echo "$TAG: FAILED compiling $f" >&2
		exit 1
	fi
	objs="$objs $o"
done

echo "$TAG: linking (-nostdlib -static -no-pie -- no host crt, no host libc)..."
# shellcheck disable=SC2086
if ! $CC -g -O0 -nostdlib -static -no-pie -Wl,--gc-sections -o "$BUILD/linux_pilot_test_crt" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running (real _start, no host crt involved)..."
if "$BUILD/linux_pilot_test_crt"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL (exit $?)" >&2
	exit 1
fi
