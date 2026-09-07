#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-dlfcn-cross.sh -- tools/linux-build-dlfcn.sh's own sibling
# for x86_64/i386 (this dev host's own CPU is aarch64 -- see tools/linux-
# build-crt-cross.sh's own banner for the cross-build/qemu-user
# discipline this script follows identically, just proving src/dlfcn/
# linux/plat_dlfcn.c's x86_64/i386 relocation support instead of the CRT).
#
# Unlike tools/linux-build-dlfcn.sh (which links the target test program
# against the REAL `make lib/libc.a`), this script uses a CURATED file
# list -- the same one tools/linux-build-crt-cross.sh already proved,
# plus exactly what dlopen()/dlsym()/dlclose()/dlerror() themselves need
# (malloc, the dlfcn front door, plat_dlfcn.c). A curated list is not a
# lesser proof of THIS file's own relocation support -- exactly the same
# reasoning tools/linux-build-crt.sh's own banner already gives for why
# ITS curated list was a real, first-time proof of the CRT layer
# specifically.
#
# Usage: tools/linux-build-dlfcn-cross.sh <x86_64|i386>
# Env:   SPICULE_CLANG (default clang), SPICULE_QEMU_X86_64 (default
#        qemu-x86_64), SPICULE_QEMU_I386 (default qemu-i386)

set -eu

arch=${1:?"usage: $0 <x86_64|i386>"}
srcdir=$(cd "$(dirname "$0")/.." && pwd)
CLANG=${SPICULE_CLANG:-clang}
TAG="linux-build-dlfcn-cross($arch)"

case "$arch" in
x86_64) target=x86_64-linux-gnu; qemu=${SPICULE_QEMU_X86_64:-qemu-x86_64} ;;
i386)   target=i386-linux-gnu;   qemu=${SPICULE_QEMU_I386:-qemu-i386} ;;
*) echo "$TAG: unsupported arch \"$arch\" (expected x86_64 or i386)" >&2; exit 1 ;;
esac

BUILD=${SPICULE_LINUX_DLFCN_CROSS_BUILD:-$srcdir/obj/linux-dlfcn-cross-build-$arch}
CC="$CLANG --target=$target -fuse-ld=lld"

cd "$srcdir"
mkdir -p "$BUILD"

echo "$TAG: configuring (platform=linux, cross $CC)..."
(cd "$BUILD" && "$srcdir/configure" --srcdir="$srcdir" --platform=linux --target="$target" CC="$CC" \
	CFLAGS="-fno-stack-protector" >/dev/null)

cfg_arch=$(sed -n 's/^ARCH *= *//p' "$BUILD/config.mak" | head -1)
if [ "$cfg_arch" != "$arch" ]; then
	echo "$TAG: configure picked ARCH=$cfg_arch, expected $arch" >&2
	exit 1
fi

echo "$TAG: building lib/crt1.o + lib/start.o..."
"${MAKE:-make}" -C "$BUILD" -f "$srcdir/Makefile" srcdir="$srcdir" \
	lib/crt1.o lib/start.o >/dev/null

echo "$TAG: building the target .so's (host $CLANG, real $arch shared objects)..."
if ! $CLANG --target="$target" -shared -fPIC -nostdlib -fuse-ld=lld -Wl,--hash-style=sysv \
	-Wl,-soname,linux_pilot_test_dlopen_lib.so \
	-o "$BUILD/linux_pilot_test_dlopen_lib.so" \
	fuzz/linux_pilot_test_dlopen_lib.c; then
	echo "$TAG: FAILED building the target .so" >&2
	exit 1
fi
if ! $CLANG --target="$target" -shared -fPIC -nostdlib -fuse-ld=lld -Wl,--hash-style=sysv \
	-Wl,-soname,linux_pilot_test_dlopen_tlslib.so \
	-o "$BUILD/linux_pilot_test_dlopen_tlslib.so" \
	fuzz/linux_pilot_test_dlopen_tlslib.c; then
	echo "$TAG: FAILED building the TLS-bearing target .so" >&2
	exit 1
fi

FILES="
	fuzz/linux_pilot_test_dlopen_cross.c
	fuzz/linux_pilot_dlfcn_cross_yield.c
	src/fcntl/open.c
	src/fcntl/linux/plat_fcntl.c
	src/unistd/read.c
	src/unistd/close.c
	src/unistd/linux/plat_fd.c
	src/internal/fd.c
	src/internal/linux/plat_fd_init.c
	src/internal/linux/fdpos.c
	src/internal/errno.c
	src/internal/ldbl_layout_check.c
	src/exit/linux/plat_exit.c
	src/exit/exit.c
	src/socket/sendrecv.c
	src/socket/linux/plat_socket.c
	src/string/memcpy.c
	src/string/memset.c
	src/string/memmove.c
	src/string/memchr.c
	src/string/memcmp.c
	src/string/strlen.c
	src/string/strcmp.c
	src/string/strncmp.c
	src/string/strerror.c
	src/string/strrchr.c
	src/string/memrchr.c
	src/stdlib/mbrtowc.c
	src/math/fabs.c
	src/math/fpclassify.c
	src/math/fenv.c
	src/malloc/crt_alloc.c
	src/malloc/malloc.c
	src/malloc/linux/plat_malloc.c
	src/dlfcn/dlfcn.c
	src/dlfcn/linux/plat_dlfcn.c
	src/stdio/printf.c
	src/stdio/rw.c
	src/stdio/buf.c
	src/stdio/mem.c
	src/stdio/seek.c
	src/stdio/file.c
	src/unistd/write.c
	src/unistd/lseek.c
	src/misc/resource.c
	src/misc/linux/plat_misc.c
	src/process/children.c
	src/process/linux/plat_process.c
	src/thread/pthread.c
	src/thread/pthread_cancel.c
	src/thread/pthread_tsd.c
	src/thread/linux/plat_thread.c
	src/misc/sched.c
	src/unistd/getpid.c
	src/unistd/ids.c
	src/unistd/linux/plat_unistd.c
	src/signal/signal.c
	src/signal/linux/sigdelivery.c
	src/signal/linux/plat_signal.c
	src/signal/$arch/altstack.S
	arch/$arch/src/sigreturn_trampoline.S
"
# arch/i386/src/int64.c: i386 has no hardware 64-bit divide, so clang's
# own code generator emits calls to __divdi3/__umoddi3/etc for a plain
# `long long / long long` on this arch alone -- the identical, real (not
# hypothetical) link requirement tools/linux-build-crt-cross.sh's own
# FILES list already documents in full for src/thread/linux/
# plat_thread.c's __plat_wait_one(), linked into THIS script's own FILES
# list too (pthread_once()'s deferral loop, see below).
if [ "$arch" = "i386" ]; then
	FILES="$FILES
	arch/i386/src/int64.c
"
fi
# src/unistd/getpid.c (getpid()/getppid()/gettid()) and src/unistd/ids.c
# (getuid()/getgid()/getpgrp()/...) join the list alongside signal.c:
# sigdelivery.c's own __sig_lock() calls gettid(), and signal.c's own
# make_siginfo()/kill()/__sigchld_job_control() call getpid()/getuid()/
# getpgrp() directly. src/unistd/linux/plat_unistd.c backs both
# (__plat_getpid()/__plat_gettid()/__plat_detect_uid()). All three are
# already-portable/already-ported files, already proven multi-arch by
# tools/linux-build-crt-cross.sh's own FILES list, just missing from
# this script's own curated subset until signal.c itself was added.
# This list was stale since before crt/linux/crt1.c grew its own
# `__fd_init(); __signal_init(); __fenv_init();` sequence (unconditional
# in __linux_start_main(), same as tools/linux-build-crt.sh's own
# fuzz/linux_pilot_test_crt.c uses): this script links the REAL
# lib/crt1.o too, so it needs the identical closure, and never got it.
# Traced and closed the same portable subset tools/linux-build-crt-
# cross.sh's own comment already documents in full (exit.c, crt_alloc.c,
# fenv.c, and everything exit()/__exit_internal() reaches in turn:
# children.c's __child_resume_stopped(), stdio/file.c's __stdio_exit()),
# plus two gaps specific to this script's own dlfcn/printf-based FILES:
# src/string/strrchr.c's real body needs memrchr.c (plat_dlfcn.c's own
# dirname_of() call to strrchr()), and plat_dlfcn.c's self_symtab_load()
# calls the real pthread_once() (src/thread/pthread_tsd.c, needing
# pthread.c/pthread_cancel.c alongside it same as tools/
# linux-build-crt-cross.sh's own thread block) and, through
# pthread_cancel.c's own deferral loop, sched_yield() (src/misc/sched.c).
#
# src/signal/linux/plat_signal.c, src/process/linux/plat_process.c and
# src/thread/linux/plat_thread.c (added to FILES above, alongside
# arch/$arch/src/sigreturn_trampoline.S) USED TO be exactly this gap:
# __signal_init() (crt1.c's own unconditional call) and exit()'s own
# __plat_sig_default_terminate() call both bottom out in plat_signal.c;
# children.c's __child_resume_stopped() bottoms out in plat_process.c;
# and pthread_cancel.c's own locking (__plat_fast_lock/_unlock(), used by
# its cancellation-state machinery) bottoms out in plat_thread.c. All
# three used to hardcode aarch64's `svc #0` raw-syscall calling
# convention with no x86_64/i386 branch at all; that is now closed for
# real (see tools/linux-build-crt-cross.sh's own updated comment for the
# fuller account of what closing it took -- real per-arch syscall
# numbers, real per-arch raw_syscall() bodies, and two real per-arch
# struct-layout fixes, not just number swaps). fuzz/linux_pilot_dlfcn_
# cross_yield.c's own former __plat_thread_alertable_yield() stand-in was
# removed for the identical reason (a real, reproduced `duplicate
# symbol` once the real plat_thread.c version was linked alongside it);
# its __mq_fd_closed()/__raise_internal() stand-ins were NOT closed at
# the same time, since plat_signal.c's own x86_64/i386 port landed
# separately and later -- see below.
#
# src/signal/signal.c itself (kill(), __sig_current_mask_copy(),
# __signal_init()), src/signal/linux/sigdelivery.c and src/signal/$arch/
# altstack.S are now added too: plat_signal.c's real x86_64/i386 port
# (proved by tools/linux-build-crt-cross.sh) closed the reason signal.c
# used to be left out (it would have collided with fuzz/linux_pilot_
# dlfcn_cross_yield.c's own __raise_internal() stub, which stood in for
# exactly this still-unported subsystem). That stub is removed from
# that file now that the real definition is linked instead.
# __mq_fd_closed() stays: mqueue.c's own much larger subsystem is still
# genuinely out of this pass's scope.

INC="-I$srcdir/src/internal -I$BUILD/obj/include -I$srcdir/include -I$srcdir/arch/$arch -I$srcdir/arch/generic"
CFLAGS="-std=c99 -nostdinc -fno-builtin -fno-stack-protector -g -O0 -ffunction-sections -fdata-sections \
$INC -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL -Wall -Wno-unused-function"

echo "$TAG: compiling the test program + curated support files (cross $CC)..."
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
# -Wl,-u,host_provided_value: forces the linker to treat this symbol as
# a GC root despite --gc-sections -- see fuzz/linux_pilot_test_dlopen_
# cross.c's own comment on host_provided_value() for why plain
# __attribute__((used)) alone (a compiler-level "don't dead-code-
# eliminate this", not a linker-level GC root) was not enough: nothing
# in the STATIC link graph itself calls it, only the dlopen()'d .so's
# own runtime relocation does, invisible to --gc-sections' own
# reachability analysis.
if ! $CC -g -O0 -nostdlib -static -no-pie -Wl,--gc-sections -Wl,-u,host_provided_value -o "$BUILD/linux_pilot_test_dlopen" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running under $qemu (real _start, real dlopen(), no host crt involved)..."
if (cd "$BUILD" && "$qemu" ./linux_pilot_test_dlopen); then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL (exit $?)" >&2
	exit 1
fi
