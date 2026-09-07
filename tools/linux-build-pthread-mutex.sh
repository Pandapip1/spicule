#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-pthread-mutex.sh -- build and run the pthread_mutex_t
# front-door pilot natively. See tools/linux-build-open.sh for the
# pattern this mirrors.
#
# Proves __plat_fast_lock()/__plat_fast_unlock() (src/internal/
# plat_thread.h) against the REAL src/thread/pthread_mutex.c front
# door (pthread_mutex_init/_lock/_trylock/_timedlock/_unlock/_destroy),
# statically linked into one native, runnable ELF binary -- no Wine,
# no emulation, on whatever host this script runs on.
#
# Usage: tools/linux-build-pthread-mutex.sh
# Env:   SPICULE_CC (default clang), SPICULE_ARCH (default x86_64 -- see
#          tools/linux-build.sh's own banner for why this is unrelated
#          to the host's real CPU architecture)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
ARCH=${SPICULE_ARCH:-x86_64}
OBJ=${SPICULE_LINUX_OBJ:-$srcdir/obj/linux-pilot-pthread-mutex}
TAG=linux-build-pthread-mutex

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

INC="-Isrc/internal -Isrc/thread -Iobj/include -Iinclude -Iarch/$ARCH -Iarch/generic"
CFLAGS="-std=c99 -nostdinc -fno-builtin -g -O0 -ffunction-sections -fdata-sections \
$INC -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL -Wall -Wno-unused-function"

FILES="
	src/thread/pthread_mutex.c
	src/thread/pthread.c
	src/thread/pthread_cancel.c
	src/thread/linux/plat_thread.c
	src/thread/linux/aarch64/clone.S
	src/internal/linux/tls_setup.c
	src/unistd/getpid.c
	src/unistd/linux/plat_unistd.c
	src/unistd/linux/plat_fd.c
	src/internal/fd.c
	src/internal/linux/plat_fd_init.c
	src/time/clock_gettime.c
	src/time/linux/plat_time.c
	src/internal/errno.c
	fuzz/linux_pilot_harness_pthread_mutex.c
	fuzz/linux_pilot_test_pthread_mutex.c
"
# src/thread/pthread_cancel.c: pthread.c's pthread_join() calls
# __pthread_testcancel() (a real cancellation-point check, not previously
# there), defined only in this file. Linking the whole object pulls in
# every symbol it references, same as pthread.c's own functions already
# did (see fuzz/linux_pilot_harness_pthread_mutex.c's own comment) --
# redirect_async_cancel()'s arch/$(ARCH)/src/cancel_trampoline.S
# dependency is stubbed there rather than added here, since it is real
# assembly this pilot never actually reaches (pthread_cancel() itself is
# never called).
#
# src/internal/fd.c + src/internal/linux/plat_fd_init.c were missing:
# src/unistd/linux/plat_unistd.c's syncfs() calls the real __fd_get(),
# a real, previously-hidden gap CI never reached (tools/
# linux-build-crt.sh and tools/linux-build-fs.sh both failed to link
# first, until this session fixed them). Traced by reading
# plat_unistd.c's real call; unlike tools/linux-build-fs.sh/-open.sh/
# -misc.sh's own __free gap, nothing reachable here ever calls
# __fd_install_at() (only __fd_get(), a read-only accessor), so
# --gc-sections drops __fd_release_dynamic()'s own __free() call before
# the link needs it -- confirmed by linking clean with no allocator
# files added at all.
#
# fuzz/linux_pilot_harness_pthread_mutex.c's own calloc() stub also
# needed a real, independent fix: it declared `unsigned long`
# nmemb/size parameters, but this tree's size_t (obj/include/bits/
# alltypes.h's _Addr) is `long long` on both aarch64 and x86_64 --
# distinct types at this width, so clang rejected it as a conflicting
# redeclaration against <stdlib.h>'s real `size_t` prototype pulled in
# transitively. Never caught before for the identical reason as every
# other gap on this page: nothing has actually compiled this file since
# it was written. Fixed by matching calloc()'s real declared signature
# (size_t, not unsigned long).

echo "$TAG: compiling ($CC, native ELF)..."
objs=""
for f in $FILES; do
	base=$(basename "$f")
	o="$OBJ/${base%.*}.o"
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -c -o "$o" "$f"; then
		echo "$TAG: FAILED compiling $f" >&2
		exit 1
	fi
	objs="$objs $o"
done

echo "$TAG: linking..."
# shellcheck disable=SC2086
if ! $CC -g -O0 -Wl,--gc-sections -o "$OBJ/linux_pilot_test_pthread_mutex" $objs; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running..."
if "$OBJ/linux_pilot_test_pthread_mutex"; then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL" >&2
	exit 1
fi
