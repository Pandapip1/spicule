#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linux-build-dlfcn.sh -- build and run fuzz/linux_pilot_test_dlopen.c,
# a real, running proof of src/dlfcn/linux/plat_dlfcn.c (dlopen()/
# dlsym()/dlclose()/dlerror() on the Linux platform pilot: a from-
# scratch ELF64 loader, not a wrapper over an existing one -- see that
# file's own banner for the full design).
#
# Unlike most tools/linux-build-*.sh pilots (e.g. linux-build-malloc.sh,
# which deliberately links against the HOST's own crt/libc to keep the
# pilot lightweight), this one follows tools/linux-build-crt.sh's own,
# heavier discipline instead: the test PROGRAM is built and linked
# entirely on spicule's own crt/linux/crt1.c + crt/linux/aarch64/start.S
# + the real lib/libc.a (-nostdlib -static -no-pie, no host crt, no
# host libc). This is not incidental: plat_dlfcn.c's own symbol-
# resolution-against-the-static-binary mechanism reads the RUNNING
# BINARY'S OWN /proc/self/exe symtab and treats every symbol's st_value
# as an already-absolute address -- true only for a real non-PIE,
# spicule-owned image, not for a PIE binary belonging to the host's
# glibc. So this is also the first pilot that specifically needs the
# "real freestanding" build to even test the thing it is testing, not
# just to prove startup in general the way linux-build-crt.sh does.
#
# lib/libc.a itself is now built via the REAL configure/Makefile
# (unlike linux-build-crt.sh's curated FILES list, which predates most
# of this platform pilot's own build-out and is now stricter than the
# tree actually needs: `make lib/libc.a` for PLATFORM=linux/aarch64
# builds cleanly end to end, no curated file list required).
#
# The target .so (fuzz/linux_pilot_test_dlopen_lib.c) and its TLS-
# bearing sibling (fuzz/linux_pilot_test_dlopen_tlslib.c) are each
# built with the HOST's own clang/lld as ordinary aarch64 shared
# objects -- they are not spicule code, they are the thing being loaded,
# same relationship any ELF loader's test .so has to the loader test
# itself. -Wl,--hash-style=sysv guarantees a DT_HASH entry: plat_
# dlfcn.c's own banner documents that DT_GNU_HASH-only objects are not
# supported yet, and this host's default linker may otherwise emit
# GNU-hash-only output.
#
# Usage: tools/linux-build-dlfcn.sh
# Env:   SPICULE_CC (default clang)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
BUILD=${SPICULE_LINUX_DLFCN_BUILD:-$srcdir/obj/linux-dlfcn-build}
TAG=linux-build-dlfcn

cd "$srcdir"

mkdir -p "$BUILD"

echo "$TAG: configuring (platform=linux, native $CC)..."
# -mno-outline-atomics: without it, this host's clang emits calls to
# libgcc/compiler-rt's __aarch64_cas4_acq()-family outline-atomics
# helpers from malloc/pthread's atomic builtins -- unavailable in a
# -nostdlib link (found empirically: the first `make lib/libc.a` this
# script's own history landed with omitted this and failed to link
# with exactly those undefined references). Matches this task's own
# documented build invocation.
(cd "$BUILD" && "$srcdir/configure" --srcdir="$srcdir" --platform=linux CC="$CC" \
	CFLAGS="-fno-stack-protector -mno-outline-atomics" >/dev/null)

cfg_arch=$(sed -n 's/^ARCH *= *//p' "$BUILD/config.mak" | head -1)
if [ "$cfg_arch" != "aarch64" ]; then
	echo "$TAG: this build host configured ARCH=$cfg_arch, but crt/linux/aarch64/start.S is the only arch implemented so far -- see crt/linux/crt1.c's own banner." >&2
	exit 1
fi

echo "$TAG: building the real lib/libc.a + lib/crt1.o + lib/start.o..."
"${MAKE:-make}" -C "$BUILD" -f "$srcdir/Makefile" srcdir="$srcdir" \
	lib/libc.a lib/crt1.o lib/start.o >/dev/null

echo "$TAG: building the target .so's (host $CC, real aarch64 shared objects)..."
if ! $CC -shared -fPIC -nostdlib -Wl,--hash-style=sysv \
	-Wl,-soname,linux_pilot_test_dlopen_lib.so \
	-o "$BUILD/linux_pilot_test_dlopen_lib.so" \
	fuzz/linux_pilot_test_dlopen_lib.c; then
	echo "$TAG: FAILED building the target .so" >&2
	exit 1
fi
if ! $CC -shared -fPIC -nostdlib -Wl,--hash-style=sysv \
	-Wl,-soname,linux_pilot_test_dlopen_tlslib.so \
	-o "$BUILD/linux_pilot_test_dlopen_tlslib.so" \
	fuzz/linux_pilot_test_dlopen_tlslib.c; then
	echo "$TAG: FAILED building the TLS-bearing target .so" >&2
	exit 1
fi

INC="-I$srcdir/src/internal -I$BUILD/obj/include -I$srcdir/include -I$srcdir/arch/aarch64 -I$srcdir/arch/generic"
# -fno-stack-protector: see tools/linux-build-crt.sh's own comment.
CFLAGS="-std=c99 -nostdinc -fno-builtin -fno-stack-protector -g -O0 \
$INC -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -Wall -Wno-unused-function"

echo "$TAG: compiling the test program ($CC, native ELF, spicule's own headers)..."
# CFLAGS is deliberately a shell word list here: this script is POSIX sh,
# and each flag must reach the compiler as a separate argument.
# shellcheck disable=SC2086
if ! $CC $CFLAGS -c -o "$BUILD/linux_pilot_test_dlopen.o" fuzz/linux_pilot_test_dlopen.c; then
	echo "$TAG: FAILED compiling the test program" >&2
	exit 1
fi

echo "$TAG: linking (-nostdlib -static -no-pie -- no host crt, no host libc)..."
if ! $CC -g -O0 -nostdlib -static -no-pie -o "$BUILD/linux_pilot_test_dlopen" \
	"$BUILD/lib/crt1.o" "$BUILD/lib/start.o" \
	"$BUILD/linux_pilot_test_dlopen.o" "$BUILD/lib/libc.a"; then
	echo "$TAG: FAILED linking" >&2
	exit 1
fi

echo "$TAG: running (real _start, real dlopen(), no host crt involved)..."
if (cd "$BUILD" && ./linux_pilot_test_dlopen); then
	echo "$TAG: PASS"
	exit 0
else
	echo "$TAG: FAIL (exit $?)" >&2
	exit 1
fi
