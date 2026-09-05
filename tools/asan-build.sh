#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build ntlibc natively (Linux/ELF) under AddressSanitizer + UBSan and run
# whichever of test/*.c can be built that way.  See CONTRIBUTING.md.
#
# The library targets NT, so a native build cannot be complete: anything
# that ends up calling into ntdll needs a stub.  fuzz/ntstubs.c provides
# those.  Which src/*.c take part is decided *mechanically* -- every file
# is compiled, and the ones the compiler accepts are kept -- rather than
# from a hand-maintained list that would rot.  The pure-C floating-point
# runtime helper under arch/$ARCH is included too: it is directly testable
# and is exactly where compiler-generated integer conversions land.  Likewise
# for the tests: a test is run if and only if it links.
#
# Usage: tools/asan-build.sh [--quiet | --objects-only]
#   --objects-only  build the instrumented library objects and stop; used
#                   by fuzz/Makefile so the fuzzers and this script share
#                   one mechanically derived file list.
# Env:   NTLIBC_SAN_MODE (default asan; `ubsan` drops AddressSanitizer --
#          see the long comment above the SAN_MODE case below for when
#          that is the only mode that runs, and for what it stops
#          catching when it is),
#        NTLIBC_CC (default clang), NTLIBC_ASAN_OBJ (default obj/asan),
#        NTLIBC_ASAN_EXTRA (extra CFLAGS, e.g. -fsanitize=fuzzer-no-link),
#        NTLIBC_LEAKS (default 1; set 0 to switch LeakSanitizer off)
#        NTLIBC_ASAN_CONVERSION=1 (see CONVSAN below)
#        NTLIBC_CFI=1 (add cfi-icall and LTO; `make cfi` sets it)
#        ASAN_JOBS (default: nproc) -- how many src/*.c compiles and how
#          many test links to run at once.  The test *runs* are always
#          serial; see the comment above the link phase for why that is
#          a correctness constraint and not a tuning decision.  Output is
#          byte-identical at any value.

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${NTLIBC_CC:-clang}
OBJ=${NTLIBC_ASAN_OBJ:-$srcdir/obj/asan}
ARCH=${NTLIBC_ARCH:-x86_64}

# The tag every diagnostic below carries, computed here -- before the
# ARCH/config-mismatch check just below, which is the first thing that
# uses it -- rather than down by NTLIBC_SAN_MODE's own case statement,
# which runs far later.  Mirrors that later logic (SAN_MODE's default and
# NTLIBC_CFI's override) against the raw env vars, since $SAN_MODE itself
# does not exist yet.  Under `set -u` an unset $TAG here is not a style
# nit, it is a crash: the very first diagnostic this script can print
# (the ARCH mismatch below) referenced $TAG before anything set it.
TAG=${NTLIBC_SAN_MODE:-asan}
[ "${NTLIBC_CFI:-0}" = 1 ] && TAG=cfi

# This build compiles src/*.c *natively* (64-bit ELF) but includes
# obj/include/bits/alltypes.h, which `make` generates from
# arch/$(ARCH)/bits/alltypes.h.in and which therefore follows whatever
# arch configure was last run for.  Configure for i386, run `make asan`,
# and a 64-bit build silently picks up 32-bit size_t/ssize_t/intptr_t:
# snprintf("%zd", (ssize_t)-5) prints 4294967291, SIZE_MAX != (size_t)-1,
# and stdio/fcntl fault outright.  Those look exactly like library bugs
# and were reported as such, repeatedly, before anyone noticed the build
# was simply mismatched.
#
# Refuse instead of producing that.  config.mak is the record of what the
# tree is configured for; if it disagrees with the arch this script is
# building for, stop and say how to fix it.
if [ -f "$srcdir/config.mak" ]; then
	cfg_arch=$(sed -n 's/^ARCH *= *//p' "$srcdir/config.mak" | head -1)
	if [ -n "$cfg_arch" ] && [ "$cfg_arch" != "$ARCH" ]; then
		echo "$TAG: tree is configured for ARCH=$cfg_arch but this build is $ARCH." >&2
		echo "$TAG: obj/include/bits/alltypes.h would give a $cfg_arch-width" >&2
		echo "$TAG: size_t/ssize_t to a native $ARCH build -- wrong, and it" >&2
		echo "$TAG: fails in ways that look like library bugs." >&2
		echo "$TAG: reconfigure first (./configure --host=$ARCH-win32 CC=$ARCH-win32-tcc)," >&2
		echo "$TAG: or set NTLIBC_ARCH=$cfg_arch if you really meant that." >&2
		exit 2
	fi
fi
mode=${1:-}
EXTRA=${NTLIBC_ASAN_EXTRA:-}

# LeakSanitizer is on, and that is the point.  ntlibc's malloc is
# RtlAllocateHeap, which fuzz/ntstubs.c answers with ASan's own allocator,
# so LSan sees every ntlibc allocation with a full ntlibc stack -- there is
# nothing here it cannot account for and no suppression file is needed.
# Leaving it off costs real bugs: sscanf leaking a BUFSIZ block per call
# went unnoticed through a green `make check` until LSan caught it in one
# run.  Set NTLIBC_LEAKS=0 only to isolate some other failure.
LEAKS=${NTLIBC_LEAKS:-1}

# See the long comment in tools/fuzz.sh: with $DEBUGINFOD_URLS set (Ubuntu
# exports it from /etc/profile.d/debuginfod.sh, so every login shell has
# it), llvm-symbolizer makes a doomed HTTPS request for each module's
# build-id before it reads the DWARF already inside the binary, and ASan's
# blocking read() on the symbolizer pipe stalls with it.  Cleared here so a
# failing test still prints a symbolized trace instead of being killed by
# the timeout below with nothing to show.
export DEBUGINFOD_URLS=

# -shared-libasan is not cosmetic either: with the static runtime, ASan's
# own calls to sysconf()/malloc() bind at link time to ntlibc's versions,
# and ASan starts up on an NT libc that is not initialised yet.  In the
# shared runtime they go through libc.so like any other library's.
#
# NTLIBC_SAN_MODE PICKS WHICH SANITIZER THIS BUILD CARRIES, and there are
# exactly two because there are exactly two environments to build for.
#
#   asan  (the default, and the only one whose findings count)
#         ASan + UBSan, as everything below assumes.
#
#   ubsan UBSan alone.  Not a preference and not a faster variant: it is
#         the only mode that starts at all on a host with
#         vm.overcommit_memory=2.
#
#         The mechanism, because it will otherwise be mistaken for a
#         broken toolchain and "fixed" by deleting this mode: ASan
#         reserves its ~15 TB shadow with mmap(PROT_READ|PROT_WRITE,
#         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_NORESERVE).  Linux's
#         do_mmap() honours MAP_NORESERVE only when
#         sysctl_overcommit_memory != OVERCOMMIT_NEVER; under strict
#         overcommit (2) the flag is dropped, the 15 TB is charged
#         against CommitLimit, and the mapping is refused with ENOMEM.
#         Every ASan-linked binary then dies before main() with
#         "AddressSanitizer failed to allocate 0xdfff0001000 bytes".
#         That is a property of the host's sysctl, not of this tree: no
#         build flag, rlimit or ASAN_OPTIONS setting avoids it, because
#         the shadow is not optional.
#
#         WHAT THIS MODE DOES NOT CATCH, which is most of why `asan` is
#         the default: UBSan has no shadow memory and therefore no heap
#         instrumentation.  No heap-buffer-overflow, no use-after-free,
#         no double-free, no LeakSanitizer -- $LEAKS below is inert
#         here.  What survives is the whole -fsanitize=undefined group
#         plus $CONVSAN/$INTSAN: signed overflow, shifts, alignment,
#         bad enum/bool values, integer truncation.  A memory-safety
#         claim CANNOT be based on a run in this mode.  CI's runners
#         have default overcommit and run the `asan` mode; they are the
#         only authority for memory-safety findings, and a clean ubsan
#         run is not evidence that an ASan run would have been clean.
#
#         A harness or test that wants out-of-bounds detection here has
#         to bring its own: fuzz/fuzz_pathname.c writes an eight-byte
#         0xAB guard past the string it hands to basename()/dirname()
#         and checks it afterwards, precisely so it means something in
#         this mode.
#
# -shared-libsan for the same reason -shared-libasan is used above, and
# it is not optional either: with the static UBSan runtime, its start-up
# call to sysconf(_SC_SIGSTKSZ) binds at link time to *ntlibc's*
# sysconf, which answers 0, and the runtime dies in
# SetAlternateSignalStack with "failed to allocate 0x0 bytes (error
# code: 22)" before the program starts.  Measured, not anticipated.
SAN_MODE=${NTLIBC_SAN_MODE:-asan}
case $SAN_MODE in
asan)
	SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -shared-libasan"
	SAN_RT=libclang_rt.asan-x86_64.so
	;;
ubsan)
	SAN="-fsanitize=undefined -fno-sanitize-recover=undefined -shared-libsan"
	SAN_RT=libclang_rt.ubsan_standalone-x86_64.so
	;;
*)
	echo "asan-build: NTLIBC_SAN_MODE must be asan or ubsan, not $SAN_MODE" >&2
	exit 2
	;;
esac

# -fno-wrapv reasserts this script's own precondition for the
# signed-integer-overflow check in $SAN's -fsanitize=undefined group: that
# signed overflow is undefined behaviour, which is what the sanitizer is
# there to catch.  A plain clang already treats it that way with no flag
# needed (C11 6.5p5), so this is a no-op there -- but nixpkgs' clang
# cc-wrapper injects -fwrapv by default (its standard `strictoverflow`
# hardening flag, part of $NIX_HARDENING_ENABLE), which makes signed
# overflow well-defined and silently compiles signed-integer-overflow
# checking to nothing, with no build failure to reveal it.  Measured: see
# the `asan` job's comment in .github/workflows/ci.yml for the `INT_MAX +
# 1` reproduction that found this.  Applied to both SAN_MODE cases, since
# -fwrapv would defeat the same UBSan check whether or not ASan is also
# linked, and unconditionally rather than only under Nix, so this script's
# own behaviour does not depend on which clang wrapper happens to be on
# PATH.
SAN="$SAN -fno-wrapv"

# cfi-icall needs whole-program type information, hence LTO.  Keep it out
# of the normal ASan loop because every test link then repeats LTO codegen.
# It is an ASan-mode extension, not a meaningful addition to the reduced
# UBSan-only fallback used on strict-overcommit hosts.
LTOFLAGS=
if [ "${NTLIBC_CFI:-0}" = 1 ]; then
	if [ "$SAN_MODE" != asan ]; then
		echo "asan-build: NTLIBC_CFI=1 requires NTLIBC_SAN_MODE=asan" >&2
		exit 2
	fi
	SAN="$SAN -fsanitize=cfi-icall"
	LTOFLAGS="-flto -fno-sanitize-trap=cfi-icall"
fi
# TAG was already computed, near ARCH above, from the same two env vars
# this recomputes it from ($NTLIBC_SAN_MODE / $NTLIBC_CFI) -- it has to be
# usable that early for the ARCH/config-mismatch check, well before
# $SAN_MODE exists. Recorded here as a no-op reassignment, not deleted
# outright, so a log still says which mode produced it right next to the
# case statement that decided it, and so nobody "cleans up" the earlier
# one thinking it is dead code.
TAG=$SAN_MODE
[ "${NTLIBC_CFI:-0}" = 1 ] && TAG=cfi
RTDIR=$($CC -print-file-name=$SAN_RT)
RTDIR=$(dirname "$RTDIR")
LINKFLAGS="-Wl,-rpath,$RTDIR"

# -fsanitize=implicit-conversion is NOT part of the -fsanitize=undefined
# group; it is a separate group of three checks, and they have very
# different signal in this codebase.  Measured over the native test run
# plus a 4x90s libFuzzer run of fuzz/ (~6.5M execs per harness).  That
# measurement was taken when fuzz/ held four harnesses; it now holds
# eight (path, printf, scanf, strftime, strptime, strtod, strtol, utf).
# The four added since have NOT been measured for implicit-conversion
# findings, so the counts below describe the four that were -- they are
# not a claim about the current set:
#
#   implicit-{un,}signed-integer-truncation
#       0 findings.  A libc narrows constantly -- `unsigned char` in the
#       ctype and string code, int->char in the digit paths -- but UBSan
#       reports only when the value actually *changes*, and none of those
#       ever do.  So it costs nothing today and it is the class that would
#       catch a real narrowing bug: on by default, and made fatal below so
#       one fails the run rather than scrolling past.
#
#   implicit-integer-sign-change
#       6 sites, every one a deliberate idiom and none a bug: memmove.c's
#       `-2*n` overlap test, the `unsigned u = i` in ffs/ffsl/ffsll,
#       time_impl.h's `mp + (mp < 10 ? 3 : -9)` month wrap, and open.c's
#       `~FILE_WRITE_DATA` mask.  Off by default and report-only when on,
#       the way tools/lint.sh treats LINT_CONVERSION: worth a periodic
#       read, not worth a gate.  NTLIBC_ASAN_CONVERSION=1 enables it.
#
# Neither catches an *explicit* cast -- `(USHORT)v` is silent under all
# three -- so this is not a substitute for reading narrowing casts.
#
# CONVSAN applies to the library only, never to test/*.c or ntstubs.c:
# a narrowing in test code is not a finding about ntlibc.
CONVSAN="-fsanitize=implicit-signed-integer-truncation,implicit-unsigned-integer-truncation \
 -fno-sanitize-recover=implicit-signed-integer-truncation,implicit-unsigned-integer-truncation"
if [ "${NTLIBC_ASAN_CONVERSION:-0}" = 1 ]; then
	CONVSAN="$CONVSAN -fsanitize=implicit-integer-sign-change"
fi

INC="-I$srcdir/src/internal -I$srcdir/obj/include -I$srcdir/include \
     -I$srcdir/arch/$ARCH -I$srcdir/arch/generic"
# -fvisibility=hidden matters: without it ntlibc's own malloc() lands in
# the executable's dynamic symbol table and preempts glibc's, so ld.so and
# ASan's own start-up allocate through RtlAllocateHeap before the shim's
# constructor has run.  Hidden keeps ntlibc's definitions for ntlibc (and
# the tests, which are in the same module) and out of everyone else's way.
# -fsanitize=unsigned-integer-overflow,unsigned-shift-base (the "integer"
# group's checks beyond -fsanitize=undefined) are not undefined behaviour
# -- unsigned wraparound is modular arithmetic, C99 6.2.5p9 -- so the
# point of enabling them is not finding UB but forcing every deliberate
# wraparound in the library to say so via __wraps (include/features.h),
# leaving an unmarked one visible as a real finding.  Fatal, like the
# truncation checks above, and library-only: never test/*.c or ntstubs.c.
INTSAN="-fsanitize=unsigned-integer-overflow,unsigned-shift-base \
 -fno-sanitize-recover=unsigned-integer-overflow,unsigned-shift-base"

# NTLIBC_USE_KERNEL32 is deliberately never defined here, unlike the real
# tcc/config.mak build (see the Makefile's CFLAGS_ALL). This build has no
# real kernel32 -- ntstubs.c stands in for ntdll, not for kernel32 on top
# of it -- and crt1.c calls __signal_init() unconditionally, so turning
# the define on would require this file to answer LdrLoadDll() (loading
# "kernel32.dll") and LdrGetProcedureAddress() (resolving
# "SetConsoleCtrlHandler" specifically) for *every* test and fuzz binary,
# not just ones that care about it -- crt1.c is linked into all of them.
# That part is a bounded, ~30-line addition (a fake module handle from
# LdrLoadDll, a name comparison and a stub SetConsoleCtrlHandler from
# LdrGetProcedureAddress) and would be worth doing the day something
# here actually needs to drive src/signal/signal.c's ctrl_handler().
# Nothing does yet: none of fuzz/fuzz_*.c touch signal handling, and even
# with the stubs in place there would be no way to *invoke*
# ctrl_handler() from here -- a native Linux process cannot receive a
# real console control event, and libFuzzer's byte-stream inputs have no
# natural mapping onto one either. So the stubs would only buy coverage
# of install_ctrl_handler()'s two Ldr* calls succeeding, not of the
# handler logic they install, which is the actual point of the guarded
# code. That handler logic already gets run for real -- against genuine
# kernel32.dll, under Wine and on real Windows -- by `make check` and CI's
# windows-test job on an --enable-kernel32 build (see
# .github/workflows/ci.yml); that is the right place for it, not a
# simulation here.
# -D_NTLIBC_NATIVE_BUILD says out loud what four files under src/ need to
# know: that this is the native (ELF) compile-and-link, not a build for
# NT.  src/internal/{rpath,pe,delayload}.c and src/dlfcn/nt/plat_dlfcn.c
# (the guard used to live directly in src/dlfcn/dlfcn.c, before that file
# was split into a thin platform-agnostic front door plus this NT
# backend -- see src/internal/plat_dlfcn.h's own banner) call Ldr* entry
# points that fuzz/ntstubs.c does not answer, and #error themselves out
# of this build so their objects never reach a link that would then fail
# for every *other* test too.  They used to infer it from AddressSanitizer
# being active; see the long comment in src/internal/rpath.c for why that
# proxy had to go.
#
# -U__linux__ is not cosmetic either, and belongs on the same line as
# _NTLIBC_NATIVE_BUILD above because it exists to make that macro's own
# promise true. This build compiles real 64-bit ELF object code on a real
# Linux host, so clang's *driver* cannot help predefining __linux__ for
# its own default target triple (`clang -dM -E -x c /dev/null` shows it,
# with no source-level -D anywhere) -- but this build's whole model, laid
# out in the big comment at the top of this file and in the `linux)` case
# of the file-selection loop below, is "cover the NT backend, answered by
# fuzz/ntstubs.c in-process": every src/*/linux/* source is unconditionally
# excluded, on purpose, well before this point. src/internal/nt.h's own
# NT_LAYOUT_SIZE/NT_LAYOUT_OFFSET section states the invariant this line
# restores in so many words: "__linux__ is never defined for any of
# [i386-win32/x86_64-win32/native-ASan builds]" -- a promise that line was
# relying on, not one this build was actually keeping, until now.
#
# Left unfixed, shared (non-nt/non-linux-directory) source compiled here
# sees __linux__ true and takes the real-Linux-backend branch of its own
# `#if defined(__linux__)` -- calling into a src/*/linux/*.c symbol this
# build's own file-selection loop just excluded. That is not
# hypothetical: src/ioctl/ioctl.c's TIOCGWINSZ case calls
# __plat_tiocgwinsz() (only defined in the excluded
# src/ioctl/linux/plat_ioctl.c) this way, src/termios/termios.c's entire
# body is `#ifndef __linux__`-gated and compiles to zero symbols this way
# (silently resolving tcgetattr()/tcsetattr() to the *host's* real libc at
# link time instead, since this build's final link is not -nostdlib --
# the same hazard class fuzz/fuzz_sort.c's STATRENAME/__real_stat()
# already documents for stat()), and src/process/exec.c calls
# __plat_process_exec() (only defined in the excluded
# src/process/linux/plat_process.c) the same way -- three independent
# undefined-reference sites from one wrong preprocessor bit, not three
# unrelated bugs. Undefining it here, in the one compiler invocation that
# actually has the wrong state, fixes all of them (and every future one
# of the same shape) at the root instead of patching each call site with
# its own `&& !defined(_NTLIBC_NATIVE_BUILD)`, and touches nothing else:
# the real NT build (`$(CC) ... $(CFLAGS_ALL)` in the top-level Makefile)
# never defines __linux__ in the first place, and the real PLATFORM=linux
# build needs and still gets the true predefine, since that build's own
# CFLAGS_ALL (Makefile) is entirely separate from this script's and is
# not touched here.
CFLAGS="$SAN $CONVSAN $INTSAN $LTOFLAGS -g -O1 -std=c99 -nostdinc -fno-builtin -fvisibility=hidden -U__linux__ \
        -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_NTLIBC_INTERNAL -D_NTLIBC_NATIVE_BUILD $INC $EXTRA"

if [ ! -f "$srcdir/obj/include/bits/alltypes.h" ]; then
	echo "$TAG: obj/include/bits/alltypes.h missing -- run 'make' first" >&2
	exit 1
fi

# CAN ASAN ACTUALLY START HERE?  Asked before compiling 297 files that
# would then be unable to run, and asked in one place -- see
# tools/asan-available.sh, which carries the mechanism, the reasoning for
# `unavailable` rather than `error`, and the exit-77 convention.  It is
# the same script fuzz/Makefile's run and coverage targets call, so the
# two cannot drift into disagreeing about whether this host can run ASan.
#
# Not asked in ubsan mode, which has no shadow to reserve and starts
# anywhere; and not asked for --objects-only, which builds objects for
# somebody else to link and never runs anything -- gating it would break
# `make -C fuzz` on a host where the harnesses are perfectly buildable.
if [ "$SAN_MODE" = asan ] && [ "$mode" != "--objects-only" ]; then
	"$srcdir/tools/asan-available.sh" || exit $?
fi

# Two concurrent runs share $OBJ and clobber each other: the `rm -rf`
# below deletes objects the other run is still compiling into and linking
# against.  The build then fails in ways that look nothing like the real
# cause and everything like a bug elsewhere in the library -- a SEGV
# inside memcpy, or a test that appears to have been broken all along.
# That misdiagnosis is expensive and has happened more than once, so this
# is enforced rather than documented.  mkdir is atomic, so it is both the
# check and the lock; a run killed with SIGKILL leaves the directory
# behind, which is what the second message below is for.
if ! mkdir "$OBJ.lock" 2>/dev/null; then
	echo "$TAG: another build is using $OBJ ($OBJ.lock exists)." >&2
	echo "$TAG: wait for it, or remove the lock if no build is running." >&2
	exit 1
fi
trap 'rmdir "$OBJ.lock" 2>/dev/null || :' EXIT INT TERM

rm -rf "$OBJ"
mkdir -p "$OBJ/obj" "$OBJ/test"

# ---- 1. which src/*.c compile natively? ------------------------------------
#
# Excluded by hand, with a reason each:
#   src/*/<other-arch>/*  -- wrong architecture, not an NT dependency
#   src/*/linux/*         -- this native harness exercises the NT backend
#                           through fuzz/ntstubs.c
#   src/dlfcn/dlfcn.c     -- the native harness's allocator bootstrap uses
#                           the host dlopen/dlsym; linking ntlibc's front
#                           door would intercept those calls recursively
#   src/signal/nt/sigdelivery.c -- ntstubs supplies the native harness's
#                                  deliberately non-delivering stand-ins
#   src/internal/$ARCH/teb.c -- reads gs:0x30; ntstubs.c supplies __teb()

: > "$OBJ/compiled.txt"
: > "$OBJ/skipped.txt"
: > "$OBJ/partial.txt"

# How many compiles and links to run at once.  These are 282 independent
# clang invocations followed by 54 independent links; each reads the
# source tree and writes only files named after its own input, so this
# parallelises with no change to what is built.  ASAN_JOBS=1 restores
# the fully serial behaviour, and is the safe fallback when neither
# nproc nor getconf exists.
: "${ASAN_JOBS:=}"
if [ -z "$ASAN_JOBS" ]; then
	ASAN_JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

# Phase 1a, serial and process-free: decide what happens to each source.
# The worklist line is "index<TAB>file<TAB>mode<TAB>reason", where mode
# is `skip`, `full` or `ubsan`.
#
# The index is what keeps this reproducible.  Nothing below appends to
# compiled.txt/skipped.txt/partial.txt from a worker, and NOTHING appends
# to them from this pass either: every line of all three manifests is
# written by the serial merge in phase 1c, in source order, exactly as
# the single serial loop this replaces wrote them.  Concurrent appends to
# a shared file are not guaranteed atomic once a write exceeds a pipe
# buffer, and even when they are, the *order* would depend on scheduling
# -- so the manifests this script's own report points a reader at would
# differ run to run on an unchanged tree.  Deciding early and emitting
# late costs one extra field in the worklist and buys byte-identical
# output.
cwork="$OBJ/compile-worklist"
: > "$cwork"
cidx=0
for f in $(cd "$srcdir" && { find src -name '*.c';
	[ ! -f "arch/$ARCH/src/fpconv.c" ] || echo "arch/$ARCH/src/fpconv.c";
} | sort); do
	cidx=$((cidx + 1))
	# A third path component can name either an architecture or a platform.
	# Keep our architecture and the NT backend exercised by ntstubs; skip
	# other architectures and the real-Linux backend.  Treating every such
	# directory as an architecture used to skip both nt/ and linux/, leaving
	# every __plat_* reference unresolved after the platform split.
	sub=$(echo "$f" | awk -F/ '$1 == "src" && NF == 4 { print $3 }')
	case $sub in
	i386|x86_64|aarch64)
		if [ "$sub" != "$ARCH" ]; then
			printf '%06d\t%s\tskip\t(other architecture)\n' "$cidx" "$f" >> "$cwork"
			continue
		fi ;;
	linux)
		printf '%06d\t%s\tskip\t(other platform; native harness exercises NT through ntstubs.c)\n' \
			"$cidx" "$f" >> "$cwork"
		continue ;;
	esac
	case $f in
	src/dlfcn/dlfcn.c)
		printf '%06d\t%s\tskip\t(host dlopen/dlsym are required by the native allocator bootstrap)\n' \
			"$cidx" "$f" >> "$cwork"
		continue ;;
	*/teb.c)
		printf '%06d\t%s\tskip\t(reads gs:0x30; __teb() comes from ntstubs.c)\n' \
			"$cidx" "$f" >> "$cwork"
		continue ;;
	src/signal/nt/sigdelivery.c)
		printf '%06d\t%s\tskip\t(native signal-delivery stand-ins come from ntstubs.c)\n' \
			"$cidx" "$f" >> "$cwork"
		continue ;;
	esac
	# A few files use the musl aligned-word scan: align to sizeof(size_t),
	# then read whole words.  Such a read can go past the end of the string
	# object but never past the end of its page, so it is safe in fact --
	# ASan tracks objects, not pages, and reports every call.  Build those
	# with UBSan only, and say so, rather than drown the run in noise.
	case $f in
	src/string/strlen.c)
		printf '%06d\t%s\tubsan\t(built UBSan-only: aligned word-at-a-time scan)\n' \
			"$cidx" "$f" >> "$cwork" ;;
	*)
		printf '%06d\t%s\tfull\t-\n' "$cidx" "$f" >> "$cwork" ;;
	esac
done

# Phase 1b, parallel.  compile_one INDEX FILE MODE always writes
# $cpar/INDEX.rc -- `ok` or `fail` -- including on success, because the
# merge below counts those files.  A worker that dies without reporting
# is then a hard failure rather than a source file that quietly stops
# being compiled: dropping objects here would shrink the library the
# tests link against, which is precisely how `make asan` once reported
# success having verified nothing.
UBSAN_ONLY_CFLAGS=$(echo "$CFLAGS" | sed 's/-fsanitize=address,undefined/-fsanitize=undefined/')
cpar="$OBJ/cpar"
mkdir -p "$cpar" || exit 1
compile_one() {
	c_idx=$1 c_f=$2 c_mode=$3
	case $c_mode in
	ubsan) c_flags=$UBSAN_ONLY_CFLAGS ;;
	*)     c_flags=$CFLAGS ;;
	esac
	c_o="$OBJ/obj/$(echo "$c_f" | tr / _).o"
	# $c_flags is a flag list and must word-split.
	# shellcheck disable=SC2086
	if $CC -c $c_flags -w "$srcdir/$c_f" -o "$c_o" 2> "$c_o.err"; then
		echo ok > "$cpar/$c_idx.rc"
	else
		rm -f "$c_o"
		echo fail > "$cpar/$c_idx.rc"
	fi
}

cshard=0
while [ "$cshard" -lt "$ASAN_JOBS" ]; do
	(
		awk -v n="$ASAN_JOBS" -v k="$cshard" 'NR % n == k' "$cwork" \
		| while IFS="$(printf '\t')" read -r idx f cmode creason; do
			[ -z "$idx" ] && continue
			[ "$cmode" = skip ] && continue
			compile_one "$idx" "$f" "$cmode"
		done
		# Explicit, because the alternative is worse than it looks.
		# A shard whose last loop iteration ends on a `[ ... ] &&
		# continue` that evaluates false exits 1 -- for no reason but
		# which files happened to land in which shard.  Measured, in
		# this shell: `wait` with no operands then returns 0 ANYWAY,
		# even for `( exit 3 ) &`, and even under `set -e`.  So the
		# failure would not have aborted the run; it would have been
		# swallowed.  That cuts both ways and the second way is the one
		# that matters: A REWRITE THAT JUDGED ITS WORKERS BY `wait`
		# WOULD REPORT SUCCESS NO MATTER WHAT THEY DID.  This design
		# never asks.  A worker succeeded if and only if it wrote its
		# result file, and the merge below counts those.  `exit 0` says
		# that the shard's own status is deliberately meaningless rather
		# than accidentally so.
		exit 0
	) &
	cshard=$((cshard + 1))
done
wait

# Phase 1c, serial merge in source order.  This is where all three
# manifests are written, so their contents and their order are what the
# serial loop produced, whatever ASAN_JOBS was.
cmissing=0
while IFS="$(printf '\t')" read -r idx f cmode creason; do
	[ -z "$idx" ] && continue
	if [ "$cmode" = skip ]; then
		echo "$f  $creason" >> "$OBJ/skipped.txt"
		continue
	fi
	[ "$cmode" = ubsan ] && echo "$f  $creason" >> "$OBJ/partial.txt"
	o="$OBJ/obj/$(echo "$f" | tr / _).o"
	if [ ! -f "$cpar/$idx.rc" ]; then
		cmissing=$((cmissing + 1))
		echo "$f  (NO RESULT: the compile worker for this file never reported)" >> "$OBJ/skipped.txt"
		rm -f "$o"
		continue
	fi
	if [ "$(cat "$cpar/$idx.rc")" = ok ]; then
		echo "$f" >> "$OBJ/compiled.txt"
	else
		echo "$f  (see $o.err)" >> "$OBJ/skipped.txt"
	fi
done < "$cwork"
if [ "$cmissing" -ne 0 ]; then
	echo "$TAG: FAILED -- $cmissing compile worker(s) never reported a result, so those" >&2
	echo "$TAG: source files were never built.  A parallel phase that loses work must fail," >&2
	echo "$TAG: not link a smaller library and call the run a pass." >&2
	exit 1
fi

# ntstubs.c is test-support code, not part of the library, so it does not
# get the intentional-wraparound scrutiny below: build it without INTSAN.
stubcflags="$(echo "$CFLAGS" | sed "s!$INTSAN!!")"
# shellcheck disable=SC2086
$CC -c $stubcflags -w "$srcdir/fuzz/ntstubs.c" -o "$OBJ/ntstubs.o"
SHIMOBJS="$OBJ/ntstubs.o"
if [ "$SAN_MODE" = ubsan ]; then
	# The UBSan-only runtime has no ASan allocator entry points.  Use the
	# existing host-libc forwarding shim that fuzz/Makefile uses in the
	# same mode; it is deliberately compiled against host headers.
	$CC -c -g -O1 "$srcdir/fuzz/ubsanshim.c" -o "$OBJ/ubsanshim.o"
	SHIMOBJS="$SHIMOBJS $OBJ/ubsanshim.o"
fi

# An archive would be wrong here.  libclang_rt.asan.so exports weak
# strcmp/strlen/strxfrm/memcpy/... interceptors and the driver puts it
# ahead of our inputs, so every one of those references would be satisfied
# from the DSO and the matching archive member never pulled -- i.e. the
# tests would be exercising glibc, not ntlibc.  Linking the objects
# unconditionally, hidden, makes ntlibc's definitions the ones that bind.
#
# One consequence of that is worth stating, because it cost a long
# debugging session: the precompiled runtime linked in here (libFuzzer,
# compiler-rt, libstdc++) does not only get preempted, it also *calls*
# some of these libc-named functions -- and it was compiled against the
# host's headers, so it stack-allocates the host's struct sizes.  ntlibc's
# definition wins the call, so an ntlibc struct that is *larger* than the
# host's, for one of the functions that runtime calls, makes the callee
# write past the caller's frame.  struct rusage did exactly that: a stray
# `long __reserved[16]` made it 272 bytes against the host's 144, and
# getrusage()'s memset(ru, 0, sizeof *ru) smashed the return address of
# libFuzzer's GetPeakRSSMb() -- every harness died at execution #2 with a
# jump to address 0, for as long as the harnesses had existed.
#
# This is a constraint on *this build*, not on ntlibc's ABI.  ntlibc's
# headers are the ones its users compile against, and matching glibc's
# layouts is explicitly not a goal.  It binds only the handful of
# functions the precompiled runtime itself calls, and only in the
# direction of "must not be bigger than the host's": a struct that is
# smaller (struct stat, for one) is harmless here, since the host-ABI
# caller simply over-allocates.
# Object names are generated above from source paths with `tr / _`, so the
# glob can never produce a name needing quoting.  LIBOBJS is expanded
# unquoted below, as a list of link inputs.
LIBOBJS=$(echo "$OBJ"/obj/*.o)

if [ "$mode" = "--objects-only" ]; then
	echo "$TAG: $(wc -l < "$OBJ/compiled.txt") src/*.c objects in $OBJ/obj"
	exit 0
fi

nsrc=$(wc -l < "$OBJ/compiled.txt")
nskip=$(wc -l < "$OBJ/skipped.txt")
echo "$TAG: $nsrc of $((nsrc + nskip)) src/*.c compiled natively ($nskip skipped, see $OBJ/skipped.txt)"

# ---- 2. run the tests that a native build can say anything about -----------
#
# A test is run unless it is on this list, and each entry says why it is
# not.  The kinds left: those that assert the target ABI, which a native
# compiler does not have (math's 80- vs 64-bit long double; strto used
# to be here too, see test/strto.c, now fixed instead of skipped); and
# posix-misc, blocked on an actual architecture mismatch, not a build-
# system one (see its entry below); and those that reach an NT-only
# primitive a native process has no counterpart for -- the Ldr* loader
# entry points (spawn-stdhandle-attr, posix-rename-symlink), which do not
# even link here.  Process cloning (fork()) is not on
# this list any more: fuzz/ntstubs.c's RtlCloneUserProcess is a real host
# fork(2), not a stub.  Neither is the wait-status pair (waitpid-overflow,
# posix-signal): fuzz/ntstubs.c now carries a dying process's full exit
# code to its reaper out of band, alongside the host's own 8-bit one (see
# xstatus_record()/xstatus_init() there).  Nothing else is excused -- in
# particular a genuine ASan or UBSan finding in ntlibc must fail here.
not_native()
{
	case $1 in
	posix-dl)
		echo "calls ntlibc_rpath_load/_sym/_error to demonstrate how much of dlfcn.h already exists; those live in src/internal/rpath.c, which is NT-only (LdrLoadDll/LdrGetProcedureAddress against a real NT image) and so is excluded from this build -- see obj/asan/skipped.txt. Its dlfcn/mman/termios/spawn clauses are fenced UNIMPL/N-A anyway; the live parts run under 'make check'" ;;
	rpath)
		echo "exercises the delay-load/\$ORIGIN machinery in src/internal/{rpath,delayload}.c, which is PE-only (LdrLoadDll/LdrGetProcedureAddress against a real NT image) and is therefore not compiled into this build at all -- see obj/asan/skipped.txt. Covered by 'make check' under Wine instead" ;;
	delayall)
		echo "proof of the -Wl,--delay-all path (crt/delayload2.c, PE-only, same reason as rpath/delayload.c above) against a plugin DLL built with a real PE tcc -- neither the delay-load runtime nor a matching delayall_check() exists for this native build to link against. Covered by 'make check' under Wine instead, on both arches" ;;
	posix-misc)
		echo "uses sigsetjmp, whose src/setjmp/x86_64/setjmp.S is genuinely Win64-ABI machine code (first arg in %rcx, xmm6-15 treated as callee-saved) -- not merely unbuilt, but wrong if assembled for a SysV caller: %rcx is not this ABI's first-argument register and its xmm6-15 are caller-saved scratch, so jmp_buf would be silently corrupted rather than just fail to link" ;;
	spawn-stdhandle-attr)
		echo "resolves NtCreateUserProcess itself, at run time, with LdrGetDllHandle()/LdrGetProcedureAddress() against a loaded ntdll.dll (see its resolve_ncup()) -- module-handle and export-table primitives that only the NT loader has, and that fuzz/ntstubs.c cannot stand in for: there is no ntdll image in a native ELF process to hand back a handle to, and the syscall it goes on to look up is the very thing under test, so a stub answering it would be testing the stub. Its subject is what real NT's PsAttributeStdHandleInfo does to the child's process parameters, which needs a real NT process anyway. Covered by 'make check' under Wine (and real Windows CI)" ;;
	posix-rename-symlink)
		echo "builds a directory-flavoured reparse point with Win32 CreateSymbolicLinkW(SYMBOLIC_LINK_FLAG_DIRECTORY), resolved at run time through LdrLoadDll()/LdrGetProcedureAddress() because ntlibc declares no kernel32 imports (see test_rename_dir_over_forced_directory_symlink()). Those two Ldr* entry points are NT-loader primitives with no stub in fuzz/ntstubs.c, so the whole file fails to link natively -- 'undefined reference to LdrGetProcedureAddress / LdrLoadDll' -- not just that one group. A stub cannot supply them either: there is no kernel32.dll PE image in an ELF process to load or to walk an export table of, and the object the export produces is the very thing under test -- an entry carrying FILE_ATTRIBUTE_DIRECTORY and FILE_ATTRIBUTE_REPARSE_POINT at once, which is NT's file-attribute model and not something a host symlink(2) has. Standing in with a POSIX symlink would delete the subject and leave the measurement asserting against the stand-in, the same objection recorded for spawn-stdhandle-attr above. Covered by 'make check' under Wine (and real Windows CI)" ;;
	spawn-runtimedata-stress)
		echo "needs RuntimeData-based descriptor inheritance for a fd above 2, which this stub's RtlCreateUserProcess (fuzz/ntstubs.c) does not model: it execve()s a real host binary, and the fresh child's __ntshim_init constructor wires up only StandardInput/Output/Error (FD2H(0..2)) before calling __fd_init -- there is no PEB-parameters blob carrying a RuntimeData table across that real execve the way real NT's process-parameters copy does. Covered by 'make check' under Wine (and real Windows CI) instead, where RtlCreateUserProcess is the real thing" ;;
	posix-kill-perm-win)
		echo "asserts that NT denies PROCESS_TERMINATE on the protected System process (pid 4), which is NT access-control policy and not something this build has. fuzz/ntstubs.c's NtOpenProcess is NOTIMPL, so it answers STATUS_NOT_IMPLEMENTED, which src/signal/signal.c's kill() correctly maps to ESRCH rather than EPERM -- the test then fails on an assertion about real NT while measuring a stub. Teaching the stub to answer STATUS_ACCESS_DENIED for pid 4 would be modelling Windows' process table inside the stub and then asserting against the model, the same objection recorded for spawn-stdhandle-attr above. Its subject needs a real NT process table; it runs on the real-Windows CI leg, which is what *-win.c is for. NOTE: this is a per-test exclusion on purpose -- do NOT generalise it to a *-win pattern. The -win suffix means 'Wine cannot run this', which is a different axis from 'the native stub build cannot run this': fork-win, fork-handles-win, fork-cloexec-exec-win and process-win all PASS here, because this build has a real fork() where Wine lacks RtlCloneUserProcess" ;;
	posix-signal-crossproc)
		echo "exercises src/signal/sigdelivery.c's named-NT-event transport and manager thread between two independently spawned ntlibc processes. That source is NT-only and is therefore absent from this native ELF build; fuzz/ntstubs.c supplies refusing/no-op boundary stubs so unrelated signal users still link, but no host signal can enter ntlibc's private disposition and pending-state machinery. Running this test would assert against that deliberate refusal, not exercise the transport. Covered by 'make check' under Wine and by every real-Windows CI leg" ;;
	posix-pgrp-crossproc)
		echo "requires two pieces of named-NT-event state across independently spawned processes: ids.c's process-group-leader publication and sigdelivery.c's caught-signal transport. The native shim deliberately refuses named events and omits the NT delivery thread, so getpgid(child) sees only the inherited sentinel and killpg() cannot run the child's SIGUSR1 handler. Modelling only the group id would still leave the test asserting against an absent signal transport; both mechanisms run under 'make check' in Wine and real-Windows CI" ;;
	posix-fcntl-lock-crossproc)
		echo "passes an ordinary synthetic VFS file descriptor through __spawn(), whose native implementation crosses a real execve. The shim's RuntimeData reconstruction deliberately restores only VFS directory lifetime handles; it has no shared kernel file object from which to reconstruct an ordinary in-memory file handle or its NT byte-range lock. Same-process record locking remains exercised by posix-unistd here; the inherited-handle conflict runs under 'make check' in Wine and real-Windows CI" ;;
	pthread-async-ub-win)
		echo "requires real NT threads, suspension, and context redirection to deliver asynchronous pthread cancellation. The native sanitizer shim deliberately refuses NtCreateThreadEx and has no NT thread context to suspend or rewrite, so this test cannot reach either the diagnostic or its controls there. Every child mode is exercised directly under patched Wine; the parent-side death-status adjudication runs on real Windows, because Wine leaves a self-NtTerminateProcess child's NT process handle unsignalled" ;;
	entry-arg)
		echo "measures the first argument the *PE image entry point* is called with -- __entry_arg0, set by crt/crt1.c's _start. This build has no crt1.o at all: it compiles src/*.c natively and gets its startup from fuzz/ntstubs.c's __ntshim_init constructor, so the symbol does not exist and the link fails outright. There is no native stand-in either: the quantity under measurement is what ntdll's RtlUserThreadStart hands a PE entry point, and an ELF process entered through glibc's _start has no such caller to measure. Its other two readings (TEB.ProcessEnvironmentBlock via fs:0x18/gs:0x30, and NtQueryInformationProcess(ProcessBasicInformation)) are equally NT-only. Covered by 'make check' under Wine and, which is the point of the file, by the real-Windows CI leg"	;;
	sh-main)
		echo "spawns obj/sh/sh.exe, a PE program built by \$(CC) from sh/main.c -- this build compiles src/*.c natively and produces no such binary at all, so the test would find nothing to exercise (it exits 77 rather than passing vacuously). What it covers is the shell *utility's* argument handling, exit status and diagnostics, which needs a real process; the engine those diagnostics come from is src/sh/*.c, which this build does compile and test/sh-engine.c does run here. Covered by 'make check' under Wine, and on the real-Windows CI leg, whose artefact carries obj/sh/sh.exe for exactly this reason -- see the upload step in .github/workflows/ci.yml" ;;
	*)  echo "" ;;
	esac
}

# The OTHER axis, and why there are two lists rather than one pattern.
#
# `-win` in a test's name means "Wine cannot run this".  That is not the
# same claim as "the native stub build cannot run this", which is what
# not_native() above records -- and the two genuinely come apart.
# Verified by content, not assumed: obj/asan/test holds real ELF
# executables for fork-win, fork-handles-win, fork-cloexec-exec-win,
# process-win and posix-fork-clauses-win, each with an empty .link.err
# and a non-empty .out, and obj/asan/unlinkable.txt is empty.  They link
# and they RUN here, because this build has a real fork() where Wine
# lacks RtlCloneUserProcess.  posix-kill-perm-win is excluded above for a
# reason that has nothing to do with Wine.  So not_native() must stay a
# per-test list and must NOT grow a `*-win` pattern; see the note in
# posix-kill-perm-win's own entry.
#
# What that leaves is a gap rather than an error.  A NEW test/*-win.c
# named in neither list is rejected by nothing: it is simply linked, and
# what happens next is decided by whether the link happens to succeed.
# If it does, `make asan` runs it while `make check` skips it -- the
# Makefile's TEST_RUN filters `%-win.exe` mechanically, by suffix, with
# no per-test opinion at all -- so the two harnesses diverge on a file
# nobody made a decision about, and the divergence is invisible because
# both stay green.  tools/test-policy.py does not cover this: it governs
# source-level NTLIBC_TEST fences inside a test, not which harness runs
# the file.
#
# This list closes the gap by making the absence loud instead.  Every
# test/*-win.c must appear in exactly one of the two lists, so adding one
# forces an explicit answer on each axis separately.  Membership here
# asserts only the native-build axis -- "the stub build CAN run this" --
# and says nothing about Wine, which is what the suffix already said.
win_runs_native()
{
	case $1 in
	fork-win|fork-handles-win|fork-cloexec-exec-win|process-win|posix-fork-clauses-win)
		echo yes ;;
	# posix-pipe-wquota-win: added when this list first became mandatory,
	# and answered by measurement rather than by reading the file.  The
	# -win suffix on it is a statement about Wine only (wine-9.0 pins
	# WriteQuotaAvailable to a literal 0, wine-10.x returns the full
	# quota unreduced -- neither can distinguish a fixed select.c from a
	# broken one).  This build is not Wine: fuzz/ntstubs.c models the
	# field, so the run here is not vacuous.  Measured, obj/asan/test/
	# posix-pipe-wquota-win.out on the tree that added the test:
	#     control  fresh pipe: select=1 poll=1
	#     filled   65536 bytes of a 65536-byte requested quota
	#     full     pipe: select=0 poll=0
	#     drained  32768 bytes
	#     drained  pipe: select=1 poll=1
	#     PASS
	# i.e. all three cells moved, which is exactly the discrimination the
	# two Wines cannot make.
	posix-pipe-wquota-win)
		echo yes ;;
	*)  echo "" ;;
	esac
}

# Enforced before anything is linked, so the diagnostic is about the
# missing decision rather than about a link error downstream of it.
win_unclassified=
for wt in $(cd "$srcdir" && echo test/*-win.c); do
	wn=$(basename "$wt" .c)
	[ "$wn" = "*-win" ] && continue          # no matches: the glob stayed literal
	[ -n "$(not_native "$wn")" ] && continue
	[ -n "$(win_runs_native "$wn")" ] && continue
	win_unclassified="$win_unclassified $wn"
done
if [ -n "$win_unclassified" ]; then
	echo "$TAG: test/*-win.c named in NEITHER list:$win_unclassified" >&2
	echo "$TAG:" >&2
	echo "$TAG: The -win suffix says Wine cannot run it. It does not say" >&2
	echo "$TAG: whether THIS build -- native ELF against fuzz/ntstubs.c --" >&2
	echo "$TAG: can. Those are different axes and each needs its own answer." >&2
	echo "$TAG:" >&2
	echo "$TAG: Left unanswered the file is linked anyway, and the outcome is" >&2
	echo "$TAG: decided by whether that link happens to succeed: if it does," >&2
	echo "$TAG: 'make asan' runs it while 'make check' skips it (the Makefile" >&2
	echo "$TAG: filters %-win.exe by suffix), and the two harnesses diverge" >&2
	echo "$TAG: with both still reporting green." >&2
	echo "$TAG:" >&2
	echo "$TAG: Pick one, in tools/asan-build.sh:" >&2
	echo "$TAG:   not_native()      -- and give the reason it cannot run here," >&2
	echo "$TAG:                        which is what that list stores." >&2
	echo "$TAG:   win_runs_native() -- it runs natively despite the suffix," >&2
	echo "$TAG:                        as fork-win and process-win do." >&2
	exit 2
fi


TINC="-I$srcdir/obj/include -I$srcdir/include -I$srcdir/arch/$ARCH -I$srcdir/arch/generic"
ran=0 passed=0 nolink=0 skipped=0 unverified=0
: > "$OBJ/unlinkable.txt"

# ---- 2a. link every test, in parallel --------------------------------------
#
# The link and the run used to be one loop body.  They are separated
# because only ONE of the two halves is safe to run concurrently, and
# saying which is the whole point of the split:
#
#   The links are.  54 independent $CC invocations, each reading the same
#   read-only $LIBOBJS and writing one output named after its own test.
#   They are the same shape as the 282 compiles above and are the second
#   half of this script's build cost.
#
#   The RUNS ARE NOT, and they are deliberately left serial.  Every test
#   executes with this script's own working directory -- the source tree
#   root -- and several write fixed-name files into it: .hidden-glob-test,
#   cap1.txt..cap4.txt, script1.sh, script2.sh, sh-main-out.txt,
#   gfi1.gfitxt (that is what .gitignore's eleven entries are, ae93540).
#   test/posix-glob.c additionally *globs* that directory, so it does not
#   merely need its own names, it needs nothing else creating files
#   beside it while it looks.  Running these concurrently in one shared
#   directory would produce failures that depend on timing, in a
#   sanitizer build whose entire purpose is to make failures
#   deterministic.  Giving each test a private mktemp -d cwd -- what
#   tools/run-tests.py already does -- would fix that and is worth doing,
#   but it is a behavioural change to how every test sees the world and
#   belongs in its own commit with its own evidence, not smuggled in
#   behind a speedup.
#
# link_one INDEX NAME TESTSRC always writes $lpar/INDEX.rc, for the same
# reason compile_one does.
lwork="$OBJ/link-worklist"
: > "$lwork"
lidx=0
for t in $(cd "$srcdir" && echo test/*.c); do
	lidx=$((lidx + 1))
	n=$(basename "$t" .c)
	printf '%06d\t%s\t%s\n' "$lidx" "$n" "$t" >> "$lwork"
done

lpar="$OBJ/lpar"
mkdir -p "$lpar" || exit 1
link_one() {
	l_idx=$1 l_n=$2 l_t=$3
	l_exe="$OBJ/test/$l_n"
	# $SAN/$LTOFLAGS/$TINC/$LINKFLAGS/$SHIMOBJS/$LIBOBJS are flag and object lists.
	# shellcheck disable=SC2086
	if $CC $SAN $LTOFLAGS -g -O1 -std=c99 -nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_GNU_SOURCE \
	     -D_NTLIBC_NATIVE_BUILD -w \
	     $TINC $LINKFLAGS "$srcdir/$l_t" $SHIMOBJS $LIBOBJS -o "$l_exe" \
	     2> "$l_exe.link.err"; then
		echo ok > "$lpar/$l_idx.rc"
	else
		echo fail > "$lpar/$l_idx.rc"
	fi
}

lshard=0
while [ "$lshard" -lt "$ASAN_JOBS" ]; do
	(
		awk -v n="$ASAN_JOBS" -v k="$lshard" 'NR % n == k' "$lwork" \
		| while IFS="$(printf '\t')" read -r idx n t; do
			[ -z "$idx" ] && continue
			[ -n "$(not_native "$n")" ] && continue
			link_one "$idx" "$n" "$t"
		done
		# See the compile shard's `exit 0` above for why this is here.
		exit 0
	) &
	lshard=$((lshard + 1))
done
wait

# ---- 2b. run them, serially, in the original order -------------------------
while IFS="$(printf '\t')" read -r idx n t; do
	[ -z "$idx" ] && continue
	exe="$OBJ/test/$n"
	why=$(not_native "$n")
	if [ -n "$why" ]; then
		skipped=$((skipped + 1))
		[ "$mode" = "--quiet" ] || echo "  SKIP $n  ($why)"
		continue
	fi
	if [ ! -f "$lpar/$idx.rc" ]; then
		# See 2a: a link worker that never reported.  Counted as
		# unlinkable rather than dropped, so the `nolink` floor below
		# catches it -- a test that silently stops being linked is
		# exactly the shape of defect 1.
		nolink=$((nolink + 1))
		echo "$n: NO RESULT -- the link worker for this test never reported" \
			>> "$OBJ/unlinkable.txt"
		continue
	fi
	if [ "$(cat "$lpar/$idx.rc")" = ok ]; then
		ran=$((ran + 1))
		# test/malloc and test/posix-alloc assert that malloc()/calloc()/
		# realloc() return NULL with ENOMEM for a request that cannot be
		# satisfied -- what C99 7.20.3.3p3 requires. ASan's default
		# allocator_may_return_null=0 aborts inside its own allocator on
		# such a request, so that path is never reached; the option makes
		# ASan behave like a conforming allocator instead, so it permits
		# the behaviour under test rather than relaxing a check. Both
		# files define __asan_default_options() to the same effect, but
		# the dynamic runtime this script needs (-shared-libasan) never
		# lets a program's definition preempt its own, so it is set here
		# too -- for just these tests, so every other test keeps the
		# strict default.
		aopts=detect_leaks=$LEAKS
		case $n in
		malloc|posix-alloc) aopts=$aopts,allocator_may_return_null=1 ;;
		esac
		if ASAN_OPTIONS=$aopts UBSAN_OPTIONS=print_stacktrace=1 \
		   timeout 120 "$exe" > "$exe.out" 2>&1 < /dev/null; then
			passed=$((passed + 1))
			[ "$mode" = "--quiet" ] || echo "  PASS $n"
		else
			rc=$?
			if [ "$rc" = 77 ]; then
				# Same "ran, but declined to verify something it detected
				# at run time" outcome tools/run-tests.py's own rc=77
				# bucket reports (test/posix-socket.c's network probe,
				# specifically: this build's fuzz/ntstubs.c stub volume
				# has no \Device\Afd node, so socket() itself fails
				# here). Not a pass -- nothing was verified -- and not a
				# FAIL either, since nothing that ran gave a wrong
				# answer.
				unverified=$((unverified + 1))
				[ "$mode" = "--quiet" ] || echo "  UNVERIFIED $n  (output in $exe.out)"
			else
				echo "  FAIL $n  (output in $exe.out)"
				[ "$mode" = "--quiet" ] || sed -n '1,25p' "$exe.out" | sed 's/^/        /'
			fi
		fi
	else
		nolink=$((nolink + 1))
		echo "$n: $(grep -o 'undefined reference to .*' "$exe.link.err" | sort -u | tr '\n' ' ')" \
			>> "$OBJ/unlinkable.txt"
	fi
done < "$lwork"

echo "$TAG: $passed/$ran tests passed, $unverified unverified, $skipped not applicable natively, $nolink unlinkable"

# implicit-integer-sign-change is recoverable, so a test that reports one
# still passes and the report scrolls by unread.  Collect the distinct
# sites and say how many there were.  (The truncation checks are fatal, so
# they turn up as a FAIL above and need no summary.)
if [ "${NTLIBC_ASAN_CONVERSION:-0}" = 1 ]; then
	nconv=$(grep -h 'runtime error: implicit conversion' "$OBJ"/test/*.out 2>/dev/null \
		| sed 's/: runtime error.*//' | sort -u | tee "$OBJ/conversion.txt" | wc -l)
	echo "$TAG: $nconv implicit-conversion site(s) -> $OBJ/conversion.txt (report-only)"
fi
# ---- 3. did this stage actually verify anything? --------------------------
#
# The pass condition used to be `passed + unverified == ran` and nothing
# else, which is vacuously true when nothing ran.  That is not a
# hypothetical: commit ad5305b added sched_yield() over NtYieldExecution()
# without a matching fuzz/ntstubs.c stub, every test/*.c links the whole
# instrumented library, so all 48 test binaries stopped linking at once --
# and this stage compiled 282 files under ASan+UBSan, ran zero tests, and
# exited 0.  A green stage that verified nothing is worse than a red one.
#
# So three conditions, not one.
#
# (a) Nothing may fail to link.  This is deliberately `> 0` and not a
#     floor or an allowlist: unlike tools/linkcheck.sh -- whose
#     linkcheck_exception() has to excuse symbols its *call-site
#     generator* cannot express (hsearch/inet_ntoa take a struct by
#     value; the __rpath group resolves a symbol the calling program
#     defines) -- this loop has no generator limitation to excuse.  A
#     test that a native build genuinely cannot link belongs in
#     not_native() above, with a written reason, where it is counted as
#     `skipped` and never reaches this counter.  So every remaining
#     unlinkable test is a missing stub or a real regression, and the
#     right number of those is zero.  $OBJ/unlinkable.txt names them.
#
# (b) Something must have run.  Belt and braces against the next variant
#     of the same failure: if some future change empties this loop by a
#     route that leaves nolink at 0 -- an over-broad not_native(), a glob
#     that matches nothing, a test/ directory that moved -- the stage
#     must not report success for it either.
#
# (c) Everything that ran must have passed or declined to verify, which
#     is the original condition, kept.
rc=0
if [ "$nolink" -gt 0 ]; then
	echo "$TAG: FAILED -- $nolink test(s) did not link; see $OBJ/unlinkable.txt" >&2
	echo "$TAG: a test a native build cannot link belongs in not_native() with a reason," >&2
	echo "$TAG: not silently dropped from the run." >&2
	rc=1
fi
if [ "$ran" -eq 0 ]; then
	echo "$TAG: FAILED -- no tests ran at all; this stage verified nothing." >&2
	rc=1
fi
[ "$((passed + unverified))" = "$ran" ] || rc=1
exit $rc
