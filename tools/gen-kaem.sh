#!/usr/bin/env bash
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# tools/gen-kaem.sh -- regenerate boot/kaem/build-$(PLATFORM)-$(ARCH).kaem
# from the real Makefile's own build recipe, so the kaem bootstrap script
# can never silently drift out of sync with the Makefile as source files
# are added, removed, or renamed.
#
# This script itself requires a normal dev environment (bash, GNU make,
# sed, awk, sort, mktemp) -- it is a *generator*, run by a developer (or by
# `make kaem`) on a machine that already has the regular toolchain. It is
# not itself meant to run under kaem; only its *output* is kaem-compatible.
#
# How it works: it asks the real Makefile what it would do, via
#   make -j1 -n -B lib/libc.a lib/crt1.o [lib/start.o]
# (-B forces every recipe to print regardless of what obj/ and lib/
# currently contain; -n means "print, don't run"; asking for exactly the
# handful of libraries/objects the bootstrap stage actually needs --
# rather than the default `all` target -- excludes the empty stub libs
# (libm.a, libpthread.a, ...), lib/ntdll.def, the spicule-tcc wrapper
# script, and lib/delayload2.o (an optional helper only programs using
# -Wl,--delay-all need, on either platform), none of which the kaem
# bootstrap stage needs), and then mechanically rewrites that dry-run
# output into kaem-legal syntax:
#   - `mkdir -p DIR` lines are expanded into the full parent-before-child
#     chain of bare `mkdir` commands (kaem's assumed toolset may not have a
#     -p-capable mkdir -- see CONTRIBUTING.md and the comments emitted into
#     the generated script itself for the full rationale).
#   - the `rm -f lib/libc.a` step is dropped: it is only needed for
#     re-builds over a dirty tree, coreutils rm is not assumed to be on
#     PATH at this bootstrap stage, and the generated script assumes (and
#     documents) a clean tree.
#   - the `cat A B > obj/include/bits/alltypes.h` step becomes a single
#     `catm obj/include/bits/alltypes.h A B` (mescc-tools-extra's
#     concatenator), since kaem has no `>` redirection.
#   - the archive step (`$(AR) rcs lib/libc.a ...`) is carried through
#     with its command name variabilized like every other tool -- see the
#     per-platform note below on what that name actually is, which is not
#     the same shape for every platform.
#   - everything else (every compile command, and the crt object copies)
#     is carried through close to verbatim, with only whitespace
#     normalized.
#   - a final pass then puts ${srcdir}/ in front of every path read from the
#     source tree, and replaces every command *name* with a variable
#     (${bin_mkdir}, ${bin_cp}, ${bin_catm}, ${CC}, and -- platform=linux
#     only, see below -- ${bin_ar}) so the caller supplies absolute paths:
#     kaem does no PATH lookup when it is itself a win32 PE32 binary, and
#     does not append the .exe the tools are installed with. See the
#     comments on that pass, and the header it emits.
#
# Usage:
#   ./configure --host=x86_64-win32 CC=x86_64-win32-tcc   # platform=nt, if not already done
#   ./configure --platform=linux CC=clang \                # platform=linux, if not already done
#     CFLAGS="-fno-stack-protector -mno-outline-atomics"
#   ./tools/gen-kaem.sh                          # regenerate every platform+arch pair the current --platform knows (the default)
#   ./tools/gen-kaem.sh --arch=i386 [out]        # just one arch of the default platform (nt), for debugging
#   ./tools/gen-kaem.sh --platform=nt --arch=aarch64 [out]     # explicit platform+arch
#   ./tools/gen-kaem.sh --platform=linux --arch=aarch64 [out]  # ditto, for linux
#
# With no --arch, this regenerates boot/kaem/build-$platform-$a.kaem for
# every arch under arch/ (bar arch/generic, which is not a target of its
# own, and bar any arch $platform has no real bootstrap recipe for yet --
# see kaem_platform_arches() below) under $platform (--platform, "nt" if
# not given). Doing them all every time is deliberate: a new source file
# otherwise lands in whichever bootstrap script the developer happened to
# have configured and silently misses the others, and CI's drift check
# only regenerates one leg, so the stale one can sit broken indefinitely.
#
# The compiler/archiver names are *not* taken from config.mak. They are
# derived per platform -- see the `case "$PLATFORM"` below -- and handed to
# make as command-line overrides, so the committed scripts are a pure
# function of the source tree rather than of whatever path ./configure was
# last pointed at -- an absolute CC in config.mak used to get baked into
# the generated output verbatim. config.mak is still required and still
# supplies the platform/arch-independent bits (CFLAGS_C99FSE, CFLAGS_AUTO,
# and, for platform=linux, the real CFLAGS -- see below).
#
# --platform exists because arch/ and PLATFORM are independent axes (see
# the Makefile's own PLAT_GLOBS comment): arch/aarch64 alone backs both
# PLATFORM=linux (native) and PLATFORM=nt (Windows-on-ARM64). The filename
# therefore keys on *both* platform and arch, not arch alone -- an
# arch-only filename would collide between the two.
#
# Both "nt" and "linux" get a real kaem bootstrap leg: CONTRIBUTING.md's
# live-bootstrap rationale (a source-traceable path back to a trusted seed,
# with no binary blob anywhere in the chain, the way Guix's
# gzip-mesboot0/live-bootstrap works) is not an NT-only idea -- it applies
# the same way to this project's native-Linux target, which has its own
# real Full Source Bootstrap seed to trace back to, exactly comparable to
# the Windows/x86 one kaem's NT legs already trace back to. What differs
# between the two legs is not *whether* one is needed, only *what the real
# recipe is* -- the same relationship the three existing nt arches already
# have to each other (i386 vs. x86_64 vs. aarch64: same shape, different
# compiler name and object list), extended across the platform axis too:
#
#   - Compiler: nt's is a per-arch cross tcc, $ARCH-win32-tcc, which also
#     doubles as the archiver (tcc -ar). linux's is a single, arch-
#     independent native compiler, clang -- confirmed working via
#     `nix-shell -p llvmPackages_18.clang` -- and clang has no self-
#     archiving mode (`clang -ar` is a plain "unknown argument" error, not
#     tcc's "-ar must be first" complaint), so the real recipe's archive
#     step calls a genuinely separate program: a real `ar`(1) (this
#     project's own ./configure discovers this itself -- see its
#     "checking for archiver" probe -- and lands on plain `ar` for
#     platform=linux since `clang -ar` does not look like tcc's usage
#     banner). The generated linux script therefore needs a SIXTH
#     variable its nt counterparts do not, ${bin_ar}, naming that real
#     archiver's path -- documented in the generated file's own header.
#   - CRT: nt's crt/crt1.c defines _start itself, in C -- tcc's PE linker
#     accepts a plain C function named _start as the entry point with
#     -nostdlib, so one object is the whole story. linux's real ELF entry
#     point cannot be C at all (the kernel hands the new process's first
#     thread a bare stack pointer with argc/argv/envp/auxv on it and no
#     return address -- see crt/linux/aarch64/start.S's own header for why
#     that boundary needs hand-written assembly the same way musl and
#     glibc keep it), so PLATFORM=linux's real crt is two objects,
#     crt/linux/crt1.c (argv/environ/TLS setup, calls main()) AND
#     crt/linux/$(ARCH)/start.S (the actual `_start` symbol, which calls
#     into crt1.c's entry function) -- both real, both required, and both
#     copied into lib/ under their own names (crt1.o, start.o). The
#     generated linux script's target list is therefore `lib/libc.a
#     lib/crt1.o lib/start.o`, not just the first two.
#   - Flags: nt has no arch-independent CFLAGS of its own beyond what
#     config.mak's CFLAGS_AUTO probes; linux's real recipe adds
#     `-fno-stack-protector -mno-outline-atomics` (see any recent
#     PLATFORM=linux commit's own verification steps) via CFLAGS itself,
#     which is why the usage line above shows CFLAGS= on the linux
#     ./configure and not the nt one. This generator does not need to
#     force these onto the make command line the way it forces
#     PLATFORM/ARCH/CC/AR: they are ordinary config.mak content, already
#     present in every compile line the dry run prints, the same way
#     CFLAGS_AUTO already is for nt.
#   - Arch coverage: today the tree's only real PLATFORM=linux entry point
#     is aarch64's (crt/linux/aarch64/start.S) -- i386 and x86_64 have no
#     crt/linux/$(ARCH)/ of their own yet (crt/linux/crt1.c's own header:
#     "x86_64 next"). kaem_platform_arches() below skips a linux arch with
#     no real entry point rather than asking make to satisfy a `lib/
#     start.o` goal that has no rule -- the same "loud, immediate error
#     rather than a silent wrong guess" instinct as everything else here,
#     applied where it would otherwise be an unhelpful Makefile error
#     ("No rule to make target") rather than a clear one from this script.
#
# Everything else in the mechanism -- the mkdir-chain expansion, the
# cat->catm rewrite, the ${srcdir}/ path-prefixing pass, the per-line
# command-name variabilization -- is genuinely platform-agnostic and
# needed no change at all to serve platform=linux; see the classify/rewrite
# passes below for the (small) places that do differ, each commented where
# it happens.

set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f config.mak ]; then
	echo "gen-kaem.sh: config.mak not found -- run ./configure first, e.g.:" >&2
	echo "  ./configure --host=x86_64-win32 CC=x86_64-win32-tcc" >&2
	exit 1
fi

# Every arch/<a>/ except the shared arch/generic/ fallback headers, AND
# except an arch with no arch/<a>/src/ files of its own at all, for any
# platform. This is a defensive guard rather than a live filter today --
# arch/i386, arch/x86_64 and arch/aarch64 all have real arch/<a>/src/*.[cS]
# files now (arch/aarch64 didn't, briefly: it grew its first ones only once
# Windows-on-ARM64 work started needing arch-specific code of its own, e.g.
# chkstk.S; before that it was PLATFORM=linux's alone and this guard did
# skip it). It stays because ARCH_GLOBS is keyed on arch, not on
# --platform, so a *future* arch added for exactly one platform, before it
# has any arch/<a>/src/ files of its own yet, would hit it again: below
# this point every path assumes at least one ARCHCC-classified dry-run line
# exists -- without this guard, an empty arch/<a>/src/ would silently reach
# `field ARCHCC | ...`, whose `grep` finds nothing and returns 1, which --
# under this script's own `set -euo pipefail` -- aborts the whole run with
# NO error message at all.
#
# Note this says nothing about *which platforms* an arch's src/ files are
# for -- ARCH_GLOBS applies them to every PLATFORM build of that arch
# (files there may still be internally #ifdef'd per platform, e.g.
# cancel_trampoline.S's NT-vs-not landing pad). Whether a given
# platform+arch pair is one this generator actually knows how to build a
# real recipe for is decided separately, by kaem_platform_arches() below.
kaem_arches() {
	for d in arch/*/; do
		a=${d%/}; a=${a#arch/}
		[ "$a" = generic ] && continue
		[ -n "$(find "arch/$a/src" -maxdepth 1 \( -name '*.c' -o -name '*.S' \) 2>/dev/null)" ] || continue
		echo "$a"
	done
}

# Which of kaem_arches()'s arches this generator can actually produce a
# real $1 (platform) recipe for. For "nt", every arch kaem_arches() names
# qualifies -- crt/crt1.c is a single platform-agnostic file, needing no
# per-arch entry point of its own (see the top-of-file note on why nt gets
# away with one crt object). For "linux", an arch only qualifies once it
# has a real crt/linux/$a/ entry point (crt/linux/$(ARCH)/start.S or
# equivalent) -- today that is aarch64 alone. Checked here, up front,
# rather than left for the dry run to discover: asking make for a `lib/
# start.o` goal with no rule for it is a Makefile error ("No rule to make
# target 'lib/start.o'"), not a clear one from this script, and would abort
# the whole "do every arch" loop below over an arch that was never real to
# begin with.
kaem_platform_arches() {
	for a in $(kaem_arches); do
		case "$1" in
		linux)
			[ -n "$(find "crt/linux/$a" -maxdepth 1 \( -name '*.c' -o -name '*.S' \) 2>/dev/null)" ] || continue
			;;
		esac
		echo "$a"
	done
}

ARCH=""
PLATFORM="nt"
OUT=""
for arg in "$@"; do
	case $arg in
		--arch=*) ARCH=${arg#--arch=} ;;
		--platform=*) PLATFORM=${arg#--platform=} ;;
		-*)
			echo "gen-kaem.sh: unknown option '$arg'" >&2
			exit 1
			;;
		*) OUT=$arg ;;
	esac
done

# The only platforms this generator knows a real build recipe for. "nt" is
# the default; "linux" is the direct extension this comment's header
# describes. Validated up front, before ARCH is even looked at, so an
# unsupported --platform is a loud, immediate error rather than a silent
# wrong guess for either the CC/AR derivation below or the per-arch loop.
case "$PLATFORM" in
	nt|linux) ;;
	*)
		echo "gen-kaem.sh: unsupported --platform='$PLATFORM' -- this generator only" >&2
		echo "gen-kaem.sh: knows a real build recipe for 'nt' and 'linux' today." >&2
		exit 1
		;;
esac

# No --arch: do the whole set, one child invocation each, for whichever
# arches kaem_platform_arches() says $PLATFORM actually has a real recipe
# for (today: all three nt arches, or aarch64 alone for linux).
if [ -z "$ARCH" ]; then
	if [ -n "$OUT" ]; then
		echo "gen-kaem.sh: an output file only makes sense with --arch=ARCH" >&2
		exit 1
	fi
	for a in $(kaem_platform_arches "$PLATFORM"); do
		"$0" --platform="$PLATFORM" --arch="$a"
	done
	exit 0
fi

if [ ! -d "arch/$ARCH" ]; then
	echo "gen-kaem.sh: no such arch '$ARCH' (have: $(kaem_arches | tr '\n' ' '))" >&2
	exit 1
fi

# CC/AR: the only per-platform knowledge this generator has beyond the arch
# guard above. Both are forced onto the make command line below (which
# beats config.mak's own assignments), so this works for any platform+arch
# regardless of what ./configure was last run with -- see the top-of-file
# note on why that matters.
case "$PLATFORM" in
	nt)
		# $ARCH-win32-tcc, acting as both compiler and archiver (tcc -ar,
		# mirroring the Makefile's AR = $(CC) -ar) -- see configure's own
		# "checking for archiver" probe, which lands here first because
		# `$CC -ar` prints tcc's usage banner.
		CC="${ARCH}-win32-tcc"
		AR="$CC -ar"
		;;
	linux)
		# A single native compiler, arch-independent (today's one real
		# linux arch, aarch64, runs it natively; a future second arch
		# would still just be "clang" -- nothing here is $ARCH-prefixed
		# the way nt's cross tcc name is, because linux's real build has
		# no such convention: configure's own probe just tries `cc`,
		# `clang`, `gcc` in turn on whatever host it runs on). Confirmed
		# against this project's own configure output (`./configure
		# --platform=linux CC=clang ...` -> `CC = clang` in config.mak).
		#
		# AR is a real, separate archiver -- clang has no tcc-style
		# self-archiving mode (`clang -ar` is a plain "unknown argument"
		# error), so configure's own probe falls through to a real ar(1)
		# and lands on plain `ar` (confirmed: `ar --version` -> GNU
		# Binutils). This is the one place platform=linux's kaem leg needs
		# a tool nt's never did -- see ${bin_ar} in the generated header
		# below.
		if [ -z "$(find "crt/linux/$ARCH" -maxdepth 1 \( -name '*.c' -o -name '*.S' \) 2>/dev/null)" ]; then
			echo "gen-kaem.sh: no real PLATFORM=linux entry point for arch '$ARCH' yet" >&2
			echo "gen-kaem.sh: (crt/linux/$ARCH/ has no .c/.S files -- today only:" >&2
			echo "gen-kaem.sh:   $(kaem_platform_arches linux | tr '\n' ' ')" >&2
			echo "gen-kaem.sh: does)." >&2
			exit 1
		fi
		CC=clang
		AR="ar"
		;;
esac

# The real per-platform CFLAGS, forced onto the make command line for the
# same reason PLATFORM/ARCH/CC/AR already are (see the note below): a
# config.mak left over from a *different* ./configure invocation must not
# silently change what this dry run's compile lines say. Both platforms
# get an explicit value here, not just linux, and this bit for real, not
# hypothetically -- caught by running the two platforms back to back, the
# way `make kaem` now does (see the Makefile): after configuring for
# platform=linux (CFLAGS=-fno-stack-protector -mno-outline-atomics),
# regenerating the *nt* legs right after picked up that same CFLAGS in
# every nt compile line, because nothing cleared it for nt -- config.mak's
# leftover linux CFLAGS silently outlived the platform it was set for. nt's
# own real recipe has no CFLAGS of its own (the documented, verified
# ./configure --host=$ARCH-win32 CC=$ARCH-win32-tcc invocation always
# leaves it empty; --enable-debug's -g flows through CFLAGS_AUTO, not
# CFLAGS, so forcing CFLAGS="" here does not touch it), so forcing it
# empty here is a no-op against that documented invocation and a real fix
# against every other config.mak state -- exactly the CC/AR precedent,
# just for the one variable this generator had not yet forced.
MAKE_OVERRIDES=(PLATFORM="$PLATFORM" ARCH="$ARCH" CC="$CC" AR="$AR")
case "$PLATFORM" in
	nt) MAKE_OVERRIDES+=(CFLAGS="") ;;
	linux) MAKE_OVERRIDES+=(CFLAGS="-fno-stack-protector -mno-outline-atomics") ;;
esac

# bin/*.exe -- the standalone POSIX utility programs (true, false, test,
# and whatever else lands in bin/ as this grows) -- get built by the nt
# leg too, unlike sh(1p): sh/main.c is deliberately NOT a kaem target
# (see the Makefile's own "boot/kaem/ builds the *library*, not this
# program" comment on obj/sh's directory rule), because system()/popen()/
# wordexp() are the only things that need a real shell at all, and none
# of those matter until well past this bootstrap stage. The POSIX
# utilities are different: their whole reason for existing (see the
# project's POSIX-utilities plan) is to remove the bootstrap's own
# dependency on mescc-tools-extra's cp/mkdir -- a value this script's
# own boot/kaem/*.kaem output provides nothing toward if it never builds
# them. Computed as a real glob over bin/*.c, not hand-listed, so a new
# utility added there is picked up the next time this script runs with
# no edit here.
#
# linux does NOT get these: bin/*.exe's real link recipe hardcodes
# -lntdll (obj/bin/%.exe's Makefile rule, unconditionally, the same way
# $(SH_EXE)'s does) and the Makefile's own `all:` target only ever
# chases $(BIN_EXES) under PLATFORM=nt for exactly that reason -- there
# is no rule that would let this dry run produce a linux recipe for
# them at all yet. Extending bin/*.c's own build to cover platform=linux
# is a separate, not-yet-done piece of the platform-abstraction work,
# out of scope here.
BIN_TARGETS=()
for f in bin/*.c; do
	[ -e "$f" ] || continue
	name=${f#bin/}
	BIN_TARGETS+=("obj/bin/${name%.c}.exe")
done

# The kaem bootstrap stage's real target list. Both platforms build
# lib/libc.a and lib/crt1.o; linux additionally needs lib/start.o, the real
# ELF entry point object crt/crt1.c's single-file nt equivalent has no
# counterpart for (see the top-of-file note). Neither platform's list
# includes lib/delayload2.o: that object is an opt-in helper for programs
# using -Wl,--delay-all, not something the bootstrap stage itself needs, on
# either platform.
case "$PLATFORM" in
	nt) TARGETS=(lib/libc.a lib/crt1.o "${BIN_TARGETS[@]}") ;;
	linux) TARGETS=(lib/libc.a lib/crt1.o lib/start.o) ;;
esac

OUT=${OUT:-boot/kaem/build-${PLATFORM}-${ARCH}.kaem}
mkdir -p "$(dirname "$OUT")"

DRYRUN=$(mktemp)
trap 'rm -f "$DRYRUN"' EXIT

# PLATFORM/ARCH/CC/AR/CFLAGS (see MAKE_OVERRIDES above) are forced on the
# command line (which beats config.mak's own assignments) so this works
# for any platform+arch regardless of what
# ./configure was last run with -- see the note at the top of this file.
# Forcing PLATFORM here specifically closes a real footgun: without it, a
# config.mak left over from a different --platform would make this dry run
# (and so the bootstrap script it produces) silently describe a different
# platform's object list instead -- wrong content under a name that
# promises otherwise.
if ! make --no-print-directory -j1 -n -B \
		"${MAKE_OVERRIDES[@]}" \
		"${TARGETS[@]}" >"$DRYRUN" 2>&1; then
	echo "gen-kaem.sh: 'make -n -B ${TARGETS[*]}' failed for $PLATFORM/$ARCH:" >&2
	cat "$DRYRUN" >&2
	exit 1
fi

MKDIRS=$(mktemp)
trap 'rm -f "$DRYRUN" "$MKDIRS"' EXIT

# Pass 1: pull every `mkdir -p DIR` line's DIR out, and expand each into its
# full chain of ancestors (obj/src/foo -> obj, obj/src, obj/src/foo), one
# per line. `sort -u` in the C locale then gives a parent-before-child,
# duplicate-free ordering for free: '/' sorts before any letter or digit,
# so a directory's own line is always a strict, lexicographically-smaller
# prefix of any of its descendants' lines.
awk '/^mkdir -p /{print $3}' "$DRYRUN" | while IFS= read -r d; do
	acc=""
	IFS='/' read -ra parts <<<"$d"
	for part in "${parts[@]}"; do
		if [ -z "$acc" ]; then acc="$part"; else acc="$acc/$part"; fi
		echo "$acc"
	done
done | LC_ALL=C sort -u >"$MKDIRS"

# Pass 2: classify every non-mkdir line from the dry run and normalize
# whitespace (the Makefile's CFLAGS_ALL leaves double spaces where optional
# variables like CPPFLAGS/CFLAGS are empty; harmless to kaem's tokenizer,
# but ugly to read).
#
# The AR line is matched against $AR (the real archive command, "arcmd"
# below), not $CC: for nt those are the same string modulo " -ar" (AR="$CC
# -ar"), so the pattern behaves exactly as before; for linux they are two
# unrelated programs (CC=clang, AR=ar), and the archive line genuinely
# starts with "ar ", not "clang ". Matching on the real $AR value, whatever
# shape it has, is what makes this one classify rule correct for both.
awk -v cc="$CC" -v arcmd="$AR" '
	function norm(s) { gsub(/  +/, " ", s); sub(/^ +/, "", s); sub(/ +$/, "", s); return s }
	/^mkdir -p /      { next }
	/^rm -f lib\/libc\.a$/ { next }
	# The obj/bin/%.exe Makefile rule depends on $(ALL_LIBS), the same
	# broad prerequisite $(SH_EXE) already has (both, unlike lib/libc.a
	# itself, ask for the *whole* library surface, not just what they
	# actually link against) -- so once BIN_TARGETS makes any bin/*.exe
	# a real dry-run target, the empty stub libs ($(EMPTY_LIBS): libm.a,
	# librt.a, libpthread.a, libcrypt.a, libutil.a, libxnet.a,
	# libresolv.a, libdl.a) show up in the dry run for the first time.
	# Dropped here for the same reason this script own header comment
	# already gives for excluding them from TARGETS entirely: nothing in
	# a bin/*.exe real link line references (-Llib -lc -lntdll, never
	# -lm/-lpthread/...) needs them built. Matched by requiring the line
	# END right after the archive name (no object arguments follow,
	# because these archives are empty) -- lib/libc.a own real rm/AR
	# lines never match either pattern, since that one has a genuine
	# object list after it.
	/^rm -f lib\/lib[A-Za-z]+\.a$/ { next }
	$0 ~ ("^" arcmd " rcs lib/lib[A-Za-z]+\\.a$") { next }
	# lib/ntdll.def, by contrast, IS genuinely needed: tcc resolves
	# `-lntdll` by finding lib/ntdll.def on its -L path and reading it as
	# the DLL import surface (the same way the Makefile own
	# `$(DEF_FILES)` prerequisite already documents), so any bin/*.exe
	# link line that ends in -lntdll (all of them) is unlinkable without
	# this file copy having run first.
	/^cp tools\/ntdll\.def lib\/ntdll\.def$/ { print "DEFCOPY\t" norm($0); next }
	/^cat / {
		# kaem has no shell redirection (`>` is just another argument
		# token, not a redirect), so this becomes a catm invocation
		# (from mescc-tools-extra) below. Expected shape:
		#   cat IN1 IN2 > OUT
		line = norm($0)
		n = split(line, a, " ")
		if (n != 5 || a[4] != ">") {
			print "OTHER\t" $0
			next
		}
		print "CATM\t" a[5] "\t" a[2] "\t" a[3]
		next
	}
	# delayload2.o, like the empty stub libs above, is only visible in
	# this dry run at all because $(ALL_LIBS) (via $(CRT_LIBS)) is a
	# blanket prerequisite of obj/bin/%.exe/$(SH_EXE) -- it is an
	# optional helper only programs using -Wl,--delay-all need (see the
	# top-of-file note on why TARGETS never included it), and no
	# bin/*.exe link line below passes that flag. Dropped for the same
	# reason, matched (like the empty-lib rules) before the generic
	# CRTCOPY/compile rules so it never reaches them.
	/^cp obj\/crt\/delayload2\.o lib\/delayload2\.o$/ { next }
	$0 ~ ("^" cc " .*-c -o obj/crt/delayload2\\.o ") { next }
	/^cp obj\/crt\//  { print "CRTCOPY\t" norm($0); next }
	$0 ~ ("^" arcmd " rcs lib/libc\\.a ") { print "AR\t" norm($0); next }
	# A bin/*.exe link line: same $(CC) as every MODCC/ARCHCC/CRTCC
	# compile line, but a *link* (no "-c", "-o obj/bin/NAME.exe" rather
	# than "-o obj/.../NAME.o") -- matched before the generic "-c -o"
	# compile rule below so it never falls through into MODCC/ARCHCC by
	# mistake, even though the two patterns cannot actually overlap (a
	# link line has no "-c").
	$0 ~ ("^" cc " ") && $0 ~ /-o obj\/bin\/[^ ]+\.exe /  { print "BINLINK\t" norm($0); next }
	$0 ~ ("^" cc " .* -c -o ") {
		line = norm($0)
		# find the object file named after "-o "
		n = split(line, a, " -o ")
		obj = a[2]
		sub(/ .*/, "", obj)
		if (obj ~ /^obj\/crt\//)      print "CRTCC\t" line
		else if (obj ~ /^obj\/arch\//) print "ARCHCC\t" line
		else                           print "MODCC\t" line
		next
	}
	{ print "OTHER\t" $0 }
' "$DRYRUN" >"${DRYRUN}.classified"

if grep -q '^OTHER' "${DRYRUN}.classified"; then
	echo "gen-kaem.sh: dry run produced lines this generator doesn't know" >&2
	echo "how to classify -- Makefile must have changed shape; update" >&2
	echo "tools/gen-kaem.sh. Offending lines:" >&2
	grep '^OTHER' "${DRYRUN}.classified" >&2
	exit 1
fi

field() { grep "^$1"$'\t' "${DRYRUN}.classified" | cut -f2-; }

CATM_ROW=$(grep '^CATM'$'\t' "${DRYRUN}.classified" || true)
CATM_OUT=$(printf '%s' "$CATM_ROW" | cut -f2)
CATM_IN1=$(printf '%s' "$CATM_ROW" | cut -f3)
CATM_IN2=$(printf '%s' "$CATM_ROW" | cut -f4)
CRT_CC=$(field CRTCC)
CRT_COPY=$(field CRTCOPY)
AR_LINE=$(field AR)
# Empty for platform=linux by construction (BIN_TARGETS is only ever
# non-empty for nt -- see its own comment above), so this is deliberately
# not part of the "missing a required step" check below the way AR_LINE
# etc. are: an empty BIN_LINES is only wrong on the nt leg, checked
# separately, right after.
BIN_LINES=$(field BINLINK || true)
DEF_LINE=$(field DEFCOPY || true)

if [ -z "$CATM_OUT" ] || [ -z "$CRT_CC" ] || [ -z "$CRT_COPY" ] || [ -z "$AR_LINE" ]; then
	echo "gen-kaem.sh: dry run is missing one of the expected single-shot" >&2
	echo "steps (alltypes.h concatenation, crt object compile(s), crt" >&2
	echo "object copy/copies, libc.a archive)." >&2
	exit 1
fi

if [ "$PLATFORM" = nt ] && [ -z "$BIN_LINES" ]; then
	echo "gen-kaem.sh: expected at least one bin/*.exe link line in the nt" >&2
	echo "dry run (bin/*.c is not empty) but found none -- BIN_TARGETS/the" >&2
	echo "BINLINK classify rule must have gone out of sync with the" >&2
	echo "Makefile's obj/bin/%.exe recipe." >&2
	exit 1
fi

if [ -n "$BIN_LINES" ] && [ -z "$DEF_LINE" ]; then
	echo "gen-kaem.sh: found bin/*.exe link line(s) but no lib/ntdll.def" >&2
	echo "copy in the dry run -- every bin/*.exe link ends in -lntdll, so" >&2
	echo "this should be impossible; the DEFCOPY classify rule must have" >&2
	echo "gone out of sync with the Makefile." >&2
	exit 1
fi

# Per-platform prose for the generated header: what this leg's real recipe
# needs beyond srcdir/CC/bin_mkdir/bin_cp/bin_catm, and how a developer
# regenerates it. Kept as plain string variables, each already carrying its
# own `#`/`#   ` comment-prefix on every line (printed with printf, not
# spliced into a heredoc, so multi-line values cannot lose that prefix on
# their second and later lines) rather than duplicating the whole header
# per platform, since everything else in it (the tool list's shared
# preamble, the mkdir-order rationale, the variable-substitution rationale)
# is genuinely identical between legs.
case "$PLATFORM" in
nt)
	TARGET_DESC="${ARCH}-win32"
	PRODUCES_LINE="# boot/kaem/build-${PLATFORM}-${ARCH}.kaem -- kaem-only bootstrap build of
# spicule for ${TARGET_DESC}, producing lib/libc.a, lib/crt1.o and the
# standalone POSIX utility programs (obj/bin/*.exe -- true, false, test,
# ...) without make, without a real shell, and without a general-purpose
# ar."
	CONFIGURE_LINE="#   ./configure --host=${ARCH}-win32 CC=${CC}"
	MAKEKAEM_TARGETS="lib/libc.a, lib/crt1.o and every obj/bin/*.exe"
	GUIX_TAIL="# for the full rationale and the analogy to Guix's gzip-mesboot0."
	CC_BULLET="#   - \${CC}, a win32-cross tcc for ${ARCH} (${CC}), acting as both
#     compiler and archiver (tcc -ar rcs, no external ar/ranlib needed --
#     this mirrors what the real Makefile does via \$(AR) = \$(CC) -ar).
#     It must be the compiler alone, with no flags appended: tcc requires
#     \`-ar' to be its very first argument, and rejects it anywhere else
#     with \"cannot parse -ar here\"."
	NOTASSUMED_TAIL="# coreutils rm, or a standalone binutils ar."
	TOOL_VARS="#   CC         the ${CC} above
#   bin_mkdir  \\
#   bin_cp      >  the three mescc-tools-extra programs above
#   bin_catm   /"
	TOOLCOUNT="four"
	INVOKE_VARS="CC=/path/to/${CC}.exe bin_mkdir=/path/to/mkdir.exe bin_cp=/path/to/cp.exe bin_catm=/path/to/catm.exe"
	SHORT_INVOKE_VARS="CC=... bin_mkdir=... bin_cp=... bin_catm=..."
	VARCOUNT="Five"
	CRT_COMMENT="#
# crt1.o: compiled like any other object, then copied into lib/ under its
# install name (mirrors the Makefile's \`lib/%.o: obj/crt/%.o\` / \`cp\` rule).
#"
	ARCHIVE_COMMENT="#
# Archive every libc/arch object into lib/libc.a using tcc's built-in
# self-archiving mode (tcc -ar), exactly as the Makefile's AR = \$(CC) -ar
# does -- no standalone binutils ar required.
#"
	BINLINK_COMMENT="#
# Link each standalone POSIX utility program (obj/bin/*.exe) against the
# lib/libc.a and lib/crt1.o just built above -- mirrors the Makefile's
# \`obj/bin/%.exe: \$(srcdir)/bin/%.c \$(ALL_LIBS)\` pattern rule, one link
# per source file under that directory, no different in kind from that
# rule's own \${CC} ... -nostdlib -o ... -Llib -lc -lntdll invocation.
# This is why these lines come last: every one of them needs lib/libc.a
# to already exist, which the archive step directly above just produced.
#"
	;;
linux)
	TARGET_DESC="${ARCH}-linux"
	PRODUCES_LINE="# boot/kaem/build-${PLATFORM}-${ARCH}.kaem -- kaem-only bootstrap build of
# spicule for ${TARGET_DESC}, producing lib/libc.a, lib/crt1.o and
# lib/start.o, without make, without a real shell, and without a
# general-purpose ar."
	CONFIGURE_LINE="#   ./configure --platform=linux CC=${CC} CFLAGS=\"-fno-stack-protector -mno-outline-atomics\""
	MAKEKAEM_TARGETS="lib/libc.a, lib/crt1.o and lib/start.o"
	GUIX_TAIL="# for the full rationale and the analogy to Guix's gzip-mesboot0 -- this
# applies the same way to linux's own real Full Source Bootstrap seed as
# it does to nt's."
	CC_BULLET="#   - \${CC}, a native C compiler for ${TARGET_DESC} (${CC}) -- unlike nt's
#     cross tcc, this compiler does not also act as archiver (see
#     \${bin_ar} below): clang has no self-archiving mode at all (\`clang
#     -ar\` is a plain \"unknown argument\" error, not tcc's \"-ar must be
#     first\" complaint). The real CFLAGS (-fno-stack-protector
#     -mno-outline-atomics) are not assumed of \${CC} itself -- they are
#     already literal text on every compile line below, the same way
#     \$(CFLAGS_AUTO) already is for nt, so nothing here needs to know what
#     they are, only that \${CC} is the plain compiler and nothing more.
#   - \${bin_ar}, a real archiver (this tree's own \`ar rcs\` -- GNU
#     binutils' ar or llvm-ar, whichever the bootstrapping machine has;
#     confirmed here against GNU Binutils' ar). Not one of the three
#     mescc-tools-extra programs below: unlike nt, where tcc's own -ar mode
#     means no separate archiver is ever needed, linux's real archive step
#     calls a genuinely different program than the compiler, so this leg
#     needs a tool nt's never did."
	NOTASSUMED_TAIL="# coreutils rm, or a standalone binutils ar OTHER than \${bin_ar} itself,
# which this leg names explicitly rather than assuming."
	TOOL_VARS="#   CC         the ${CC} above
#   bin_ar     a real archiver (see above)
#   bin_mkdir  \\
#   bin_cp      >  the three mescc-tools-extra programs above
#   bin_catm   /"
	TOOLCOUNT="five"
	INVOKE_VARS="CC=/path/to/${CC} bin_ar=/path/to/ar bin_mkdir=/path/to/mkdir.exe bin_cp=/path/to/cp.exe bin_catm=/path/to/catm.exe"
	SHORT_INVOKE_VARS="CC=... bin_ar=... bin_mkdir=... bin_cp=... bin_catm=..."
	VARCOUNT="Six"
	CRT_COMMENT="#
# crt1.o and start.o: two objects, not one -- unlike nt's crt/crt1.c
# (which defines _start itself, in C: tcc's PE linker accepts a plain C
# function named _start as the entry point under -nostdlib), a native ELF
# entry point cannot be C at all -- the kernel hands the new process a bare
# stack pointer with argc/argv/envp/auxv on it and no return address, a
# boundary that needs hand-written assembly the same way musl and glibc
# keep it (see crt/linux/\$(ARCH)/start.S's own header). crt1.c does the
# argv/environ/TLS setup and calls main(); start.S is the real \`_start\`
# symbol and calls into crt1.c's entry function. Both are compiled like any
# other object, then copied into lib/ under their install names (mirrors
# the Makefile's \`lib/%.o: obj/crt/.../%.o\` / \`cp\` rule).
#"
	ARCHIVE_COMMENT="#
# Archive every libc/arch object into lib/libc.a using a real archiver
# (\${bin_ar}), exactly as the Makefile's AR = ar does here -- unlike nt,
# clang has no self-archiving mode to fall back on, so this is a genuinely
# separate program from \${CC}, not a mode of it.
#"
	;;
esac

{
	cat <<HEADER
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
HEADER
	printf '%s\n' "$PRODUCES_LINE"
	cat <<HEADER
#
# GENERATED FILE -- do not hand-edit. Regenerate with:
HEADER
	printf '%s\n' "$CONFIGURE_LINE"
	cat <<HEADER
#   ./tools/gen-kaem.sh
# (or \`make kaem\`, which does the same via this Makefile's own recipe for
HEADER
	printf '# %s, so this script can never silently drift out of\n' "$MAKEKAEM_TARGETS"
	cat <<HEADER
# sync with the Makefile as source files are added/removed/changed).
#
# This is NOT the normal way to build spicule. It exists solely for the
# "right after mes compiles tcc" point in a from-scratch bootstrap chain
# (live-bootstrap style), where the only command driver available is kaem
# (from mescc-tools) and make/bash do not exist yet. See CONTRIBUTING.md
HEADER
	printf '%s\n' "$GUIX_TAIL"
	cat <<HEADER
#
# Assumed available tools, and nothing else -- each named by a variable this
# script's caller must set to the tool's path (see "must be set" below):
HEADER
	printf '%s\n' "$CC_BULLET"
	cat <<HEADER
#   - \${bin_mkdir}, \${bin_cp} and \${bin_catm}, all three from
#     mescc-tools-extra -- the companion package to mescc-tools (kaem's own
#     home), so it is already
#     on hand wherever kaem is. \`catm OUT IN...\` is its minimal
#     concatenator; it stands in for the shell's \`cat IN... > OUT\`, which
#     kaem cannot express because it has no redirection. Of the fifteen
#     programs mescc-tools-extra ships (catm, chmod, cp, match, mkdir,
#     replace, rm, sha256sum, sha3sum, unbz2, ungz, untar, unxz, wrap)
#     this script uses exactly three.
#   - kaem's own builtins (cd, set, echo, if/then/else/fi, etc. -- unused
#     here)
# Notably NOT assumed: make, a POSIX shell, sed or awk (mescc-tools-extra
# has neither, and nothing else in it can do a capture-group rewrite),
HEADER
	printf '%s\n' "$NOTASSUMED_TAIL"
	cat <<HEADER
#
# ${VARCOUNT} variables must be set, and the working directory must be writable:
#   srcdir     the source tree.  Every path this reads from the tree is
#              \${srcdir}-relative; every path it writes is relative to the
#              working directory.
HEADER
	printf '%s\n' "$TOOL_VARS"
	printf '# The %s tool variables hold paths, not names to look up.  kaem does no\n' "$TOOLCOUNT"
	cat <<HEADER
# PATH search of its own when it is itself a win32 PE32 binary -- the form it
# has at the bootstrap point this script exists for -- so a bare \`mkdir'
# there is \`Subprocess error -1', and it does not append the \`.exe' the
# tools are installed with either.  Give absolute paths and neither matters.
#
# From the repository root, in place, with the tools in one directory:
#   srcdir=. ${INVOKE_VARS} kaem --strict --file boot/kaem/build-${PLATFORM}-${ARCH}.kaem
# Or with the sources read-only somewhere else, which is the case a
# from-scratch bootstrap actually has -- an unpacked tarball or a store path
# it may not write to, and no recursive copy at this stage to stage it with:
#   cd /some/empty/writable/dir
#   srcdir=/path/to/spicule ${SHORT_INVOKE_VARS} kaem --strict --file .../build-${PLATFORM}-${ARCH}.kaem
# (On a developer machine with a POSIX shell the tools are unsuffixed and
# \`command -v' fills these in, e.g. bin_cp=\$(command -v cp).)
#
# kaem substitutes an unset variable as nothing, so a forgotten srcdir fails
# on /src/... and a forgotten tool leaves a command whose name is its own
# first argument -- either way a loud failure, never a quiet wrong one.
#
# This script assumes a clean tree (no pre-existing obj/ or lib/): every
# directory below is created with a single bare \`\${bin_mkdir} DIR\`, never
# with -p, in strict parent-before-child order. Two reasons for that, both explained
# in CONTRIBUTING.md:
#   1. \`mkdir -p\` is not guaranteed to exist at this bootstrap point -- the
#      handwritten early-stage tools favor minimality, and depending on -p
#      would be an unverified assumption at exactly the point where an
#      unverified assumption is most expensive to be wrong about.
#   2. kaem has no branching/conditionals worth using for "did this already
#      exist" logic, and no loop construct to factor this out -- so the
#      dependency-ordered flat list below is both the safe option and the
#      only option that fits kaem's model.
# (For what it's worth: mescc-tools-extra's own \`mkdir\` *does* implement
# --parents/-p, in a way that tolerates an already-existing directory
# without erroring -- see mescc-tools-extra/mkdir.c's create_dir(). So
# \`\${bin_mkdir} -p\` would probably also work here if that's the mkdir
# pointed at. This script still doesn't rely on it, since a minimal mkdir
# providing only bare POSIX mkdir(1) semantics is not ruled out at this
# stage, and the parent-first plain-mkdir list costs nothing extra to emit.)
#
# For the same reason (clean-tree assumption, no coreutils rm assumed to be
# on PATH), this script does not \`rm -f lib/libc.a\` before archiving,
# unlike the Makefile's \`lib/libc.a:\` rule -- there is nothing to remove
# yet. If you re-run this script's *output* over a non-clean tree, remove
# obj/ and lib/ first with whatever tool you have.

#
# Create output directories, parent before child.
#
HEADER
	sed 's/^/mkdir /' "$MKDIRS"
	cat <<MID1

#
# Assemble obj/include/bits/alltypes.h out of two pre-expanded halves.
#
# The Makefile builds this header with one
#   cat $CATM_IN1 $CATM_IN2 > $CATM_OUT
# which kaem cannot run as-is: \`>\` is just another plain argument token to
# kaem, not a redirection operator, so there is nowhere for cat's stdout to
# go. mescc-tools-extra's \`catm\` exists for exactly this situation -- it
# takes the output file as its first argument and concatenates the rest
# into it (catm.c opens argv[1] with O_TRUNC|O_CREAT and copies argv[2..]
# through) -- so the whole step is one catm invocation and no redirection.
#
# Both inputs are *.h.gen files: the committed, already-expanded form of
# the compact TYPEDEF/STRUCT/UNION DSL in the matching *.h.in. The
# expansion is done at development time by tools/gen-alltypes.sh (\`make
# alltypes\`) rather than here, because it needs a capture-group rewrite
# (\`TYPEDEF unsigned _Addr size_t;\` -> a four-line __NEED_/__DEFINED_
# guarded block) that nothing available at this bootstrap point can do:
# there is no sed and no awk, and mescc-tools-extra's \`replace\` does
# literal substring substitution only. Compiling a helper on the spot is no
# way out either -- the tcc on PATH here is a *cross* compiler emitting
# win32 PE, so anything it builds will not run on the build host.
#
# Splitting the expansion from the concatenation is only sound because
# mkalltypes.sed's rules are all purely per-line (no hold space, no range
# addresses), so expanding each half separately and concatenating gives the
# same bytes as concatenating and then expanding -- verified byte-for-byte
# against the old single-sed output for both arches. The *.h.gen files are
# kept honest by the same regenerate-and-diff check that keeps this script
# honest (\`make generated\`, plus .githooks/pre-commit and CI).
#
MID1
	printf 'catm %s %s %s\n' "$CATM_OUT" "$CATM_IN1" "$CATM_IN2"
	printf '\n%s\n' "$CRT_COMMENT"
	printf '%s\n' "$CRT_CC"
	printf '%s\n' "$CRT_COPY"
	cat <<'MID3'

#
# Compile every libc source file into obj/, one literal command per file
# (mirrors the Makefile's `obj/%.o: $(srcdir)/%.c` / `.S` rules, applied to
# BASE_SRCS for this arch after arch-override filtering).
#
MID3
	field MODCC
	cat <<'MID4'

#
# Per-arch overrides/extra objects from arch/$(ARCH)/src/.
#
MID4
	field ARCHCC
	printf '\n%s\n' "$ARCHIVE_COMMENT"
	printf '%s\n' "$AR_LINE"
	if [ -n "$BIN_LINES" ]; then
		printf '\n#\n# lib/ntdll.def: every link line below (one per standalone utility\n'
		printf '# program) ends in -lntdll,\n'
		printf '# which tcc resolves by finding lib/ntdll.def on its -L path and\n'
		printf '# reading it as ntdll.dll'"'"'s import surface -- so this copy has to\n'
		printf '# happen before any of them can link.\n#\n'
		printf '%s\n' "$DEF_LINE"
		printf '\n%s\n' "$BINLINK_COMMENT"
		printf '%s\n' "$BIN_LINES"
	fi
} >"$OUT.tmp"

# Source paths become ${srcdir}-relative; output paths stay relative to the
# working directory.  The two are already distinguishable in what make -n
# printed: everything the build *writes* is under obj/ or lib/, and
# everything it *reads* from the tree is ./arch, ./include, src/, crt/, bin/ or tools/.
#
# Without this the script can only run with the working directory set to the
# source tree, which is the one thing a from-scratch bootstrap cannot
# arrange: the sources arrive read-only (a nix store path, an unpacked
# tarball owned by the build driver), and nothing at this stage has a
# recursive copy to stage them with -- mescc-tools-extra's cp takes files,
# one at a time, and there is no shell to loop in.  With it, kaem runs in a
# writable empty directory and reads the tree wherever it is.
#
# srcdir must be set.  From the repository root that is `srcdir=.`; kaem
# substitutes an unset variable as nothing, so a forgotten one fails loudly
# on /src/... rather than quietly reading something else.
#
# The same pass turns every command name into a variable: ${bin_mkdir},
# ${bin_cp}, ${bin_catm} for the three mescc-tools-extra programs, ${CC} for
# the compiler, and -- platform=linux only, see the header this script
# emits -- ${bin_ar} for the real archiver linux's recipe needs and nt's
# does not (nt's archive line already starts with ${CC}, from AR=$CC -ar,
# so the ${CC} substitution below already covers it; the ${bin_ar}
# substitution is therefore a deliberate no-op for nt, run only after the
# ${CC} one so it never has anything left to match there).  A bare name
# needs the running shell to search PATH, and kaem does not: built as a
# win32 PE32 binary -- which is what it is at the point this script exists
# for -- it execs the command name as given, so `mkdir` is `Subprocess
# error -1' and only an absolute path runs.  The tools are also installed
# with a .exe suffix there, which kaem does not append either, so even a
# PATH-searching kaem would miss them.  Naming them by variable lets the
# build driver hand over the absolute, suffixed path it already knows.
#
# Anchoring each substitution at the start of the line is what keeps it from
# touching prose: every command in the emitted script begins its line, and
# every comment begins with `#'.  Only the command name is replaced, so ${CC}
# expands to the program alone and `-ar' stays tcc's *first* argument, which
# it insists on ("cannot parse -ar here" otherwise).
#
# As with srcdir, an unset one of these substitutes to nothing and the
# resulting command is malformed rather than plausible.
# The ${...} here are deliberately single-quoted: they are literal text
# emitted *into* the generated kaem file, for kaem to expand at bootstrap
# time, not values for this script to expand now. shellcheck 0.9 flags all
# six as SC2016 ("expressions don't expand in single quotes"); 0.11 does
# not, which is why this only showed up in CI.
# shellcheck disable=SC2016
sed -e 's,-I\./,-I${srcdir}/,g' \
    -e 's,\([ \t]\)\./,\1${srcdir}/,g' \
    -e 's,\([ \t]\)\(src/\|crt/\|arch/\|bin/\|tools/\),\1${srcdir}/\2,g' \
    -e 's,^mkdir ,${bin_mkdir} ,' \
    -e 's,^cp ,${bin_cp} ,' \
    -e 's,^catm ,${bin_catm} ,' \
    -e "s,^${CC} ,\${CC} ," \
    -e "s,^${AR} ,\${bin_ar} ," \
    "$OUT.tmp" >"$OUT"
rm -f "$OUT.tmp"

rm -f "${DRYRUN}.classified"

echo "gen-kaem.sh: wrote $OUT ($(wc -l <"$OUT") lines)" >&2
