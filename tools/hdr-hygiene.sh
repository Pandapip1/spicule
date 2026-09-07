#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# hdr-hygiene.sh -- prove every public spicule header is usable *on its own*.
#
# The bug this exists to catch: a full-source bootstrap (building Make and
# gnulib against spicule) found that spicule has no <pwd.h> at all, and
# nothing in-tree noticed, because nothing in the tree includes a header
# spicule does not have.  That is the "missing outright" half of the class
# (see test/POSIX-COVERAGE.md and the sibling inventory this script does
# not produce).  This script is the other half: headers that exist but are
# not *usable* -- one that only compiles if something else was included
# first, that breaks when included twice, that leaks identifiers, or that
# silently depends on a feature-test macro nobody set.  In-tree code never
# catches this because it always includes headers in one habitual, working
# order.
#
# For every header found under include/ and obj/include/ (mechanically, via
# find -- see fuzz/Makefile's LIBHDR comment for why a hand-listed set is
# the wrong shape here: it stops mentioning the header somebody adds
# tomorrow), this:
#
#   solo    compiles the header as the *only* #include in a TU.  Catches
#           "works only if you included <stddef.h> first".
#   twice   #includes it twice in one TU.  Catches a missing/broken
#           include guard.
#   cxx     same as solo, compiled as C++, for any header that promises
#           extern "C" (`grep -l 'extern "C"'`).  That promise is not
#           tested anywhere else in this tree.
#
# each under both arches (i386, x86_64) with this project's own strict
# dialect: -std=c99 -nostdinc, the same include path shape tools/lint.sh
# uses (see cppflags_for there; duplicated here rather than sourced, same
# as lint.sh does not source asan-build.sh -- these scripts stay
# independently readable).
#
# A header that is *deliberately* order-dependent, or has a real reason
# not to stand alone, goes in the EXCEPTIONS list below with a comment,
# the same discipline tools/asan-build.sh's not_native() uses -- so the
# gate stays green and the exception stays visible rather than silently
# skipped.
#
# Usage:
#   tools/hdr-hygiene.sh              run every stage, every arch
#   tools/hdr-hygiene.sh solo twice   run only the named stages
# Env:
#   HYGIENE_ARCHS=...      arches to check (default: i386 x86_64)
#   HYGIENE_STRICT=0       always exit 0 (report only)
#   HYGIENE_ALLOW_MISSING=1  skip a stage whose tool is absent instead of
#                          failing (see tools/lint.sh's require_tool for
#                          why this defaults off)

set -u

# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

builddir=obj/hygiene
: "${HYGIENE_ARCHS:=i386 x86_64}"
: "${HYGIENE_STRICT:=1}"
: "${HYGIENE_ALLOW_MISSING:=0}"
missing=0
findings=0
pass=0
fail=0

note() { printf '%s\n' "$*"; }
hdr() { printf '\n=== %s ===\n' "$*"; }

# report_missing DESCRIPTION -- the "a tool this stage needs is not here"
# path, factored out of require_tool so a stage whose requirement is not
# one `command -v`-able name can take it too.  The cxx stage needs *some*
# C++ compiler (g++ or clang++), not a particular one; before this it
# simply skipped whichever was absent and, when both were, counted a
# clean pass for every header it never compiled.  Always returns 1.
report_missing() {
	if [ "$HYGIENE_ALLOW_MISSING" = 1 ]; then
		note "SKIP: $1 (HYGIENE_ALLOW_MISSING=1)"
		return 1
	fi
	note "MISSING: $1"
	missing=1
	return 1
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 && return 0
	report_missing "$1 is not installed."
}

# Every header this gate is responsible for.  Derived with find, never
# hand-listed (see the file header comment).  Two roots:
#   include/           the public headers, committed
#   obj/include/        generated (bits/alltypes.h) -- content is
#                       per-arch (arch/$ARCH/bits/alltypes.h.gen +
#                       include/alltypes.h.gen), so it is not read from
#                       here; gen_alltypes below rebuilds it per arch the
#                       same way tools/lint.sh does.
all_headers() {
	find include -name '*.h' | sort
	echo "obj/include/bits/alltypes.h"
}

# bits/alltypes.h for a given arch, assembled exactly as the Makefile
# does it (and as tools/lint.sh's gen_alltypes does), so this can check
# an arch the tree is not currently configured for.
gen_alltypes() {
	mkdir -p "$builddir/$1/include/bits" || return 1
	cat "arch/$1/bits/alltypes.h.gen" include/alltypes.h.gen \
		> "$builddir/$1/include/bits/alltypes.h"
}

# ---------------------------------------------------------------------
# Exceptions: headers that are deliberately not self-contained, or that
# have a real, documented reason to fail one of the stages below.  Empty
# today -- every header in this tree passes solo/twice/cxx outright, so
# there is nothing to list.  Format, if this ever grows:
#
#   is_exception <path> <stage> && { note "EXCEPT: ..."; continue; }
#
# with the reason given inline at the case arm, same shape as
# tools/asan-build.sh's not_native().
# ---------------------------------------------------------------------
is_exception() {
	hpath=$1 stage=$2
	case "$hpath:$stage" in
	# example (currently none):
	# include/foo.h:solo) return 0 ;;
	*) return 1 ;;
	esac
}

# The include path a header needs to be found as <...>, and the spelling
# used in the generated #include line, mirroring tools/lint.sh's
# cppflags_for/gen_alltypes.
incpath_for() {
	case $1 in
	obj/include/*) printf '%s\n' "${1#obj/include/}" ;;
	include/*)     printf '%s\n' "${1#include/}" ;;
	esac
}

# Deliberately *no* -D_XOPEN_SOURCE/-D_ALL_SOURCE here, unlike
# tools/lint.sh's cppflags_for: those are what the library's own build
# sets for itself (CFLAGS_ALL in the Makefile), but this gate is
# checking what an ordinary consumer of the installed headers gets, with
# no feature-test macro set at all -- include/features.h's own default
# (_BSD_SOURCE + _XOPEN_SOURCE=700) is exactly what must carry a header
# on its own.
cppflags_for() {
	echo "-std=c99 -nostdinc -fno-builtin" \
	     "-Iarch/$1 -Iarch/generic -I$builddir/$1/include -Iinclude -Isrc/internal"
}

run_one() {
	# $1 = header spelling (e.g. sys/stat.h), $2 = arch, $3 = stage,
	# $4 = compiler invocation, $5 = extra flags (dialect), $6 = ext (.c/.cpp)
	spelling=$1 arch=$2 stage=$3 cc=$4 extra=$5 ext=$6
	tu="$builddir/tu$ext"
	case $stage in
	solo)  printf '#include <%s>\n' "$spelling" > "$tu" ;;
	twice) printf '#include <%s>\n#include <%s>\n' "$spelling" "$spelling" > "$tu" ;;
	cxx)   printf '#include <%s>\n' "$spelling" > "$tu" ;;
	esac
	flags=$(cppflags_for "$arch")
	# -std=c99 is a C-only flag; a C++ compile drops it in favour of a
	# fixed C++ dialect (the header does not get to pick which C++
	# standard a consumer builds under, so this just needs *a* valid
	# one -- C++11 is old enough that every compiler here has it).
	case $stage in
	cxx) flags=$(printf '%s\n' "$flags" | sed 's/-std=c99/-std=c++11/') ;;
	esac
	# shellcheck disable=SC2086
	if $cc $flags $extra -c -o "$builddir/tu.o" "$tu" > "$builddir/last.log" 2>&1; then
		return 0
	fi
	return 1
}

stage_run() {
	stage=$1
	hdr "$stage"
	require_tool gcc || return 1

	# Which compilers this stage will really use, decided once, before
	# any header is looked at -- rather than per header, inside the loop,
	# with a `continue` that left ok=1 behind it.  That `continue` was the
	# bug: on a machine with neither g++ nor clang++ the cxx stage
	# compiled nothing, incremented `pass` once per header anyway, and
	# reported a passing C++-compatibility check over zero C++ compiles.
	# A stage with no compiler is a missing tool, which is what
	# HYGIENE_ALLOW_MISSING is for; it is not "nothing to do".
	compilers=""
	if [ "$stage" = cxx ]; then
		for cxx in g++ clang++; do
			command -v "$cxx" >/dev/null 2>&1 && compilers="$compilers $cxx"
		done
		[ -n "$compilers" ] || {
			report_missing "no C++ compiler (tried g++ and clang++), so the cxx stage cannot check that extern \"C\" promise"
			return 1
		}
	else
		for base in gcc clang; do
			command -v "$base" >/dev/null 2>&1 && compilers="$compilers $base"
		done
		[ -n "$compilers" ] || {
			report_missing "no C compiler (tried gcc and clang), so the $stage stage cannot run"
			return 1
		}
	fi

	# Headers this stage actually compiled.  A stage that compiled none
	# of them has proved nothing, whatever `pass` says.
	checks=0
	for arch in $HYGIENE_ARCHS; do
		gen_alltypes "$arch" || { note "cannot generate bits/alltypes.h for $arch"; findings=1; continue; }
		for h in $(all_headers); do
			spelling=$(incpath_for "$h")
			[ -n "$spelling" ] || continue
			if is_exception "$h" "$stage"; then
				continue
			fi
			# The cxx stage is only responsible for headers that make
			# the extern "C" promise -- a header that makes none is not
			# skipped work, it is out of scope, and is not counted.
			if [ "$stage" = cxx ]; then
				grep -q 'extern "C"' "$h" || continue
			fi
			ok=1
			for cc in $compilers; do
				case $stage in
				cxx) run_one "$spelling" "$arch" cxx "$cc" "-x c++" .cpp || ok=0 ;;
				*)   run_one "$spelling" "$arch" "$stage" "$cc" "" .c || ok=0 ;;
				esac
			done
			checks=$((checks + 1))
			if [ "$ok" = 1 ]; then
				pass=$((pass + 1))
			else
				fail=$((fail + 1))
				findings=1
				note "FAIL [$arch/$stage]: $spelling"
				sed 's/^/    /' "$builddir/last.log" 2>/dev/null | tail -5
			fi
		done
	done
	if [ "$checks" -eq 0 ]; then
		note "FAILED [$stage]: no header was compiled at all -- this stage checked nothing."
		note "  (a header that is deliberately exempt belongs in is_exception() with a"
		note "  reason; an empty run is not an exemption.)"
		findings=1
		return 1
	fi
	note "$stage: $checks header/arch compile(s), using$compilers"
}

stages=${*:-solo twice cxx}
mkdir -p "$builddir" || exit 1
for s in $stages; do
	case $s in
	solo|twice|cxx) stage_run "$s" ;;
	*) note "unknown stage: $s"; exit 2 ;;
	esac
done

hdr "summary"
note "$pass check(s) passed, $fail failed"
if [ "$missing" -ne 0 ]; then
	note "one or more stages could not run because a tool is missing."
	exit 2
fi
if [ "$findings" -eq 0 ]; then
	note "no findings"
	exit 0
fi
note "findings above"
[ "$HYGIENE_STRICT" = 0 ] && exit 0
exit 1
