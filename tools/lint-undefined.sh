#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# lint-undefined.sh -- flag a public header declaring a function that is
# never defined anywhere in this library.
#
# This is the inverse of the -Wmissing-prototypes stage in tools/lint.sh
# (which catches a *definition* with no public prototype): here the bug
# is a *prototype* with no definition, which -Wmissing-prototypes cannot
# see -- it only warns about the translation units it is fed, and a
# header is never itself compiled as one.  Nothing short of trying to
# link every declared symbol catches it, which is how all three known
# instances of this bug were actually found:
#
#   - system()/posix_close(): declared in include/stdlib.h and
#     include/unistd.h, defined nowhere -- any program calling either
#     failed to link with "unresolved reference".
#   - __find_program(): declared in src/internal/libc.h (an *internal*
#     header, so out of this script's scope, but the same shape of bug),
#     defined nowhere -- broke every link touching execv/execvp.
#   - malloc_usable_size(): the mirror image (defined, but never
#     declared anywhere) -- caught by -Wmissing-prototypes, not this
#     script, and mentioned here only to explain why this script checks
#     "undefined", not "undeclared".
#
# What this checks: every function *declared* in include/**/*.h must be
# *defined* somewhere in src/, arch/, or crt/ -- as a C function
# definition, or (arch/*/src/*.S) as an assembly global symbol, or as a
# name tools/ntdll.def exports (an import from ntdll.dll, resolved by
# the linker rather than compiled here at all: NtClose and friends, plus
# LdrLoadDll/LdrGetDllHandle/LdrGetProcedureAddress).  No public header
# declares an Nt*/Ldr* name directly today, but the check is there in
# case one ever does.
#
# What counts as "declared" or "defined" is answered by a real clang AST
# walk, tools/clang/LintDeclScanner.cpp -- run once per header (in decl
# mode) and once per .c file (in def mode) -- not by parsing C by hand.
# This used to be tools/lint-decls.awk, a character-at-a-time scanner
# shared with tools/lint-unreferenced.sh, which only ever stripped
# /* */ comments (never // ones) and treated "the first identifier
# immediately followed by '('" as a declarator name.  Both blind spots
# were live bugs, not theoretical: nearly every .c file in this tree
# carries a `// NOLINTBEGIN(misc-include-cleaner)` banner near its top
# (see CONTRIBUTING.md), and the awk's failure to strip it meant that
# banner got parsed as a fake 3-argument "NOLINTBEGIN(...)" declarator
# that swallowed the real definition immediately following it --
# `awk -v MODE=def -f tools/lint-decls.awk src/stdlib/abs.c` printed
# "NOLINTBEGIN<TAB>11" instead of "abs<TAB>11". That silently discarded
# abs()'s real definition and made this script misreport abs, bsearch,
# div, ecvt, fcvt, mblen, mkostemps, __ctype_get_mb_cur_max and others
# as "declared but never defined", even though every one of them is
# genuinely defined and archived into lib/libc.a. See
# tools/clang/LintDeclScanner.cpp's own header comment for the fuller
# story (it is the same class of bug tools/clang/DeclScanner.cpp already
# fixed for tools/linkcheck.sh) and its exact output contract.
#
# What counts as "declared": a top-level FunctionDecl with no body, in a
# header preprocessed the same way a real consumer's #include would see
# it (-D_XOPEN_SOURCE=700 -D_ALL_SOURCE, no -D_SPICULE_INTERNAL -- a
# public header is not library-internal code).  What counts as
# "defined": a top-level FunctionDecl WITH a body, in a .c file
# preprocessed the way this library's own build compiles it
# (-D_SPICULE_INTERNAL -Isrc/internal, matching the Makefile's
# CFLAGS_ALL).  Neither distinguishes a function's storage class (a
# `static` definition satisfies "defined" exactly like an external one),
# matching the old awk scanner, which never looked at linkage either.
#
# The .c-file scan runs once per arch this tree supports (i386, x86_64,
# aarch64), each with that arch's own real source set (the same
# base-file/arch-override/platform-override selection tools/lint.sh's
# own sources_for()/platform_for() apply for its clang-based stages,
# duplicated here rather than sourced -- tools/lint.sh dispatches
# immediately when run, so it cannot be sourced for just its helper
# functions without also running its own stage loop) and that arch's own
# --target= triple, rather than a single fixed arch: the old awk-based
# scan was arch- and platform-*blind* (a plain `find src arch crt -name
# '*.c'`, no override logic at all), so a function defined only under,
# say, arch/aarch64/src/ or src/*/linux/* was already counted as
# defined, and scanning only one arch here would have made that a new,
# false "never defined" finding -- a regression this rewrite is not
# allowed to introduce. See tools/lint-unreferenced.sh's own header for
# why an aarch64/i386 .c file can fail outright under a *mismatched*
# fixed arch (a real, observed failure mode, not a hypothetical one),
# which is the reason each arch gets its own real source set and target
# rather than one CFLAGS for everything.
#
# A declaration that is genuinely never meant to be implemented (a
# documented, permanent stub) is not this script's business to flag
# forever.  Mark it by adding a comment containing the literal text
# `undefined-ok:` and a reason, on the declaration's own line (every
# marker in this tree today is a trailing same-line comment; see
# tools/clang/LintDeclScanner.cpp's header for the exact text-range rule
# this applies):
#
#   int nice(int);  /* undefined-ok: no NT priority mapping decided yet */
#
# This subsumes what used to be a second, independent regex-based
# "markednames" pass with its own copy of the same naive name-extraction
# heuristic (a real risk: it turned out to be *wrong* by construction --
# it treated any declaration merely adjacent to a marked one as marked
# too, not just the one the marker actually named).  The AST walk
# computes undefined_ok per real declaration directly, so there is only
# ever one name-extraction heuristic in this script now, not two that
# could quietly drift apart.
#
# Usage:
#   tools/lint-undefined.sh [header ...]     default: include/**/*.h
#
# Environment:
#   LINT_STRICT=0      always exit 0 (report only)
#
# Exit status is 1 if any finding was reported (unless LINT_STRICT=0).
#
# Requires clang-18, clang++-18 and llvm-config-18 (with Clang 18's
# development libraries, for libclang-cpp.so.18*) on PATH -- the same
# toolchain tools/linkcheck.sh and tools/lint.sh's clang-based stages
# already require. Unlike the awk-based scanner this replaced, this is
# no longer a build-nothing, tool-nothing text scan: a header needs a
# real preprocess (obj/include/bits/alltypes.h's shape, generated here
# into a private tmpdir exactly the way tools/lint.sh's gen_alltypes()
# does, so this script does not depend on a prior `make`), and a .c file
# needs the same for the arch it belongs to.

set -u

# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

: "${LINT_STRICT:=1}"

headers=${*:-}
if [ -z "$headers" ]; then
	headers=$(find include -type f -name '*.h' | sort)
fi
# How many headers this run is responsible for, for the floor near the
# report below.  $headers is a whitespace-separated list and is meant to
# word-split here, exactly as it does at every `for h in $headers` below.
# shellcheck disable=SC2086
nheaders=$(printf '%s\n' $headers | grep -c . || true)

workdir=$(mktemp -d) || exit 1
trap 'rm -rf "$workdir"' EXIT INT TERM

# ---------------------------------------------------------------------
# The scanner: tools/clang/LintDeclScanner.cpp, a real clang AST walk
# (see that file's own header comment for the full contract). Built
# once, the same way tools/linkcheck.sh builds tools/clang/DeclScanner.cpp
# and tools/lint.sh builds its own PluginASTAction/CheckerRegistry clang
# plugins: clang++-18 against llvm-config-18's own flags, plus
# libclang-cpp.so.18* found under llvm-config-18's libdir, which
# FrontendPluginRegistry-based plugins need and llvm-config's own
# --libs/--system-libs do not provide.
# ---------------------------------------------------------------------
for lintdecls_tool in clang-18 clang++-18 llvm-config-18; do
	command -v "$lintdecls_tool" >/dev/null 2>&1 || {
		echo "lint-undefined: FAILED -- '$lintdecls_tool' not found on PATH." >&2
		echo "lint-undefined: the declaration scanner (tools/clang/LintDeclScanner.cpp) is a" >&2
		echo "lint-undefined: real clang AST walk, built and run the same way" >&2
		echo "lint-undefined: tools/linkcheck.sh builds tools/clang/DeclScanner.cpp -- see that" >&2
		echo "lint-undefined: script for what to install (CI: clang-18 libclang-18-dev llvm-18-dev)." >&2
		exit 1
	}
done
lintdecls_libdir=$(llvm-config-18 --libdir) || {
	echo "lint-undefined: FAILED -- 'llvm-config-18 --libdir' failed." >&2
	exit 1
}
lintdecls_clang_cpp=$(find "$lintdecls_libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
	-print 2>/dev/null | sort | head -n 1)
if [ -z "$lintdecls_clang_cpp" ]; then
	echo "lint-undefined: FAILED -- Clang 18 development libraries (libclang-cpp.so.18*) not" >&2
	echo "lint-undefined: found under '$lintdecls_libdir'.  Install them the same way CI does" >&2
	echo "lint-undefined: (libclang-18-dev)." >&2
	exit 1
fi
lintdecls_plugin="$workdir/spicule-lintdecls.so"
# llvm-config deliberately returns shell words, not one argument.
# shellcheck disable=SC2046
clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
	tools/clang/LintDeclScanner.cpp -o "$lintdecls_plugin" "$lintdecls_clang_cpp" \
	$(llvm-config-18 --ldflags --libs --system-libs) || {
	echo "lint-undefined: FAILED -- could not build tools/clang/LintDeclScanner.cpp into a" >&2
	echo "lint-undefined: clang plugin." >&2
	exit 1
}

# scan_one MODE FILE -- runs the plugin once, appending its stdout to
# the caller's redirect and any diagnostics to $workdir/scan.err.
# Returns nonzero (without aborting the loop it's called from -- callers
# accumulate this into their own _rc) on a scan failure, matching
# tools/linkcheck.sh's own scan()/check_one() shape: a per-item failure
# is recorded, not fatal to the whole run, so one broken file cannot
# silently truncate every other file's findings from the report.
scan_one() {
	# shellcheck disable=SC2086
	clang-18 -std=c99 -fsyntax-only $lintdecls_flags \
		-Xclang -load -Xclang "$lintdecls_plugin" \
		-Xclang -add-plugin -Xclang spicule-lintdecls \
		-Xclang -plugin-arg-spicule-lintdecls -Xclang "$1" \
		-Xclang -plugin-arg-spicule-lintdecls -Xclang "$2" \
		"$2" 2>> "$workdir/scan.err"
}

# ---- declared: name<TAB>file:line, one per header prototype, plus ---------
# ---- markednames: names covered by an `undefined-ok:` marker --------------
#
# One AST pass per header does both jobs at once (columns: name, path,
# line, undefined_ok) -- see the header comment above for why this
# folds what used to be lint-decls.awk's decl mode AND this script's own
# separate regex-based markednames pass into one real parse.
#
# Headers are preprocessed the way a real consumer's #include sees them:
# -D_XOPEN_SOURCE=700 -D_ALL_SOURCE, no -D_SPICULE_INTERNAL. ARCH=x86_64
# for bits/alltypes.h's shape -- a public header's declared function set
# does not vary by arch in this tree (checked: no header is arch-gated),
# so any one arch's types answer "what does this header declare" the
# same as any other; x86_64 matches tools/lint-unreferenced.sh's own
# default for the identical reason.
gendir="$workdir/gen/x86_64"
mkdir -p "$gendir/include/bits" || exit 1
cat "arch/x86_64/bits/alltypes.h.gen" include/alltypes.h.gen > "$gendir/include/bits/alltypes.h" || exit 1
lintdecls_flags="-nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -Iarch/x86_64 -Iarch/generic -I$gendir/include -Iinclude"

declfile="$workdir/declared"
markednames="$workdir/markednames"
: > "$declfile"
: > "$markednames"
: > "$workdir/scan.err"
decl_rc=0
for h in $headers; do
	scan_one decl "$h" || decl_rc=1
done > "$workdir/decl.raw"
while IFS="$(printf '\t')" read -r nm path ln ok; do
	[ -z "$nm" ] && continue
	printf '%s\t%s:%s\n' "$nm" "$path" "$ln" >> "$declfile"
	[ "$ok" = 1 ] && printf '%s\n' "$nm" >> "$markednames"
done < "$workdir/decl.raw"
sort -u -o "$markednames" "$markednames"
if [ "$decl_rc" -ne 0 ]; then
	echo "lint-undefined: FAILED -- the header scanner (clang-18 +" >&2
	echo "lint-undefined: tools/clang/LintDeclScanner.cpp) exited nonzero on at least one" >&2
	echo "lint-undefined: header; the declared-symbol list is incomplete, so nothing below" >&2
	echo "lint-undefined: can be trusted.  Diagnostics:" >&2
	sed 's/^/lint-undefined: /' "$workdir/scan.err" >&2
	exit 1
fi

# ---- defined: names from src/, arch/, crt/ C sources -----------------------
#
# One real per-arch source set and target per arch this tree supports
# (see the header comment above for why arch- and platform-blind
# coverage, not a single fixed arch, is required to avoid a regression
# from the old awk scan's own blind-but-complete behaviour). No sh/ or
# bin/: neither is part of libc.a and nothing they define is declared in
# include/ (see the Makefile's own SH_SRCS/BIN_SRCS comments).
platform_for() {
	case $1 in
	i386|x86_64) echo nt ;;
	aarch64)     echo linux ;;
	esac
}
triple_for() {
	case $1 in
	i386)    echo i686-w64-mingw32 ;;
	x86_64)  echo x86_64-w64-mingw32 ;;
	aarch64) echo aarch64-linux-gnu ;;
	esac
}
# The same source set the Makefile builds for one arch: base sources,
# minus any a same-named arch/ or platform/ override replaces, plus the
# arch sources, plus the platform sources -- see tools/lint.sh's
# sources_for() (this is a deliberate, commented duplicate of it; see
# the header comment above for why sourcing tools/lint.sh itself is not
# viable here).
sources_for() {
	arch=$1
	plat=$(platform_for "$arch")
	for f in src/*/*.c crt/*.c arch/"$arch"/src/*.c src/*/"$arch"/*.c \
	         src/*/"$plat"/*.c crt/"$plat"/*.c; do
		[ -e "$f" ] || continue
		case $f in
		src/*/*.c)
			d=${f%/*}; b=${f##*/}
			[ -e "$d/$arch/$b" ] && [ "${d##*/}" != "$arch" ] && continue
			;;
		esac
		echo "$f"
	done
}

definedfile="$workdir/defined"
: > "$definedfile"
def_rc=0
for arch in i386 x86_64 aarch64; do
	agendir="$workdir/gen/$arch"
	mkdir -p "$agendir/include/bits" || exit 1
	cat "arch/$arch/bits/alltypes.h.gen" include/alltypes.h.gen > "$agendir/include/bits/alltypes.h" || exit 1
	t=$(triple_for "$arch")
	lintdecls_flags="-nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL -Iarch/$arch -Iarch/generic -I$agendir/include -Iinclude -Isrc/internal ${t:+--target=$t}"
	for f in $(sources_for "$arch"); do
		scan_one def "$f" || def_rc=1
	done >> "$workdir/def.raw"
done
if [ "$def_rc" -ne 0 ]; then
	echo "lint-undefined: FAILED -- the .c-file scanner (clang-18 +" >&2
	echo "lint-undefined: tools/clang/LintDeclScanner.cpp) exited nonzero on at least one .c" >&2
	echo "lint-undefined: file; the defined-symbol list is incomplete, so nothing below can" >&2
	echo "lint-undefined: be trusted.  Diagnostics:" >&2
	sed 's/^/lint-undefined: /' "$workdir/scan.err" >&2
	exit 1
fi
cut -f1 "$workdir/def.raw" | sort -u > "$definedfile"

# ---- defined: assembly globals (*.S under src/, arch/, crt/) ------------
sfiles=$(find src arch crt -type f -name '*.S' 2>/dev/null)
for f in $sfiles; do
	grep -E '^\.globl?' "$f" 2>/dev/null
done | sed -e 's/^\.globl\?//' -e 's/_(\([A-Za-z_][A-Za-z0-9_]*\))/\1/g' \
	| tr ',' '\n' | tr -d ' \t' | grep -v '^$' >> "$definedfile"
sort -u -o "$definedfile" "$definedfile"

# ---- defined: names the linker resolves via ntdll.def --------------------
if [ -f tools/ntdll.def ]; then
	grep -v -E '^[[:space:]]*(;|LIBRARY|EXPORTS[[:space:]]*$)' tools/ntdll.def \
		| tr -d ' \t\r' | grep -v '^$' >> "$definedfile"
	sort -u -o "$definedfile" "$definedfile"
fi

# ---- floors: did this run have anything to compare? ----------------------
#
# The exit status below is a function of $findings alone, and $findings can
# only rise for a name that appears in $declfile.  So an empty $declfile --
# no headers found, or scan() stopping recognising prototypes -- prints
# "no findings" and exits 0, which is the same `0 = 0` defect
# tools/asan-build.sh had (855fdb2).  An empty $definedfile is the mirror
# image: every declared name would then look undefined, which is loud
# rather than silent, but it means the definition scan broke and the
# report is meaningless either way.
ndecl=$(grep -c . "$declfile" || true)
ndef=$(grep -c . "$definedfile" || true)
if [ "$ndecl" -eq 0 ]; then
	printf 'lint-undefined: FAILED -- no declarations were found in %s header(s).\n' \
		"$nheaders" >&2
	printf 'lint-undefined: nothing was compared, so this run verified nothing.\n' >&2
	exit 1
fi
if [ "$ndef" -eq 0 ]; then
	printf 'lint-undefined: FAILED -- no definitions were found in src/, arch/, crt/ or\n' >&2
	printf 'lint-undefined: tools/ntdll.def, so every one of the %s declared name(s) would\n' "$ndecl" >&2
	printf 'lint-undefined: be reported undefined.  The definition scan is broken, not the tree.\n' >&2
	exit 1
fi

# ---- report ---------------------------------------------------------------
sort -u -t "$(printf '\t')" -k1,1 "$declfile" | while IFS="$(printf '\t')" read -r nm loc; do
	[ -z "$nm" ] && continue
	grep -qxF "$nm" "$definedfile" && continue
	grep -qxF "$nm" "$markednames" && continue
	printf '%s: %s: declared but never defined (and not marked undefined-ok)\n' "$loc" "$nm"
done > "$workdir/report"

cat "$workdir/report"
# tools/lint.sh's stage_* functions all funnel their findings through its
# show_findings(), which is what calls tools/lint-gh-annotate.sh -- but
# this script runs standalone (see the dispatch at tools/lint.sh's tail:
# `undefined) tools/lint-undefined.sh ;;`, not a stage_undefined that
# could call back into lint.sh), so it calls the same shared helper
# directly.  A no-op unless GITHUB_ACTIONS=true; see that script's header.
tools/lint-gh-annotate.sh error "$workdir/report"
findings=$(grep -c . "$workdir/report")

if [ "$findings" -eq 0 ]; then
	printf 'lint-undefined: no findings (%s declared name(s) checked against %s definition(s))\n' \
		"$ndecl" "$ndef"
	exit 0
fi
printf 'lint-undefined: %d finding(s)\n' "$findings"
[ "$LINT_STRICT" = 0 ] && exit 0
exit 1
