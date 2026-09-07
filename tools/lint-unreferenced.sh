#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# lint-unreferenced.sh -- flag a function that a public header declares,
# that this library implements, and that no test/*.c references.
#
# tools/lint-undefined.sh answers "is every declared function defined?".
# This answers the next question along: of the ones that are defined, how
# many does the test suite never so much as call?  That population was
# discovered by hand once already -- test/POSIX-GAP-ACCOUNTING.md's "the
# remaining 112 implemented-but-unasserted functions" is the same set,
# described in prose after an audit -- and writing the very first
# assertion for one of them (vdprintf) immediately exposed a leak.  A
# number that costs an audit to obtain gets recomputed roughly never;
# this makes it a few seconds of a gate instead.
#
# ---------------------------------------------------------------------
# What "referenced" means here, and which way it errs
# ---------------------------------------------------------------------
#
# A name is REFERENCED if a test object file carries an undefined-symbol
# entry for it: the compiler emitted a relocation against that name from
# code it actually compiled.  Every test/*.c is compiled natively to an
# object with the same flags tools/asan-build.sh uses for them, and
# `nm --undefined-only` over the results is the reference set.
#
# This is deliberately narrower than the textual grep the earlier audit
# used (48d4025, "grepped against the concatenation of all test/*.c"),
# and narrower in the direction that matters: a name in a comment is not
# a reference.  `alarm` appears in test/fork-handles-win.c only inside a
# sentence explaining that it is a stub, and the grep counted that.
#
# Three consequences worth stating rather than discovering:
#
#   1. Only DIRECT references count.  test/posix-unistd.c calls symlink(),
#      and src/unistd/link.c's symlink() calls symlinkat() -- so symlinkat
#      is exercised, and this script still reports it, correctly: no test
#      names it, so no test can assert anything specific about it.
#      Transitive reachability is a coverage question and needs a coverage
#      instrument, not this one.
#   2. Ordinary code the native compile does not see does not count.  Policy
#      fences are the deliberate exception: tools/test-policy.py compiles
#      PASS, BUG and FLAKY cases as independent translation units, so this
#      script preprocesses those buildable fences with macro expansion and
#      counts their call sites too.  UNIMPL and NA fences stay off: the former
#      is defined by not building, and the latter is deliberately not probed.
#   3. "Referenced" is not "asserted".  A test that calls a function and
#      ignores the result satisfies this check.  It is still the right
#      first cut: a function no test even mentions is a larger and far
#      more tractable problem than the assertion-quality one behind it.
#   4. A function a public header also #defines as a macro can never
#      produce an undefined symbol, however hard a test calls it, so it
#      would be a permanent false positive.  The analysis this implements
#      supposed there were none of these in the tree; there are exactly
#      two -- include/alloca.h:29-33 defines `alloca` to
#      __builtin_alloca where the compiler has one (test/alloca.c does
#      call it, and the object carries no `alloca` relocation at all),
#      and include/setjmp.h does the same for `setjmp`.  Both are found
#      mechanically rather than listed by name, and the count is printed,
#      so a third one appearing is visible rather than silently excused.
#
# WHICH WAY THIS ERRS: toward reporting FEWER names than are truly
# unreferenced, never more.  Two files (test/rpath.c, test/delayall.c)
# are PE-only and do not compile natively at all; rather than let their
# references vanish -- which would report their subjects as unreferenced
# when they are the best-tested things in the tree -- their identifiers
# are harvested textually, comments and all.  That is the generous
# reading, and it is confined to those two files.  The result is that
# every name this script reports is a name no test object references and
# no PE-only test even mentions, so a reader who investigates one never
# discovers it was already covered.  The cost is that a name mentioned in
# a comment in exactly those two files is let through; today that
# suppresses two names (gets, spicule_delayLoadHelper2), which is a price
# worth paying for a worklist that does not cry wolf.
#
# ---------------------------------------------------------------------
# The floors
# ---------------------------------------------------------------------
#
# This script's finding count can only rise for a name that is in all
# three sets, so every set going empty is a silent pass -- the exact
# shape tools/asan-build.sh had (855fdb2) and that the rest of this tree
# has since been taught to reject.  Worse, the reference set going *big*
# is also a silent pass, and that is the easy accident: a test that stops
# compiling loses its references, which makes findings go UP; a build
# flag that makes every compile fail makes the reference set empty and
# every implemented function a finding, which is loud.  The dangerous
# direction is the quiet one, so the compile step is checked file by file
# rather than in aggregate:
#
#   * every test/*.c must either compile or be named in NOT_NATIVE below,
#     with a reason.  A partial run is a failure, not a smaller number.
#   * the declared, implemented and referenced sets must each be
#     non-empty.
#
# ---------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------
#
# Every declared-and-implemented function no test references is a
# finding, reported live, every run, with no ratchet and no committed
# count to compare against: a nonzero count fails.  The full sorted list
# is written to obj/lint/unreferenced.txt on every run.
#
# Usage:
#   tools/lint-unreferenced.sh
#
# Environment:
#   CC_NATIVE=...      native compiler for the test objects (default:
#                      clang, then cc)
#   LINT_JOBS=N        parallel compiles (default: nproc)
#   LINT_STRICT=0      always exit 0 (report only).  Does not relax the
#                      floors: a run that compiled nothing is a broken
#                      run, not a report of zero findings.
#
# Exit status is 1 if the finding count is nonzero, or if any floor was
# not met.
#
# The declared/implemented sets (which functions a header prototypes,
# and which a .c file actually defines) come from a real clang AST walk,
# tools/clang/LintDeclScanner.cpp -- see tools/lint-undefined.sh's header
# comment for the false-positive bug class this fixes in what used to be
# a shared hand-rolled awk scanner (tools/lint-decls.awk). This adds a
# clang-18/clang++-18/llvm-config-18 (with Clang 18 development
# libraries) requirement on top of the native-compiler-and-nm one
# already documented above, the same toolchain tools/linkcheck.sh and
# tools/lint.sh's clang-based stages already require.

set -u

# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

: "${LINT_STRICT:=1}"
: "${LINT_JOBS:=}"
if [ -z "$LINT_JOBS" ]; then
	LINT_JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

# The native compile is an ELF/LP64 compile of test sources written
# against this tree's own headers -- the same thing tools/asan-build.sh
# does, minus the sanitizers and minus the link.  Only -c is needed, so
# no ntstubs.o and no library.
: "${CC_NATIVE:=}"
if [ -z "$CC_NATIVE" ]; then
	if command -v clang >/dev/null 2>&1; then CC_NATIVE=clang
	elif command -v cc >/dev/null 2>&1; then CC_NATIVE=cc
	fi
fi
if [ -z "$CC_NATIVE" ]; then
	printf 'lint-unreferenced: MISSING -- no native compiler (tried clang, cc).\n' >&2
	printf 'lint-unreferenced: this stage cannot run, and a stage that cannot run\n' >&2
	printf 'lint-unreferenced: must not report success.\n' >&2
	exit 1
fi

# ARCH for the header set.  This is a native build, so the only sensible
# answer is the one whose bits/ headers describe this machine's word
# size; x86_64 is the tree's LLP64 arch and the one asan-build uses.
ARCH=${SPICULE_ARCH:-x86_64}

# Tests that genuinely cannot be compiled natively, with the reason, in
# the style of tools/asan-build.sh's not_native().  Anything here is
# scanned textually instead (see the header comment); anything NOT here
# must compile, or this run fails.
NOT_NATIVE="rpath delayall"
not_native_why() {
	case $1 in
	rpath)    echo "exercises the delay-load/\$ORIGIN machinery in src/internal/{rpath,delayload}.c, which is PE-only (LdrLoadDll/LdrGetProcedureAddress against a real NT image)" ;;
	delayall) echo "proof of the -Wl,--delay-all path (crt/delayload2.c, PE-only, same reason)" ;;
	*)        echo "" ;;
	esac
}

workdir=$(mktemp -d) || exit 1
trap 'rm -rf "$workdir"' EXIT INT TERM

# ---------------------------------------------------------------------
# The declared/implemented scanner: tools/clang/LintDeclScanner.cpp, a
# real clang AST walk that replaced tools/lint-decls.awk (see that
# file's own header comment, and tools/lint-undefined.sh's, for the
# false-positive bug class this fixes -- `// NOLINTBEGIN(...)` comments
# and ownership.h's `withtok()` prefix attribute both defeated the old
# awk's "first identifier before '('" heuristic). Built once, the same
# way tools/linkcheck.sh builds tools/clang/DeclScanner.cpp.
# ---------------------------------------------------------------------
for lintdecls_tool in clang-18 clang++-18 llvm-config-18; do
	command -v "$lintdecls_tool" >/dev/null 2>&1 || {
		echo "lint-unreferenced: FAILED -- '$lintdecls_tool' not found on PATH." >&2
		echo "lint-unreferenced: the declaration scanner (tools/clang/LintDeclScanner.cpp) is" >&2
		echo "lint-unreferenced: a real clang AST walk, built and run the same way" >&2
		echo "lint-unreferenced: tools/linkcheck.sh builds tools/clang/DeclScanner.cpp -- see" >&2
		echo "lint-unreferenced: that script for what to install (CI: clang-18 libclang-18-dev" >&2
		echo "lint-unreferenced: llvm-18-dev)." >&2
		exit 1
	}
done
lintdecls_libdir=$(llvm-config-18 --libdir) || {
	echo "lint-unreferenced: FAILED -- 'llvm-config-18 --libdir' failed." >&2
	exit 1
}
lintdecls_clang_cpp=$(find "$lintdecls_libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
	-print 2>/dev/null | sort | head -n 1)
if [ -z "$lintdecls_clang_cpp" ]; then
	echo "lint-unreferenced: FAILED -- Clang 18 development libraries (libclang-cpp.so.18*)" >&2
	echo "lint-unreferenced: not found under '$lintdecls_libdir'.  Install them the same way" >&2
	echo "lint-unreferenced: CI does (libclang-18-dev)." >&2
	exit 1
fi
lintdecls_plugin="$workdir/spicule-lintdecls.so"
# llvm-config deliberately returns shell words, not one argument.
# shellcheck disable=SC2046
clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
	tools/clang/LintDeclScanner.cpp -o "$lintdecls_plugin" "$lintdecls_clang_cpp" \
	$(llvm-config-18 --ldflags --libs --system-libs) || {
	echo "lint-unreferenced: FAILED -- could not build tools/clang/LintDeclScanner.cpp into a" >&2
	echo "lint-unreferenced: clang plugin." >&2
	exit 1
}
scan_one() {
	# scan_one MODE FILE -- see tools/lint-undefined.sh's identical helper.
	# shellcheck disable=SC2086
	clang-18 -std=c99 -fsyntax-only $lintdecls_flags \
		-Xclang -load -Xclang "$lintdecls_plugin" \
		-Xclang -add-plugin -Xclang spicule-lintdecls \
		-Xclang -plugin-arg-spicule-lintdecls -Xclang "$1" \
		-Xclang -plugin-arg-spicule-lintdecls -Xclang "$2" \
		"$2" 2>> "$workdir/scan.err"
}
: > "$workdir/scan.err"

# ---- declared: every function a public header prototypes ------------------
#
# Headers are preprocessed the way a real consumer's #include sees them
# (no -D_SPICULE_INTERNAL), ARCH=x86_64 for bits/alltypes.h's shape -- see
# tools/lint-undefined.sh's identical choice and its reasoning (a public
# header's declared function set does not vary by arch in this tree).
headers=$(find include -type f -name '*.h' | sort)
nheaders=$(printf '%s\n' "$headers" | grep -c . || true)
hdrgendir="$workdir/gen/x86_64"
mkdir -p "$hdrgendir/include/bits" || exit 1
cat "arch/x86_64/bits/alltypes.h.gen" include/alltypes.h.gen > "$hdrgendir/include/bits/alltypes.h" || exit 1
lintdecls_flags="-nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -Iarch/x86_64 -Iarch/generic -I$hdrgendir/include -Iinclude"
decl_rc=0
for h in $headers; do
	scan_one decl "$h" || decl_rc=1
done > "$workdir/decl.raw"
if [ "$decl_rc" -ne 0 ]; then
	echo "lint-unreferenced: FAILED -- the header scanner (clang-18 +" >&2
	echo "lint-unreferenced: tools/clang/LintDeclScanner.cpp) exited nonzero on at least one" >&2
	echo "lint-unreferenced: header.  Diagnostics:" >&2
	sed 's/^/lint-unreferenced: /' "$workdir/scan.err" >&2
	exit 1
fi
cut -f1 "$workdir/decl.raw" | sort -u > "$workdir/declared"
ndecl=$(grep -c . "$workdir/declared" || true)

# ---- macro-shadowed: declared as a function AND #defined as a macro -------
# See consequence 4 in the header.  A call to one of these never becomes a
# relocation, so it can never be "referenced" by this script's definition
# and would be a permanent finding.  Derived, not listed.
# shellcheck disable=SC2086
grep -rhE '^[[:space:]]*#[[:space:]]*define[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' $headers \
	| sed 's/.*define[[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\).*/\1/' \
	| sort -u > "$workdir/macros"
comm -12 "$workdir/declared" "$workdir/macros" > "$workdir/shadowed"
nshadow=$(grep -c . "$workdir/shadowed" || true)
comm -23 "$workdir/declared" "$workdir/shadowed" > "$workdir/declared.eff"
mv -f "$workdir/declared.eff" "$workdir/declared"
ndecl=$(grep -c . "$workdir/declared" || true)

# ---- implemented: every function src/, arch/, crt/, sh/ define ------------
#
# Deliberately NOT including tools/ntdll.def, unlike lint-undefined.sh: a
# name the linker imports from ntdll.dll is not something this library
# implements, so "no test references it" is not a gap in this tree's own
# coverage.  sh/ is left out for the mirror reason -- it is a program
# built on top of libc.a, not part of it, and nothing it defines is
# declared in include/ (checked: the two sets do not intersect today).
#
# One real per-arch source set and target per arch this tree supports
# (i386, x86_64, aarch64), not a single fixed arch: the old awk-based
# scan was arch- and platform-*blind* (a plain `find src arch crt -name
# '*.c'`, no Makefile override logic at all), so a function defined only
# under, say, arch/aarch64/src/ or src/*/linux/* was already counted as
# implemented, and scanning only one arch here would make that a new,
# false "unreferenced" finding once the required-arch test source (see
# below) also cannot exercise it -- a regression this rewrite must not
# introduce. A mismatched fixed arch is also not merely imprecise here:
# tools/lint.sh's own stage_totality() comment records hitting a hard
# `#error unsupported architecture` compiling an aarch64-only file under
# the wrong target, a real observed failure, not a hypothetical one.
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
# The same source set the Makefile builds for one arch -- see
# tools/lint.sh's sources_for() (this is a deliberate, commented
# duplicate of it, matching tools/lint-undefined.sh's identical copy;
# tools/lint.sh dispatches immediately when run, so it cannot be sourced
# for just its helper functions without also running its own stage loop).
lintdecls_sources_for() {
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
def_rc=0
: > "$workdir/def.raw"
for arch in i386 x86_64 aarch64; do
	agendir="$workdir/gen/$arch"
	mkdir -p "$agendir/include/bits" || exit 1
	cat "arch/$arch/bits/alltypes.h.gen" include/alltypes.h.gen > "$agendir/include/bits/alltypes.h" || exit 1
	t=$(triple_for "$arch")
	lintdecls_flags="-nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL -Iarch/$arch -Iarch/generic -I$agendir/include -Iinclude -Isrc/internal ${t:+--target=$t}"
	for f in $(lintdecls_sources_for "$arch"); do
		scan_one def "$f" || def_rc=1
	done >> "$workdir/def.raw"
done
if [ "$def_rc" -ne 0 ]; then
	echo "lint-unreferenced: FAILED -- the .c-file scanner (clang-18 +" >&2
	echo "lint-unreferenced: tools/clang/LintDeclScanner.cpp) exited nonzero on at least one" >&2
	echo "lint-unreferenced: .c file.  Diagnostics:" >&2
	sed 's/^/lint-unreferenced: /' "$workdir/scan.err" >&2
	exit 1
fi
cut -f1 "$workdir/def.raw" | sort -u > "$workdir/implemented"
sfiles=$(find src arch crt -type f -name '*.S' 2>/dev/null)
for f in $sfiles; do
	grep -E '^\.globl?' "$f" 2>/dev/null
done | sed -e 's/^\.globl\?//' -e 's/_(\([A-Za-z_][A-Za-z0-9_]*\))/\1/g' \
	| tr ',' '\n' | tr -d ' \t' | grep -v '^$' >> "$workdir/implemented"
sort -u -o "$workdir/implemented" "$workdir/implemented"
nimpl=$(grep -c . "$workdir/implemented" || true)

# ---- referenced: undefined symbols of natively compiled test objects ------
gendir=$workdir/gen/include/bits
mkdir -p "$gendir" "$workdir/obj" || exit 1
cat "arch/$ARCH/bits/alltypes.h.gen" include/alltypes.h.gen > "$gendir/alltypes.h" || exit 1

TINC="-I$workdir/gen/include -I$srcdir/include -I$srcdir/arch/$ARCH -I$srcdir/arch/generic"

# -O0, not asan-build's -O1: at -O1 a call whose result is unused can be
# eliminated before it ever becomes a relocation, which would report a
# function as unreferenced because the optimiser agreed the test did
# nothing with it.  -fno-builtin is kept for the same reason one level
# down -- it stops the compiler folding str*/mem* calls into inline code.
CFLAGS_NATIVE="-c -O0 -std=c99 -nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -w"

ntests=0 ncompiled=0 nexcluded=0
: > "$workdir/tocompile"
for t in test/*.c; do
	n=$(basename "$t" .c)
	ntests=$((ntests + 1))
	case " $NOT_NATIVE " in
	*" $n "*)
		nexcluded=$((nexcluded + 1))
		printf '%s\t%s\n' "$t" "$(not_native_why "$n")" >> "$workdir/textscan"
		continue ;;
	esac
	printf '%s\n' "$t" >> "$workdir/tocompile"
done

if [ -s "$workdir/tocompile" ]; then
	# $CFLAGS_NATIVE and $TINC are flag lists and must word-split; the
	# $workdir splice into the single-quoted child script is the
	# close-quote/reopen-quote trick tools/lint.sh uses for $pardir, for
	# the same reason (this shell substitutes it, the child does not).
	# shellcheck disable=SC2086,SC2016
	xargs -P "$LINT_JOBS" -I{} sh -c '
		f=$1; cc=$2; shift 2
		n=$(basename "$f" .c)
		# shellcheck disable=SC2086
		"$cc" "$@" "$f" -o "'"$workdir"'/obj/$n.o" \
			2> "'"$workdir"'/obj/$n.err"
	' _ {} "$CC_NATIVE" $CFLAGS_NATIVE $TINC < "$workdir/tocompile"
fi

: > "$workdir/nocompile"
while read -r t; do
	n=$(basename "$t" .c)
	if [ -f "$workdir/obj/$n.o" ]; then
		ncompiled=$((ncompiled + 1))
	else
		printf '%s\n' "$t" >> "$workdir/nocompile"
	fi
done < "$workdir/tocompile"

: > "$workdir/symrefs"
if ls "$workdir"/obj/*.o >/dev/null 2>&1; then
	nm --undefined-only "$workdir"/obj/*.o 2>/dev/null \
		| awk '{ print $NF }' | sed 's/@@.*//' | grep -v '^$' >> "$workdir/symrefs"
fi
sort -u -o "$workdir/symrefs" "$workdir/symrefs"
nsym=$(grep -c . "$workdir/symrefs" || true)

# Policy-fenced tests are absent from the ordinary objects above because
# test/test-policy.h deliberately expands every SPICULE_TEST() to zero.
# The policy runner turns one buildable case on at a time.  For reference
# accounting it is enough (and much cheaper) to turn every buildable kind on
# for preprocessing: no definitions are linked, while macro expansion keeps
# indirect public helpers such as __pthread_cleanup_push visible.  Line
# markers restrict extraction to the test source itself, excluding the public
# header prototypes that preprocessing also emits.
: > "$workdir/policyrefs"
: > "$workdir/policyfail"
mkdir -p "$workdir/policy" || exit 1
for t in test/*.c; do
	n=$(basename "$t" .c)
	case " $NOT_NATIVE " in
	*" $n "*) continue ;;
	esac
	# TINC deliberately expands to the four generated/source include options.
	# shellcheck disable=SC2086
	if ! sed -E 's/^([[:space:]]*#[[:space:]]*if[[:space:]]+)SPICULE_TEST\([[:space:]]*(PASS|BUG|FLAKY),[^)]*\)/\1 1/' "$t" |
		"$CC_NATIVE" -E -std=c99 -nostdinc -fno-builtin -D_XOPEN_SOURCE=700 \
		-D_GNU_SOURCE -I"$srcdir/test" $TINC -x c - \
		> "$workdir/policy/$n.i" 2> "$workdir/policy/$n.err"; then
		printf '%s\n' "$t" >> "$workdir/policyfail"
		continue
	fi
	awk '
		$1 == "#" && $2 ~ /^[0-9]+$/ {
			active = ($3 == "\"<stdin>\"")
			next
		}
		active { print }
	' "$workdir/policy/$n.i" |
		grep -oE '[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(' |
		sed 's/[[:space:]]*($//' >> "$workdir/policyrefs" || true
done
sort -u -o "$workdir/policyrefs" "$workdir/policyrefs"
npolicy=$(grep -c . "$workdir/policyrefs" || true)

cp "$workdir/symrefs" "$workdir/referenced"
cat "$workdir/policyrefs" >> "$workdir/referenced"
# The generous textual pass, for the PE-only files only.
if [ -f "$workdir/textscan" ]; then
	while IFS="$(printf '\t')" read -r t why; do
		printf 'lint-unreferenced: %s scanned textually, not compiled: %s\n' \
			"$t" "$why" >&2
		grep -oE '[A-Za-z_][A-Za-z0-9_]*' "$t"
	done < "$workdir/textscan" >> "$workdir/referenced"
fi
sort -u -o "$workdir/referenced" "$workdir/referenced"
nref=$(grep -c . "$workdir/referenced" || true)

# ---- floors ---------------------------------------------------------------
floor_failed=0
if [ "$ndecl" -eq 0 ]; then
	printf 'lint-unreferenced: FAILED -- no function declarations found in %s header(s).\n' \
		"$nheaders" >&2
	printf 'lint-unreferenced: nothing was compared, so this run verified nothing.\n' >&2
	floor_failed=1
fi
if [ "$nimpl" -eq 0 ]; then
	printf 'lint-unreferenced: FAILED -- no definitions found in src/, arch/, crt/ or sh/.\n' >&2
	printf 'lint-unreferenced: the "is it implemented" filter would then pass nothing, so\n' >&2
	printf 'lint-unreferenced: this run reports zero findings by construction.\n' >&2
	floor_failed=1
fi
if [ "$ntests" -eq 0 ]; then
	printf 'lint-unreferenced: FAILED -- no test/*.c found at all.\n' >&2
	floor_failed=1
fi
if [ -s "$workdir/nocompile" ]; then
	printf 'lint-unreferenced: FAILED -- %d of %d test source(s) did not compile:\n' \
		"$(grep -c . "$workdir/nocompile")" "$((ntests - nexcluded))" >&2
	while read -r t; do
		n=$(basename "$t" .c)
		printf 'lint-unreferenced:   %s\n' "$t" >&2
		sed -n '1,3p' "$workdir/obj/$n.err" 2>/dev/null | sed 's/^/lint-unreferenced:     /' >&2
	done < "$workdir/nocompile"
	printf 'lint-unreferenced: a test that does not compile contributes no references, so\n' >&2
	printf 'lint-unreferenced: its subjects would be reported unreferenced.  Fix the compile,\n' >&2
	printf 'lint-unreferenced: or add the test to NOT_NATIVE in this script with a reason --\n' >&2
	printf 'lint-unreferenced: never leave it silently uncounted.\n' >&2
	floor_failed=1
fi
if [ -s "$workdir/policyfail" ]; then
	printf 'lint-unreferenced: FAILED -- policy-fence preprocessing failed for:\n' >&2
	while read -r t; do
		n=$(basename "$t" .c)
		printf 'lint-unreferenced:   %s\n' "$t" >&2
		sed -n '1,3p' "$workdir/policy/$n.err" 2>/dev/null |
			sed 's/^/lint-unreferenced:     /' >&2
	done < "$workdir/policyfail"
	printf 'lint-unreferenced: those cases contribute no trustworthy references.\n' >&2
	floor_failed=1
fi
# Counted on the nm output alone, not on the merged set: the textual pass
# over the two PE-only files contributes ~370 identifiers no matter what
# the symbol scan does, so a floor on the merged set could not tell a
# working nm from a broken one.
if [ "$nsym" -eq 0 ]; then
	printf 'lint-unreferenced: FAILED -- the %d compiled test object(s) yielded no\n' \
		"$ncompiled" >&2
	printf 'lint-unreferenced: undefined symbols at all.  Every implemented function would\n' >&2
	printf 'lint-unreferenced: then look unreferenced; the reference scan is broken, not the\n' >&2
	printf 'lint-unreferenced: tests.\n' >&2
	floor_failed=1
fi
[ "$floor_failed" -ne 0 ] && exit 1

# ---- report ---------------------------------------------------------------
comm -12 "$workdir/declared" "$workdir/implemented" > "$workdir/declimpl"
ndeclimpl=$(grep -c . "$workdir/declimpl" || true)
comm -23 "$workdir/declimpl" "$workdir/referenced" > "$workdir/unreferenced"
findings=$(grep -c . "$workdir/unreferenced" || true)

mkdir -p obj/lint
cp "$workdir/unreferenced" obj/lint/unreferenced.txt

printf 'lint-unreferenced: %s declared, %s implemented, %s both.\n' \
	"$ndecl" "$nimpl" "$ndeclimpl"
printf 'lint-unreferenced: %s name(s) referenced: %s undefined symbol(s) over %d compiled\n' \
	"$nref" "$nsym" "$ncompiled"
printf 'lint-unreferenced:   test object(s), plus %d PE-only source(s) scanned textually.\n' \
	"$nexcluded"
printf 'lint-unreferenced:   %s call name(s) recovered from buildable policy fences.\n' \
	"$npolicy"
printf 'lint-unreferenced: %s declaration(s) excluded as macro-shadowed: %s\n' \
	"$nshadow" "$(tr '\n' ' ' < "$workdir/shadowed")"
printf 'lint-unreferenced: %s declared-and-implemented function(s) no test references\n' "$findings"
printf 'lint-unreferenced: full list -> obj/lint/unreferenced.txt\n'

if [ "$findings" -gt 0 ]; then
	printf 'lint-unreferenced: FAILED -- %d declared-and-implemented function(s) no test\n' \
		"$findings" >&2
	printf 'lint-unreferenced: references:\n' >&2
	sed 's/^/lint-unreferenced:   /' obj/lint/unreferenced.txt >&2
	[ "$LINT_STRICT" = 0 ] && exit 0
	exit 1
fi
exit 0
