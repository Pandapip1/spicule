#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# tools/libc-test.sh -- build and run musl's libc-test corpus
# (third_party/libc-test, a git submodule pinned at the SHA recorded in
# third_party/README.md) against this library, and
# adjudicate every result against test/libc-test-expected.txt.
#
# WHY THIS SCRIPT IS SHAPED THE WAY IT IS
#
# test/external-suites.md measured this corpus against the tree and found
# 22 behavioural defects on the first run. A ledger must make those known
# states reviewable without turning into an append-only exemption list.
#
#   * test/libc-test-expected.txt lists only the tests whose disposition
#     deviates from PASS, plus one trailing wildcard row (case "*") that
#     declares PASS as this corpus's own default for every test with no
#     more specific row -- the same mechanism test/posix-opts-expected.txt
#     uses (commit 93bbaa3, "test: default posix-opts cases to PASS via an
#     explicit wildcard row"; tools/testlib.py's resolve() is what applies
#     it). Which tests are real is independent of what the ledger lists:
#     this script globs third_party/libc-test/src/{functional,regression}
#     itself and hands that list to test-policy.py's --cases-file, so a
#     trimmed ledger cannot silently drop a real test from adjudication --
#     an unlisted one still resolves, just via the wildcard row rather than
#     an explicit one. A test built/run here that is in neither the ledger
#     nor that independently-discovered list is still a hard error: today
#     that can only be the on-demand math corpus below, which deliberately
#     carries no ledger rows at all.
#   * Pedantic requires BUG to compile and fail and UNIMPL not to compile.
#     A fixed defect therefore forces the ledger to be updated.
#   * The ledger carries pinned counts in its header, and this script
#     checks them. A disposition population cannot change silently.
#   * The ledger uses the same PASS/BUG/UNIMPL/NA/FLAKY dispositions as
#     the in-tree suite. Raw compiler and process outcomes remain separate.
#
# OBSERVATIONS AND DISPOSITIONS
#
# Same contract as tools/run-tests.py (see its header): 0 pass, 77 "ran
# but declined to check something", anything else fail.  Mapped here:
#
#   does not compile/link  -> UNBUILDABLE observation. UNIMPL expects it.
#                             52 of the 146
#                             tests die at #include; that is the gap
#                             accounting restated as a build error, and
#                             it is evidence of nothing about behaviour.
#   output contains the    -> NA for this runtime. The shim
#   shim's stub marker        stubs two helpers it cannot implement here
#                             (both need enforced resource limits); a test
#                             whose premise was stubbed
#                             out did not check its premise.
#   output contains Wine's -> NA for this runtime. Detected at run time from
#   RtlCloneUserProcess       the output, never from a static list: these
#   string                    same tests run for real on the Windows CI
#                             leg and on a Wine build that implements it,
#                             and a baked-in exclusion would hide that.
#   otherwise              -> the exit status is the verdict.
#
# The summary prints UNIMPL even when it is the largest number,
# because "39% of this suite cannot be compiled against this library" is
# the most useful single fact this stage produces.  And a run in which
# nothing was actually adjudicated exits non-zero (the VERIFIED_FLOOR
# below) -- measure M1 of test/verification-measures.md applied here.
#
# THE MATH CORPUS
#
# Present in the submodule but never built by default, and not wired into
# tools/gate.sh; `tools/libc-test.sh math` says so and exits non-zero
# unless explicitly pointed at a checkout.  See the `math` case below for
# the two reasons (licence, and 82 untriaged failures).
#
# Usage:
#   tools/libc-test.sh              build + run + adjudicate (the gate)
#   tools/libc-test.sh math         the on-demand math corpus
#   tools/libc-test.sh --selftest   prove the guards below still fire
#
# Env:
#   WINE            wine binary (default: config.mak's WINE)
#   LIBC_TEST_JOBS  parallel workers (default: nproc)
#   LIBC_TEST_MATH  path to a full libc-test checkout, for `math`
#   SPICULE_TEST_PROFILE  whitespace-separated additional KEY=VALUE selectors

set -u

# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

SUITE="$srcdir/third_party/libc-test"
LEDGER="$srcdir/test/libc-test-expected.txt"
SHIM="$srcdir/test/libc-test-shim-src/libc-test-shim.c"

# The literal the shim prints from every stubbed helper.  Load-bearing:
# --selftest asserts it still occurs in the shim, so renaming it in one
# place without the other fails loudly instead of silently promoting the
# stubbed tests to passes.
SHIM_MARK='SHIM-STUBBED: '
# The literal Wine prints when RtlCloneUserProcess is missing.
WINE_MARK='RtlCloneUserProcess'

# The floor on this stage: how many tests must produce a real verdict
# (built, ran, was neither shim-stubbed nor Wine-blocked) for the run to
# count as having verified anything.  Deliberately well below the 86 seen
# on a Wine that implements RtlCloneUserProcess -- it is a floor, not the
# expected value, and it exists so that a run where the toolchain, the
# library or Wine has fallen over cannot report success.  It only moves
# deliberately.
VERIFIED_FLOOR=70

# Normal skips known BUG and UNIMPL cases. Pedantic probes both to catch
# stale classifications. Strict performs the same probes, then disallows
# either disposition and requires every FLAKY case to pass.
: "${SPICULE_TEST_MODE:=normal}"
: "${SPICULE_TEST_RUNTIME:=wine}"
: "${SPICULE_TEST_PROFILE:=}"
case "$SPICULE_TEST_MODE" in
	normal|pedantic|strict) ;;
	*) echo "libc-test: SPICULE_TEST_MODE must be normal, pedantic or strict." >&2; exit 2 ;;
esac

usage() { sed -n '2,82p' "$0" | sed 's/^# \{0,1\}//'; }

# ------------------------------------------------------- the submodule

# third_party/libc-test is a git submodule (see .gitmodules and
# third_party/README.md).  A clone made without
# --recurse-submodules leaves it as an EMPTY DIRECTORY -- not a stale
# one, not a partial one -- and every loop below that walks
# "$SUITE"/src/... would then find nothing and adjudicate nothing.
#
# That must be a loud failure and never a skip, for exactly the reason
# the `math` case below exits 2 rather than shrugging: a verification
# stage that reports success having run zero tests is worse than one that
# is missing, because it looks like evidence.  This project closed nine
# such stages in a day (test/verification-measures.md); an absent
# submodule must not open a tenth.
#
# Note what this check is NOT: it is not a network fallback.  There is no
# cached copy to degrade to and no fetch attempted here.  It names the
# one command that fixes it and gets out of the way.
require_suite() {
	if [ -f "$SUITE/COPYRIGHT" ] && [ -d "$SUITE/src/functional" ] &&
	   [ -d "$SUITE/src/common" ] && [ -d "$SUITE/src/regression" ]; then
		return 0
	fi
	echo "libc-test: third_party/libc-test is empty or incomplete." >&2
	echo "libc-test: it is a git submodule -- musl's libc-test, pinned at the" >&2
	echo "libc-test: SHA recorded in third_party/README.md -- and this clone" >&2
	echo "libc-test: does not have it checked out.  Fix it with:" >&2
	echo "libc-test:" >&2
	echo "libc-test:     git submodule update --init --recursive" >&2
	echo "libc-test:" >&2
	echo "libc-test: (or clone with --recurse-submodules next time)." >&2
	echo "libc-test: This is an error, not a skip.  Without the corpus this" >&2
	echo "libc-test: stage would build nothing, run nothing and adjudicate" >&2
	echo "libc-test: nothing -- and a stage that reports success having" >&2
	echo "libc-test: checked nothing is the exact failure this project's" >&2
	echo "libc-test: verification measures exist to prevent." >&2
	exit 2
}

# ---------------------------------------------------------------- ledger

# Parsed once into three shell-safe lookup files rather than re-grepped
# per test. $2, if given, is a newline-separated file naming the real,
# independently-discovered case list (see its construction below, right
# before this is called) -- passed straight through to test-policy.py's
# --cases-file so an unlisted real case still resolves via the ledger's
# wildcard row instead of vanishing from adjudication. --selftest calls
# this with no $2: it only checks that the ledger parses, and does not
# require the corpus to be checked out at all.
read_ledger() {
	[ -f "$LEDGER" ] || { echo "libc-test: missing $LEDGER" >&2; return 1; }
	awk -v out="$1" '
	/^#[ \t]*COUNTS[ \t]/ { print "COUNTS " $0 > out "/counts"; next }
	/^[ \t]*#/ || /^[ \t]*$/ { next }
	{
		if (NF < 3) { print "MALFORMED " $0 > out "/errors"; next }
		name=$1; selector=$2; status=$3
		reason=""
		for (i=4;i<=NF;i++) reason = reason (i>4?" ":"") $i
		if (status != "PASS" && status != "BUG" && status != "UNIMPL" &&
		    status != "NA" && status != "FLAKY") {
			print "BADSTATUS " name " " status > out "/errors"; next
		}
		if (status != "PASS" && reason == "") {
			print "NOREASON " name > out "/errors"; next
		}
		key=name SUBSEP selector
		if (key in seen) { print "DUPLICATE " name " " selector > out "/errors"; next }
		seen[key]=1
		print name "\t" selector "\t" status "\t" reason > out "/base"
	}' "$LEDGER"
	[ -f "$1/errors" ] && return 0
	profile_args=""
	for term in $SPICULE_TEST_PROFILE; do
		profile_args="$profile_args --profile $term"
	done
	cases_args=""
	[ -n "${2:-}" ] && cases_args="--cases-file $2"
	# profile selectors are whitespace-separated, so this one has to split.
	# shellcheck disable=SC2086
	"$srcdir/tools/test-policy.py" resolve --suite libc-test \
		--defaults "$LEDGER" --profile "runtime=$SPICULE_TEST_RUNTIME" \
		$cases_args $profile_args > "$1/rows" || return 1
	return 0
}

ledger_status() { awk -F'\t' -v n="$1" '$1==n{print $2; f=1} END{if(!f) print "ABSENT"}' "$W/rows"; }
ledger_reason() { awk -F'\t' -v n="$1" '$1==n{print $3}' "$W/rows"; }

# ------------------------------------------------------------------ math

# --selftest checks only in-tree artefacts (the shim and the ledger) and
# is deliberately still usable without the corpus; everything else needs
# it, so demand it here, before any work.
[ "${1:-}" = "--selftest" ] || require_suite

if [ "${1:-}" = "math" ]; then
	# The submodule brings src/math with it -- it is on disk, roughly
	# 9.6 MB of it -- but it is deliberately NOT built, for two
	# independent reasons, either sufficient:
	#
	#  1. Licence.  src/math/ucb/ and src/math/crlibm/ are BSD- and
	#     GPL-licensed third-party vectors (libc-test's own COPYRIGHT
	#     says so); the rest of the corpus is uniformly MIT.  This tree
	#     distributes a 20-byte gitlink, not those vectors, and building
	#     them into anything we ship would change that.
	#  2. Readiness.  82 of its 174 linkable tests fail here and there
	#     is no ledger for any of them, so this mode reports; it does
	#     not adjudicate.  external-suites.md says it stays on demand
	#     until those are triaged.
	#
	# What it must NOT do is quietly succeed.  No opt-in, no run, no
	# zero exit -- the same rule the submodule guard above enforces.
	if [ -z "${LIBC_TEST_MATH:-}" ]; then
		echo "libc-test: the math corpus is present in the submodule but is" >&2
		echo "libc-test: not adjudicated by this tree: 82 of its 174 linkable" >&2
		echo "libc-test: tests fail here and none has been triaged, and its" >&2
		echo "libc-test: vectors under src/math/ucb and src/math/crlibm are" >&2
		echo "libc-test: BSD/GPL rather than MIT (test/external-suites.md and" >&2
		echo "libc-test: third_party/README.md).  To run it anyway, opt in" >&2
		echo "libc-test: explicitly:" >&2
		echo "libc-test:" >&2
		echo "libc-test:     LIBC_TEST_MATH=third_party/libc-test $0 math" >&2
		echo "libc-test:" >&2
		echo "libc-test: This is an error, not a skip: a stage that reports" >&2
		echo "libc-test: success having run nothing is the thing this" >&2
		echo "libc-test: project's verification measures exist to prevent." >&2
		exit 2
	fi
	if [ ! -d "$LIBC_TEST_MATH/src/math" ]; then
		echo "libc-test: LIBC_TEST_MATH=$LIBC_TEST_MATH has no src/math." >&2
		exit 2
	fi
	echo "libc-test: the math corpus has no ledger yet; every result below is"
	echo "libc-test: UNCLASSIFIED by construction.  This mode reports; it does"
	echo "libc-test: not adjudicate, and it is not wired into tools/gate.sh."
	MATH_SRC="$LIBC_TEST_MATH"
else
	MATH_SRC=""
fi

# -------------------------------------------------------------- selftest

if [ "${1:-}" = "--selftest" ]; then
	rc=0
	if ! grep -q "$SHIM_MARK" "$SHIM"; then
		echo "selftest: FAIL -- $SHIM no longer prints '$SHIM_MARK'." >&2
		echo "selftest: the stubbed-helper detection in this script is keyed" >&2
		echo "selftest: to that literal; without it two structurally" >&2
		echo "selftest: runtime-NA tests would be adjudicated as ordinary" >&2
		echo "selftest: failures or passes." >&2
		rc=1
	else
		echo "selftest: OK -- shim marker present in test/libc-test-shim-src/libc-test-shim.c"
	fi
	W=$(mktemp -d) || exit 1
	trap 'rm -rf "$W"' EXIT
	if read_ledger "$W" && [ ! -f "$W/errors" ]; then
		echo "selftest: OK -- ledger parses with no malformed rows"
	else
		echo "selftest: FAIL -- ledger has malformed rows:" >&2
		cat "$W/errors" >&2 2>/dev/null
		rc=1
	fi
	# Every non-PASS disposition must explain why it applies.
	bad="$W/bad-ledger"
	printf '# COUNTS PASS=0 BUG=0 UNIMPL=0 NA=0 FLAKY=0\nsome-test runtime=wine NA\n' > "$bad"
	mkdir -p "$W/b"
	# read_ledger reads the global LEDGER; save and restore it rather
	# than prefixing the call, because a variable assignment prefixed to
	# a FUNCTION invocation persists after it in some POSIX shells and
	# would leave the rest of this script pointed at a fake ledger.
	real_ledger="$LEDGER"
	LEDGER="$bad"
	read_ledger "$W/b" 2>/dev/null
	LEDGER="$real_ledger"
	if grep -q '^NOREASON some-test$' "$W/b/errors" 2>/dev/null; then
		echo "selftest: OK -- an unexplained non-PASS row is rejected"
	else
		echo "selftest: FAIL -- an unexplained NA row was accepted." >&2
		rc=1
	fi
	exit $rc
fi

if [ "${1:-}" != "" ] && [ "${1:-}" != "math" ]; then
	usage; exit 2
fi

# ---------------------------------------------------------------- config

[ -f "$srcdir/config.mak" ] || {
	echo "libc-test: no config.mak; run ./configure first." >&2; exit 2; }
cfg() { sed -n "s/^$1 *= *//p" "$srcdir/config.mak" | tail -1; }
CC=$(cfg CC); ARCH=$(cfg ARCH)
CFLAGS_C99FSE=$(cfg CFLAGS_C99FSE); CFLAGS_AUTO=$(cfg CFLAGS_AUTO)
: "${WINE:=$(cfg WINE)}"
: "${LIBC_TEST_JOBS:=$(nproc 2>/dev/null || echo 1)}"

[ -n "$CC" ] || { echo "libc-test: config.mak has no CC." >&2; exit 2; }
[ -f "$srcdir/lib/libc.a" ] || {
	echo "libc-test: lib/libc.a is missing; run make first." >&2; exit 2; }
if [ -z "$WINE" ]; then
	# Same reasoning as tools/run-tests.py: "no wine at all" is the whole
	# stage going empty, not a per-test exception, so it fails.
	echo "libc-test: config.mak has no WINE and none was given." >&2
	echo "libc-test: nothing would run; that is a failure, not a skip." >&2
	exit 1
fi

# The shim-marker pin, enforced on every run and not only under
# --selftest: the two 77s that come from a stubbed helper are detected by
# grepping the test's output for this literal, so if the shim stops
# printing it those tests silently become ordinary failures or -- worse
# -- ordinary passes.  Cheap enough to do unconditionally.
if ! grep -q "$SHIM_MARK" "$SHIM"; then
	echo "libc-test: FAILED -- test/libc-test-shim-src/libc-test-shim.c no longer prints" >&2
	echo "libc-test: '$SHIM_MARK', which is what this script keys the" >&2
	echo "libc-test: stubbed-helper 77s to.  See --selftest." >&2
	exit 1
fi

INC="-I$srcdir/arch/$ARCH -I$srcdir/arch/generic -Iobj/include -I$srcdir/include -I$SUITE/src/common"

W=$(mktemp -d "${TMPDIR:-/tmp}/spicule-libctest.XXXXXX") || exit 1
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/out" obj/libc-test

# The real, independently-discovered case list test/libc-test-expected.txt's
# wildcard row depends on: every source musl's libc-test ships directly
# under functional/ and regression/ -- never the on-demand math corpus
# below, which carries no ledger rows at all and stays unaccounted for on
# purpose. Built from the filesystem, not from what the (now much shorter)
# ledger happens to list, for the same reason tools/posix-opts.py passes
# its own IFACES.rglob("*.c") discovery to --cases-file: trimming the
# ledger down to its exceptions must not let any real corpus member
# silently fall out of adjudication. Reused below as the base of $corpus
# too, so the two lists cannot drift apart.
ledger_corpus=""
for f in "$SUITE"/src/functional/*.c "$SUITE"/src/regression/*.c; do
	[ -f "$f" ] || continue
	ledger_corpus="$ledger_corpus $f"
done
for f in $ledger_corpus; do
	basename "$f" .c
done > "$W/cases.txt"

read_ledger "$W" "$W/cases.txt" || exit 2
if [ -f "$W/errors" ]; then
	echo "libc-test: test/libc-test-expected.txt is malformed:" >&2
	sed 's/^/    /' "$W/errors" >&2
	exit 2
fi

# ----------------------------------------------------------------- build

# The helpers we keep from upstream's src/common. setrlim.c and fdfill.c are
# deliberately absent: test/libc-test-shim-src/libc-test-shim.c replaces them
# (see its header for each one's reason). vmfill.c is real: mmap()'s registry
# grows dynamically, so the helper can run to actual address-space exhaustion.
#
# utf8.c needs <langinfo.h> and nl_langinfo(CODESET), which this library
# has (include/langinfo.h, src/misc/langinfo.c), so upstream's own
# helper compiles and does its real job here: its setlocale() chain
# finds no named UTF-8 locale, falls through to setlocale(LC_CTYPE, ""),
# and then nl_langinfo(CODESET) answers "UTF-8" -- which is the truth on
# this target, UTF-8 being the only encoding this library has.  Running
# the real helper rather than a stub is what lets the tests behind it
# be adjudicated on their behaviour instead of parked as unverified.
HELPERS="print rand path memfill utf8 vmfill"
hobjs=""
for h in $HELPERS; do
	# shellcheck disable=SC2086  # $CC/$CFLAGS_*/$INC are word lists from
	# config.mak, exactly as the Makefile's own recipes use them.
	if ! $CC -c $CFLAGS_C99FSE $CFLAGS_AUTO -D_GNU_SOURCE $INC \
	     -o "obj/libc-test/$h.o" "$SUITE/src/common/$h.c" 2>"$W/$h.err"; then
		echo "libc-test: the shared harness helper $h.c does not compile." >&2
		echo "libc-test: this is not a per-test gap -- nothing can run." >&2
		sed 's/^/    /' "$W/$h.err" >&2
		exit 1
	fi
	hobjs="$hobjs obj/libc-test/$h.o"
done
# shellcheck disable=SC2086
if ! $CC -c $CFLAGS_C99FSE $CFLAGS_AUTO -D_GNU_SOURCE $INC \
     -o obj/libc-test/shim.o "$SHIM" 2>"$W/shim.err"; then
	echo "libc-test: test/libc-test-shim-src/libc-test-shim.c does not compile." >&2
	sed 's/^/    /' "$W/shim.err" >&2
	exit 1
fi
hobjs="$hobjs obj/libc-test/shim.o"

# See test/libc-test-shim-src/libc-test-rpath-stub.c's own header: the
# no-op __rpath a real dlopen() consumer with no extra search
# directories would define. Compiled once here; linked in per-test
# below, only for the sources that actually call dlopen() (build_one()),
# rather than unconditionally, so a corpus source that never touches
# dlopen() never carries an unused definition into its link.
RPATH_STUB="$srcdir/test/libc-test-shim-src/libc-test-rpath-stub.c"
# shellcheck disable=SC2086
if ! $CC -c $CFLAGS_C99FSE $CFLAGS_AUTO -D_GNU_SOURCE $INC \
     -o obj/libc-test/rpath-stub.o "$RPATH_STUB" 2>"$W/rpath-stub.err"; then
	echo "libc-test: $RPATH_STUB does not compile." >&2
	sed 's/^/    /' "$W/rpath-stub.err" >&2
	exit 1
fi

# $ledger_corpus (functional/ + regression/, built above for --cases-file)
# is this build/run list's base; math, when opted in, is appended on top
# of it and deliberately stays outside the ledger's case list.
corpus="$ledger_corpus"
[ -n "$corpus" ] && [ -n "$MATH_SRC" ] && corpus="$corpus $(echo "$MATH_SRC"/src/math/*.c)"
if [ -z "$corpus" ]; then
	echo "libc-test: the corpus in $SUITE has no test sources." >&2
	echo "libc-test: see 'git submodule update --init --recursive'." >&2
	exit 1
fi

# Every test source here is built and linked as its own single-file
# program: $f plus the shared harness helpers ($hobjs) is the whole
# link line, because that is what upstream's own Makefile does for the
# overwhelming majority of this corpus. tls_align.c is the sole
# exception (grep LDLIBS over every functional/*.mk and regression/*.mk
# to confirm): tls_align.mk links it against a second translation unit,
# tls_align_dso.c, which defines the `t[]` descriptor array tls_align.c
# only declares `extern` -- upstream's own harness builds that second
# file as a DSO (or, for its "-static" variant, a plain .o) and links it
# in at build time, never via dlopen(). That is a fundamentally
# different need from this corpus's *_dlopen/*_dso.mk tests (dlopen,
# tls_align_dlopen, tls_init_dlopen, tls_get_new-dtv), which load their
# companion .so at runtime and so hit this project's real, separate
# __rpath gap (see include/spicule/rpath.h and those tests' ledger rows);
# tls_align needs nothing dlopen-related at all, just one more file on
# the link line. This table is the minimal fix for that one case,
# without teaching this script to parse .mk files in general for a
# corpus where it is otherwise unneeded.
extra_srcs_for() {
	case "$1" in
	tls_align) echo "$SUITE/src/functional/tls_align_dso.c" ;;
	esac
}

build_one() {
	f=$1; n=$(basename "$f" .c)
	want=$(ledger_status "$n")
	if [ "$want" = NA ] ||
	   { [ "$SPICULE_TEST_MODE" = normal ] &&
	     { [ "$want" = BUG ] || [ "$want" = UNIMPL ]; }; }; then
		echo NA > "$W/out/$n.state"
		return
	fi
	# __rpath (include/spicule/rpath.h) is documented as a symbol the
	# CALLING PROGRAM defines, not one libc provides -- see
	# tools/linkcheck.sh's linkcheck_exception() for the identical story
	# against the library's own dlopen()/dlsym()/dlclose()/dlerror()
	# entry points. Every upstream corpus source that calls dlopen()
	# hits the same unresolved reference here for the same reason
	# (confirmed by `grep -l dlopen` over the corpus: exactly dlopen.c,
	# tls_align_dlopen.c, tls_init_dlopen.c and tls_get_new-dtv.c, the 4
	# cases this used to fail for), so link in the no-op-search-path
	# companion object built above whenever the source references it.
	rpath_obj=""
	grep -q 'dlopen(' "$f" && rpath_obj="obj/libc-test/rpath-stub.o"
	extra=$(extra_srcs_for "$n")
	# shellcheck disable=SC2086
	if $CC $CFLAGS_C99FSE $CFLAGS_AUTO -D_GNU_SOURCE $INC -nostdlib \
	    -o "obj/libc-test/$n.exe" "$srcdir/lib/crt1.o" "$f" $extra $hobjs $rpath_obj \
	    -L"$srcdir/lib" -lc -lntdll > "$W/out/$n.build" 2>&1; then
		echo built > "$W/out/$n.state"
	else
		echo UNBUILDABLE > "$W/out/$n.state"
		rm -f "obj/libc-test/$n.exe"
	fi
}

# Progress goes to stderr, never stdout.  stdout carries the adjudicated
# report in corpus order so two runs of the same tree are diffable and a
# redirect still yields a stable artefact; this channel is for a human (or
# a CI log) watching a run that has not finished yet.  A harness that
# speaks only at the end has nothing to say when it is killed part way,
# which is precisely the state the Open POSIX job has been in.
n_corpus=$(echo "$corpus" | wc -w)
echo "libc-test: building $n_corpus tests with $CC ..."
echo "libc-test: building $n_corpus tests with $CC ..." >&2
build_start=$(date +%s)
built_n=0
# shellcheck disable=SC2086
for f in $corpus; do
	build_one "$f"
	built_n=$((built_n + 1))
	bn=$(basename "$f" .c)
	# UNBUILDABLE is the expected state for a large part of this corpus,
	# so it is not itself news.  It is news when the ledger expected the
	# test to run: that verdict is already final here and does not need
	# the run phase to confirm it.
	if [ "$(cat "$W/out/$bn.state" 2>/dev/null)" = UNBUILDABLE ]; then
		case "$(ledger_status "$bn")" in
		PASS|FLAKY) echo "libc-test: FAIL $bn (expected to run, did not build)" >&2 ;;
		esac
	fi
	if [ $((built_n % 25)) -eq 0 ] || [ "$built_n" -eq "$n_corpus" ]; then
		echo "libc-test: built $built_n/$n_corpus" >&2
	fi
done
build_end=$(date +%s)

# ------------------------------------------------------------------- run

runner="$W/runone.sh"
cat > "$runner" <<'EOF'
#!/bin/sh
n=$(basename "$1" .exe)
d=$(mktemp -d "$W/work.XXXXXX") || { echo 1 > "$W/out/$n.rc"; exit 0; }
# 120s, not the 25s this started with: the gate runs every stage
# at once and Wine process startup under that contention was measured
# at 40x its idle cost, which timed 14 trivial tests out and reported
# them as behavioural failures.  The genuine hang risk here is
# `winedbg --auto`, and WINEDLLOVERRIDES above is what removes it --
# a fork that cannot clone aborts in ~0.3s.  So this bound exists to
# stop a wedged test wedging the stage, not to police runtime, and it
# should be far above anything a working test needs.
( cd "$d" && WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d \
    timeout -k 5 120 "$WINE" "$1" ) > "$W/out/$n.log" 2>&1 </dev/null
rc=$?
echo $rc > "$W/out/$n.rc"
rm -rf "$d"
# Progress from inside an xargs -P worker: unordered by construction, one
# short line per test so the writes stay atomic and do not interleave
# mid-line.  Adjudication still happens once, later, in corpus order --
# this only says which tests have finished and how they exited.
echo "libc-test: ran $n (rc=$rc)" >&2
EOF
chmod +x "$runner"
export W WINE

exes=""
for f in $corpus; do
	n=$(basename "$f" .c)
	# A binary from an earlier run may still exist after this profile marks
	# the case NA/BUG/UNIMPL. Only execute cases this invocation actually
	# built; filesystem existence alone makes stale artifacts bypass policy.
	[ "$(cat "$W/out/$n.state" 2>/dev/null)" = built ] &&
		[ -x "obj/libc-test/$n.exe" ] &&
		exes="$exes $srcdir/obj/libc-test/$n.exe"
done
run_start=$(date +%s)
echo "libc-test: running $(echo "$exes" | wc -w) built test(s) with $LIBC_TEST_JOBS worker(s) ..." >&2
if [ -n "$exes" ]; then
	# shellcheck disable=SC2086
	printf '%s\n' $exes | xargs -P "$LIBC_TEST_JOBS" -I{} sh "$runner" {}
fi
run_end=$(date +%s)

# ----------------------------------------------------------- adjudicate

passed=0; bugs=0; flaky=0; na=0; unimpl=0
regressions=""; unexpected=""; stale=""; absent=""; timeouts=""
verified=0

for f in $corpus; do
	n=$(basename "$f" .c)
	want=$(ledger_status "$n")
	state=$(cat "$W/out/$n.state" 2>/dev/null || echo UNBUILDABLE)

	if [ "$want" = ABSENT ]; then
		absent="$absent $n"
		continue
	fi

	if [ "$state" = NA ]; then
		case "$want" in
		BUG) bugs=$((bugs + 1)); echo "BUG $n (not probed in normal mode) -- $(ledger_reason "$n")" ;;
		UNIMPL) unimpl=$((unimpl + 1)); echo "UNIMPL $n (not probed in normal mode) -- $(ledger_reason "$n")" ;;
		NA) na=$((na + 1)); echo "NA $n -- $(ledger_reason "$n")" ;;
		*) stale="$stale $n(ledger:$want,actual:NA)" ;;
		esac
		continue
	fi

	if [ "$state" = UNBUILDABLE ]; then
		why=$(grep -m1 -i 'error\|include' "$W/out/$n.build" 2>/dev/null | sed 's/^ *//')
		if [ "$want" = UNIMPL ]; then
			unimpl=$((unimpl + 1))
			echo "UNIMPL $n -- ${why:-no diagnostic}"
		else
			echo "UNBUILDABLE $n -- ${why:-no diagnostic}"
			stale="$stale $n(ledger:$want,actual:UNBUILDABLE)"
		fi
		continue
	fi
	if [ "$want" = UNIMPL ]; then
		stale="$stale $n(ledger:UNIMPL,actual:built)"
	fi

	rc=$(cat "$W/out/$n.rc" 2>/dev/null || echo 1)
	log="$W/out/$n.log"

	# Environment-derived 77s, both read out of the test's OWN output at
	# run time.  Never a static list: on the real-Windows CI leg and on a
	# Wine that implements RtlCloneUserProcess these same tests produce a
	# real verdict, and that must be visible without editing anything.
	if grep -qF "$WINE_MARK" "$log" 2>/dev/null; then
		na=$((na + 1))
		echo "NA $n (rc=77) -- fork unavailable under this wine ($WINE_MARK)"
		continue
	fi
	if grep -qF "$SHIM_MARK" "$log" 2>/dev/null; then
		na=$((na + 1))
		echo "NA $n (rc=77) -- $(grep -m1 -F "$SHIM_MARK" "$log" | sed "s/.*$SHIM_MARK//")"
		continue
	fi

	# A test killed by the timeout above did not produce a verdict: it
	# did not finish.  Counting rc=124 as "it failed" would let a
	# wedged or merely slow test satisfy a BUG row -- observed
	# exactly once, when a 25s bound under gate contention turned 14
	# trivial tests into "regressions" and quietly let `fcntl`'s
	# unresolved row be satisfied by a timeout rather than by the
	# behaviour it describes.  Its own bucket, and it fails the stage.
	if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
		timeouts="$timeouts $n"
		echo "TIMEOUT $n (rc=$rc) -- killed after 120s; this is not a verdict"
		continue
	fi

	verified=$((verified + 1))
	case "$want" in
	PASS)
		if [ "$rc" = 0 ]; then
			passed=$((passed + 1))
		else
			regressions="$regressions $n"
			echo "FAIL $n (rc=$rc) -- ledger says this passes"
			sed 's/^/    /' "$log" | head -20
		fi ;;
	BUG)
		if [ "$rc" = 0 ]; then
			unexpected="$unexpected $n"
		else
			bugs=$((bugs + 1))
			echo "BUG $n (failed as declared) -- $(ledger_reason "$n")"
		fi ;;
	FLAKY)
		flaky=$((flaky + 1))
		if [ "$SPICULE_TEST_MODE" = strict ] && [ "$rc" != 0 ]; then
			regressions="$regressions $n(FLAKY-strict)"
		fi
		echo "FLAKY $n (rc=$rc) -- $(ledger_reason "$n")" ;;
	esac
done

echo
echo "=== libc-test summary (build $((build_end - build_start))s, run $((run_end - run_start))s) ==="
echo "$passed PASS, $bugs BUG, $unimpl UNIMPL, $na NA, $flaky FLAKY"
echo
if [ "$SPICULE_TEST_MODE" = normal ]; then
	echo "$unimpl of $(echo "$corpus" | wc -w) tests are classified UNIMPL and were not"
	echo "compiled in normal mode. Pedantic verifies that each still fails to build."
else
	echo "UNIMPL is printed above even though it is one of the largest"
	echo "numbers here: $unimpl of $(echo "$corpus" | wc -w) tests cannot be compiled against this"
	echo "library at all, almost all of them at #include.  That is the gap"
	echo "accounting restated as a build error, and it is the single most"
	echo "useful fact this stage produces.  It is not a pass."
fi

rc=0

if [ -n "$absent" ]; then
	echo
	echo "libc-test: FAILED -- test(s) built/run here that are outside both"
	echo "libc-test: test/libc-test-expected.txt and this script's own"
	echo "libc-test: independently-discovered case list (\$W/cases.txt, built"
	echo "libc-test: by the functional/regression glob just above 'read_ledger"
	echo "libc-test: \"\$W\" \"\$W/cases.txt\"'):$absent"
	echo "libc-test: every functional/regression test already resolves --"
	echo "libc-test: an explicit ledger row for an exception, or that ledger's"
	echo "libc-test: trailing wildcard row's PASS default for everything else"
	echo "libc-test: (mirroring test/posix-opts-expected.txt's own wildcard row,"
	echo "libc-test: commit 93bbaa3).  The only way to reach this branch today"
	echo "libc-test: is the on-demand math corpus, which deliberately carries no"
	echo "libc-test: ledger rows at all (see the 'math' case above); anything"
	echo "libc-test: else here means a test exists that neither this script's"
	echo "libc-test: own discovery nor the ledger's wildcard accounts for,"
	echo "libc-test: which should not be possible without a bug in one of them."
	rc=1
fi
if [ -n "$timeouts" ]; then
	echo
	echo "libc-test: FAILED -- test(s) killed by the timeout:$timeouts"
	echo "libc-test: a test that did not finish has not been adjudicated."
	echo "libc-test: neither a pass nor a known failure -- find out why it"
	echo "libc-test: hung, or why this machine is that slow, before touching"
	echo "libc-test: test/libc-test-expected.txt."
	rc=1
fi
if [ -n "$regressions" ]; then
	echo
	echo "libc-test: FAILED -- regression(s):$regressions"
	rc=1
fi
if [ -n "$unexpected" ]; then
	echo
	echo "libc-test: FAILED -- BUG test(s) now PASS:$unexpected"
	echo "libc-test: that is a fixed defect.  Update test/libc-test-expected.txt"
	echo "libc-test: (disposition PASS, and the COUNTS header) in the same commit as"
	echo "libc-test: the fix, so the ledger cannot outlive what it describes."
	rc=1
fi
if [ -n "$stale" ]; then
	echo
	echo "libc-test: FAILED -- ledger disagrees with what actually built:$stale"
	rc=1
fi
# ---- the counts pin ------------------------------------------------------
#
# The whole anti-drift mechanism, in six lines.  The ledger's header states,
# as numbers, how many of the real, independently-discovered corpus cases
# (functional/ + regression/, never math) resolve to each disposition once
# the wildcard default is applied -- this compares them against $W/rows,
# which is exactly that: one resolved line per case named in $W/cases.txt,
# built via --cases-file (see read_ledger()), not the raw row count of
# test/libc-test-expected.txt itself (that file lists only the exceptions
# plus the wildcard row, so its own row count no longer means "how many
# tests"). Profile overrides live separately in test/test-profiles.tsv, so
# these counts remain stable across runners.
#
counts=$(sed -n 's/^#[ \t]*COUNTS[ \t]*//p' "$LEDGER" | tail -1)
if [ -z "$counts" ]; then
	echo
	echo "libc-test: FAILED -- test/libc-test-expected.txt has no '# COUNTS' header." >&2
	rc=1
else
	for kv in $counts; do
		k=${kv%%=*}; v=${kv#*=}
		a=$(awk -F'\t' -v k="$k" '$2==k {c++} END{print c+0}' "$W/rows")
		if [ "$a" -ne "$v" ]; then
			echo
			echo "libc-test: FAILED -- ledger header says $k=$v, resolved profile has $a."
			rc=1
		fi
	done
fi

if [ "$SPICULE_TEST_MODE" = strict ]; then
	strict_bug=$(awk -F'\t' '$2=="BUG"{c++}END{print c+0}' "$W/rows")
	strict_unimpl=$(awk -F'\t' '$2=="UNIMPL"{c++}END{print c+0}' "$W/rows")
	if [ "$strict_bug" -gt 0 ] || [ "$strict_unimpl" -gt 0 ]; then
		echo "libc-test: STRICT disallows $strict_bug BUG and $strict_unimpl UNIMPL disposition(s)."
		rc=1
	fi
fi

# ---- the floor -----------------------------------------------------------
if [ "$SPICULE_TEST_MODE" != normal ] && [ "$verified" -lt "$VERIFIED_FLOOR" ]; then
	echo
	echo "libc-test: FAILED -- only $verified test(s) produced a real verdict;"
	echo "libc-test: this stage's floor is $VERIFIED_FLOOR.  Everything else was"
	echo "libc-test: UNIMPL or NA, so this run checked almost"
	echo "libc-test: nothing about the library's behaviour and must not be"
	echo "libc-test: reported as success.  (tools/libc-test.sh: VERIFIED_FLOOR)"
	rc=1
fi
if [ "$verified" -eq 0 ]; then
	echo "libc-test: NOT ONE TEST WAS ADJUDICATED.  This run verified nothing."
	rc=1
fi

if [ "$rc" -ne 0 ]; then
	echo
	echo "libc-test FAILED."
fi
exit $rc
