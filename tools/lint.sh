#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# lint.sh -- opt-in static checking for ntlibc.
#
# This is deliberately NOT part of `make all` or `make check`.  The library
# itself is built with tcc, which accepts a great deal that gcc and clang
# diagnose; this script runs the checks tcc cannot, using whichever of
# gcc/clang/clang-tidy/cppcheck/shellcheck happen to be installed, and skips
# (loudly) the ones that are not.  Nothing here may ever become a build
# dependency, and nothing compiler-specific may be added to src/ to satisfy
# it -- findings get reported and judged, not blanket-silenced.
#
# Stages, in order:
#   warn      -fsyntax-only builds of the whole library with gcc and clang,
#             for every arch, under a curated warning set (see WARN_FLAGS).
#   analyze   clang's static analyzer (via clang-tidy if present, else
#             `clang --analyze`), which is the stage that finds real
#             uninitialised-value and leak paths rather than style nits.
#   cppcheck  cppcheck --enable=warning,portability, if installed.
#   shell     shellcheck over configure, the git hooks and tools/*.sh.
#   sizearith currently opt-in while its initial proof backlog is triaged, and
#             being progressively migrated onto the same Z3 proof power as
#             totality/arithub below.  tools/lint-sizearith.py checks
#             allocator arithmetic and raw geometric growth.  A Clang 18
#             analyzer plugin additionally proves every explicit integer
#             narrowing cast and array index from real types, extents, and
#             path constraints, and proves that tagged result values are read
#             only from their selected normal or special arm.  Every part
#             self-tests before scanning the tree.
#   totality  currently opt-in while its initial proof backlog is triaged.
#             A Clang 18 AST plugin extracts loop ranks and call-size
#             relations.  tools/lint-totality.py checks every loop, rejects
#             open indirect-call graphs, and applies size-change termination
#             to recursive components.  Sentinel walks are explicit ranks.
#   arithub   currently opt-in while its initial proof backlog is triaged.
#             Path-sensitive Clang checkers require every integer divisor to
#             be proven nonzero and every shift count to be proven within the
#             promoted left operand's width, and every signed arithmetic result
#             to remain representable.  Its relational side solver requires
#             Clang/LLVM 18 development files, pkg-config, and Z3 development
#             headers and library.
#   ownership enabled by default.
#             Manual header/stub contracts identify producers, reallocations,
#             and unique freers. Path-sensitive checkers prove every dynamic
#             allocation is released or transferred before function exit,
#             independently prove freer bodies, treat aliases as borrows, prove
#             synchronization-object lifecycles, and require every dereference
#             to have nonnull, live, in-bounds, aligned storage. Descriptor,
#             stream, directory, semaphore, mapping, and handle acquire/use/
#             release state is tracked as well. Parameterized memory tokens
#             prove spans for memory and I/O operations and prove memcpy ranges
#             do not overlap in the same analyzer pass. `alloclife` and
#             `memcontracts` are compatibility aliases for this merged stage.
#   initproof on by default; path-sensitively proves that scalar and field
#             loads do not read definitely uninitialized storage.
#   fallible  on by default; rejects discarded results from known fallible
#             system, I/O, mapping, semaphore, and pthread APIs.
#   provenance
#             currently opt-in while its initial proof backlog is triaged,
#             after tools/clang/PointerProvenanceChecker.cpp's own
#             individually-justified call-site exemption table was removed
#             (2026-09-03) so every finding it covered is reported live
#             instead of silently recognised.  A Clang 18 analyzer plugin
#             proves common provenance for ordered pointer comparisons and
#             subtraction, and rejects integer-derived pointers.  Constant
#             sentinels (NT's own pseudo-handle convention,
#             SIG_DFL/SIG_IGN/SIG_ERR, MAP_FAILED, and this tree's own
#             invalid nl_catd/iconv_t/sem_t/fenv_t markers) and
#             pointer/integer/pointer alignment round trips are still
#             recognised rather than flagged; a boundary no C-level analysis
#             can see across (hand-written assembly, the kernel's own ABI, a
#             hardware fault handler) is not, until each such site is
#             re-proved by another means.
#   locks     on by default; path-sensitively proves mutex, rwlock, and
#             spinlock acquire/release, wait, destroy, and function-exit state.
#   abizeroinit
#             on by default; proves that a stack-local struct or array
#             passed by address into an OUT or IN-OUT Nt*/Zw* syscall
#             argument is fully initialized, including padding, before the
#             call -- catching the InitializeObjectAttributes-style
#             footgun of setting fields one at a time and never proving
#             the whole object (and, cheaply from the same state, an OUT
#             parameter nothing ever reads back).
#   reentrancy
#             on by default. A path-sensitive Clang checker proves that
#             the pointer strtok/gmtime/localtime/asctime/ctime/getdate hand
#             back into internal static storage is not read, dereferenced,
#             or passed on after a later call to the same (or, in general, a
#             sibling) family member has invalidated it.
#   lockset   on by default.
#             Clang's own Thread Safety Analysis (-Wthread-safety), driven by
#             capability/guarded_by/acquire_capability/release_capability
#             attributes behind src/internal/thread_annotations.h's
#             clang-and-lockset-stage-only macros, proves that ntlibc's own
#             guarded internal globals are only ever touched while the
#             internal lock that is supposed to protect them is held --
#             the "which lock guards this data" question `locks` above does
#             not ask at all.
#   variadic  on by default; proves printf/scanf format literalness, argument
#             counts, promoted types, pointer targets, and length modifiers.
#   signals   on by default; checks directly registered signal handlers for
#             async-signal-safe calls and volatile sig_atomic_t-only writes.
#   errno     on by default; path-sensitively proves errno discipline in
#             ntlibc's own implementation: every read of errno is reachable
#             only from the call whose failure it is checking (no stale
#             read after an intervening errno-capable call, e.g. a cleanup
#             close()), and only after some call or direct assignment on
#             that path could actually have set it (no trusting leftover
#             errno state from function entry).
#   purity    on by default for false claims; eligible-but-unannotated
#             candidates remain advisory and are listed in the reports.
#             A Clang 18 AST plugin walks every function's whole body and
#             reachable in-TU call graph and proves __attribute__((pure))
#             eligibility (no errno, no writes through a pointer or global,
#             no I/O, no reads of mutable global/static state, no locking,
#             every callee itself pure) -- and, symmetrically, disproves the
#             claim for any function already marked pure that fails it,
#             which is a real correctness bug rather than a style nit.
#   loopcond  currently opt-in while its first tree-wide pass is triaged.
#             A Clang 18 AST plugin (tools/clang/LoopConditionChecker.cpp)
#             walks every for/while/do header and flags a condition that
#             compounds, via && or ||, a structural bound (a range, a
#             count, a cursor-vs-NULL/sentinel test) with a distinct,
#             apparently incidental data-dependent condition (a found/
#             success/error flag, or an unrelated function-call result).
#             The fix is always the same: keep the primary condition in
#             the loop header and move the other into an explicit
#             `if (...) break;` in the loop body -- which this stage does
#             not do itself, only reports. A conditional `break` inside an
#             otherwise-clean range/cursor loop is the pattern this steers
#             code towards, not a finding in its own right.
#   undefined tools/lint-undefined.sh: a public header declaring a
#             function nothing defines.  Needs clang-18/clang++-18/
#             llvm-config-18 (a real AST walk, tools/clang/
#             LintDeclScanner.cpp, same as the totality/ownership/etc.
#             stages below).
#   unreferenced
#             tools/lint-unreferenced.sh: a function a public header
#             declares, this library implements, and no test/*.c
#             references.  Needs a native C compiler, nm, and
#             clang-18/clang++-18/llvm-config-18 (same AST walk as
#             `undefined` above).
#   widthmod  tools/lint-widthmod.sh: printf/scanf's `z` and `t` length
#             modifiers read or written as `long`, which is 32 bits on
#             this LLP64 target while size_t and ptrdiff_t are 64.  No
#             tool needed.
#
# Usage:
#   tools/lint.sh                 run every stage
#   tools/lint.sh warn analyze    run only the named stages
#
# Tool versions matter, and have caught this project out three times: a
# green local run is not a green CI run if the versions differ.  CI (see
# .github/workflows/ci.yml) installs clang-tidy-18 and shellcheck 0.9 from
# ubuntu-24.04's apt; a newer local pair may report neither cppcheck's
# suppression-file syntax complaints, nor clang-analyzer findings that 18
# reports and 21 does not, nor SC2016 in tools/gen-kaem.sh's sed.  To
# reproduce CI's exact toolchain locally:
#
#   nix-shell -p llvmPackages_18.clang-tools \
#     --run 'CLANG_TIDY=clang-tidy tools/lint.sh analyze'
#   nix-shell -I nixpkgs=channel:nixos-23.11 -p shellcheck \
#     --run 'tools/lint.sh shell'
#
# Environment:
#   LINT_ARCHS=...        arches to check (default: every dir under arch/
#                         except `generic`)
#   LINT_CONVERSION=1     additionally enable -Wconversion -Wsign-conversion.
#                         Off by default: ~50 findings, the large majority of
#                         which are the deliberate `~0777`-style mask idioms
#                         and NT-type narrowings this code is written around.
#                         Worth a periodic read, not worth a gate.
#   LINT_STRICT=0         always exit 0 (report only)
#   LINT_TIDY_EXACT=1     require the running clang-tidy's enabled check
#                         set to equal tools/clang-tidy-checks.txt
#                         exactly, rather than merely to be a superset of
#                         its required list.  Set by the two stages whose
#                         purpose is to reproduce one pinned toolchain
#                         (tools/gate.sh's lint-analyze-pinned and
#                         ci.yml's analyze leg); see that file's header.
#   LINT_ALLOW_MISSING=1  skip a stage whose tool is absent instead of
#                         failing.  Off by default: a stage that cannot
#                         run is a failure, because a silent skip makes a
#                         local 'no findings' mean less than CI's -- which
#                         is how the shellcheck, cppcheck and clang-tidy
#                         backlogs each went unseen for a while.
#
# Exit status is 1 if any stage produced findings, so this can be used as a
# gate once the current backlog is dealt with.  It does not pass today; see
# the report in the commit that added this file.
#

set -u

# `CDPATH=` is an assignment prefixing the `cd`, not a botched assignment.
# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

builddir=obj/lint
: "${LINT_CONVERSION:=0}"
: "${LINT_STRICT:=1}"
: "${LINT_ALLOW_MISSING:=0}"
missing=0

# How many files/stages to run at once. warn/analyze run one process per
# source file (the actual work, e.g. clang-tidy on one TU, dwarfs process
# startup), and the top-level stages are themselves independent, so
# both parallelise for free. LINT_JOBS=1 restores the old fully serial
# behaviour, which is also the safe fallback if nproc/getconf are both
# missing.
: "${LINT_JOBS:=}"
if [ -z "$LINT_JOBS" ]; then
	LINT_JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi

# Every arch/ subdirectory except the generic fallback header tree.
if [ -z "${LINT_ARCHS:-}" ]; then
	LINT_ARCHS=
	for d in arch/*/; do
		a=${d%/}; a=${a#arch/}
		[ "$a" = generic ] && continue
		LINT_ARCHS="$LINT_ARCHS $a"
	done
fi

findings=0
note() { printf '%s\n' "$*"; }

# show_findings FILE [SEVERITY] -- print the findings a stage has just
# counted.
#
# A count is not something anyone can act on.  These logs are written
# under obj/lint/, which is a build directory: in CI it lives inside the
# runner and is never uploaded, so "-> obj/lint/x86_64.analyze.log.uniq"
# names a file nobody reading the red board can open.  Every stage below
# printed a number and a path to a file that, in the one place the number
# matters, does not exist.  Two separate people asked independently where
# the analyzer's count came from, and neither could answer it from the
# log; a stage that reports a count it cannot explain is a stage nobody
# can act on, and acting on it is the entire purpose.
#
# Bounded, because a stage that has genuinely fallen over emits thousands
# of lines and burying the summary underneath them is its own failure
# mode: the first $LINT_SHOW, then how many were elided and the path that
# still holds all of them.
#
# SEVERITY ("error", the default, or "warning") is passed straight to
# tools/lint-gh-annotate.sh, which turns FILE into GitHub Actions
# `::error`/`::warning` workflow-command lines -- inline annotations on
# the PR diff -- for whichever lines are shaped like a finding.  That
# script is a no-op unless GITHUB_ACTIONS=true, so this adds nothing to
# a local run's output: see its header for why the gate belongs there,
# not here, and why every one of the ~20 call sites below funnels
# through this one function instead of each deciding for itself whether
# it is allowed to print a workflow command.
: "${LINT_SHOW:=40}"
show_findings() {
	[ -s "$1" ] || return 0
	sed "${LINT_SHOW}q" "$1" | sed 's/^/    /'
	_tot=$(grep -c . "$1" || true)
	[ "$_tot" -le "$LINT_SHOW" ] ||
		note "    ... and $((_tot - LINT_SHOW)) more, all of them in $1"
	tools/lint-gh-annotate.sh "${2:-error}" "$1"
}
hdr() { printf '\n=== %s ===\n' "$*"; }

# A stage whose tool is absent is a *failure*, not a pass.  Silently
# degrading is how three stages went untriaged for weeks: shellcheck and
# cppcheck simply never ran here, and the analyzer quietly fell back to
# `clang --analyze`, which runs none of the bugprone-*/cert-* checks --
# so a local "no findings" meant "the checks you care about did not
# run".  CI has all of them, so a green local run has to mean the same
# thing CI means.  LINT_ALLOW_MISSING=1 restores the old behaviour for
# anyone who genuinely cannot install one.
# report_missing DESCRIPTION -- the "a tool this stage needs is not here"
# path, factored out of require_tool so a stage whose tool is not a
# single `command -v`-able name can take it too.  stage_warn's compiler
# is picked by pick_cc(), which may answer with a mingw-w64 cross gcc, a
# `clang --target=` invocation, or the native compiler with -m32/-m64 --
# no one name to test -- and before this it simply printed "SKIP" and
# carried on, which meant a machine with no C compiler at all passed the
# warning stage *at the default LINT_ALLOW_MISSING=0*.  Always returns 1,
# so callers can `report_missing ... || continue`.
report_missing() {
	if [ "$LINT_ALLOW_MISSING" = 1 ]; then
		note "SKIP: $1 (LINT_ALLOW_MISSING=1)"
		return 1
	fi
	note "MISSING: $1"
	note "  install it, or set LINT_ALLOW_MISSING=1 to skip it and accept"
	note "  that this run checks less than CI does."
	missing=1
	# When the top-level stages run in parallel (see the dispatch loop at
	# the bottom of this file), each one runs in its own subshell, so a
	# plain `missing=1` above only ever changes that subshell's copy --
	# the parent shell's $missing never sees it. LINT_MISSING_MARKER, if
	# set, names a file whose mere existence (one per offending subshell,
	# via $$) the parent checks after `wait` instead.
	[ -n "${LINT_MISSING_MARKER:-}" ] && : > "$LINT_MISSING_MARKER.$$"
	return 1
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 && return 0
	report_missing "$1 is not installed, so this stage cannot run."
}

#
# The warning set.  -Wall -Wextra plus the checks that actually mean
# something for a freestanding libc.  Two families are deliberately absent:
#
#   -Wcast-qual        ~50 hits, essentially all of them the const-stripping
#                      return that C requires of strchr/memchr/strstr and
#                      friends.  Unfixable by construction.
#   -Wconversion       see LINT_CONVERSION above.
#
# The project's own CFLAGS_AUTO carries -Wno-unused-function; keep it, so
# lint does not disagree with the build about static inline helpers.
#
WARN_FLAGS="-Wall -Wextra -Wno-unused-function \
-Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
-Wvla -Wpointer-arith -Wwrite-strings -Wundef"
[ "$LINT_CONVERSION" = 1 ] && WARN_FLAGS="$WARN_FLAGS -Wconversion -Wsign-conversion"

# bits/alltypes.h for an arch, assembled exactly as the Makefile does it, so
# lint can check an arch the tree is not currently configured for.
#
# Idempotent and safe under concurrent callers: with the top-level
# stages now able to run at once (see the dispatch loop below), more than
# one of them can ask to generate the same arch's header at nearly the
# same moment. Skipping when the destination already exists avoids
# redoing the (cheap but non-zero) work every time; writing to a temp
# file and `mv`-ing it into place, rather than redirecting straight into
# the destination, means a compiler process that opens the header while a
# second generator is mid-write never sees a truncated file -- `mv` on
# the same filesystem is a single rename, not a byte-by-byte copy.
#
# The skip is conditional on the destination MATCHING what this tree
# would generate, not merely on it existing.  A bare -f cache never
# expires, and obj/ survives a checkout: a local run after any commit
# that touches either alltypes.h.gen went on linting against the
# previous tree's types.  That is not a stale-cache annoyance, it is a gate reporting
# about a tree that is not there -- it produced 83 phantom "incomplete
# definition of type 'struct tm'" errors here, against the 1 real
# finding CI reports, and made the stage look locally unreproducible.
# CI never sees it because CI always starts from an empty checkout,
# which is the worst possible split: the wrong answer appears only where
# someone is trying to reproduce a real one.
#
# Compared, not stat'd.  Mtimes are the wrong instrument twice over: `-nt`
# is not POSIX sh (SC3013, and this file is #!/bin/sh), and a checkout can
# leave a stale file whose mtime is newer than the source it is stale
# against.  The two inputs total 8KB, so generating unconditionally and
# comparing costs nothing measurable, and it keeps the temp-plus-`mv`
# shape the concurrency note above depends on.
#
# The temp name itself has to be unique per concurrent caller, not merely
# per top-level process.  Every stage in the dispatch loop below runs as
# `( ... ) &` -- a background subshell of this same script -- and `$$`
# names the *top-level* process in a subshell exactly as it does in its
# parent; it does not pick up the subshell's own (different) pid. Two
# stages that both want the same arch's header (nearly every stage does)
# and land in here at close to the same moment used to compute the
# identical "$dest.$$.tmp" path and then race each other's
# `cat`/`cmp`/`mv`/`rm` of that one shared file: whichever lost found its
# tmp already consumed by the winner and failed with "mv: cannot stat
# ...: No such file or directory" -- confirmed by running two such
# concurrent callers against the same arch outside this script and
# watching that exact failure appear intermittently. `mktemp` asks the
# kernel for a name nobody else, in this process or any other, can also
# be holding; any name this script computed itself (bigger salt on `$$`,
# a counter, ...) would just be a fancier way to land on the same
# collision, since every caller is either literally the same top-level
# pid (subshells) or would need its own source of the same uniqueness
# `mktemp` already provides for free.
gen_alltypes() {
	dest=$builddir/$1/include/bits/alltypes.h
	mkdir -p "$builddir/$1/include/bits" || return 1
	tmp=$(mktemp "$dest.XXXXXX") || return 1
	cat "arch/$1/bits/alltypes.h.gen" include/alltypes.h.gen > "$tmp" || {
		rm -f "$tmp"; return 1
	}
	if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
		rm -f "$tmp"
		return 0
	fi
	mv -f "$tmp" "$dest"
}

cppflags_for() {
	echo "-std=c99 -nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_NTLIBC_INTERNAL" \
	     "-Iarch/$1 -Iarch/generic -I$builddir/$1/include -Iinclude -Isrc/internal"
}

# Which of configure's two --platform values a given ARCH actually builds
# under -- see the Makefile's own PLATFORM/PLAT_GLOBS comment for the
# axis this mirrors. sources_for() below used to hardcode "nt" here,
# which was correct for i386/x86_64 (both win32-only) but silently wrong
# for aarch64: it pulled every NT-only backend file (src/*/nt/*.c) into
# the one arch that can never build or run them, AND never pulled in the
# aarch64 leg's own real backend (src/*/linux/*.c) at all. The first half
# of that bug is not hypothetical -- it is exactly what made the
# signal-safety stage hit a hard `#error unsupported architecture` out of
# src/thread/nt/plat_thread.c's `#if defined(__x86_64__)/#elif
# defined(__i386__)` chain when LINT_ARCHS included aarch64, because that
# file has no aarch64 arm and was never supposed to be compiled under it
# in the first place -- `make`, via PLATFORM=linux, never puts it in
# lib/libc.a for a Linux build. This function is what has to agree with
# that. There is no arch this tree builds under platform=nt other than
# the two win32 ones, and no arch under platform=linux other than
# aarch64 today, so the mapping is a plain per-arch table, not derived
# from triple_for() (a different axis -- see its own comment) or
# inferred from whether a mingw triple exists.
platform_for() {
	case $1 in
	i386|x86_64) echo nt ;;
	aarch64)     echo linux ;;
	esac
}

# The same source set the Makefile builds: base sources, minus any that an
# arch/ subdirectory of the same module overrides, plus the arch sources,
# plus src/*/$(platform)/*.c and crt/$(platform)/*.c (the PLATFORM axis's
# own additive backend files, keyed per-arch by platform_for() above --
# see the Makefile's PLAT_GLOBS and src/internal/plat_handle.h) --
# plus sh/*.c and bin/*.c, the sh(1p) binary and the standalone POSIX
# utility binaries.  Neither is part of libc.a (both are programs, see
# the Makefile's SH_SRCS/BIN_SRCS comments), but both are first-party C
# in this repo built by `make all`, and nothing else in these gates
# compiles them with a warning set: leaving them out would mean the
# deliverables a user actually runs are the ones gcc/clang/cppcheck
# never look at.
sources_for() {
	arch=$1
	plat=$(platform_for "$arch")
	for f in src/*/*.c crt/*.c sh/*.c bin/*.c arch/"$arch"/src/*.c src/*/"$arch"/*.c \
	         src/*/"$plat"/*.c crt/"$plat"/*.c; do
		[ -e "$f" ] || continue
		case $f in
		src/*/*.c)
			# skip a base source that arch/ replaces
			d=${f%/*}; b=${f##*/}
			[ -e "$d/$arch/$b" ] && [ "${d##*/}" != "$arch" ] && continue
			;;
		esac
		echo "$f"
	done
}

# Getting the target ABI right matters here: both win32 targets are
# ILP32/LLP64 (`long` is 32 bits on each), while aarch64 is the Linux target
# whose inline assembly and ABI-specific types require an aarch64 triple.
# A native pass with the wrong ABI still catches most of what we care about,
# but it is not the same compile, so prefer, in order:
#
#   1. clang --target=<triple>, which needs no cross toolchain installed at
#      all, because -nostdinc means we never touch the target's headers;
#   2. an installed target-prefixed gcc;
#   3. the native compiler with -m32/-m64, with a printed caveat.
#
triple_for() {
	case $1 in
	i386)   echo i686-w64-mingw32 ;;
	x86_64) echo x86_64-w64-mingw32 ;;
	aarch64) echo aarch64-linux-gnu ;;
	esac
}

# --target=<triple> for clang; empty if the arch has no known triple.
pick_target() {
	t=$(triple_for "$1")
	[ -n "$t" ] && echo "--target=$t"
}

pick_cc() {
	base=$1 arch=$2
	triple=$(triple_for "$arch")
	case $arch in i386) bits=-m32 ;; *) bits=-m64 ;; esac
	if [ "$base" = clang ] && [ -n "$triple" ] && command -v clang >/dev/null 2>&1; then
		echo "clang --target=$triple"
	elif [ -n "$triple" ] && command -v "$triple-$base" >/dev/null 2>&1; then
		echo "$triple-$base"
	elif [ "$arch" != aarch64 ] && command -v "$base" >/dev/null 2>&1; then
		echo "$base $bits"
	fi
}

stage_warn() {
	hdr "warning build"
	any=0
	# How many (arch, compiler) passes actually happened.  Checked at the
	# bottom: a warning stage that ran none of them has diagnosed nothing,
	# and must not report success just because nothing complained.
	passes=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { note "cannot generate alltypes for $arch"; any=1; continue; }
		flags=$(cppflags_for "$arch")
		srcs=$(sources_for "$arch")
		nsrc=$(printf '%s\n' "$srcs" | grep -c . || true)
		for base in gcc clang; do
			cc=$(pick_cc "$base" "$arch")
			# Absent tool, not "nothing to do": this used to print SKIP
			# and continue with $any still 0, so a machine with neither
			# gcc nor clang passed this stage outright.  Route it through
			# the same LINT_ALLOW_MISSING decision every other stage uses.
			[ -n "$cc" ] || { report_missing "no usable $base for $arch (tried a mingw-w64 $base, clang --target=, and plain $base)"; continue; }
			case $cc in
			*-w64-mingw32*) ;;
			*) note "note: $cc targets the host, not $arch-win32;" \
				"install a mingw-w64 gcc for an ABI-faithful pass" ;;
			esac
			out=$builddir/$arch.$base.log
			: > "$out"
			# One `-fsyntax-only` process per file, up to LINT_JOBS at
			# once: each is independent (no shared state but the source
			# tree, which this only reads), so this is embarrassingly
			# parallel. Every worker writes its own file under $pardir
			# (named for its source path, slashes flattened) instead of
			# appending to $out directly -- concurrent appends from
			# separate processes to one fd are not guaranteed atomic
			# once a diagnostic exceeds a pipe-buffer-sized write, which
			# would otherwise interleave two files' output mid-line.
			# shellcheck disable=SC2086
			set -- $cc
			cc_prog=$1; cc_extra=${2:-}
			pardir=$(mktemp -d "$builddir/warn.XXXXXX") || return 1
			# $srcs and $flags/$WARN_FLAGS are meant to word-split here --
			# one xargs input line per source file, and each flag as its
			# own argument to the per-file sh -c below. $pardir inside the
			# single-quoted script is the closing-quote/reopening-quote
			# trick (not a mistake shellcheck should expand): it is
			# spliced in by *this* shell so the child script -- which
			# genuinely must not expand $id itself until it runs -- gets
			# a literal path.
			# shellcheck disable=SC2086,SC2016
			printf '%s\n' $srcs | xargs -P "$LINT_JOBS" -I{} sh -c '
				f=$1; prog=$2; extra=$3; shift 3
				id=$(printf %s "$f" | tr / _)
				# shellcheck disable=SC2086
				"$prog" $extra -fsyntax-only "$@" "$f" \
					> "'"$pardir"'/$id.log" 2>&1
			' _ {} "$cc_prog" "$cc_extra" $flags $WARN_FLAGS
			# One log per source file, whether or not that file had
			# anything to say -- so counting them is how this stage knows
			# a compile was really attempted for every source.  Without
			# it, "no diagnostics" and "no compiles" are the same output:
			# an xargs whose input went empty (sources_for matching
			# nothing after a directory rename, say) leaves $n at 0 and
			# the old code called that a pass.  The count is taken before
			# $pardir is removed, and compared against the source list
			# rather than merely against zero, so a partial run -- some
			# files reached, some not -- fails too.
			nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
			ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"
			rm -rf "$pardir"
			if [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
				note "$cc [$arch]: FAILED -- $nlog of $nsrc source file(s) were compiled."
				note "  the warning build did not cover the source set, so a clean result"
				note "  here would mean nothing.  This is not a findings count of zero."
				any=1
				continue
			fi
			passes=$((passes + 1))
			# Header diagnostics repeat once per translation unit; collapse
			# them, and drop the source-quote/caret lines gcc interleaves.
			n=$(grep -E '(warning|error):' "$out" | sed 's/^ *//' | sort -u \
				| tee "$out.uniq" | wc -l)
			note "$cc [$arch]: $nsrc file(s), $n unique diagnostic(s) -> $out.uniq"
			show_findings "$out.uniq" warning
			[ "$n" -gt 0 ] && any=1
		done
	done
	if [ "$passes" -eq 0 ] && [ "$LINT_ALLOW_MISSING" != 1 ]; then
		note "warn: FAILED -- no (arch, compiler) pass ran at all; this stage"
		note "  compiled nothing and therefore diagnosed nothing."
		any=1
	fi
	return $any
}

# check_list_ok TIDY -- assert that the clang-tidy binary $1 offers the
# checks tools/clang-tidy-checks.txt says it must.
#
# .clang-tidy at the tree root selects by wildcard (bugprone-*, cert-*,
# clang-analyzer-*, misc-*), and a wildcard resolves to whatever the tool
# in $PATH implements.  So "analyze found 0 findings" is a statement
# about the machine as much as about the code, and the two ways it goes
# wrong are both invisible in that sentence: a tool that offers fewer
# checks than the pin, and the `clang --analyze` fallback below, which
# offers none of them at all.  Measured on the canonical probe
# `long long widen(int a, int b) { return a * b; }`: clang-tidy 18 with
# this tree's .clang-tidy reports bugprone-implicit-widening-of-
# multiplication-result; `clang --analyze` on the same file and target
# reports nothing.  That is defect 5's class.
#
# Run once per stage, not per arch: --list-checks reads .clang-tidy from
# the working directory, which is $srcdir either way.
check_list_ok() {
	tidy=$1
	listfile=tools/clang-tidy-checks.txt
	if [ ! -f "$listfile" ]; then
		note "analyze: FAILED -- $listfile is missing, so there is nothing to hold"
		note "  the running clang-tidy to.  A wildcard check list with no committed"
		note "  expectation is not a check; it is whatever the machine has."
		return 1
	fi
	req=$(mktemp "$builddir/checks.req.XXXXXX") || return 1
	exempt=$(mktemp "$builddir/checks.exempt.XXXXXX") || return 1
	got=$(mktemp "$builddir/checks.got.XXXXXX") || return 1
	sed -e 's/[[:space:]]*$//' "$listfile" \
		| grep -v -e '^#' -e '^[[:space:]]*$' > "$req.all"
	grep -v '^-' "$req.all" | sort -u > "$req"
	sed -n 's/^-//p' "$req.all" | sort -u > "$exempt"
	rm -f "$req.all"
	"$tidy" --list-checks 2>/dev/null | sed -n 's/^    //p' | sort -u > "$got"

	nreq=$(grep -c . "$req" || true)
	ngot=$(grep -c . "$got" || true)
	if [ "$nreq" -eq 0 ]; then
		note "analyze: FAILED -- $listfile names no required checks."
		note "  An empty expectation is satisfied by any tool, including one that"
		note "  offers nothing at all."
		rm -f "$req" "$exempt" "$got"
		return 1
	fi
	rc=0
	nmiss=$(comm -23 "$req" "$got" | grep -c . || true)
	if [ "$nmiss" -ne 0 ]; then
		note "analyze: FAILED -- $tidy offers $ngot check(s) and is missing $nmiss that"
		note "  $listfile requires:"
		comm -23 "$req" "$got" | sed 's/^/    /'
		note "  A tool that offers fewer checks reports the same '0 findings' as one"
		note "  that offers all of them.  Install the pinned clang-tidy, or move the"
		note "  check to the exempt list in $listfile with the reason, in this commit."
		rc=1
	fi
	nextra=$(comm -13 "$req" "$got" | grep -vxF -f "$exempt" 2>/dev/null | grep -c . || true)
	if [ "${LINT_TIDY_EXACT:-0}" = 1 ]; then
		nmissex=$(comm -23 "$exempt" "$got" | grep -c . || true)
		if [ "$nextra" -ne 0 ] || [ "$nmissex" -ne 0 ]; then
			note "analyze: FAILED -- LINT_TIDY_EXACT=1, but $tidy's enabled set is not"
			note "  exactly what $listfile records.  This stage exists to reproduce one"
			note "  pinned toolchain; a difference here means the pin is not pinning."
			comm -13 "$req" "$got" | grep -vxF -f "$exempt" 2>/dev/null \
				| sed 's/^/    only in the tool: /'
			comm -23 "$exempt" "$got" | sed 's/^/    only in the file: /'
			rc=1
		fi
	fi
	[ "$rc" -eq 0 ] && note "analyze: $tidy offers $ngot check(s); all $nreq required present ($nextra newer than the pin)."
	rm -f "$req" "$exempt" "$got"
	return $rc
}

stage_analyze() {
	hdr "static analyzer"
	require_tool clang || return $missing
	any=0
	# CLANG_TIDY lets a caller (CI) pin an exact binary/version -- clang-tidy's
	# findings vary release to release (newer LLVM adds checks under the
	# families this project enables), so an unpinned `command -v clang-tidy`
	# is a gate that can flip red on a toolchain image bump alone.
	: "${CLANG_TIDY:=clang-tidy}"
	require_tool "$CLANG_TIDY" || [ "$LINT_ALLOW_MISSING" = 1 ] || return 1
	tidy=$(command -v "$CLANG_TIDY" 2>/dev/null || true)
	if [ -n "$tidy" ]; then
		check_list_ok "$tidy" || any=1
	else
		# The fallback is no longer allowed to be silent about what it
		# is not running.  It cannot reach here at all unless
		# LINT_ALLOW_MISSING=1 (see require_tool above), so this is a
		# run whose caller has accepted a weaker check -- but "weaker"
		# has to be a number, not an adjective.
		nreq=$(grep -v -e '^#' -e '^-' -e '^[[:space:]]*$' \
			tools/clang-tidy-checks.txt 2>/dev/null | grep -c . || true)
		note "analyze: clang --analyze offers 0 of the $nreq check(s)"
		note "  tools/clang-tidy-checks.txt requires: it runs the clang-analyzer"
		note "  engine only, and none of bugprone-*, cert-* or misc-*.  This run"
		note "  cannot catch anything those families catch, whatever it reports."
	fi
	# The three exemptions in tools/clang-tidy-checks.txt are excused on
	# one condition -- that this stage compiles no C++ -- and a condition
	# that is only written down is a condition that stops being true
	# quietly.  Assert it against the source set actually being fed in.
	for arch in $LINT_ARCHS; do
		cxx=$(sources_for "$arch" | grep -E '\.(cc|cpp|cxx|C)$' || true)
		if [ -n "$cxx" ]; then
			note "analyze: FAILED -- this stage is being handed C++ sources:"
			printf '%s\n' "$cxx" | sed 's/^/    /'
			note "  The three exemptions in tools/clang-tidy-checks.txt are excused"
			note "  solely because no C++ reaches clang-tidy here.  That is no longer"
			note "  true, so they must be re-justified or removed before this passes."
			any=1
		fi
		break
	done
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { note "cannot generate alltypes for $arch"; any=1; continue; }
		flags=$(cppflags_for "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.analyze.log
		: > "$out"
		target=$(pick_target "$arch")
		# One process per source file, up to LINT_JOBS at once -- this is
		# the single most expensive stage (clang-tidy's checks dwarf
		# process startup), so it is the one parallelising this way
		# matters most for. Same per-worker-file-then-cat approach as
		# stage_warn, for the same reason (no interleaved writes).
		pardir=$(mktemp -d "$builddir/analyze.XXXXXX") || return 1
		# See stage_warn's comment above on $flags word-splitting and the
		# $pardir close/reopen-quote splice -- same reasoning applies here.
		if [ -n "$tidy" ]; then
			# .clang-tidy at the tree root supplies the check list.
			# shellcheck disable=SC2086,SC2016
			sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
				f=$1; tidy=$2; target=$3; shift 3
				id=$(printf %s "$f" | tr / _)
				# shellcheck disable=SC2086
				"$tidy" --quiet "$f" -- $target "$@" \
					> "'"$pardir"'/$id.log" 2>/dev/null
			' _ {} "$tidy" "$target" $flags
		else
			# shellcheck disable=SC2086,SC2016
			sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
				f=$1; target=$2; shift 2
				id=$(printf %s "$f" | tr / _)
				# shellcheck disable=SC2086
				clang $target --analyze -Xanalyzer -analyzer-output=text \
					"$@" -o /dev/null "$f" \
					> "'"$pardir"'/$id.log" 2>&1
			' _ {} "$target" $flags
			note "note: clang-tidy not installed; using \`clang --analyze\`," \
				"which runs clang-analyzer-* but none of the bugprone-*/cert-* checks"
		fi
		# Same floor as stage_warn's, for the same reason and the same
		# line of code: one log per source file is written regardless of
		# whether that file had a finding, so "no logs" and "no findings"
		# produced identical output and the old `ls ... && cat` treated
		# both as a pass.  Count the logs against the source list before
		# $pardir goes away.
		nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
		ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"
		rm -rf "$pardir"
		if [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
			note "analyzer [$arch]: FAILED -- $nlog of $nsrc source file(s) were analyzed."
			note "  the analyzer did not cover the source set, so a clean result here"
			note "  would mean nothing.  This is not a findings count of zero."
			any=1
			continue
		fi
		analyzed=$((analyzed + 1))
		n=$(grep -E '(warning|error):' "$out" | sed 's/^ *//' | sort -u \
			| tee "$out.uniq" | wc -l)
		note "analyzer [$arch]: $nsrc file(s), $n unique finding(s) -> $out.uniq"
		show_findings "$out.uniq" warning
		[ "$n" -gt 0 ] && any=1
	done
	if [ "$analyzed" -eq 0 ] && [ "$LINT_ALLOW_MISSING" != 1 ]; then
		note "analyze: FAILED -- no arch was analyzed at all; this stage examined"
		note "  nothing and therefore found nothing."
		any=1
	fi
	return $any
}

stage_cppcheck() {
	hdr "cppcheck"
	require_tool cppcheck || return $missing
	any=0
	# cppcheck 2.13 (what Ubuntu 24.04 ships, and so what CI runs) rejects
	# the comment and blank lines that document why each suppression exists
	# -- "Failed to add suppression. No id." -- while 2.21 accepts them.
	# Keep the documentation in the file and hand cppcheck a stripped copy,
	# so the same tree passes on both.
	suppr=$builddir/cppcheck-suppressions.stripped
	mkdir -p "$builddir"
	sed -e 's/[[:space:]]*#.*//' -e '/^[[:space:]]*$/d' \
		tools/cppcheck-suppressions.txt > "$suppr"
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || continue
		out=$builddir/$arch.cppcheck.log
		asm_define=
		case "$arch" in
		i386) arch_define=-D__i386__=1 ;;
		x86_64) arch_define=-D__x86_64__=1 ;;
		aarch64)
			arch_define=-D__aarch64__=1
			# cppcheck does not parse GNU register variables such as
			# `register long x8 __asm__("x8")`.  Strip only that
			# function-like declaration suffix; statement-form
			# `__asm__ volatile (...)` remains visible to its parser.
			asm_define='-D__asm__(x)='
			;;
		esac
		# shellcheck disable=SC2046,SC2086
		cppcheck --quiet --enable=warning,portability --std=c99 --max-configs=12 \
			--inline-suppr --suppressions-list="$suppr" \
			--error-exitcode=0 -j "$LINT_JOBS" \
			-DNTLIBC_LINT=1 -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_NTLIBC_INTERNAL \
			"$arch_define" $asm_define \
			-Iarch/"$arch" -Iarch/generic -I"$builddir/$arch/include" \
			-Iinclude -Isrc/internal \
			$(sources_for "$arch") > "$out" 2>&1
		n=$(grep -c . "$out")
		note "cppcheck [$arch]: $n line(s) -> $out"
		show_findings "$out" warning
		[ "$n" -gt 0 ] && any=1
	done
	return $any
}

stage_shell() {
	hdr "shellcheck"
	require_tool shellcheck || return $missing
	out=$builddir/shellcheck.log
	mkdir -p "$builddir"
	# No -s: these scripts are a deliberate mix of #!/bin/sh (configure,
	# the hooks, install.sh, this file) and #!/usr/bin/env bash (the two
	# generators), and forcing one dialect would report the other half's
	# perfectly valid syntax as errors.  shellcheck reads the shebangs
	# itself.
	#
	# .githooks/commit-msg and fuzz/coverage.sh were both added (28cef016,
	# 8fe4e4ea) after this line was last written and never joined it, so
	# this stage had never once checked either file -- confirmed by
	# running the tool on them directly, outside this script, before
	# this fix.
	shellcheck configure .githooks/pre-commit .githooks/commit-msg \
		fuzz/coverage.sh tools/*.sh > "$out" 2>&1
	rc=$?
	n=$(grep -cE '^In .* line [0-9]+:' "$out")
	note "shellcheck: $n finding(s) -> $out"
	show_findings "$out"
	# show_findings above never emits a GitHub annotation for $out: the
	# human ("tty") format shellcheck defaults to -- which is what makes
	# it worth reading at a terminal -- has no "path:line[:col]:" prefix
	# tools/lint-gh-annotate.sh can parse (a bare "In FILE line N:"
	# header, then a source-context line, then an indented caret line).
	# Rather than teach the shared parser that one tool's multi-line
	# shape, ask shellcheck itself for the same findings a second time,
	# in its machine-readable `-f gcc` output -- cheap, since it is the
	# same files and shellcheck is not the slow part of this stage --
	# purely to drive annotations.  Gated on GITHUB_ACTIONS directly
	# (matching tools/lint-gh-annotate.sh's own gate) so a local run
	# never pays for or sees this second pass at all.
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		gccout=$builddir/shellcheck.gcc.log
		shellcheck -f gcc configure .githooks/pre-commit .githooks/commit-msg \
			fuzz/coverage.sh tools/*.sh > "$gccout" 2>&1
		tools/lint-gh-annotate.sh warning "$gccout"
	fi
	[ "$rc" -eq 0 ] && return 0
	return 1
}

stage_sizearith() {
	hdr "checked size arithmetic, integer casts, indices, and tagged results"
	any=0
	mkdir -p "$builddir"
	# Captured to a file, then cat -- not run bare -- purely so the same
	# real findings this already printed can also reach
	# tools/lint-gh-annotate.sh: unlike every stage_* above, this driver
	# scans the whole tree itself and prints straight to this stage's
	# stdout, with no intermediate log file show_findings could read.
	# The capture-then-cat prints the identical bytes in the identical
	# place a plain local run always has, so this changes nothing a
	# person at a terminal sees.
	out=$builddir/sizearith.report
	tools/lint-sizearith.py > "$out" 2>&1
	rc=$?
	cat "$out"
	[ "$rc" -eq 0 ] || any=1
	tools/lint-gh-annotate.sh error "$out"

	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	require_tool pkg-config || return $missing
	if ! pkg-config --exists z3; then
		report_missing "Z3 development headers and library are not installed, so the SizeCast relational-bound fallback cannot be proved."
		return $missing
	fi
	if ! z3_flags=$(pkg-config --cflags --libs z3); then
		report_missing "pkg-config could not resolve Z3 compiler and linker flags."
		return $missing
	fi
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
		-print 2>/dev/null | sort | head -n 1)
	if [ -z "$clang_cpp" ]; then
		report_missing "Clang 18 development libraries are not installed, so integer casts cannot be proved."
		return $missing
	fi

	plugin=$builddir/ntlibc-size-cast-checker.so
	# NTLIBC_ARITHMETIC_Z3 turns on both SizeCastChecker.cpp's own
	# CastZ3Proof fallback (a same-width relational bound Clang's
	# interval-only RangeConstraintManager cannot combine on its own --
	# see CastZ3Proof's own comment) and arithub's ArithmeticZ3Proof; both
	# checkers live in this one translation unit and this one plugin, the
	# same way NTLIBC_OWNERSHIP_ANALYSIS below turns on ArrayIndex's
	# elements_withtok contract reading.
	#
	# -fexceptions must follow --cxxflags, not precede it: --cxxflags
	# carries LLVM's own -fno-exceptions, and the later flag wins (see
	# stage_arithub's identical build for the same requirement -- z3++.h's
	# `throw exception(...)` calls fail to compile outright otherwise).
	# llvm-config and pkg-config deliberately return shell words, not one
	# argument.
	# shellcheck disable=SC2046,SC2086
	clang++-18 -fPIC -shared -DNTLIBC_ARITHMETIC_Z3 \
		$(llvm-config-18 --cxxflags) -fexceptions \
		tools/clang/SizeCastChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) $z3_flags || return 1

	fixture_log=$builddir/cast-range-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-cast-range-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.SizeCast \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	array_fixture_log=$builddir/array-index-fixtures.log
	: > "$array_fixture_log"
	for fixture in tools/lint-array-index-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.ArrayIndex \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$array_fixture_log" 2>&1 || any=1
	done
	tagged_fixture_log=$builddir/tagged-result-fixtures.log
	: > "$tagged_fixture_log"
	for fixture in tools/lint-tagged-result-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.TaggedResult \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$tagged_fixture_log" 2>&1 || any=1
	done
	sentinel_fixture_log=$builddir/integer-sentinel-fixtures.log
	: > "$sentinel_fixture_log"
	for fixture in tools/lint-integer-sentinel-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.IntegerSentinel \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$sentinel_fixture_log" 2>&1 || any=1
	done

	cast_logs=
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch")
		target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.cast-range.log
		pardir=$(mktemp -d "$builddir/cast-range.XXXXXX") || return 1
		# Each analyzer owns a log, avoiding interleaved path diagnostics.
		# NTLIBC_OWNERSHIP_ANALYSIS turns on include/ownership.h's
		# elements_withtok(token, extent) attribute, already written on
		# every argc/argv-shaped utility entry point purely for
		# OwnershipChecker's benefit.  ntlibc.ArrayIndex reads the same
		# attribute to learn a pointer parameter's element count where no
		# statement in this translation unit could otherwise tell it one.
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.SizeCast,ntlibc.ArrayIndex,ntlibc.TaggedResult,ntlibc.IntegerSentinel \
				-DNTLIBC_OWNERSHIP_ANALYSIS \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?
		nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
		: > "$out"
		ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"
		rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
			note "cast analyzer [$arch]: FAILED -- $nlog of $nsrc source file(s) completed."
			show_findings "$out"
			any=1
			continue
		fi
		analyzed=$((analyzed + 1))
		cast_logs="$cast_logs $out"
	done
	if [ "$analyzed" -eq 0 ]; then
		note "cast analyzer: FAILED -- no architecture was analyzed."
		return 1
	fi
	# Same capture-then-cat-then-annotate shape as tools/lint-sizearith.py
	# above, and for the same reason: these three drivers print real
	# per-file findings straight to this stage's stdout, with no log
	# show_findings could read on their behalf.
	# The logs are intentionally word-split: one argument per architecture.
	cast_report=$builddir/cast-range.report
	# shellcheck disable=SC2086
	tools/lint-cast-range.py --fixtures "$fixture_log" $cast_logs > "$cast_report" 2>&1
	rc=$?
	cat "$cast_report"
	[ "$rc" -eq 0 ] || any=1
	tools/lint-gh-annotate.sh error "$cast_report"

	array_report=$builddir/array-index.report
	# shellcheck disable=SC2086
	tools/lint-array-index.py --fixtures "$array_fixture_log" $cast_logs > "$array_report" 2>&1
	rc=$?
	cat "$array_report"
	[ "$rc" -eq 0 ] || any=1
	tools/lint-gh-annotate.sh error "$array_report"

	tagged_report=$builddir/tagged-result.report
	# shellcheck disable=SC2086
	tools/lint-tagged-result.py --fixtures "$tagged_fixture_log" $cast_logs > "$tagged_report" 2>&1
	rc=$?
	cat "$tagged_report"
	[ "$rc" -eq 0 ] || any=1
	tools/lint-gh-annotate.sh error "$tagged_report"

	sentinel_report=$builddir/integer-sentinel.report
	# shellcheck disable=SC2086
	tools/lint-integer-sentinel.py --fixtures "$sentinel_fixture_log" $cast_logs > "$sentinel_report" 2>&1
	rc=$?
	cat "$sentinel_report"
	[ "$rc" -eq 0 ] || any=1
	tools/lint-gh-annotate.sh error "$sentinel_report"
	return $any
}

stage_totality() {
	hdr "totality and bounded execution"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	require_tool pkg-config || return $missing
	if ! pkg-config --exists z3; then
		report_missing "Z3 development headers and library are not installed, so scalar loop transitions cannot be proved."
		return $missing
	fi
	if ! z3_flags=$(pkg-config --cflags --libs z3); then
		report_missing "pkg-config could not resolve Z3 compiler and linker flags."
		return $missing
	fi
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
		-print 2>/dev/null | sort | head -n 1)
	if [ -z "$clang_cpp" ]; then
		report_missing "Clang 18 development libraries are not installed, so termination cannot be proved."
		return $missing
	fi

	plugin=$builddir/ntlibc-totality-checker.so
	# llvm-config and pkg-config deliberately return shell words, not one
	# argument.
	# shellcheck disable=SC2046,SC2086
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) -fexceptions \
		tools/clang/TotalityChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) $z3_flags || return 1

	fixture_log=$builddir/totality-fixtures.log
	fixture_err=$builddir/totality-fixtures.err
	: > "$fixture_log"
	: > "$fixture_err"
	for fixture in tools/lint-totality-fixtures/*.c; do
		clang-18 -std=c99 -fsyntax-only \
			-Xclang -load -Xclang "$plugin" \
			-Xclang -add-plugin -Xclang ntlibc-totality "$fixture" \
			>> "$fixture_log" 2>> "$fixture_err" || any=1
	done
	if [ -s "$fixture_err" ]; then
		note "totality fixtures: compiler diagnostics -> $fixture_err"
		show_findings "$fixture_err"
		any=1
	fi
	tools/lint-totality.py --fixtures "$fixture_log" || any=1

	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch")
		target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.totality.log
		err=$builddir/$arch.totality.err
		report=$builddir/$arch.totality.report
		pardir=$(mktemp -d "$builddir/totality.XXXXXX") || return 1
		# One fact stream per translation unit avoids interleaved TSV records.
		# This stage's plugin is a plain -fsyntax-only PluginASTAction, not a
		# clang --analyze checker, so unlike every other stage in this file
		# that reads one of include/ownership.h's annotate(...) macros,
		# clang never predefines __clang_analyzer__ here -- confirmed by
		# comparing `clang -fsyntax-only` against `clang --analyze` on the
		# same trivial input, the latter alone defining it. Without this
		# flag, ownership.h's withtok(null_terminated) would go dark for
		# this scan the same way elements_withtok already required it
		# below stage_sizearith, and TotalityChecker's real "withtok:
		# null_terminated" == match at every genuine call site would never
		# fire, silently losing loop-termination proofs for every real
		# NUL-terminated-string parameter in the tree.
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target -fsyntax-only -Xclang -load -Xclang "$plugin" \
				-Xclang -add-plugin -Xclang ntlibc-totality \
				-DNTLIBC_OWNERSHIP_ANALYSIS "$@" "$f" \
				> "'"$pardir"'/$id.log" 2> "'"$pardir"'/$id.err"
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?
		nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
		: > "$out"
		: > "$err"
		ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"
		ls "$pardir"/*.err >/dev/null 2>&1 && cat "$pardir"/*.err > "$err"
		rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
			note "totality extractor [$arch]: FAILED -- $nlog of $nsrc source file(s) completed."
			show_findings "$err"
			any=1
			continue
		fi
		analyzed=$((analyzed + 1))
		if tools/lint-totality.py "$out" > "$report" 2>&1; then
			note "totality [$arch]: proved -> $report"
		else
			note "totality [$arch]: findings -> $report"
			show_findings "$report"
			any=1
		fi
	done
	if [ "$analyzed" -eq 0 ]; then
		note "totality extractor: FAILED -- no architecture was analyzed."
		return 1
	fi
	return $any
}

stage_arithub() {
	hdr "division and shift proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	require_tool pkg-config || return $missing
	if ! pkg-config --exists z3; then
		report_missing "Z3 development headers and library are not installed, so relational arithmetic constraints cannot be proved."
		return $missing
	fi
	if ! z3_flags=$(pkg-config --cflags --libs z3); then
		report_missing "pkg-config could not resolve Z3 compiler and linker flags."
		return $missing
	fi
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
		-print 2>/dev/null | sort | head -n 1)
	if [ -z "$clang_cpp" ]; then
		report_missing "Clang 18 development libraries are not installed, so arithmetic preconditions cannot be proved."
		return $missing
	fi

	plugin=$builddir/ntlibc-arithmetic-ub-checker.so
	algebra_test=$builddir/ntlibc-exact-c-scalar-smt-test
	# llvm-config and pkg-config deliberately return shell words, not one
	# argument.
	# shellcheck disable=SC2046,SC2086
	clang++-18 -std=c++17 tools/clang/ExactCScalarSMTTest.cpp \
		-o "$algebra_test" $z3_flags || return 1
	"$algebra_test" || return 1
	# shellcheck disable=SC2046,SC2086
	# -fexceptions must follow --cxxflags, not precede it: --cxxflags
	# carries LLVM's own -fno-exceptions, and the later flag wins.  Without
	# this (as stage_totality's identical build already has it), z3++.h's
	# `throw exception(...)` calls fail to compile outright -- this stage
	# could not build its plugin at all, on any machine, until this was
	# added; confirmed by removing the flag and reproducing the same
	# "cannot use 'throw' with exceptions disabled" error in isolation.
	clang++-18 -fPIC -shared -DNTLIBC_ARITHMETIC_Z3 \
		$(llvm-config-18 --cxxflags) -fexceptions \
		tools/clang/SizeCastChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) $z3_flags || return 1

	# These built-ins add a same-operation assumption before a plugin's
	# PreStmt callback.  Disable only the overlapping checks so ntlibc's
	# checkers prove their own obligations from the real current path state.
	fixture_log=$builddir/arithmetic-ub-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-arithmetic-ub-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.Divisor,ntlibc.ShiftCount,ntlibc.SignedArithmetic,ntlibc.ArithmeticContract \
			-Xclang -analyzer-disable-checker=core.DivideZero,core.BitwiseShift \
			-Xclang -analyzer-output=text -DNTLIBC_ARITHMETIC_ANALYSIS "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-arithmetic-ub.py --fixtures "$fixture_log" || any=1

	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch")
		target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.arithmetic-ub.log
		report=$builddir/$arch.arithmetic-ub.report
		pardir=$(mktemp -d "$builddir/arithmetic-ub.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.Divisor,ntlibc.ShiftCount,ntlibc.SignedArithmetic,ntlibc.ArithmeticContract \
				-Xclang -analyzer-disable-checker=core.DivideZero,core.BitwiseShift \
				-Xclang -analyzer-output=text -DNTLIBC_ARITHMETIC_ANALYSIS "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?
		nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
		: > "$out"
		ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"
		rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
			note "arithmetic analyzer [$arch]: FAILED -- $nlog of $nsrc source file(s) completed."
			show_findings "$out"
			any=1
			continue
		fi
		analyzed=$((analyzed + 1))
		if tools/lint-arithmetic-ub.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "arithmetic proofs [$arch]: proved -> $report"
		else
			note "arithmetic proofs [$arch]: findings -> $report"
			show_findings "$report"
			any=1
		fi
	done
	if [ "$analyzed" -eq 0 ]; then
		note "arithmetic analyzer: FAILED -- no architecture was analyzed."
		return 1
	fi
	return $any
}

stage_ownership() {
	hdr "ownership, allocation lifetime, borrow, and memory proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	require_tool pkg-config || return $missing
	if ! pkg-config --exists z3; then
		report_missing "Z3 development headers and library are not installed, so the memory contract's no-wrap side condition and pointer extent bounds beyond the ad hoc linear prover cannot be proved."
		return $missing
	fi
	if ! z3_flags=$(pkg-config --cflags --libs z3); then
		report_missing "pkg-config could not resolve Z3 compiler and linker flags."
		return $missing
	fi
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
		-print 2>/dev/null | sort | head -n 1)
	if [ -z "$clang_cpp" ]; then
		report_missing "Clang 18 development libraries are not installed, so pointer ownership cannot be proved."
		return $missing
	fi

	token_test=$builddir/token-algebra-test
	# llvm-config deliberately returns shell words, not one argument.
	# shellcheck disable=SC2046
	clang++-18 $(llvm-config-18 --cxxflags) \
		tools/clang/TokenAlgebraTest.cpp -o "$token_test" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	"$token_test" || return 1

	lifecycle_test=$builddir/lifecycle-algebra-test
	clang++-18 -std=c++17 -Wall -Wextra -Werror \
		tools/clang/LifecycleAlgebraTest.cpp -o "$lifecycle_test" || return 1
	"$lifecycle_test" || return 1

	# MemoryContractChecker.cpp's own no-wrap side condition uses a real Z3
	# proof (see MemoryContractZ3Proof), the same way stage_arithub's
	# SizeCastChecker.cpp does. Z3 is a hard requirement for this stage (see
	# the pkg-config check above), so the flag is always defined here.
	#
	# -fexceptions must follow --cxxflags, not precede it: --cxxflags
	# carries LLVM's own -fno-exceptions, and the later flag wins (see
	# stage_arithub's identical build for the same requirement -- z3++.h's
	# `throw exception(...)` calls fail to compile without it).
	memory_contract_cxxflags="-DNTLIBC_MEMORY_CONTRACT_Z3 -fexceptions"

	plugin=$builddir/ntlibc-ownership-checker.so
	# llvm-config and pkg-config deliberately return shell words, not one
	# argument.
	# shellcheck disable=SC2046,SC2086
	# -fexceptions must follow --cxxflags, not precede it: --cxxflags
	# carries LLVM's own -fno-exceptions, and the later flag wins (see
	# stage_arithub's identical build for the same requirement). Both
	# NTLIBC_MEMORY_CONTRACT_Z3 (MemoryContractChecker.cpp's no-wrap side
	# condition) and NTLIBC_OWNERSHIP_Z3 (OwnershipChecker.cpp's extent
	# bounds fallback) share this one -fexceptions, since z3++.h's `throw
	# exception(...)` calls are compiled into this one translation unit
	# either way.
	clang++-18 -fPIC -shared -DOWNERSHIP_CHECKER_BUNDLE -DNTLIBC_OWNERSHIP_Z3 \
		$(llvm-config-18 --cxxflags) $memory_contract_cxxflags \
		tools/clang/OwnershipChecker.cpp \
		tools/clang/AllocationLifetimeChecker.cpp \
		tools/clang/MemoryContractChecker.cpp \
		-o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) $z3_flags || return 1

	fixture_log=$builddir/ownership-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-ownership-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.Ownership,ntlibc.OwnedConstruct,ntlibc.OwnershipContract,ntlibc.AggregateElementToken,ntlibc.CapabilityToken,ntlibc.OwnershipType,ntlibc.ValidPointer,ntlibc.Resource \
			-DNTLIBC_OWNERSHIP_ANALYSIS \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-ownership.py --fixtures "$fixture_log" || any=1

	allocation_fixture_log=$builddir/allocation-lifetime-fixtures.log
	: > "$allocation_fixture_log"
	for fixture in tools/lint-allocation-lifetime-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.AllocationLifetime \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$allocation_fixture_log" 2>&1 || any=1
	done
	tools/lint-allocation-lifetime.py --fixtures "$allocation_fixture_log" || any=1

	memory_fixture_log=$builddir/memory-contract-fixtures.log
	: > "$memory_fixture_log"
	for fixture in tools/lint-memory-contract-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.MemoryContract \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$memory_fixture_log" 2>&1 || any=1
	done
	tools/lint-memory-contracts.py --fixtures "$memory_fixture_log" || any=1

	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags="$(cppflags_for "$arch")"
		target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.ownership.log
		report=$builddir/$arch.ownership.report
		allocation_report=$builddir/$arch.allocation-lifetime.report
		memory_report=$builddir/$arch.memory-contract.report
		pardir=$(mktemp -d "$builddir/ownership.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			owner="'"$pardir"'/$id.owner"
			pointer="'"$pardir"'/$id.pointer"
			allocation="'"$pardir"'/$id.allocation"
			combined="'"$pardir"'/$id.log"
			# Keep the high-volume pointer proof search from consuming the
			# exploration budget needed by ownership/lifecycle proofs.
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.Ownership,ntlibc.OwnedConstruct,ntlibc.OwnershipContract,ntlibc.AggregateElementToken,ntlibc.CapabilityToken,ntlibc.OwnershipType,ntlibc.Resource \
				-DNTLIBC_OWNERSHIP_ANALYSIS \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "$owner" 2>&1
			owner_rc=$?
			# Ownership also supplies allocation provenance to ValidPointer.
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.Ownership,ntlibc.ValidPointer,ntlibc.MemoryContract \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "$pointer" 2>&1
			pointer_rc=$?
			# Allocation lifetime has its own state space and path budget, but
			# consumes the same declaration axioms from this combined plugin.
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.AllocationLifetime \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "$allocation" 2>&1
			allocation_rc=$?
			cat "$owner" "$pointer" "$allocation" > "$combined"
			[ "$owner_rc" -eq 0 ] && [ "$pointer_rc" -eq 0 ] && \
				[ "$allocation_rc" -eq 0 ]
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?
		nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
		: > "$out"
		ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"
		rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
			note "ownership analyzer [$arch]: FAILED -- $nlog of $nsrc source file(s) completed."
			show_findings "$out"
			any=1
			continue
		fi
		analyzed=$((analyzed + 1))
		if tools/lint-ownership.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "ownership proofs [$arch]: proved -> $report"
		else
			note "ownership proofs [$arch]: findings -> $report"
			show_findings "$report"
			any=1
		fi
		if tools/lint-allocation-lifetime.py --fixtures "$allocation_fixture_log" \
			"$out" > "$allocation_report" 2>&1; then
			note "allocation lifetime proofs [$arch]: proved -> $allocation_report"
		else
			note "allocation lifetime proofs [$arch]: findings -> $allocation_report"
			show_findings "$allocation_report"
			any=1
		fi
		if tools/lint-memory-contracts.py --fixtures "$memory_fixture_log" \
			"$out" > "$memory_report" 2>&1; then
			note "memory token proofs [$arch]: proved -> $memory_report"
		else
			note "memory token proofs [$arch]: findings -> $memory_report"
			show_findings "$memory_report"
			any=1
		fi
	done
	if [ "$analyzed" -eq 0 ]; then
		note "ownership analyzer: FAILED -- no architecture was analyzed."
		return 1
	fi
	return $any
}

stage_initproof() {
	hdr "definite-initialization proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for initialization proofs."; return $missing; }
	plugin=$builddir/ntlibc-initialization-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/InitializationChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/initialization-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-initialization-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.InitializedRead \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-initialization.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.initialization.log
		report=$builddir/$arch.initialization.report
		pardir=$(mktemp -d "$builddir/initialization.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.InitializedRead \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-initialization.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "initialization proofs [$arch]: proved -> $report"
		else
			note "initialization proofs [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_fallible() {
	hdr "fallible-result proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for fallible-result proofs."; return $missing; }
	plugin=$builddir/ntlibc-fallible-result-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/FallibleResultChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/fallible-result-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-fallible-result-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.FallibleResult \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-fallible-result.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.fallible-result.log
		report=$builddir/$arch.fallible-result.report
		pardir=$(mktemp -d "$builddir/fallible-result.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.FallibleResult \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-fallible-result.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "fallible-result proofs [$arch]: proved -> $report"
		else
			note "fallible-result proofs [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_provenance() {
	hdr "pointer-provenance proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for provenance proofs."; return $missing; }
	plugin=$builddir/ntlibc-pointer-provenance-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/PointerProvenanceChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/pointer-provenance-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-pointer-provenance-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.PointerProvenance \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-pointer-provenance.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.pointer-provenance.log
		report=$builddir/$arch.pointer-provenance.report
		pardir=$(mktemp -d "$builddir/pointer-provenance.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.PointerProvenance \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-pointer-provenance.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "pointer provenance [$arch]: proved -> $report"
		else
			note "pointer provenance [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_locks() {
	hdr "lock-discipline proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for lock proofs."; return $missing; }
	plugin=$builddir/ntlibc-lock-discipline-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/LockDisciplineChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/lock-discipline-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-lock-discipline-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.LockDiscipline \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-lock-discipline.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.lock-discipline.log
		report=$builddir/$arch.lock-discipline.report
		pardir=$(mktemp -d "$builddir/lock-discipline.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.LockDiscipline \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-lock-discipline.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "lock discipline [$arch]: proved -> $report"
		else
			note "lock discipline [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

# Clang's own Thread Safety Analysis, driven entirely by attributes behind
# src/internal/thread_annotations.h -- unlike the stages above and below
# this one, there is no custom checker plugin to build: -Wthread-safety and
# its diagnostics are the ground truth, so this is a plain -fsyntax-only
# flags-only pass, structurally the closest thing in this file to
# stage_warn()/stage_variadic() rather than to stage_locks()/
# stage_signals(). NTLIBC_LOCKSET_ANALYSIS is the macro
# thread_annotations.h requires (on top of __clang__) before any
# NTLIBC_* annotation macro emits a real attribute at all; every other
# clang-based stage in this file compiles the same tree without it and so
# never sees these attributes.
stage_lockset() {
	hdr "lockset (guarded-by) proof obligations"
	any=0
	require_tool clang-18 || return $missing
	# -c alongside -fsyntax-only changes nothing about what gets analyzed
	# or emitted -- -fsyntax-only stops before code generation regardless,
	# so no .o ever appears -- but it does tell a Nix stdenv cc-wrapper
	# clang-18 that this is not a link step. Without it, the wrapper still
	# appends its own -Wl,-dynamic-linker=/-L linker flags (it only skips
	# them for -c/-S/-E/-M/-MM), which clang then reports right back as
	# "argument unused during compilation" -- warning noise from the
	# wrapper, unrelated to thread safety, that would otherwise trip the
	# safe.c fixture's "must compile silent" check below on Nix alone.
	lockset_flags="-DNTLIBC_LOCKSET_ANALYSIS -Wthread-safety -Wthread-safety-analysis -Wthread-safety-precise -Wno-unused-function -c"
	fixture_log=$builddir/lockset-fixtures.log
	: > "$fixture_log"
	# Two fixtures, two expectations: the correctly guarded one must stay
	# silent, and the clear violation must not.  A self-test that only
	# checked "no crash" would pass just as happily if -Wthread-safety
	# never fired at all -- see tools/lint-lockset-fixtures/*.c.
	# shellcheck disable=SC2086
	safe_out=$(clang-18 -fsyntax-only $lockset_flags tools/lint-lockset-fixtures/safe.c 2>&1)
	printf '%s\n' "$safe_out" >> "$fixture_log"
	if printf '%s' "$safe_out" | grep -q 'warning:\|error:'; then
		note "lockset: FAILED -- tools/lint-lockset-fixtures/safe.c is a correctly guarded"
		note "  case and must compile silent; it did not:"
		printf '%s\n' "$safe_out" | sed 's/^/    /'
		any=1
	fi
	# shellcheck disable=SC2086
	unsafe_out=$(clang-18 -fsyntax-only $lockset_flags tools/lint-lockset-fixtures/unsafe.c 2>&1)
	printf '%s\n' "$unsafe_out" >> "$fixture_log"
	if ! printf '%s' "$unsafe_out" | grep -q 'thread-safety'; then
		note "lockset: FAILED -- tools/lint-lockset-fixtures/unsafe.c is a clear violation"
		note "  (an unguarded write to a guarded_by global) and produced no"
		note "  -Wthread-safety diagnostic at all; the fixture pair cannot tell"
		note "  a working checker from a silently disabled one."
		any=1
	fi
	[ "$any" -eq 0 ] && note "lockset: fixtures ok -> $fixture_log"
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.lockset.log
		pardir=$(mktemp -d "$builddir/lockset.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; target=$3; shift 3
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target -fsyntax-only "$@" "$f" \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$target" $flags $lockset_flags
		nlog=$(find "$pardir" -name '*.log' 2>/dev/null | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then
			note "lockset [$arch]: FAILED -- $nlog of $nsrc source file(s) were compiled."
			any=1
			continue
		fi
		analyzed=$((analyzed + 1))
		# This stage owns thread-safety diagnostics, not unrelated warnings
		# emitted incidentally by the syntax-only compile. Compiler errors
		# remain fatal because an uncompiled translation unit proves nothing.
		n=$(grep -E 'error:|warning:.*\[-Wthread-safety[^]]*\]' "$out" | sed 's/^ *//' | sort -u \
			| tee "$out.uniq" | wc -l)
		note "lockset [$arch]: $nsrc file(s), $n unique diagnostic(s) -> $out.uniq"
		show_findings "$out.uniq" warning
		[ "$n" -gt 0 ] && any=1
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_abizeroinit() {
	hdr "Nt*/Zw* ABI zero-initialization proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for ABI zero-init proofs."; return $missing; }
	plugin=$builddir/ntlibc-abi-zeroinit-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/AbiZeroInitChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/abi-zeroinit-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-abi-zeroinit-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.AbiZeroInit \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-abi-zeroinit.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.abi-zeroinit.log
		report=$builddir/$arch.abi-zeroinit.report
		pardir=$(mktemp -d "$builddir/abi-zeroinit.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.AbiZeroInit \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-abi-zeroinit.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "ABI zero-init [$arch]: proved -> $report"
		else
			note "ABI zero-init [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_variadic() {
	hdr "variadic ABI and format proof obligations"
	any=0
	require_tool clang-18 || return $missing
	fixture_log=$builddir/variadic-abi-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-variadic-abi-fixtures/*.c; do
		clang-18 -fsyntax-only -Wformat=2 -Wformat-pedantic "$fixture" \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-variadic-abi.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.variadic-abi.log
		report=$builddir/$arch.variadic-abi.report
		pardir=$(mktemp -d "$builddir/variadic-abi.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; target=$3; shift 3
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target -fsyntax-only -Wformat=2 -Wformat-pedantic \
				"$@" "$f" > "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; show_findings "$out"; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-variadic-abi.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "variadic ABI [$arch]: proved -> $report"
		else
			note "variadic ABI [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_signals() {
	hdr "signal-handler safety proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for signal-safety proofs."; return $missing; }
	plugin=$builddir/ntlibc-signal-safety-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/SignalSafetyChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/signal-safety-fixtures.log
	: > "$fixture_log"
	# This stage's plugin is a plain -fsyntax-only PluginASTAction, not a
	# clang --analyze checker, so clang never predefines __clang_analyzer__
	# here (see stage_totality's identical note) -- without
	# -DNTLIBC_OWNERSHIP_ANALYSIS, include/ownership.h's async_signal_safe
	# annotation goes dark and asyncSafe() finds nothing on any callee.
	for fixture in tools/lint-signal-safety-fixtures/*.c; do
		clang-18 -fsyntax-only -Xclang -load -Xclang "$plugin" \
			-Xclang -add-plugin -Xclang ntlibc-signal-safety \
			-DNTLIBC_OWNERSHIP_ANALYSIS "$fixture" \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-signal-safety.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.signal-safety.log
		report=$builddir/$arch.signal-safety.report
		pardir=$(mktemp -d "$builddir/signal-safety.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target -fsyntax-only -Xclang -load -Xclang "$plugin" \
				-Xclang -add-plugin -Xclang ntlibc-signal-safety \
				-DNTLIBC_OWNERSHIP_ANALYSIS "$@" "$f" \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; show_findings "$out"; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-signal-safety.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "signal safety [$arch]: proved -> $report"
		else
			note "signal safety [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_errno() {
	hdr "errno-discipline proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for errno-discipline proofs."; return $missing; }
	plugin=$builddir/ntlibc-errno-discipline-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/ErrnoDisciplineChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/errno-discipline-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-errno-discipline-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.ErrnoDiscipline \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-errno-discipline.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.errno-discipline.log
		report=$builddir/$arch.errno-discipline.report
		pardir=$(mktemp -d "$builddir/errno-discipline.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.ErrnoDiscipline \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-errno-discipline.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "errno discipline [$arch]: proved -> $report"
		else
			note "errno discipline [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_reentrancy() {
	hdr "reentrant-static-storage proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for reentrancy proofs."; return $missing; }
	plugin=$builddir/ntlibc-reentrancy-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/ReentrancyChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/reentrancy-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-reentrancy-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.Reentrancy \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-reentrancy.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.reentrancy.log
		report=$builddir/$arch.reentrancy.report
		pardir=$(mktemp -d "$builddir/reentrancy.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.Reentrancy \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-reentrancy.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "reentrancy [$arch]: proved -> $report"
		else
			note "reentrancy [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_purity() {
	hdr "__attribute__((pure)) eligibility and false-claim proof obligations"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for purity proofs."; return $missing; }
	plugin=$builddir/ntlibc-purity-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/PurityChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/purity-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-purity-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.Purity \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-purity.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.purity.log
		report=$builddir/$arch.purity.report
		pardir=$(mktemp -d "$builddir/purity.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.Purity \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; show_findings "$out"; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-purity.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "purity proofs [$arch]: proved -> $report"
		else
			note "purity proofs [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

stage_loopcond() {
	hdr "loop headers that compound a bound with a data-dependent condition"
	any=0
	require_tool clang-18 || return $missing
	require_tool clang++-18 || return $missing
	require_tool llvm-config-18 || return $missing
	libdir=$(llvm-config-18 --libdir)
	clang_cpp=$(find "$libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' -print 2>/dev/null | sort | head -n 1)
	[ -n "$clang_cpp" ] || { report_missing "Clang 18 development libraries are required for loop-condition analysis."; return $missing; }
	plugin=$builddir/ntlibc-loopcond-checker.so
	# shellcheck disable=SC2046
	clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
		tools/clang/LoopConditionChecker.cpp -o "$plugin" "$clang_cpp" \
		$(llvm-config-18 --ldflags --libs --system-libs) || return 1
	fixture_log=$builddir/loopcond-fixtures.log
	: > "$fixture_log"
	for fixture in tools/lint-loopcond-fixtures/*.c; do
		clang-18 --analyze -Xclang -load -Xclang "$plugin" \
			-Xclang -analyzer-checker=ntlibc.LoopCondition \
			-Xclang -analyzer-output=text "$fixture" -o /dev/null \
			>> "$fixture_log" 2>&1 || any=1
	done
	tools/lint-loopcond.py --fixtures "$fixture_log" || any=1
	analyzed=0
	for arch in $LINT_ARCHS; do
		gen_alltypes "$arch" || { any=1; continue; }
		flags=$(cppflags_for "$arch"); target=$(pick_target "$arch")
		nsrc=$(sources_for "$arch" | grep -c . || true)
		out=$builddir/$arch.loopcond.log
		report=$builddir/$arch.loopcond.report
		pardir=$(mktemp -d "$builddir/loopcond.XXXXXX") || return 1
		# shellcheck disable=SC2086,SC2016
		sources_for "$arch" | xargs -P "$LINT_JOBS" -I{} sh -c '
			f=$1; clang=$2; plugin=$3; target=$4; shift 4
			id=$(printf %s "$f" | tr / _)
			# shellcheck disable=SC2086
			"$clang" $target --analyze -Xclang -load -Xclang "$plugin" \
				-Xclang -analyzer-checker=ntlibc.LoopCondition \
				-Xclang -analyzer-output=text "$@" "$f" -o /dev/null \
				> "'"$pardir"'/$id.log" 2>&1
		' _ {} clang-18 "$plugin" "$target" $flags
		runrc=$?; nlog=$(find "$pardir" -name '*.log' | grep -c . || true)
		: > "$out"; ls "$pardir"/*.log >/dev/null 2>&1 && cat "$pardir"/*.log > "$out"; rm -rf "$pardir"
		if [ "$runrc" -ne 0 ] || [ "$nsrc" -eq 0 ] || [ "$nlog" -ne "$nsrc" ]; then any=1; show_findings "$out"; continue; fi
		analyzed=$((analyzed + 1))
		if tools/lint-loopcond.py --fixtures "$fixture_log" "$out" > "$report" 2>&1; then
			note "loop condition shape [$arch]: no findings -> $report"
		else
			note "loop condition shape [$arch]: findings -> $report"; show_findings "$report"; any=1
		fi
	done
	[ "$analyzed" -gt 0 ] || return 1
	return $any
}

requested_stages=${*:-warn analyze cppcheck shell fallible locks lockset reentrancy variadic signals abizeroinit initproof errno purity ownership undefined unreferenced widthmod}
stages=
for requested_stage in $requested_stages; do
	case $requested_stage in
	alloclife|memcontracts) normalized_stage=ownership ;;
	*) normalized_stage=$requested_stage ;;
	esac
	case " $stages " in
	*" $normalized_stage "*) ;;
	*) stages="$stages $normalized_stage" ;;
	esac
done
mkdir -p "$builddir" || exit 1

# Generate every arch's alltypes.h once, up front, before any stage that
# needs it can possibly run -- see gen_alltypes's own comment for why this
# matters once stages run concurrently.
for arch in $LINT_ARCHS; do gen_alltypes "$arch" || note "cannot generate alltypes for $arch"; done

# The stages read only from the source tree and each other's-own
# obj/lint/* output files (never one another's), so they are independent
# and run concurrently, each buffered to its own log and printed as one
# unit afterwards -- exactly the same reasoning as the per-file
# parallelism inside stage_warn/stage_analyze above, one level up. A
# single `tools/lint.sh` invocation with all of the default stages was the
# dominant cost of a full local verification pass (it does not itself
# fork off separate toolchains the way the two pinned CI-reproduction
# nix-shell invocations do); this is what cuts that down.
rundir=$(mktemp -d "$builddir/run.XXXXXX") || exit 1
export LINT_MISSING_MARKER="$rundir/missing"
for s in $stages; do
	(
		case $s in
		warn)      stage_warn ;;
		analyze)   stage_analyze ;;
		cppcheck)  stage_cppcheck ;;
		shell)     stage_shell ;;
		sizearith) stage_sizearith ;;
		totality)  stage_totality ;;
		arithub)    stage_arithub ;;
		ownership)  stage_ownership ;;
		initproof)  stage_initproof ;;
		fallible)   stage_fallible ;;
		provenance) stage_provenance ;;
		locks)      stage_locks ;;
		lockset)    stage_lockset ;;
		abizeroinit) stage_abizeroinit ;;
		reentrancy) stage_reentrancy ;;
		variadic)   stage_variadic ;;
		signals)    stage_signals ;;
		errno)      stage_errno ;;
		purity)     stage_purity ;;
		loopcond)   stage_loopcond ;;
		widthmod)  tools/lint-widthmod.sh ;;
		unreferenced) tools/lint-unreferenced.sh ;;
		undefined) tools/lint-undefined.sh ;;
		*) note "unknown stage: $s"; exit 2 ;;
		esac
		rc=$?
		echo "$rc" > "$rundir/$s.rc"
		exit "$rc"
	) > "$rundir/$s.out" 2>&1 &
done
wait

# Same floor tools/gate.sh:266-322 keeps one level up, for the same
# reason: a stage whose subshell was killed before it could write its
# .rc used to default to rc=0 here and count as a pass, so a run in
# which nothing ran at all reported "no findings".  A stage that did not
# report a result is a failure, and it has to be named -- otherwise the
# only evidence of what went missing is that the output is short.
reported=0
absent=""
for s in $stages; do
	cat "$rundir/$s.out"
	if [ ! -f "$rundir/$s.rc" ]; then
		note "MISSING: stage '$s' never reported a result (no $s.rc was written)"
		absent="$absent $s"
		findings=1
		continue
	fi
	reported=$((reported + 1))
	rc=$(cat "$rundir/$s.rc")
	[ "$rc" != 0 ] && findings=1
done
# $stages is a whitespace-separated list and is meant to word-split here,
# exactly as it does at every `for s in $stages` above.
# shellcheck disable=SC2086
nstages=$(printf '%s\n' $stages | grep -c . || true)
if [ "$reported" -ne "$nstages" ]; then
	note "lint: $reported of $nstages stage(s) reported a result; never reported:$absent"
	findings=1
fi
ls "$LINT_MISSING_MARKER".* >/dev/null 2>&1 && missing=1
rm -rf "$rundir"

hdr "summary"
if [ "$missing" -ne 0 ]; then
	note "one or more stages could not run because a tool is missing."
	note "this run checked less than CI does, so it cannot report success."
	exit 2
fi
if [ "$findings" -eq 0 ]; then
	note "no findings"
	exit 0
fi
note "findings above; logs under $builddir/"
[ "$LINT_STRICT" = 0 ] && exit 0
exit 1
