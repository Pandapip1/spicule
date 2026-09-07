#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# tools/gate.sh -- run the full pre-push verification gate with every
# independent stage running concurrently, instead of the sum-of-all-stages
# wall clock a plain sequence of `make check`/`make asan`/... gives you.
#
# Why this is safe: every stage below that touches obj/, lib/ or
# config.mak gets its own private copy of the working tree (rsync'd once,
# up front, excluding .git/obj/lib/config.mak) and runs entirely inside
# it. Nothing here ever writes into the tree gate.sh was invoked from,
# except the "generated" stage, which by its nature has to (it checks
# generated-file drift with `git diff`) -- so it is deliberately run
# alone, before any of the copies are even taken, never concurrently with
# anything else.
#
# Each stage's stdout+stderr is buffered to its own log and only ever
# printed as one unit, labelled with the stage name, so a red run still
# tells you exactly which stage failed -- interleaving that would defeat
# the point of running these concurrently.
#
# Usage:
#   tools/gate.sh                run every stage
#   tools/gate.sh check-x86_64 lint-plain      run just the named stages
#   tools/gate.sh --list         print stage names and exit
#
# Requires the same things running each `make`/`tools/*.sh` stage by hand
# would: CC (x86_64-win32-tcc / i386-win32-tcc) on PATH, wine, and for the
# two pinned lint stages, nix-shell able to fetch/build the pinned tool.
# cppcheck is a stage of `tools/lint.sh` itself (invoked as part of
# lint-plain here), not a stage of this script; if cppcheck is not
# installed and LINT_ALLOW_MISSING is not set, lint-plain fails and says
# so -- see tools/lint.sh's own comment for why a silent skip is wrong.
#
# Env:
#   GATE_JOBS_DIR   where per-stage tree copies + logs go (default: a
#                   fresh mktemp -d, removed on a clean exit; kept on
#                   failure so logs stay inspectable).
#   GATE_MAKE_JOBS  how many jobs each stage may run at once -- the -j
#                   passed to every `make` below, and the default for
#                   every sub-tool that fans out on its own (RUNTESTS_JOBS,
#                   LIBC_TEST_JOBS, OPTSRUN_JOBS, ASAN_JOBS, LINT_JOBS,
#                   LINKCHECK_JOBS).  Default 3.  Explicitly NOT nproc:
#                   see the concurrency-budget comment below.
#   GATE_STAGE_CONCURRENCY
#                   how many stages may be running at once (default 4;
#                   0 means no cap, i.e. the old launch-everything
#                   behaviour).  Stages are still all launched and still
#                   all reported -- a stage over the cap just waits for a
#                   slot before it starts working, so nothing about what
#                   the gate checks changes.
#   GATE_WINE       wine binary for the check-i386/check-x86_64 stages
#                   (default: whatever ./configure auto-detects from
#                   PATH). Set this explicitly if that wine cannot run
#                   the suite -- e.g. it predates RtlCloneUserProcess, in
#                   which case any test that forks hangs into
#                   `winedbg --auto` forever instead of exiting nonzero.

set -u

# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

: "${GATE_JOBS_DIR:=}"
own_jobs_dir=0
if [ -z "$GATE_JOBS_DIR" ]; then
	GATE_JOBS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/spicule-gate.XXXXXX") || exit 1
	own_jobs_dir=1
fi
mkdir -p "$GATE_JOBS_DIR/logs" "$GATE_JOBS_DIR/trees" || exit 1

# Every concurrent stage name, in the fixed order the summary reports them
# -- independent of start/finish order, so two runs are diffable.
ALL_STAGES="generated reuse check-i386 check-x86_64 libc-test posix-optsrun asan install-check linkcheck-i386 linkcheck-x86_64 hygiene minver lint-plain lint-analyze-pinned lint-shell-pinned"

if [ "${1:-}" = "--list" ]; then
	for s in $ALL_STAGES; do echo "$s"; done
	exit 0
fi

STAGES="${*:-$ALL_STAGES}"

# A requested name that is not a stage would otherwise select nothing and
# be silently ignored -- `tools/gate.sh check-x86_64 lint-plian` would run
# one stage and still report "gate PASSED (all stages)".  Reject it before
# anything runs, rather than discovering it in the summary.
for s in $STAGES; do
	case " $ALL_STAGES " in
	*" $s "*) ;;
	*)
		echo "gate: unknown stage '$s'" >&2
		echo "gate: known stages: $ALL_STAGES" >&2
		exit 2 ;;
	esac
done

# How many stages this run is responsible for reporting on.  The summary
# compares against it; see the floor there.
expected=0
for s in $ALL_STAGES; do
	case " $STAGES " in *" $s "*) expected=$((expected + 1)) ;; esac
done
if [ "$expected" -eq 0 ]; then
	echo "gate: no stage selected; there is nothing to verify." >&2
	exit 2
fi

# --- concurrency budget ----------------------------------------------
#
# Every stage below used to hardcode `make -j"$(nproc)"`, and every
# sub-tool a stage invokes (tools/run-tests.py, tools/libc-test.sh,
# tools/posix-opts.py, tools/asan-build.sh, tools/lint.sh,
# tools/lint-unreferenced.sh, tools/linkcheck.sh) independently defaults
# its own worker count to nproc.  All 14 stages launch at once.  So the
# thing that actually lands on the machine is a PRODUCT, not a sum:
# 14 stages x 24 CPUs is up to 336 concurrent compilers -- or, worse, 336
# concurrent Wine processes, which are not cheap in RAM.  On this
# project's development machine that reproducibly drove load average past
# 450 and swap to exhaustion, and systemd-oomd killed entire terminal
# scopes out from under unrelated work.  A per-invocation `-j2` habit is
# no defence against a number baked into a script.
#
# So the budget is expressed as the two factors of that product, and both
# are capped:
#
#   GATE_STAGE_CONCURRENCY (stages at once)  x  GATE_MAKE_JOBS (jobs each)
#
# The defaults, 4 x 3, give a peak of 12 -- half of a 24-CPU box, and a
# 28x reduction on what this script used to ask for.  Half is the point:
# the gate is something you run on your workstation while the rest of
# your work carries on, so it must leave the machine usable.  Neither
# factor is derived from nproc, deliberately -- an nproc-derived default
# is exactly the bug being fixed, and an absolute small number stays
# sane from a 4-core laptop to a 128-core server.  Raise both on a
# machine you own outright; CI sets its own (see .github/workflows).
#
# Why 3 and 4 rather than, say, 12 x 1 or 1 x 12: stage cost here is
# wildly unequal.  `reuse` and the two nix-shell lint stages are minutes
# of I/O and evaluation with almost no CPU, while posix-optsrun is 1576
# tcc compile-and-links plus 591 serial Wine runs and asan is 282 clang
# compiles.  A wide-ish stage cap lets the cheap stages retire and hand
# their slot to a heavy one, and J=3 keeps each heavy stage's own
# fan-out from collapsing to serial.
#
# Note what this is NOT: a job server.  The genuinely correct instrument
# would be one token pool shared by every worker in the run, so a stage
# that is idle lends its capacity to one that is not.  GNU make's
# jobserver could do that for the `make` halves, but every fan-out in
# tools/*.sh is an `xargs -P`, which cannot join a jobserver -- covering
# them would mean teaching six scripts a new protocol.  Two capped
# factors bound the product, which is the property that matters here, at
# a fraction of the blast radius.  If the sub-tools ever grow a shared
# pool, this becomes one number instead of two.
#
: "${GATE_MAKE_JOBS:=3}"
: "${GATE_STAGE_CONCURRENCY:=4}"

case "$GATE_MAKE_JOBS" in
''|*[!0-9]*|0)
	echo "gate: GATE_MAKE_JOBS must be a positive integer (got '$GATE_MAKE_JOBS')" >&2
	exit 2 ;;
esac
case "$GATE_STAGE_CONCURRENCY" in
''|*[!0-9]*)
	echo "gate: GATE_STAGE_CONCURRENCY must be a non-negative integer (got '$GATE_STAGE_CONCURRENCY')" >&2
	exit 2 ;;
esac

# The sub-tools each read their own knob and each default it to nproc.
# Give them all GATE_MAKE_JOBS instead -- but only where the caller has
# not already set one explicitly, so `LINT_JOBS=1 tools/gate.sh` still
# means what it says.  Without this, capping `make -j` alone would move
# the fan-out rather than remove it: `make check` at -j3 still hands off
# to tools/run-tests.py, which would still start nproc Wine processes.
: "${RUNTESTS_JOBS:=$GATE_MAKE_JOBS}"
: "${LIBC_TEST_JOBS:=$GATE_MAKE_JOBS}"
: "${OPTSRUN_JOBS:=$GATE_MAKE_JOBS}"
: "${ASAN_JOBS:=$GATE_MAKE_JOBS}"
: "${LINT_JOBS:=$GATE_MAKE_JOBS}"
: "${LINKCHECK_JOBS:=$GATE_MAKE_JOBS}"
export RUNTESTS_JOBS LIBC_TEST_JOBS OPTSRUN_JOBS ASAN_JOBS LINT_JOBS LINKCHECK_JOBS

note() { printf '%s\n' "$*" >&2; }

# rsync a clean copy of the working tree (as it stands right now,
# uncommitted changes included -- this gates what you're about to push,
# not just HEAD) into $GATE_JOBS_DIR/trees/$1, excluding build output and
# per-arch config so each stage configures its own.
#
# third_party/ is excluded from every copy EXCEPT the stages that read a
# submodule. It holds two -- musl's libc-test (~940 files, 11 MB), read
# by `libc-test`, and the Linux Test Project (~47 MB,
# of which this project reads only testcases/open_posix_testsuite/), read
# by `posix-optsrun`. Every other copy would be paying
# ~58 MB of rsync for nothing, and each copy that does get one takes only
# the submodule it actually reads.
#
# Deliberately no count of how many copies that is: it would be a
# hand-maintained number describing a list two screens further down, and
# it goes stale the moment a stage is added. Same class as
# tools/asan-build.sh's "four harnesses" when there were eight.
#
# The saving is the lesser reason. The real one is the `reuse` stage.
# rsync strips the .git that tells the `reuse` tool those files belong to
# another project, so a copy that includes them turns thousands of
# foreign files into thousands of files of ours with no SPDX headers, and
# `reuse lint` fails on every one. CI's reuse job checks out without
# submodules and therefore never sees them -- so a naive copy here makes
# the local tool and CI disagree, which is the exact failure mode that
# cost this project a round trip. Excluding third_party/ makes the gate
# lint precisely the file set CI lints.
#
# The two suite stages do get their copy, .git-file and all: the plain
# files survive rsync, which is all their drivers need.
#
# WHY THE .gitignore FILTER, which is the same bug one size down.
# Excluding third_party/ fixed `reuse` for files belonging to another
# project.  Ignored build droppings are the same failure for files
# belonging to no project: rsync copies them, the copy has no .git, and
# `reuse lint` -- which skips git-ignored files in a real checkout -- has
# no way left to know they are not ours.  CI checks out from git, so they
# do not exist there at all.
#
# This had been "fixed" repeatedly by adding .gitignore entries whose
# comments say, in as many words, that they exist to stop the reuse stage
# going red: /fuzz.log ("the `reuse` gate stage rsyncs the working tree
# and fails on any file without an SPDX header"), and the whole block of
# test droppings ("`tools/gate.sh reuse` rsyncs the working tree and fails
# on them ... Both have happened").  Those entries could not have that
# effect: nothing here read .gitignore.  They appeared to work only where
# they happened to coincide with an exclude already on this list -- *.tmp,
# /obj/, /lib/, /config.mak.  Measured on a clean tree: an untracked,
# git-ignored fuzz.log still failed the stage, naming itself.
#
# `--filter=':- .gitignore'` makes rsync read the same file git does, so
# those entries finally mean what they claim, and a dropping added
# tomorrow is covered by ignoring it rather than by editing this script.
# Note what it does NOT change: an untracked file that is not ignored is
# still copied, so uncommitted work is still gated -- which is the whole
# point of rsyncing the working tree instead of HEAD.
#
make_tree() {
	dest="$GATE_JOBS_DIR/trees/$1"
	mkdir -p "$dest"
	case "$1" in
	libc-test)
		rsync -a --delete \
			--filter=':- .gitignore' \
			--exclude=.git --exclude=/obj --exclude=/lib --exclude=/config.mak \
			--exclude='*.tmp' --exclude=/third_party/ltp/ \
			"$srcdir/" "$dest/"
		;;
	posix-optsrun)
		rsync -a --delete \
			--filter=':- .gitignore' \
			--exclude=.git --exclude=/obj --exclude=/lib --exclude=/config.mak \
			--exclude='*.tmp' --exclude=/third_party/libc-test/ \
			"$srcdir/" "$dest/"
		;;
	*)
		rsync -a --delete \
			--filter=':- .gitignore' \
			--exclude=.git --exclude=/obj --exclude=/lib --exclude=/config.mak \
			--exclude='*.tmp' --exclude=/third_party/ \
			"$srcdir/" "$dest/"
		;;
	esac
}

# The stage-concurrency semaphore.  A FIFO opened read-write (so it never
# sees EOF and no writer has to stay resident) holding one line per free
# slot; a stage reads a line to start and writes one back when it is
# done.  Every stage is still launched, still gets a log and an .rc, and
# still appears in the summary -- a stage over the cap simply blocks on
# the read until a slot frees.  GATE_STAGE_CONCURRENCY=0 skips the FIFO
# entirely and restores the old everything-at-once behaviour.
stage_sem=""
if [ "$GATE_STAGE_CONCURRENCY" -gt 0 ]; then
	stage_sem="$GATE_JOBS_DIR/stage-slots"
	mkfifo "$stage_sem" || exit 1
	exec 9<>"$stage_sem" || exit 1
	slot=0
	while [ "$slot" -lt "$GATE_STAGE_CONCURRENCY" ]; do
		printf '.\n' >&9
		slot=$((slot + 1))
	done
fi

# run_stage NAME CMD...  -- run CMD (a single sh -c string) in the
# background, buffering combined output to its log; record the exit code
# next to it. Never touches stdout/stderr directly so concurrent stages
# cannot interleave.
#
# The recorded .time deliberately measures the stage's own work, started
# after its slot is acquired, not the time it spent queued -- so per-stage
# numbers stay comparable across runs at different concurrencies.  The
# run's total wall clock in the summary is unchanged and does include
# queueing, which is where the cost of the cap should show up.
run_stage() {
	name=$1; shift
	(
		if [ -n "$stage_sem" ]; then
			# shellcheck disable=SC2034
			read -r _slot <&9
			# Release on ANY exit of this subshell, not just the
			# normal path: a slot leaked by a stage that died would
			# shrink the budget for the rest of the run, and enough
			# of them would deadlock `wait`.
			trap 'printf ".\n" >&9 2>/dev/null' EXIT
		fi
		start=$(date +%s)
		# shellcheck disable=SC2068
		sh -c "$*" > "$GATE_JOBS_DIR/logs/$name.log" 2>&1
		rc=$?
		end=$(date +%s)
		echo "$rc" > "$GATE_JOBS_DIR/logs/$name.rc"
		echo $((end - start)) > "$GATE_JOBS_DIR/logs/$name.time"
	) &
}

want() {
	case " $STAGES " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

overall_start=$(date +%s)

#
# "generated" runs alone, first, in the real tree: it's the one stage
# that legitimately mutates tracked files and diffs them against git, so
# running it next to a tree copy being rsync'd (or next to anything else
# reading the tree) is exactly the race the coordinator flagged. Every
# other stage below only ever touches its own private copy.
#
if want generated; then
	note "== generated (serial, must run alone) =="
	gen_start=$(date +%s)
	(
		make generated
		rc=$?
		if [ $rc -eq 0 ]; then
			git diff --exit-code -- 'arch/*/bits/*.h.gen' 'include/*.h.gen' || rc=$?
			git diff --exit-code -- boot/kaem/ || rc=$?
		fi
		exit $rc
	) > "$GATE_JOBS_DIR/logs/generated.log" 2>&1
	rc=$?
	gen_end=$(date +%s)
	echo "$rc" > "$GATE_JOBS_DIR/logs/generated.rc"
	echo $((gen_end - gen_start)) > "$GATE_JOBS_DIR/logs/generated.time"
fi

# Tree copies for every other wanted stage that needs its own obj/lib/
# config.mak. Taken now, after "generated" has already finished mutating
# the source tree, so every copy sees the same (post-generated) state.
for pair in \
	"check-i386:check-i386" "check-x86_64:check-x86_64" "libc-test:libc-test" \
	"posix-optsrun:posix-optsrun" "asan:asan" "install-check:install-check" \
	"linkcheck-i386:linkcheck-i386" "linkcheck-x86_64:linkcheck-x86_64" \
	"hygiene:hygiene" "lint-plain:lint-plain" \
	"lint-analyze-pinned:lint-analyze-pinned" "lint-shell-pinned:lint-shell-pinned" \
	"reuse:reuse"
do
	stage=${pair%%:*}
	want "$stage" || continue
	make_tree "$stage"
done

# --- launch every remaining stage concurrently ---

# GATE_WINE overrides which wine binary the check-* stages configure
# against; unset, ./configure auto-detects from PATH as it always has.
# Set this if PATH's wine can't actually run the suite (e.g. it predates
# RtlCloneUserProcess, so anything that forks hangs into winedbg forever
# instead of exiting) -- see CONTRIBUTING.md / project memory for which
# local wine build that is on this machine.
: "${GATE_WINE:=}"
wine_cfg=""
[ -n "$GATE_WINE" ] && wine_cfg="WINE=$GATE_WINE"

if want check-i386; then
	t="$GATE_JOBS_DIR/trees/check-i386"
	run_stage check-i386 "cd '$t' && ./configure --host=i386-win32 CC=i386-win32-tcc $wine_cfg >/dev/null && make -j$GATE_MAKE_JOBS check"
fi

if want check-x86_64; then
	t="$GATE_JOBS_DIR/trees/check-x86_64"
	run_stage check-x86_64 "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc $wine_cfg >/dev/null && make -j$GATE_MAKE_JOBS check"
fi

# libc-test: musl's regression corpus, adjudicated against
# test/libc-test-expected.txt.  Belongs beside check-x86_64 rather than
# after it: build + 146 Wine runs measure ~1.5 s wall, against a critical
# path set by asan (~198 s), so it costs the gate nothing.  Only the
# x86_64 arch -- the corpus is arch-independent C and running it twice
# would double the ledger's maintenance for no new evidence.
if want libc-test; then
	t="$GATE_JOBS_DIR/trees/libc-test"
	run_stage libc-test "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc $wine_cfg >/dev/null && make -j$GATE_MAKE_JOBS && make libc-test-pedantic"
fi

# posix-optsrun: all 1,610 Open POSIX Test Suite cases, adjudicated
# against test/posix-opts-expected.txt.  RUNS the cases the resolved
# pedantic profile says must execute, while also proving that every
# UNIMPL case still fails compilation -- which is what retired the
# separate compile-only gap map (see the Makefile's posix-optsrun
# comment for how its four invariants map onto the ledger).
#
# ~4-5 min: 591 Wine executions, each run three times (see that script's
# FLAKY section), serially on purpose because OPTS carries timing
# assertions. That makes it the second
# longest stage after asan, so it is started here beside the other suite
# stages rather than late.
#
# The concurrency budget at the top of this file matters MORE to this
# stage than to any other, which is why it takes GATE_MAKE_JOBS like the
# rest rather than the whole box. Its sweep is serial Wine, and three of
# the tests it runs sit ON the clock-observability boundary -- they are
# explicitly FLAKY in the shared disposition ledger.
# A stage that oversubscribed the machine would push more of the
# nanosleep/clock_nanosleep family across that boundary, and the cost
# would not be a slow stage: it would create misleading observations.
# OPTSRUN_JOBS is capped alongside it above for
# the reason given there -- capping `make -j` alone moves a fan-out
# rather than removing it.
#
# OPTSRUN_GITDIR points back to the source repository so the copied stage
# can verify the LTP gitlink matches the checked-out submodule.
if want posix-optsrun; then
	t="$GATE_JOBS_DIR/trees/posix-optsrun"
	run_stage posix-optsrun "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc >/dev/null && make -j$GATE_MAKE_JOBS && OPTSRUN_GITDIR='$srcdir' make posix-optsrun-pedantic"
fi

if want asan; then
	t="$GATE_JOBS_DIR/trees/asan"
	run_stage asan "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc >/dev/null && make asan"
fi

# install-check: the only stage that leaves the source tree behind
# entirely.  Every other stage here compiles against -I./include
# -I./arch/$ARCH -Iobj/include -Llib, so none of them can see a header
# that is never installed, an installed header that pulls in a path only
# the source tree has, or a broken tools/spicule-tcc wrapper.  The script
# configures and builds a second out-of-tree copy, installs it into a
# temporary prefix, and builds and runs against that prefix alone.
#
# It was written and then never wired to anything -- not CI, not this
# gate, not CONTRIBUTING.md -- which made it the same vacuous-coverage
# shape the summary floor below exists to reject, one level up: a check
# that reports nothing because it never runs.  x86_64 only, like
# libc-test: the install layout is the subject and it is not per-arch.
if want install-check; then
	t="$GATE_JOBS_DIR/trees/install-check"
	run_stage install-check "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc $wine_cfg >/dev/null && make -j$GATE_MAKE_JOBS install-check"
fi

# -j for consistency with check-i386/check-x86_64 above, which have
# always passed it: these two stages build the whole library before
# linkcheck.sh can check a single symbol, and were the only
# build-and-run stages doing it serially.  Worth 0.3s of a 9.9s stage
# on an idle machine, measured -- the tcc build is that fast.  Recorded
# with the real number because the first measurement said 73s -> 21s,
# which was seven other jobs on the machine and not this flag at all;
# every wall-clock figure taken on a loaded box is a measurement of the
# box.  The stage's real cost is inside linkcheck.sh, and that is where
# it was fixed.
if want linkcheck-i386; then
	t="$GATE_JOBS_DIR/trees/linkcheck-i386"
	run_stage linkcheck-i386 "cd '$t' && ./configure --host=i386-win32 CC=i386-win32-tcc >/dev/null && make -j$GATE_MAKE_JOBS linkcheck"
fi

if want linkcheck-x86_64; then
	t="$GATE_JOBS_DIR/trees/linkcheck-x86_64"
	run_stage linkcheck-x86_64 "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc >/dev/null && make -j$GATE_MAKE_JOBS linkcheck"
fi

# Minimum supported Windows version (tools/lint-minver.sh).  Same shape
# as ledger: reads README.md and tools/ntdll.def straight out of the
# source directory, builds nothing, needs no configure.  It is in the
# gate rather than left to `make lint` because it guards a claim no
# other stage can test -- neither Wine (no version gates in its ntdll)
# nor CI's Server 2025 (far past the floor) can observe a version floor
# at all.
if want minver; then
	run_stage minver "cd '$srcdir' && ./tools/lint-minver.sh"
fi

if want hygiene; then
	t="$GATE_JOBS_DIR/trees/hygiene"
	# hygiene.sh checks both arches itself; the Makefile's $(GENH)
	# prerequisite just needs *a* configured arch to exist.
	run_stage hygiene "cd '$t' && ./configure --host=x86_64-win32 CC=x86_64-win32-tcc >/dev/null && make hygiene"
fi

if want lint-plain; then
	t="$GATE_JOBS_DIR/trees/lint-plain"
	# On a dev machine with clang-tidy/cppcheck/shellcheck already
	# installed, use those (whatever version they are -- that's the
	# whole point of "plain"). Only reach for nix, unpinned, if every
	# one of them is missing outright -- never silently accepting
	# fewer checks: tools/lint.sh's own LINT_ALLOW_MISSING default (0)
	# is untouched either way, so a machine with some but not all of
	# the three still fails loudly, same as it always has.
	if command -v clang-tidy >/dev/null 2>&1 || command -v cppcheck >/dev/null 2>&1 || command -v shellcheck >/dev/null 2>&1; then
		run_stage lint-plain "cd '$t' && LINT_ALLOW_MISSING=\${LINT_ALLOW_MISSING:-0} tools/lint.sh"
	else
		run_stage lint-plain "cd '$t' && nix-shell -p llvmPackages.clang-tools cppcheck shellcheck --run 'LINT_ALLOW_MISSING=\${LINT_ALLOW_MISSING:-0} tools/lint.sh'"
	fi
fi

if want lint-analyze-pinned; then
	t="$GATE_JOBS_DIR/trees/lint-analyze-pinned"
	# LINT_TIDY_EXACT=1: this stage's whole purpose is to reproduce CI's
	# exact clang-tidy, so its enabled check set must equal
	# tools/clang-tidy-checks.txt exactly, not merely cover it.  A
	# difference here means the pin has stopped pinning, which is
	# otherwise invisible -- .clang-tidy selects by wildcard, so a
	# different tool silently runs a different analysis and reports the
	# same "0 findings".  lint-plain deliberately does NOT set it: it
	# runs whatever is installed, and requiring LLVM 18.1.8 of it would
	# make it unrunnable on a current machine.
	run_stage lint-analyze-pinned "cd '$t' && nix-shell -p llvmPackages_18.clang-tools --run 'CLANG_TIDY=clang-tidy LINT_TIDY_EXACT=1 tools/lint.sh analyze'"
fi

if want lint-shell-pinned; then
	t="$GATE_JOBS_DIR/trees/lint-shell-pinned"
	run_stage lint-shell-pinned "cd '$t' && nix-shell -I nixpkgs=channel:nixos-23.11 -p shellcheck --run 'tools/lint.sh shell'"
fi

if want reuse; then
	t="$GATE_JOBS_DIR/trees/reuse"
	if command -v reuse >/dev/null 2>&1; then
		run_stage reuse "cd '$t' && reuse lint"
	else
		run_stage reuse "cd '$t' && nix-shell -p reuse --run 'reuse lint'"
	fi
fi

wait

overall_end=$(date +%s)

# --- consolidated report, fixed order ---

fail=0
missing=0
reported=0
absent=""
echo
echo "=== gate summary (wall clock: $((overall_end - overall_start))s) ==="
for s in $ALL_STAGES; do
	want "$s" || continue
	rcfile="$GATE_JOBS_DIR/logs/$s.rc"
	# A wanted stage with no .rc file never reported a result: run_stage's
	# subshell was killed before it could write one, or the `if want ...`
	# block that launches it was never reached (a stage listed in
	# ALL_STAGES but never wired up, a typo in the pair list above).  This
	# used to `continue` -- the stage simply vanished from the summary and
	# left $fail untouched, so `gate PASSED (all stages)` could be printed
	# over a stage that produced nothing at all.  It is the same defect the
	# gate's own stages have been taught to reject one level down, and the
	# coordinator is the worst place to keep it: it is what every other
	# floor reports *through*.
	#
	# Observed, once, and not since: a gate invocation printed
	# "gate PASSED (all stages)" in 12 seconds with no stage lines at all
	# -- every stage failed to launch, so the loop iterated over nothing
	# and the run was green having verified nothing.  The trigger is still
	# unidentified.  That is precisely why the failure below has to name
	# the stages that did not report: the next occurrence has to leave
	# evidence of *what* did not run, not just a non-zero exit.
	if [ ! -f "$rcfile" ]; then
		echo "MISSING  $s (never reported a result -- no $s.rc was written)"
		absent="$absent $s"
		fail=1
		continue
	fi
	reported=$((reported + 1))
	rc=$(cat "$rcfile")
	t=$(cat "$GATE_JOBS_DIR/logs/$s.time" 2>/dev/null || echo '?')
	if [ "$rc" = skip ]; then
		echo "SKIP  $s"
		missing=1
	elif [ "$rc" = 0 ]; then
		echo "PASS  $s (${t}s)"
	else
		echo "FAIL  $s (rc=$rc, ${t}s)"
		fail=1
	fi
done

# The floor on the summary loop itself: every stage this run asked for
# must have reported a result.  Counted rather than inferred from the
# per-stage branch above, so the arithmetic is visible in the output and
# a future edit that adds another `continue` to that loop cannot quietly
# reopen the hole.
if [ "$reported" -ne "$expected" ]; then
	echo
	echo "gate: $reported of $expected requested stage(s) reported a result."
	if [ "$reported" -eq 0 ]; then
		echo "gate: NOT ONE STAGE RAN.  This run verified nothing whatsoever."
	fi
	echo "gate: never reported:$absent"
	echo "gate: a stage that cannot run must fail, not disappear -- if you see this,"
	echo "gate: the logs under $GATE_JOBS_DIR/logs/ are the only evidence of why."
	fail=1
fi

echo
for s in $ALL_STAGES; do
	want "$s" || continue
	rcfile="$GATE_JOBS_DIR/logs/$s.rc"
	[ -f "$rcfile" ] || continue
	rc=$(cat "$rcfile")
	if [ "$rc" != 0 ] && [ "$rc" != skip ]; then
		echo "--- $s output (last 60 lines) ---"
		tail -n 60 "$GATE_JOBS_DIR/logs/$s.log" | sed 's/^/    /'
		echo
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "gate FAILED. Full logs kept at $GATE_JOBS_DIR/logs/"
	exit 1
fi
if [ "$missing" -ne 0 ]; then
	echo "gate ran with one or more stages SKIPPED (see above) -- this checks"
	echo "less than a full run. Logs kept at $GATE_JOBS_DIR/logs/"
	exit 0
fi

echo "gate PASSED (all stages)."
[ "$own_jobs_dir" = 1 ] && rm -rf "$GATE_JOBS_DIR"
exit 0
