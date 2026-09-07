#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and run the libFuzzer harnesses in fuzz/.  See CONTRIBUTING.md.
#
#   tools/fuzz.sh                 every harness, 60s each
#   tools/fuzz.sh 300             every harness, 300s each
#   tools/fuzz.sh 300 strtod utf  just those, 300s each
#   tools/fuzz.sh --repro <file> <harness>   re-run one saved input
#
# The corpus persists between runs, in $SPICULE_FUZZ_CORPUS (default
# obj/fuzzcorpus), one subtree per harness:
#
#   $SPICULE_FUZZ_CORPUS/<h>/corpus    libFuzzer's minimized corpus
#   $SPICULE_FUZZ_CORPUS/<h>/crashes   crash-<sha1>, leak-<sha1>, ...
#
# This works because libFuzzer's file I/O goes through spicule to
# NtCreateFile, and fuzz/ntstubs.c's SPICULE_FUZZ_MIRROR implements a
# whole in-memory volume that mirrors the corpus directory into it.
# See the block comment above mirror_init() in fuzz/ntstubs.c for why
# the mirror is needed and for what is deliberately not mirrored.
#
# Every run therefore starts from what the last one learned.  A crash
# artefact survives too, as a file -- feed it back with --repro.  A
# reproducer worth keeping still belongs in test/ as a case in the
# matching test/*.c; the corpus is search state, not a regression suite.
#
# Set SPICULE_FUZZ_CORPUS= (empty) to run stateless, the way this script
# used to.
#
# -print_funcs=0 matters for speed: symbolizing each newly reached
# function shells out to llvm-symbolizer against a 200-object binary and
# costs about thirty seconds a time.  Crash reports are still symbolized.
#
# FUZZ_JOBS controls how many harness shards run concurrently (default 1).
# Exits non-zero if any harness finds something or a worker fails to report.

set -eu
srcdir=$(cd "$(dirname "$0")/.." && pwd)

# Leak detection on, for the reason given in tools/asan-build.sh: spicule's
# heap is ASan's heap here, so LSan can account for every block.  A fuzzer
# is where a leak per call shows up fastest -- libFuzzer checks after each
# input, so one leaking format string is reported in seconds rather than
# waiting for an absurd RSS to be noticed.  It found the sprintf/snprintf
# one-byte-per-call leak the moment it was switched on.
LEAKS=${SPICULE_LEAKS:-1}

# handle_abort=1 is not cosmetic, and ASan does not default it on.
#
# The differential harnesses report a wrong *result* -- something no
# sanitizer can see -- and end the run with the host's abort()
# (fuzz/host_oracle.c's host_abort).  libFuzzer's own SIGABRT handler
# never fires: it installs one with sigaction(), which resolves to
# spicule's, which on a native build delivers nothing.  So a mismatch used
# to print three lines to stderr and die with status 134, and libFuzzer
# wrote no crash artefact and named no reproducing input.
#
# With handle_abort=1 the abort goes to ASan, which prints a stack trace
# and then calls the death callback libFuzzer registered -- and *that*
# path does dump the unit:
#
#   Test unit written to .../crashes/crash-adc83b19...
#
# Measured with a deliberately wrong oracle (host_strtod returning r+1):
# without it, no file; with it, the artefact above, which
# `tools/fuzz.sh --repro` replays.

# The harnesses use the shared ASan runtime (see tools/asan-build.sh for
# why), and libFuzzer drags in libstdc++, which the linker puts ahead of
# it.  ASan refuses to start unless its runtime is first in the library
# list, so preload it -- which is what its own error message asks for.
#
# Deliberately not exported: the preload must apply to the harnesses when
# they *run*, not to the build.  Exporting it puts clang, and in
# particular ld, under ASan too, and the linker's ordinary allocations
# then trip the leak checker and fail the link:
#   SUMMARY: AddressSanitizer: 1596455 byte(s) leaked in 3224 allocation(s)
#   clang: error: linker command failed with exit code 1
# It is set per-invocation below instead.
ASAN_SO=$(${CC:-clang} -print-file-name=libclang_rt.asan-x86_64.so)

# Why --repro used to hang after printing the first two lines of an ASan
# report, and `make -C fuzz run` did not when run from CI.
#
# ASan symbolizes a crash by forking llvm-symbolizer, writing the query
# to its stdin pipe and doing a blocking read() on its stdout pipe.  The
# harness therefore cannot make progress until the symbolizer answers.
#
# llvm-symbolizer (Ubuntu's llvm-symbolizer-18, and any LLVM built with
# LLVM_ENABLE_DEBUGINFOD) looks for a module's debug info in this order:
# /usr/lib/debug/.build-id/<id>.debug, then ~/.cache/llvm-debuginfod,
# then -- if $DEBUGINFOD_URLS is set -- an HTTPS GET to each server in
# it, and only then the DWARF already inside the binary.  Ubuntu exports
# DEBUGINFOD_URLS=https://debuginfod.ubuntu.com from
# /etc/profile.d/debuginfod.sh, so every interactive login shell has it.
# The harnesses are built with -g and carry their own DWARF, and no
# distro server has ever heard of their build-id, so that request can
# only ever fail -- but it is made first, and while it is outstanding
# llvm-symbolizer sits in poll() on the TLS socket and the harness sits
# in read() on the pipe.  Measured on this build: strace shows the
# symbolizer connect to 91.189.92.252:443 and then poll(fd=5, 1000ms) in
# a loop indefinitely; the harness's kernel wchan is anon_pipe_read.
# With DEBUGINFOD_URLS cleared the same query answers in under a second
# from the in-binary DWARF.
#
# That is also the whole of the CI-versus-terminal difference: GitHub
# Actions runs each step under a *non-login* shell, which never sources
# /etc/profile.d, so the workflow's Fuzz step never had the variable set
# and never made the request.
#
# Clearing it costs nothing this script wants: the /usr/lib/debug and
# ~/.cache lookups still happen (they are local and come first), and the
# harness's own frames -- the fuzz_path.c:78:11 an issue reporter needs
# -- come from DWARF inside the executable.  The only thing given up is
# network-fetched debug info for distro shared libraries, which was
# never arriving anyway.
export DEBUGINFOD_URLS=

if [ "${1:-}" = "--repro" ]; then
	shift
	[ $# -ge 1 ] || { echo "usage: tools/fuzz.sh --repro <artefact>" >&2; exit 2; }
	art_in=$1
	# Resolved to an absolute path here, once, and used for both the
	# mirror root and the argument the harness is handed.  A relative
	# artefact used to reach libFuzzer verbatim and die with
	#     ERROR: The required directory "crash-abc" does not exist
	# -- libFuzzer stats the name through spicule, which resolves it
	# against ntstubs.c's simulated volume, where the caller's host cwd
	# does not exist.  It is a clear failure rather than a silent wrong
	# answer, but there is no reason to make the reporter in GitHub
	# issue #1 type an absolute path when the script can compute one.
	artdir=$(cd "$(dirname "$art_in")" && pwd) || exit 1
	art=$artdir/$(basename "$art_in")
	name=${2:-$(basename "$artdir")}
	make -C "$srcdir/fuzz" "$srcdir/obj/fuzz/fuzz_$name" >/dev/null
	# The artefact has to be visible in ntstubs.c's simulated volume, or
	# the harness cannot read the file it was just handed.  Before
	# SPICULE_FUZZ_MIRROR existed this branch could not work at all: it
	# answered every artefact with
	#     ERROR: The required directory "<file>" does not exist
	# which is libFuzzer saying it could not stat the path -- the
	# documented way to replay a finding, replaying nothing.
	# -timeout=0 for the reason given at the bottom of this file: the
	# alarm libFuzzer arms is fatal here, and a slow artefact replayed
	# on its own would be killed by it with nothing said.
	exec env SPICULE_FUZZ_MIRROR="$artdir" \
	     LD_PRELOAD="$ASAN_SO" \
	     ASAN_OPTIONS=detect_leaks="$LEAKS":handle_abort=1 \
	     UBSAN_OPTIONS=print_stacktrace=1 \
	     "$srcdir/obj/fuzz/fuzz_$name" -timeout=0 "$art"
fi

time=${1:-60}
if [ $# -gt 0 ]; then shift; fi
if [ $# -gt 0 ]; then
	harnesses=$*
else
	harnesses=$(find "$srcdir/fuzz" -maxdepth 1 -name 'fuzz_*.c' -printf '%f\n' |
		sed 's/^fuzz_//; s/\.c$//' | sort)
fi

if [ ! -f "$srcdir/obj/include/bits/alltypes.h" ]; then
	echo "fuzz: run 'make' first (obj/include/bits/alltypes.h is missing)" >&2
	exit 1
fi

corpus=${SPICULE_FUZZ_CORPUS-$srcdir/obj/fuzzcorpus}
: "${FUZZ_JOBS:=1}"
case $FUZZ_JOBS in
''|*[!0-9]*|0) echo "fuzz: FUZZ_JOBS must be a positive integer" >&2; exit 2 ;;
esac

# -timeout=0, AND A WATCHDOG OF OUR OWN, because libFuzzer's does not work
# here and its only observable effect was to fail a run at random.
#
# Same root cause as the handle_abort=1 note above, one signal along.
# libFuzzer arms its per-unit timeout with setitimer(ITIMER_REAL) and
# installs the SIGALRM handler with sigaction() -- and sigaction() in
# these binaries is spicule's, a strong definition in the executable, so
# libFuzzer's handler is registered in spicule's own table and the host
# kernel never hears about it.  setitimer, which spicule does not define,
# resolves to glibc and really does arm the timer.  Confirmed by nm on a
# built harness:
#
#     0000000000190368 t sigaction        <- spicule's, in the executable
#                      U setitimer        <- glibc's, at run time
#
# So SIGALRM arrives with its default disposition and the process is
# killed outright.  The timer is a REPEATING one at -timeout/2+1 seconds
# (FuzzerDriver's `SetTimer(Flags.timeout / 2 + 1)`), and -timeout
# defaults to 1200, so every harness in this tree dies at 601 s of wall
# clock with a bare "Alarm clock" on stderr: no libFuzzer diagnostic, no
# "timeout" artefact, no reproducing input.  Measured directly --
# -timeout=4 arms it at 3 s and the harness dies at 3.05 s with status
# 142 (128+SIGALRM); -timeout=0 skips SetTimer entirely and the same
# harness runs its full budget and exits 0.
#
# What that cost, which is why this is a fix and not a tidy-up: the run
# still exits non-zero, so this script called it a finding and printed
# "reproduce: ... <file>" pointing at whatever happened to be sitting in
# crashes/ -- slow-unit artefacts from earlier in the same run, which
# replay clean.  That is a report that sends a reader after an input
# that never crashed anything.
#
# 601 s is reachable at the 300 s the nightly uses, because
# -max_total_time is only checked BETWEEN inputs and fuzz_glob has units
# that run for tens of seconds: a 300 s dispatch of fuzz_glob alone
# measured "Done 399891 runs in 358 second(s)" with
# stat::slowest_unit_time_sec: 40, and the nightly runs four such
# processes on four vCPUs, where each of those units takes proportionally
# longer.
#
# Nothing is lost by turning it off: a facility whose handler is never
# called was not detecting hung units in the first place.  What replaces
# it is a real watchdog -- `timeout` around the harness -- which does
# bound a genuine hang, and whose kill is reported as a kill instead of
# as a finding.  It is deliberately loose (three times the budget plus
# five minutes) so that the ordinary overshoot above is never mistaken
# for a hang.  -max_total_time itself is unaffected: libFuzzer checks it
# in its own loop, not in the alarm handler.
watchdog=$(( time * 3 + 300 ))

make -C "$srcdir/fuzz" all

run_harness() {
	h=$1
	# The before/after counts are printed, not asserted: the point of
	# persisting a corpus is that it grows, and a run that reports the same
	# number twice is telling you the mirror stopped working.
	if [ -n "$corpus" ]; then
		mkdir -p "$corpus/$h/corpus" "$corpus/$h/crashes"
		before=$(find "$corpus/$h/corpus" -type f | wc -l)
		echo "== fuzz_$h (${time}s, corpus $before)"
		set -- -artifact_prefix="$corpus/$h/crashes/" "$corpus/$h/corpus"
		mirror=$corpus/$h
	else
		echo "== fuzz_$h (${time}s, no corpus)"
		set --
		mirror=
	fi
	# `|| st=$?` and not `if ! ...; then st=$?`.  The status wanted here
	# is the harness's, and inside the then-branch of an `if !` it is
	# gone: `!` replaces it with its own logical negation, so $? there is
	# 0 -- verified, `sh -c 'if ! (exit 124); then echo $?; fi'` prints
	# 0, not 124.  Reading it that way would have made every watchdog
	# kill look like an ordinary finding, which is the exact confusion
	# this block exists to end.
	st=0
	timeout -k 10 "$watchdog" env \
	     SPICULE_FUZZ_MIRROR="$mirror" LD_PRELOAD="$ASAN_SO" \
	     ASAN_OPTIONS=detect_leaks="$LEAKS":handle_abort=1 \
	     UBSAN_OPTIONS=print_stacktrace=1 \
	     "$srcdir/obj/fuzz/fuzz_$h" \
	     -max_total_time="$time" -timeout=0 -max_len=256 -print_funcs=0 \
	     -print_final_stats=1 \
	     "$@" || st=$?
	if [ "$st" -ne 0 ]; then
		# 124 is `timeout` reporting that it fired; 137 is the
		# SIGKILL of its own -k escalation when the harness ignored
		# the TERM.
		if [ "$st" = 124 ] || [ "$st" = 137 ]; then
			echo "   fuzz_$h DID NOT FINISH: killed by this script's watchdog after ${watchdog}s."
			echo "   This is NOT a finding and there is no input to reproduce -- the run"
			echo "   was cut short, so it has shown nothing about fuzz_$h either way."
		else
			echo "   fuzz_$h FOUND SOMETHING (input shown above)"
			if [ -n "$corpus" ]; then
				echo "   artefacts: $corpus/$h/crashes"
				find "$corpus/$h/crashes" -type f 2>/dev/null | sed 's/^/     /'
				echo "   reproduce: tools/fuzz.sh --repro $corpus/$h/crashes/<file> $h"
			fi
		fi
		rc=1
		return 1
	fi
	if [ -n "$corpus" ]; then
		echo "   corpus $before -> $(find "$corpus/$h/corpus" -type f | wc -l)"
	fi
	return 0
}

# Shard rather than starting every harness at once: libFuzzer is
# single-threaded and -max_total_time is wall time, so one shard per core
# uses the runner without oversubscribing it.
work=$(mktemp -d "${TMPDIR:-/tmp}/spicule-fuzz.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
n=0
for h in $harnesses; do
	printf '%s\n' "$h" >> "$work/shard.$((n % FUZZ_JOBS))"
	n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "fuzz: no harnesses selected" >&2; exit 2; }

workers=0
for shard in "$work"/shard.*; do
	workers=$((workers + 1))
	id=${shard##*.}
	(
		worker_rc=0
		while IFS= read -r h; do
			run_harness "$h" || worker_rc=1
		done < "$shard"
		printf '%s\n' "$worker_rc" > "$work/rc.$id"
	) > "$work/log.$id" 2>&1 &
done
wait

cat "$work"/log.*
reported=0
rc=0
for status in "$work"/rc.*; do
	[ -f "$status" ] || continue
	reported=$((reported + 1))
	[ "$(cat "$status")" -eq 0 ] || rc=1
done
if [ "$reported" -ne "$workers" ]; then
	echo "fuzz: $reported of $workers worker(s) reported a result" >&2
	rc=1
fi
exit $rc
