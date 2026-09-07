#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and run the same fuzz/fuzz_*.c harnesses tools/fuzz.sh drives,
# but under AFL++ (fuzz/Makefile's ENGINE=afl) instead of libFuzzer.  Two
# independent engines over one set of harnesses, on purpose: they explore
# with different strategies (AFL++'s deterministic byte-flip stages and
# power schedules versus libFuzzer's mutators), so a corpus one engine
# gets stuck on is not necessarily one the other does, and neither
# harness needed to change to add the second engine -- see the ENGINE
# comment at the top of fuzz/Makefile and fuzz/aflshim.c for how that
# seam works and what it took to make AFL++'s runtime coexist with this
# codebase's own ntdll shim.
#
#   tools/afl-fuzz.sh                 every harness, 60s each
#   tools/afl-fuzz.sh 300              every harness, 300s each
#   tools/afl-fuzz.sh 300 strtod utf   just those, 300s each
#   tools/afl-fuzz.sh --repro <file> <harness>   re-run one saved input
#
# The corpus persists between runs, in $SPICULE_AFL_CORPUS (default
# obj/aflcorpus), one subtree per harness, in afl-fuzz's own layout
# (single-instance mode, "-S default", untouched here):
#
#   $SPICULE_AFL_CORPUS/<h>/default/queue      afl-fuzz's own queue
#   $SPICULE_AFL_CORPUS/<h>/default/crashes    crashing inputs
#   $SPICULE_AFL_CORPUS/<h>/default/hangs      inputs that timed out
#
# A run resumes from an existing queue (afl-fuzz's own "-i -" convention)
# rather than reseeding from scratch; the very first run for a harness
# gets a one-byte throwaway seed, since AFL++ discovers real structure
# for itself far faster than libFuzzer needs a mirrored corpus directory
# for (contrast fuzz/ntstubs.c's SPICULE_FUZZ_MIRROR, which exists because
# libFuzzer's own file I/O goes through spicule; AFL++'s queue is managed
# entirely by afl-fuzz itself, a plain host binary, so no such seam is
# needed here).
#
# Needs afl++ (`apt-get install afl++` on Debian/Ubuntu, or build from
# https://github.com/AFLplusplus/AFLplusplus): afl-clang-fast, afl-fuzz
# and /usr/lib/afl/afl-compiler-rt.o (fuzz/Makefile's AFL_SYSDIR).  Skips
# cleanly (exit 0, one line, no build) when afl-fuzz is not on PATH,
# rather than failing: this is a second, optional engine alongside
# tools/fuzz.sh's libFuzzer one, not a replacement for it, and a tree
# without afl++ installed should not have `make fuzz` start failing.
set -eu
srcdir=$(cd "$(dirname "$0")/.." && pwd)

if ! command -v afl-fuzz >/dev/null 2>&1; then
	echo "afl-fuzz: afl-fuzz not on PATH -- apt-get install afl++ to run this engine (skipping)"
	exit 0
fi

# Same reasoning as tools/fuzz.sh: llvm-symbolizer's doomed HTTPS lookup
# for a build-id no debuginfod server has ever heard of otherwise adds a
# multi-second stall to every ASan report.
export DEBUGINFOD_URLS=

if [ "${1:-}" = "--repro" ]; then
	shift
	[ $# -ge 1 ] || { echo "usage: tools/afl-fuzz.sh --repro <artefact> <harness>" >&2; exit 2; }
	art_in=$1
	# As in tools/fuzz.sh: resolved to an absolute path once, so a
	# relative artefact works no matter what directory make's own output
	# leaves the caller in.
	artdir=$(cd "$(dirname "$art_in")" && pwd) || exit 1
	art=$artdir/$(basename "$art_in")
	name=${2:-$(basename "$artdir")}
	make -C "$srcdir/fuzz" ENGINE=afl "$srcdir/obj/fuzz-afl/fuzz_$name" >/dev/null
	# No SPICULE_FUZZ_MIRROR here: fuzz/afl's driver (AFL++'s own
	# aflpp_driver, from libAFLDriver.a) opens the artefact through
	# fuzz/aflshim.c's __real_open()/__real_read(), a raw host syscall,
	# not through spicule's simulated volume -- unlike libFuzzer's driver,
	# which is why tools/fuzz.sh's --repro needs that seam and this
	# does not.
	exec "$srcdir/obj/fuzz-afl/fuzz_$name" "$art"
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
	echo "afl-fuzz: run 'make' first (obj/include/bits/alltypes.h is missing)" >&2
	exit 1
fi

corpus=${SPICULE_AFL_CORPUS:-$srcdir/obj/aflcorpus}
: "${FUZZ_JOBS:=1}"
case $FUZZ_JOBS in
''|*[!0-9]*|0) echo "afl-fuzz: FUZZ_JOBS must be a positive integer" >&2; exit 2 ;;
esac

# Same loose multiple as tools/fuzz.sh, and the same reason: -V is
# checked between runs inside afl-fuzz's own loop, not by an external
# signal, so an unusually slow unit can overshoot it; this bounds a
# genuine hang without mistaking ordinary overshoot for one.
watchdog=$(( time * 3 + 300 ))

make -C "$srcdir/fuzz" ENGINE=afl all

run_harness() {
	h=$1
	out=$corpus/$h
	mkdir -p "$out"
	if find "$out/default/queue" -type f -print -quit 2>/dev/null | grep -q .; then
		before=$(find "$out/default/queue" -type f | wc -l)
		ipath=-
	else
		before=0
		rm -rf "$work/seed.$h"
		mkdir -p "$work/seed.$h"
		printf 'A' > "$work/seed.$h/seed0"
		ipath=$work/seed.$h
	fi
	echo "== fuzz_$h (${time}s, corpus $before)"
	# AFL_SKIP_CPUFREQ: this script runs harnesses concurrently
	# (FUZZ_JOBS), and afl-fuzz's own core-pinning/governor probing is
	# for a single long-lived interactive session, not a batch of short
	# ones -- it only adds noise here.
	# AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: this host's core_pattern
	# routes core dumps to an external collector (systemd-coredump, most
	# distros' default); afl-fuzz's own check for that is a hard abort
	# otherwise, not a warning.
	# -m none: ASan's ~15 TB shadow reservation (see tools/fuzz.sh and
	# tools/asan-build.sh for the mechanism) is far larger than any
	# -m limit afl-fuzz would otherwise default to, and would make every
	# run look like an out-of-memory crash.
	st=0
	timeout -k 10 "$watchdog" env \
	     AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
	     afl-fuzz -V "$time" -m none -i "$ipath" -o "$out" -- \
	     "$srcdir/obj/fuzz-afl/fuzz_$h" || st=$?
	if [ "$st" -ne 0 ]; then
		# Same convention as tools/fuzz.sh: 124 is `timeout` firing,
		# 137 its SIGKILL escalation.  Neither is a finding.
		if [ "$st" = 124 ] || [ "$st" = 137 ]; then
			echo "   fuzz_$h DID NOT FINISH: killed by this script's watchdog after ${watchdog}s."
			echo "   This is NOT a finding and there is no input to reproduce -- the run"
			echo "   was cut short, so it has shown nothing about fuzz_$h either way."
		else
			echo "   fuzz_$h afl-fuzz EXITED NON-ZERO (status $st) -- see output above"
		fi
		return 1
	fi
	after=$(find "$out/default/queue" -type f 2>/dev/null | wc -l)
	echo "   corpus $before -> $after"
	ncrash=$(find "$out/default/crashes" -type f 2>/dev/null | grep -vc '/README\.txt$' || true)
	if [ "${ncrash:-0}" -gt 0 ]; then
		echo "   fuzz_$h FOUND SOMETHING: $ncrash crashing input(s)"
		echo "   artefacts: $out/default/crashes"
		find "$out/default/crashes" -type f ! -name 'README.txt' 2>/dev/null | sed 's/^/     /'
		echo "   reproduce: tools/afl-fuzz.sh --repro $out/default/crashes/<file> $h"
		return 1
	fi
	return 0
}

# Sharding, watchdog accounting and the final report all mirror
# tools/fuzz.sh line for line; see that script's own comments for why
# each piece is there (in particular why `|| st=$?` and not `if ! ...`).
work=$(mktemp -d "${TMPDIR:-/tmp}/spicule-afl-fuzz.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
n=0
for h in $harnesses; do
	printf '%s\n' "$h" >> "$work/shard.$((n % FUZZ_JOBS))"
	n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "afl-fuzz: no harnesses selected" >&2; exit 2; }

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
	echo "afl-fuzz: $reported of $workers worker(s) reported a result" >&2
	rc=1
fi
exit $rc
