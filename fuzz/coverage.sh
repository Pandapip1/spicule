#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Answers one question, per harness: which src/*.c did it actually enter?
#
# Not "does it compile" and not "did it crash" -- a harness that runs
# clean without ever reaching the module it is named after reports a
# pass having checked nothing, and that is the failure class this exists
# to make visible.  Write a harness, run this, and look for a non-zero
# number against the file you meant to fuzz.
#
# Driven by `make -C fuzz coverage`, which builds the instrumented
# binaries and exports COVOUT/COVDATA/SAN_SO/SRCDIR.  Run it directly
# only if those are set.
#
# Each harness is run once for COV_TIME seconds with its baked-in
# profile path (see the block comment in the Makefile for why the path
# is baked in rather than taken from LLVM_PROFILE_FILE) and its own
# mirror directory, then llvm-profdata/llvm-cov turn the .profraw into
# a table.  The run is a fresh, corpus-less one on purpose: what is
# being measured is what *this harness's own generator* reaches, and
# seeding it from obj/fuzzcorpus would report a number that depends on
# whatever a previous night happened to find.
set -eu

# See the long comment in tools/fuzz.sh: an unset-here $DEBUGINFOD_URLS is
# what keeps llvm-symbolizer from making a doomed network request, and
# ASan's blocking read() on its pipe from hanging with it.
export DEBUGINFOD_URLS=

: "${COVOUT:?run via make -C fuzz coverage}"
: "${COVDATA:?run via make -C fuzz coverage}"
: "${SRCDIR:?run via make -C fuzz coverage}"
# SAN_SO, not ASAN_SO: whichever sanitizer runtime the Makefile's
# SAN_MODE selected.  ASAN_OPTIONS below is simply ignored when that
# runtime is UBSan's -- there is no LeakSanitizer in that mode to
# turn on, which is one of the things it stops detecting.
: "${SAN_SO:?run via make -C fuzz coverage}"
COV_TIME=${COV_TIME:-20}
FUNCS=${FUNCS:-}
ALL=${ALL:-}
MODULE=${MODULE:-}

# llvm-profdata/llvm-cov must match the clang that built the binaries:
# a .profraw carries a version the reader refuses to guess at.  Debian
# and Ubuntu ship them only under a -NN suffix, so the unsuffixed name
# is tried first and the compiler's own major version second, rather
# than hard-coding either.
CC=${CC:-clang}
major=$($CC -dumpversion 2>/dev/null | cut -d. -f1)
find_tool() {
	for c in "$1" "$1-$major"; do
		command -v "$c" >/dev/null 2>&1 && { printf '%s\n' "$c"; return 0; }
	done
	echo "fuzz/coverage.sh: no $1 (tried $1, $1-$major)" >&2
	return 1
}
PROFDATA=$(find_tool llvm-profdata)
COV=$(find_tool llvm-cov)

rc=0
for h in "$@"; do
	exe=$COVOUT/fuzz_$h
	dir=$COVDATA/$h
	raw=$dir/fuzz_$h.profraw
	[ -x "$exe" ] || { echo "fuzz/coverage.sh: no $exe" >&2; rc=1; continue; }

	# Emptied, not just created: ntstubs.c imports the whole mirror
	# directory into the simulated volume at start-up, so last run's
	# profraw would be read back in for no reason.
	rm -rf "$dir"; mkdir -p "$dir"

	echo "== fuzz_$h (${COV_TIME}s)"
	SPICULE_FUZZ_MIRROR=$dir \
	LD_PRELOAD=$SAN_SO ASAN_OPTIONS=detect_leaks=1:handle_abort=1 \
	UBSAN_OPTIONS=print_stacktrace=1 \
	"$exe" -max_total_time="$COV_TIME" -max_len=256 \
	       -print_funcs=0 -print_final_stats=0 >"$dir/run.log" 2>&1 \
	  || { echo "   fuzz_$h FOUND SOMETHING (see $dir/run.log)"; rc=1; }

	# A harness that died on a finding never reached exit(), so no
	# profile was flushed.  Say which of the two it is; an absent
	# .profraw reported as "0% coverage" would be the same kind of lie
	# this script exists to stop.
	if [ ! -s "$raw" ]; then
		echo "   NO PROFILE WRITTEN -- coverage unknown, not zero." >&2
		echo "   (harness died before exit(), or the mirror seam broke;" >&2
		echo "    see $dir/run.log)" >&2
		rc=1
		continue
	fi

	"$PROFDATA" merge -sparse "$raw" -o "$dir/fuzz_$h.profdata"

	set -- report "$exe" -instr-profile="$dir/fuzz_$h.profdata"
	if [ -n "$FUNCS" ]; then set -- "$@" -show-functions; fi
	if [ -n "$MODULE" ]; then set -- "$@" "$SRCDIR/$MODULE"
	elif [ -n "$FUNCS" ]; then set -- "$@" "$SRCDIR/src"
	fi
	# What is printed: every row llvm-cov has, minus the three files
	# that are not code under test (the harness itself, ntstubs.c and
	# host_oracle.c) and, by default, minus the rows with no regions
	# executed.  A full table is 280 rows of which a few dozen are
	# non-zero, and a reader who has to find those will not.  ALL=1
	# prints every row; the trailing count keeps the omission honest
	# either way, and absence from the list *is* the "never entered"
	# answer this script exists to give.
	#
	# The file column is whatever llvm-cov chose to call the file: it
	# strips the longest common directory prefix, so a whole-tree run
	# shows "src/stdio/printf.c" and a MODULE=src/stdio run shows
	# "printf.c".  Rewriting that back to a uniform shape would mean
	# guessing at the prefix it removed; the name is unambiguous in
	# the context of the invocation that produced it.
	"$COV" "$@" 2>/dev/null | sed -e 's|^\.\./||' -e "s|^$SRCDIR/||" \
	  | awk -v all="${ALL:-}" -v funcs="${FUNCS:-}" '
	  # Two table shapes.  Without -show-functions llvm-cov emits one
	  # 13-column row per file; with it, a "File \047...\047:" heading
	  # followed by 10-column rows naming "<file>:<function>".  Both
	  # reduce to (name, regions, cover).
	  /^File \047/ { next }
	  $1 == "Filename" || $1 == "Name" || $1 == "TOTAL" || $1 ~ /^-+$/ { next }
	  funcs != "" && NF == 10 { name = $1; regions = $2; cover = $4 }
	  funcs == "" && NF == 13 { name = $1; regions = $2; cover = $4 }
	  name == "" { next }
	  name ~ /(^|\/)(ntstubs|host_oracle|fuzz_[a-z]+)\.c([:.]|$)/ { name = ""; next }
	  regions == 0 { name = ""; next }       # a header with no code of its own
	  cover == "0.00%" { zero++; name = ""; if (!all) next }
	  { if (!shown++) printf "   %-44s %8s %8s\n", funcs ? "function" : "file", "regions", "cover";
	    printf "   %-44s %8d %8s\n", name, regions, cover; name = "" }
	  END {
	    if (!shown) print "   NOTHING was entered.";
	    if (zero && !all) printf "   (%d further at 0.00%% -- not entered; ALL=1 to list)\n", zero
	  }'
	echo
done
exit $rc
