#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# lint-minver.sh -- keep the library's minimum supported Windows version
# honest, by checking the one file that decides it against the one place
# that states it.
#
# The bug class this exists to catch, which shipped and went unnoticed
# for a long time: src/internal/utf.c calls RtlUTF8ToUnicodeN, which
# ntdll only started exporting in 6.1 (Windows 7).  utf.c is reachable
# from essentially every path-taking and string function, so 71 of the 72
# PEs this tree builds statically import it -- and a static import of a
# name the running ntdll does not export does not make a call fail, it
# makes the loader refuse the whole image before any of its code runs.
# The library therefore could not run on anything older than Windows 7,
# and nothing in the tree said so anywhere.
#
# It stayed invisible because of a hole in the test matrix, not because
# it was subtle: Wine implements ntdll with no version gates at all, so
# every Wine run resolves every import regardless of vintage, and CI's
# other target is Windows Server 2025, far past the floor.  Neither
# oracle can see a version floor, and no third one existed.  This script
# is the third one -- it needs no Windows at all, because the question is
# answerable from the import list itself.
#
# Two checks, both over checked-in artefacts (no build, no $(CC)):
#
#   1. Every export in tools/ntdll.def carries an NTDLL-version
#      annotation.  This is the drift guard: adding an import is a
#      one-line edit that anyone will make without thinking about
#      version floors, and an unannotated line fails here rather than
#      quietly becoming the new floor.
#
#   2. The maximum annotation equals the floor README.md declares.
#      Raising the floor is allowed -- it is a decision, not a mistake --
#      but it has to be made in both places at once, so that the README
#      can never be stale with respect to what the library actually
#      imports.
#
# What this deliberately does NOT check: whether a version annotation is
# correct.  That is a claim about Microsoft's ntdll, sourced to Geoff
# Chappell's per-release export lists and cited per-page in
# tools/ntdll.def's own header; no local check can verify it, and
# pretending otherwise would just be a second, drifting copy of the data.
#
# Nor does it check NT *behaviour* floors -- an information class or
# FSCTL newer than the import floor.  Those are real (unlink.c uses
# FileDispositionInformationEx and misc.c uses FileRenameInformationEx,
# both Windows 10) but they are not load-time failures: NT answers
# STATUS_INVALID_PARAMETER / STATUS_NOT_SUPPORTED and both call sites
# already fall back to the pre-Ex class.  A runtime fallback is the right
# shape for those; an import has no such option, which is exactly why the
# import list is the thing gated here.
set -eu

srcdir=${srcdir:-.}
def=$srcdir/tools/ntdll.def
readme=$srcdir/README.md
rc=0

[ -r "$def" ] || { echo "lint-minver: cannot read $def" >&2; exit 1; }
[ -r "$readme" ] || { echo "lint-minver: cannot read $readme" >&2; exit 1; }

# The export list is everything after the EXPORTS line that is not blank
# and not a whole-line comment.  Each such line must be
# "Name<spaces>; MAJOR.MINOR".
exports=$(sed -n '/^EXPORTS/,$p' "$def" | tail -n +2 | grep -v '^[[:space:]]*$' | grep -v '^;' || true)
if [ -z "$exports" ]; then
	echo "lint-minver: $def has no exports after its EXPORTS line -- refusing to report a floor" >&2
	exit 1
fi

unannotated=$(printf '%s\n' "$exports" | grep -vE '^[A-Za-z_][A-Za-z0-9_]*[[:space:]]+;[[:space:]]*[0-9]+\.[0-9]+[[:space:]]*$' || true)
if [ -n "$unannotated" ]; then
	echo "lint-minver: these tools/ntdll.def exports have no NTDLL-version annotation:"
	printf '%s\n' "$unannotated" | sed 's/^/    /'
	echo "    Add '; MAJOR.MINOR' -- the NTDLL version the name is first exported from."
	echo "    See tools/ntdll.def's header for where the version numbers come from."
	rc=1
fi

# Maximum annotation, compared numerically on (major, minor) rather than
# as text: "10.0" must beat "6.1", and "3.51" must lose to "4.0".
max_maj=0 max_min=0
for v in $(printf '%s\n' "$exports" | sed -n 's/.*;[[:space:]]*\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | sort -u); do
	maj=${v%%.*} min=${v##*.}
	if [ "$maj" -gt "$max_maj" ] || { [ "$maj" -eq "$max_maj" ] && [ "$min" -gt "$max_min" ]; }; then
		max_maj=$maj max_min=$min
	fi
done
max="$max_maj.$max_min"
max_names=$(printf '%s\n' "$exports" | sed -n "s/^\([A-Za-z_][A-Za-z0-9_]*\)[[:space:]]*;[[:space:]]*$max_maj\\.${max_min}[[:space:]]*$/\1/p" | tr '\n' ' ' | sed 's/[[:space:]]*$//')

# README states the floor once, in a line this script owns the format of.
declared=$(sed -n 's/^<!-- spicule-min-ntdll: \([0-9][0-9]*\.[0-9][0-9]*\) -->$/\1/p' "$readme")
if [ -z "$declared" ]; then
	echo "lint-minver: README.md has no '<!-- spicule-min-ntdll: MAJOR.MINOR -->' marker."
	echo "    That marker is where the supported floor is declared; this script compares it"
	echo "    against tools/ntdll.def, whose highest annotation is $max (from: $max_names)."
	rc=1
elif [ "$declared" != "$max" ]; then
	echo "lint-minver: declared floor and imported floor disagree."
	echo "    README.md declares NTDLL $declared."
	echo "    tools/ntdll.def's highest annotation is $max, from: $max_names"
	echo "    Either drop/replace those imports, or raise README.md's floor to $max --"
	echo "    deliberately, and update the prose around the marker to match."
	rc=1
fi

if [ "$rc" -eq 0 ]; then
	echo "lint-minver: OK -- minimum NTDLL $max ($max_names)"
fi
exit "$rc"
