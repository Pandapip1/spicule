#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Can AddressSanitizer actually START on this host?
#
#   exit 0   yes -- carry on
#   exit 77  no, and the profile says so: unavailable, not failed
#
# 77 is not a new convention.  It is the value this tree already uses for
# "ran, but declined to verify something it detected at run time" --
# tools/run-tests.py has an rc=77 bucket, and tools/asan-build.sh's own
# test loop counts a 77 as `unverified` rather than as a pass or a fail.
# "The stage could not verify anything here" is the same kind of answer
# one level up, so it gets the same number rather than a new one.
#
# ---------------------------------------------------------------------
# THE MECHANISM, because this will otherwise be read as a broken
# toolchain and "fixed" by deleting the check.
#
# ASan reserves its shadow -- about 15 TB on x86_64 -- with
# mmap(PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|
# MAP_NORESERVE).  Linux's do_mmap() honours MAP_NORESERVE only when
# sysctl_overcommit_memory != OVERCOMMIT_NEVER; with vm.overcommit_memory
# set to 2 the flag is dropped, the whole 15 TB is charged against
# CommitLimit, and the mapping is refused with ENOMEM.  Every
# ASan-instrumented binary then dies before main() with
#
#     ==N==ERROR: AddressSanitizer failed to allocate 0xdfff0001000 bytes
#     ==N==ReserveShadowMemoryRange failed while trying to map ...
#
# There is no build flag, rlimit or ASAN_OPTIONS setting that avoids it:
# the shadow is not optional, and its size is fixed by the address-space
# layout ASan was compiled for.
#
# ---------------------------------------------------------------------
# WHY A PROFILE TERM AND NOT A HARD ERROR.
#
# tools/libc-test.sh's require_suite() hard-errors on an unchecked-out
# submodule, and is right to: that is a fixable situation, one command
# fixes it, and the operator should fix it rather than run a stage that
# adjudicates nothing.  Strict overcommit is the opposite kind of fact.
# It is a deliberate, permanent setting on this host; there is no command
# for the operator to run, and telling them to change a system-wide
# memory policy so a fuzzing stage can start would be the tail wagging
# the dog.  So this is `unavailable`, not `error`: the stage declines,
# says why, names what to run instead, and does not pretend it verified
# anything.
#
# What it must NEVER become is a skip that reports success.  This project
# closed nine gate stages in a day that exited 0 having checked nothing
# (test/verification-measures.md).  77 is neither 0 nor 1 precisely so
# that a caller cannot mistake it for either.
#
# ---------------------------------------------------------------------
# WHY THE DECLARATION AND THE PROBE ARE BOTH HERE, AND WHY ONLY ONE OF
# THEM CAN CAUSE A SKIP.
#
# The declaration is capability.overcommit=no, carried in the profile
# (see test/test-profiles.tsv, which documents the term, and the
# Makefile's TEST_PROFILE default).  That is the established channel for
# "what is true about this runner", and reusing it means this fact lives
# where capability.symlink and capability.console already live rather
# than in a mechanism of its own.
#
# But that file also says, at length, that capability terms are
# DECLARATIONS and nothing can contradict them -- "declare it wrongly and
# nothing can contradict you".  For this one term the falsification is a
# single file read, so it is done, with a strict asymmetry:
#
#     the declaration can only ever cause a SKIP
#     the probe can only ever VETO one
#
# If the profile says overcommit is unavailable and /proc disagrees, the
# stage RUNS -- and says the declaration is stale.  A wrong declaration
# can therefore cost a wasted run, never a silently skipped one.  That
# direction is chosen deliberately: the failure this guards against is a
# CI runner inheriting a developer's default and quietly not running ASan
# at all, which would leave the project with no ASan coverage anywhere
# and a green board saying otherwise.
set -eu

declared=
for term in ${SPICULE_TEST_PROFILE:-}; do
	case $term in
	capability.overcommit=*) declared=${term#capability.overcommit=} ;;
	esac
done

# The probe.  Absent /proc (a container, another OS) reads as "cannot
# confirm", which vetoes nothing and lets the declaration stand.
#
# The path is overridable so that the veto branch below is testable
# without a root sysctl change.  That branch is the one protecting CI
# from inheriting a developer's declaration and silently not running
# ASan at all, so it is the one branch that must not go untested --
# and with a fixed path there is no way to reach it on a machine where
# the declaration is true.
OVERCOMMIT_PATH=${SPICULE_OVERCOMMIT_PATH:-/proc/sys/vm/overcommit_memory}
sysctl_value=unknown
[ -r "$OVERCOMMIT_PATH" ] &&
	sysctl_value=$(cat "$OVERCOMMIT_PATH" 2>/dev/null || echo unknown)

if [ "$declared" != no ]; then
	# Nothing declared, or declared available.  Note the reverse
	# mismatch -- ASan is about to fail to start and nobody said so --
	# because that is the confusing case this whole file exists to
	# stop, and the message costs one line.
	if [ "$sysctl_value" = 2 ]; then
		echo "asan-available: WARNING -- vm.overcommit_memory is 2, so ASan will" >&2
		echo "asan-available: fail to start, but the profile does not say so." >&2
		echo "asan-available: add capability.overcommit=no to TEST_PROFILE." >&2
	fi
	exit 0
fi

# A veto needs POSITIVE evidence that overcommit is available -- a value
# that was read and is not 2.  "unknown" (no /proc, unreadable) is not
# that: treating it as a veto would send every ASan binary in a
# /proc-less container to a start-up failure, with the path pointing at
# nothing.  Caught by the control that SPICULE_OVERCOMMIT_PATH exists to
# make possible, which is the whole argument for it being overridable.
if [ "$sysctl_value" != 2 ] && [ "$sysctl_value" != unknown ]; then
	echo "asan-available: WARNING -- the profile declares" >&2
	echo "asan-available: capability.overcommit=no, but vm.overcommit_memory is" >&2
	echo "asan-available: '$sysctl_value', not 2.  The declaration looks stale;" >&2
	echo "asan-available: running ASan anyway.  A declaration may skip this" >&2
	echo "asan-available: stage only when the kernel agrees with it." >&2
	exit 0
fi

echo "asan: UNAVAILABLE in this environment -- not run, and not failed." >&2
echo "asan:" >&2
echo "asan: vm.overcommit_memory is 2 (strict), and the profile declares" >&2
echo "asan: capability.overcommit=no to match.  AddressSanitizer reserves a" >&2
echo "asan: ~15 TB shadow with MAP_NORESERVE, and Linux honours that flag" >&2
echo "asan: only when overcommit is not OVERCOMMIT_NEVER -- so the whole" >&2
echo "asan: reservation is charged against CommitLimit and refused, and" >&2
echo "asan: every ASan-linked binary dies before main().  No build flag or" >&2
echo "asan: ASAN_OPTIONS setting avoids it." >&2
echo "asan:" >&2
echo "asan: NOTHING WAS VERIFIED.  This is not a pass.  CI's runners have" >&2
echo "asan: default overcommit and run this stage for real; they are the" >&2
echo "asan: only authority for memory-safety findings, and a local run" >&2
echo "asan: that ends here is not evidence about anything." >&2
echo "asan:" >&2
echo "asan: What DOES run here, without AddressSanitizer:" >&2
echo "asan:     make -C fuzz ubrun          fuzz under UBSan alone" >&2
echo "asan:     make -C fuzz ubcoverage     ... and report coverage" >&2
echo "asan: That mode detects no heap overflow, use-after-free, double" >&2
echo "asan: free or leak.  See the SAN_MODE comment in tools/asan-build.sh." >&2
exit 77
