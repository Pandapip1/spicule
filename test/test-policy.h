/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Source-level test disposition marker.  The normal compiler sees every
 * fenced case as disabled.  tools/test-policy.py enables one named case at
 * a time in a generated translation unit, so its disposition can be
 * validated without another known failure masking it.
 */
#ifndef SPICULE_TEST_POLICY_H
#define SPICULE_TEST_POLICY_H

#include <stdlib.h>
#include <string.h>

#define SPICULE_TEST(disposition, case_name) 0

/* Nonzero only inside a tools/test-policy.py probe compilation (which
 * defines it via -D), where exactly one SPICULE_TEST case above is
 * enabled to validate that case's disposition in isolation.  A file
 * that also runs its own environment-dependent live checks
 * unconditionally in main() -- outside any SPICULE_TEST fence, e.g.
 * test/posix-glob.c's test_glob_err_callback()/test_glob_noescape() --
 * can read this to keep an unrelated live check's environment gap from
 * being misread as the one probed case's own verdict. */
#ifndef SPICULE_TEST_POLICY_PROBE
#define SPICULE_TEST_POLICY_PROBE 0
#endif

/* Declared, asserted fact about which runtime this run is on, for a live
 * check in main() to adjudicate a failure against -- the same
 * declare-then-adjudicate shape test-profiles.tsv's runtime= selector
 * already uses for tools/test-policy.py's isolated SPICULE_TEST probes,
 * applied here to this suite's own whole-file CHECK() executable instead.
 * tools/run-tests.py sets SPICULE_TEST_RUNTIME from its own --profile
 * runtime=VALUE argument (the same env var name tools/test-policy.py
 * already reads for its unrelated, Python-side profile resolution), so a
 * CI leg or Makefile invocation that already declares runtime=windows or
 * runtime=wine gets this for free.
 *
 * This is a declaration, never a probe: nothing here inspects the actual
 * environment to guess which runtime it is running under.  An unset (or
 * unrecognized) value matches nothing, so an environment nobody told this
 * binary about is never mistaken for a declared exemption -- a failure
 * there stays a hard failure, which is the point. */
static inline int spicule_test_runtime_is(const char *name)
{
	const char *runtime = getenv("SPICULE_TEST_RUNTIME");
	return runtime != NULL && strcmp(runtime, name) == 0;
}

#endif
