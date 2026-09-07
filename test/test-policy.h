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

#endif
