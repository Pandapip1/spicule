/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * kill()'s [EPERM] -- kill.html ERRORS: "[EPERM] The process does not
 * have permission to send the signal to any receiving process."
 *
 * This lived in test/posix-unistd.c as an N/A fence claiming the clause
 * was "structurally impossible here", on the grounds that spicule has
 * exactly one immutable token-derived uid (src/unistd/ids.c), so no uid
 * mismatch can ever be checked.  Both halves of that were wrong.
 *
 * The reason was wrong because kill()'s EPERM has nothing to do with
 * uids.  src/signal/signal.c's kill() reaches a non-child pid through
 * NtOpenProcess and maps STATUS_ACCESS_DENIED to EPERM directly: the
 * denial is NT's own access check on the target process object, not an
 * identity comparison spicule performs.
 *
 * The verdict was wrong because that branch is reachable, and cheaply.
 * Measured on real Windows 11 Pro 22621 (build 22621), from a process
 * holding an ELEVATED token:
 *
 *   target       desired access                              status
 *   ---------------------------------------------------------------------
 *   pid 4        PROCESS_TERMINATE|QUERY_LIMITED_INFORMATION c0000022 DENIED
 *   pid 4        PROCESS_QUERY_LIMITED_INFORMATION only      00000000 SUCCESS
 *   pid 4        PROCESS_TERMINATE only                      c0000022 DENIED
 *   self         PROCESS_TERMINATE|QUERY_LIMITED_INFORMATION 00000000 SUCCESS
 *   pid 524272   PROCESS_TERMINATE|QUERY_LIMITED_INFORMATION c000000b INVALID_CID
 *
 * Three things follow, and they are why this file is shaped as it is.
 *
 * 1. No token check is needed, and none should be added.  The measuring
 *    process was elevated and pid 4 was denied anyway.  An unelevated
 *    token holds a subset of an elevated one's rights, so an ordinary
 *    process cannot do better than a denial either.  (That last step is
 *    inference from monotonicity of token rights, not a second
 *    measurement -- the unelevated case was not run.  It is stated here
 *    so nobody later "fixes" this test by adding an elevation probe.)
 *
 * 2. The denial is specific to PROCESS_TERMINATE, not to pid 4.
 *    PROCESS_QUERY_LIMITED_INFORMATION alone SUCCEEDS on pid 4.  Our
 *    call site asks for both, which is the only reason it lands on the
 *    denied side.  See the matching comment at src/signal/signal.c's
 *    NtOpenProcess call: narrowing that mask turns this EPERM into a
 *    silent success and breaks this test for a reason that looks
 *    entirely unrelated to it.
 *
 * 3. EPERM and ESRCH are separable on real NT, so both are asserted
 *    here.  The nonexistent-pid control answers STATUS_INVALID_CID
 *    (c000000b), a different status from the denial's c0000022, and the
 *    ESRCH arm keys on exactly that difference.  A bare EPERM assertion
 *    on its own could not tell "correctly denied" from "every kill()
 *    fails", which is a vacuous assertion wearing a passing result.
 *
 * Why -win.c: under Wine there is no System process and no protected-
 * process model, so pid 4 simply does not exist and kill(4, 0) answers
 * ESRCH.  That is a difference in which processes exist, not a
 * divergence in NtOpenProcess's access checking, so it is not a Wine
 * bug to patch -- it is a reason to run this on the real-Windows leg,
 * where *-win.c tests go.
 *
 * Not covered here, deliberately: kill() against a pid owned by a
 * *different user*.  That is a different mechanism (token identity
 * rather than protected-process policy), it was not measured, and it
 * cannot be measured from an elevated token, which would likely succeed
 * and report on the token rather than on NT's rule.  It stays
 * unasserted rather than being folded into this one.
 */
/* kill() is feature-test gated in include/signal.h; same define most
 * other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* The NT System process.  Its pid is architecturally 4 on every NT
 * release; it is not a value that varies per boot. */
#define SYSTEM_PID 4

/* A pid that cannot be live: NT allocates pids as multiples of 4 well
 * below this, and the control row above measured this exact value
 * answering STATUS_INVALID_CID. */
#define ABSENT_PID 524272

/* kill.html: "If sig is 0 (the null signal), error checking is
 * performed but no signal is actually sent."  So sig 0 exercises the
 * permission check on its own, with no chance of terminating anything
 * -- which matters when the target is the System process. */
static void test_kill_eperm_protected_process(void)
{
	errno = 0;
	CHECK(kill(SYSTEM_PID, 0) == -1);
	CHECK(errno == EPERM);
}

static void test_kill_esrch_absent_process(void)
{
	errno = 0;
	CHECK(kill(ABSENT_PID, 0) == -1);
	CHECK(errno == ESRCH);
}

/* The positive control.  Without it, a build in which every kill()
 * returned -1 would pass both assertions above. */
static void test_kill_self_succeeds(void)
{
	errno = 0;
	CHECK(kill(getpid(), 0) == 0);
}

int main(void)
{
	test_kill_self_succeeds();
	test_kill_eperm_protected_process();
	test_kill_esrch_absent_process();

	if (!fails) printf("posix-kill-perm: all tests passed\n");
	return fails != 0;
}
