/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Cross-process signal delivery: kill() to another spicule process now
 * consults THAT process's own disposition instead of only ever guessing
 * the default action -- see src/signal/sigdelivery.c and
 * src/signal/signal.c's file banner for the whole mechanism. This file
 * is the real-Windows/real-Wine coverage for it: windows-test builds
 * TEST_SRCS globs every test/ source (Makefile) and runs every one of
 * them, so this is checked against an actual NT kernel, not only Wine.
 *
 * Every scenario below uses __spawn(), the same real-second-process
 * primitive test/posix-sigpipe.c and test/posix-signal.c already use for
 * every child-process case in those files, and for the identical
 * reason: fork() needs RtlCloneUserProcess, which stock Wine's stub
 * hard-aborts the whole process for rather than failing it gracefully
 * (see src/process/fork.c's banner and the CI notes this project
 * carries elsewhere). __spawn() gives a genuinely separate process with
 * its own pid either way, which is exactly what cross-process delivery
 * needs to exercise -- and unlike fork(), it works identically whether
 * this binary happens to be running under stock or patched Wine.
 * src/signal/sigdelivery.c's fork-repair path (__sig_delivery_reinit_after_fork(),
 * called from src/process/fork.c) is therefore NOT covered here; it was
 * checked by hand against a RtlCloneUserProcess-patched Wine build
 * instead, for the same reason fork() itself is absent from every other
 * file in this directory.
 *
 * The one race every scenario below has to account for: __sig_delivery_init()
 * runs unconditionally during __signal_init(), which crt1.c calls before
 * main() -- but a freshly __spawn()'d process still has to be scheduled
 * and reach that point before its named pipe exists at all. A fixed
 * short grace period after __spawn() before sending the signal that
 * matters for each scenario's assertion is the same shape
 * test/posix-signal.c's own test_sa_nocldwait() already uses ("Give the
 * child a moment to actually run") for an unrelated race against the
 * same __spawn() primitive.
 */
/* sigaction() and the sigemptyset()/sigaddset()/sigprocmask() family
 * are feature-test gated in include/signal.h; same define most other
 * tests in test/ already carry for the same reason (see test/posix-glob.c's
 * comment on this exact define). */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

extern char **environ;
extern int __spawn(const char *, char *const *, char *const *);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Milliseconds since an arbitrary but fixed epoch, for the elapsed-time
 * assertions below -- none of them care about wall-clock time of day,
 * only about the difference between two readings. */
static long long now_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void sleep_ms(long ms)
{
	struct timeval tv;
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	select(0, NULL, NULL, NULL, &tv);
}

/* Give a freshly __spawn()'d spicule process time to reach
 * __sig_delivery_init() before this process's first kill() targets it --
 * see this file's banner. Generous on purpose (this project's own notes
 * record that a busy CI box manufactures false failures out of tight
 * timing margins): __signal_init() itself is a handful of NT calls, so
 * this is not a close race under any real load, only a race against
 * literally not having been scheduled yet. */
#define STARTUP_GRACE_MS 300

/* ------------------------------------------------------------------ *
 * Child scenarios.  Each is entered by re-executing this same binary
 * with a marker argument; the parent adjudicates the exit status (and,
 * for some, the elapsed time).
 * ------------------------------------------------------------------ */

static void handler_exit42(int sig) { (void)sig; _exit(42); }
static volatile sig_atomic_t handler_ran;
static void handler_mark(int sig) { (void)sig; handler_ran = 1; }
static volatile sig_atomic_t suspend_seen;
static void handler_suspend(int sig)
{
	if (sig == SIGUSR1) suspend_seen |= 1;
	if (sig == SIGUSR2) suspend_seen |= 2;
}

static void handler_self_stop(int sig)
{
	(void)sig;
	raise(SIGSTOP);
}

static int child_self_stop(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_self_stop;
	sigemptyset(&sa.sa_mask);
	/* SIGSTOP is forbidden from the handler mask.  sigaction() may accept
	 * it in the supplied set, but delivery must remove it so this raise
	 * stops immediately rather than becoming pending. */
	sigaddset(&sa.sa_mask, SIGSTOP);
	if (sigaction(SIGUSR1, &sa, NULL) != 0) return 90;
	raise(SIGUSR1);
	/* Reached only after SIGCONT lets the handler return. */
	for (;;) sleep_ms(1000);
}

/* Deliberately installs no handler for anything: this is the plain,
 * default-disposition child exit.html's clause describes. SIGHUP's real
 * kernel default action (Term) is exactly what proves a genuine SIGHUP
 * was delivered -- src/signal/linux/sigdelivery.c's own stub means a
 * real CAUGHT handler can only ever run for a signal that arrived
 * through the named-pipe listener this platform does not implement yet
 * (see signal.c's kill(), last-resort-arm comment), so testing the
 * default action, not a handler, is the only observation this platform
 * can actually make today -- and it is a faithful one: the kernel's own
 * pidfd_send_signal(2) delivery (src/signal/linux/plat_signal.c's
 * __plat_kill_terminate()) is real either way. Never reaps itself off
 * this test's process tree on purpose: this process is deliberately
 * orphaned by its own parent below, exactly the scenario under test. */
static int child_hup_target(void)
{
	for (;;) sleep_ms(1000);
}

/* The middle process of the three-process chain
 * test_orphaned_stop_gets_real_sighup() below drives: spawns
 * child_hup_target() as ITS OWN child (recorded in this process's own
 * src/process/children.c table), stops it for real with kill(...,
 * SIGSTOP), and then exits without ever resuming it itself -- the exact
 * "orphaning a stopped child" moment exit.html's clause and
 * src/process/children.c's clear_stops() describe.  `self` is this
 * process's own argv[0], forwarded so it can re-exec itself for the
 * grandchild the same way spawn_child() does at the top level.
 *
 * The grandchild is never this process's own parent's child either, so
 * the top-level test cannot waitpid() it directly; its pid is reported
 * back over this process's own stdout instead (redirected to a file by
 * the top-level test before this process was ever spawned -- the same
 * dup2()-around-__spawn() technique test/sh-main.c's run_sh() uses for
 * real redirection, and __spawn() inheriting the fd table as-is, same
 * file's own comment, is what makes that redirection visible here). */
static int child_stop_and_orphan(const char *self)
{
	char *argv[3];
	pid_t pid;
	char buf[16];
	int n;

	argv[0] = (char *)self;
	argv[1] = (char *)"--child-hup-target";
	argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) return 95;
	n = snprintf(buf, sizeof buf, "%d\n", (int)pid);
	if (n > 0) write(STDOUT_FILENO, buf, (size_t)n);
	sleep_ms(STARTUP_GRACE_MS);
	if (kill(pid, SIGSTOP) != 0) return 96;
	/* Let the real kernel-level stop actually land before this process
	 * exits -- __child_resume_stopped() only acts on a child this
	 * process's own table already records as stopped. */
	sleep_ms(200);
	return 0;
	/* __exit_internal(), reached from the return above through exit(), sends
	 * SIGHUP (where deliverable) then SIGCONT to the still-stopped
	 * child on the way out -- see src/process/children.c. */
}

/* The positive case: a real handler, installed with sigaction(), must
 * run for a signal delivered by ANOTHER process's kill() -- the exact
 * thing src/signal/signal.c's old header comment said could never
 * happen ("kill() can only end a process, not interrupt it"). SIGUSR1's
 * default action is terminate, so exit(42) from inside the handler is
 * only reachable if the real disposition was consulted; the old
 * default-action-only path would have left this process WIFSIGNALED
 * instead. */
static int child_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_exit42;
	if (sigaction(SIGUSR1, &sa, NULL) != 0) return 90;
	/* Block until something happens -- either the signal (which exits
	 * this process from inside the handler and never returns here) or
	 * this loop's own patience running out, which only happens if
	 * delivery never arrived at all. */
	sleep_ms(10000);
	return 91;   /* the signal never arrived */
}

/* The SIG_IGN case: a signal whose default action is terminate must NOT
 * end this process when ignored, even though this process never asked
 * to be interrupted for it -- proving the target's OWN disposition, not
 * this process's, is what gets consulted. */
static int child_ignore(void)
{
	if (signal(SIGUSR2, SIG_IGN) == SIG_ERR) return 90;
	sleep_ms(2000);
	return 55;   /* survived, which is the point */
}

/* Blocked-then-unblocked: a signal delivered while SIGUSR1 is blocked
 * must go to `pending`, not run the handler early, and must be drained
 * the instant sigprocmask() unblocks it -- src/signal/sigdelivery.c's
 * banner promises exactly this ("a blocked signal must go to pending
 * and be drained by the existing sigprocmask() unblock path, NOT
 * dropped"). The blocked window below (900ms, starting at THIS
 * process's own birth) is deliberately longer than the parent's
 * STARTUP_GRACE_MS(300) before it sends the signal, so the signal is
 * guaranteed to still find SIGUSR1 blocked when it arrives rather than
 * racing this process's own unblock -- the parent's elapsed-time check
 * is against the REMAINDER of this window counted from when the parent
 * sent the signal, not the whole 900ms. */
static int child_blocked(void)
{
	sigset_t set, old;
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_exit42;
	if (sigaction(SIGUSR1, &sa, NULL) != 0) return 90;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &set, &old) != 0) return 92;

	sleep_ms(900);   /* the window a premature delivery would cut short */

	if (sigprocmask(SIG_SETMASK, &old, NULL) != 0) return 93;
	/* If the unblock above did not drain and deliver a pending SIGUSR1,
	 * execution falls through to here instead of exiting 42 from the
	 * handler. */
	sleep_ms(500);
	return 60;
}

/* select()/pselect() EINTR: src/select/select.c's banner explains the
 * choice (EINTR regardless of SA_RESTART, matching Linux's select()/
 * poll()). handler_mark() does not exit -- the point is to see select()
 * itself return, not merely observe the process dying -- so a genuine
 * EINTR return proves src/signal/sigdelivery.c's wake_event actually
 * woke this wait rather than the fixed 5-second timeout doing it. */
static int child_select_eintr(void)
{
	struct sigaction sa;
	struct timeval tv;
	int r;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_mark;
	if (sigaction(SIGUSR1, &sa, NULL) != 0) return 90;

	tv.tv_sec = 5; tv.tv_usec = 0;
	r = select(0, NULL, NULL, NULL, &tv);
	if (r == -1 && errno == EINTR && handler_ran) return 42;
	if (r == 0) return 43;      /* timed out -- the wakeup never happened */
	return 44;                  /* something else entirely */
}

/* The three terminal stops and SIGCONT are catchable too.  kill() must
 * consult this installed handler before applying their default NT
 * suspend/resume action; otherwise the child either hangs suspended or
 * sleeps until select() times out. */
static int child_job_signal_eintr(int sig)
{
	struct sigaction sa;
	struct timeval tv;
	int r;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_mark;
	if (sigaction(sig, &sa, NULL) != 0) return 90;
	tv.tv_sec = 5; tv.tv_usec = 0;
	r = select(0, NULL, NULL, NULL, &tv);
	if (r == -1 && errno == EINTR && handler_ran) return 42;
	if (r == 0) return 43;
	return 44;
}

/* sigsuspend() atomically replaces the mask while it waits, then restores
 * the original mask before returning EINTR.  SIGUSR2 arrives first and is
 * held pending by the temporary mask; SIGUSR1 wakes the suspension; the
 * restoration unblocks and delivers SIGUSR2. */
static int child_sigsuspend(void)
{
	struct sigaction sa;
	sigset_t original, temporary, current;
	int r, saved;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_suspend;
	if (sigaction(SIGUSR1, &sa, NULL) < 0 ||
	    sigaction(SIGUSR2, &sa, NULL) < 0) return 90;
	sigemptyset(&original);
	sigaddset(&original, SIGUSR1);
	if (sigprocmask(SIG_SETMASK, &original, NULL) < 0) return 91;
	sigemptyset(&temporary);
	sigaddset(&temporary, SIGUSR2);
	r = sigsuspend(&temporary);
	saved = errno;
	if (sigprocmask(SIG_SETMASK, NULL, &current) < 0) return 92;
	if (r != -1 || saved != EINTR) return 93;
	if (suspend_seen != 3) return 94;
	if (!sigismember(&current, SIGUSR1) ||
	    sigismember(&current, SIGUSR2)) return 95;
	return 42;
}

static int child_sigwait(void)
{
	sigset_t set;
	int sig = 0;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (sigwait(&set, &sig) != 0) return 90;
	return sig == SIGUSR1 ? 42 : 91;
}

/* Both relative sleep interfaces use __alertable_delay(): a handler run by
 * the remote-delivery thread must end the wait promptly and leave a sensible
 * remainder.  Their return conventions intentionally differ. */
static int child_nanosleep(void)
{
	struct sigaction sa;
	struct timespec request = { 5, 0 }, remaining = { 0, 0 };
	int r, saved;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_mark;
	if (sigaction(SIGABRT, &sa, NULL) < 0) return 90;
	r = nanosleep(&request, &remaining);
	saved = errno;
	if (r != -1 || saved != EINTR || !handler_ran) return 91;
	if (remaining.tv_sec < 3 || remaining.tv_sec > 5) return 92;
	return 42;
}

static int child_clock_nanosleep(void)
{
	struct sigaction sa;
	struct timespec request = { 5, 0 }, remaining = { 0, 0 };
	int r;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_mark;
	if (sigaction(SIGABRT, &sa, NULL) < 0) return 90;
	r = clock_nanosleep(CLOCK_REALTIME, 0, &request, &remaining);
	if (r != EINTR || !handler_ran) return 91;
	if (remaining.tv_sec < 3 || remaining.tv_sec > 5) return 92;
	return 42;
}

/* ------------------------------------------------------------------ *
 * Parent side.
 * ------------------------------------------------------------------ */

static int spawn_child(const char *self, const char *mode, pid_t *pid)
{
	char *argv[3];
	argv[0] = (char *)self; argv[1] = (char *)mode; argv[2] = NULL;
	*pid = __spawn(self, argv, environ);
	return *pid > 0 ? 0 : -1;
}

static void describe(const char *what, int status)
{
	if (WIFEXITED(status))
		printf("    %s: exited %d\n", what, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("    %s: killed by signal %d\n", what, WTERMSIG(status));
	else
		printf("    %s: raw status 0x%x\n", what, (unsigned)status);
}

static void test_handler_runs_for_remote_kill(const char *self)
{
	pid_t pid;
	int status;
	long long t0, t1;

	if (spawn_child(self, "--child-handler", &pid) < 0) { CHECK(0 && "spawn failed"); return; }
	sleep_ms(STARTUP_GRACE_MS);

	t0 = now_ms();
	CHECK(kill(pid, SIGUSR1) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	t1 = now_ms();
	describe("remote handler", status);

	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
	/* Never a wait, never a hang -- the whole exchange (grace period
	 * excluded) should be over well inside a couple of seconds even on
	 * a loaded box. */
	CHECK(t1 - t0 < 5000);
}

static void test_sig_ign_survives_remote_kill(const char *self)
{
	pid_t pid;
	int status;

	if (spawn_child(self, "--child-ignore", &pid) < 0) { CHECK(0 && "spawn failed"); return; }
	sleep_ms(STARTUP_GRACE_MS);

	CHECK(kill(pid, SIGUSR2) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	describe("remote SIG_IGN", status);

	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 55);
}

static void test_blocked_signal_goes_pending(const char *self)
{
	pid_t pid;
	int status;
	long long t0, t1;

	if (spawn_child(self, "--child-blocked", &pid) < 0) { CHECK(0 && "spawn failed"); return; }
	sleep_ms(STARTUP_GRACE_MS);

	t0 = now_ms();
	CHECK(kill(pid, SIGUSR1) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	t1 = now_ms();
	describe("blocked-then-unblocked", status);

	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
	/* The child's own 900ms blocked window started around the same time
	 * as this process's STARTUP_GRACE_MS(300) wait, so roughly 600ms of
	 * it should still be left when the signal lands -- a premature
	 * delivery (the bug this guards against) would instead see the
	 * handler exit within a few ms of kill(), the same shape measured
	 * and fixed in src/select/select.c's timeout accounting while this
	 * test was being written. Generous margins in both directions:
	 * loaded-CI-box tolerant on the low side, hang-catching on the
	 * high side. */
	printf("    blocked-window elapsed: %lldms\n", t1 - t0);
	CHECK(t1 - t0 >= 400);
	CHECK(t1 - t0 < 5000);
}

static void test_select_returns_eintr(const char *self)
{
	pid_t pid;
	int status;
	long long t0, t1;

	if (spawn_child(self, "--child-select-eintr", &pid) < 0) { CHECK(0 && "spawn failed"); return; }
	sleep_ms(STARTUP_GRACE_MS);

	t0 = now_ms();
	CHECK(kill(pid, SIGUSR1) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	t1 = now_ms();
	describe("select() EINTR", status);

	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
	/* The child's select() had a 5-second timeout; if it took anywhere
	 * near that, the wake_event path did not fire and the timeout did
	 * the work instead -- exit code 42 alone cannot tell those apart
	 * (both eventually get there), but the clock can. */
	CHECK(t1 - t0 < 4000);
}

static void test_job_signal_handler(const char *self, const char *mode,
				    int sig, const char *description)
{
	pid_t pid;
	int status;

	if (spawn_child(self, mode, &pid) < 0) {
		CHECK(0 && "spawn failed");
		return;
	}
	sleep_ms(STARTUP_GRACE_MS);
	CHECK(kill(pid, sig) == 0);
	/* SIGTSTP/SIGTTIN/SIGTTOU specifically: on Linux, kill()'s sig_stops()
	 * branch (src/signal/signal.c) now asks src/signal/linux/sigdelivery.c's
	 * __sig_try_deliver_remote_nondefault() whether the target's real
	 * kernel-level disposition is non-default (a real rt_sigaction(2)
	 * dispatch installed by that child's own sigaction() call below --
	 * see plat_signal.h's __plat_sig_install_real_handler() comment) and,
	 * when it is, delivers the real signal instead of stopping the
	 * target -- so the WIFSTOPPED branch below is not expected to trigger
	 * there. NT has no such mechanism (see kill()'s own comment): its
	 * cross-process delivery still falls back unconditionally to
	 * sig_job_control()'s real suspend, so a plain waitpid(pid, &status, 0)
	 * would never wake for that stop there (only exit/termination do), and
	 * nothing else here would ever send the SIGCONT a real stop needs.
	 * WUNTRACED converts that still-real NT gap into an observable,
	 * non-hanging outcome: catch the stop, wake the child back up, and
	 * let the CHECK below fail normally -- the same "known limitation
	 * reported as an honest failure, not a hang" contract
	 * test_no_listener_does_not_hang() above already documents for the
	 * sibling no-listener gap. */
	CHECK(waitpid(pid, &status, WUNTRACED) == pid);
	if (WIFSTOPPED(status)) {
		printf("    %s: really stopped by signal %d (known NT "
		       "sigdelivery.c gap -- no real handler installed on "
		       "that platform), sending SIGCONT and reaping\n",
		       description, WSTOPSIG(status));
		CHECK(kill(pid, SIGCONT) == 0);
		CHECK(waitpid(pid, &status, 0) == pid);
	}
	describe(description, status);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
}

static void test_self_stop_is_waitable(const char *self)
{
	pid_t pid;
	int status;

	if (spawn_child(self, "--child-self-stop", &pid) < 0) {
		CHECK(0 && "spawn failed");
		return;
	}
	CHECK(waitpid(pid, &status, WUNTRACED) == pid);
	CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	/* The marker must describe a real suspension, not merely race ahead of
	 * one: after giving the child time to run, it is still live and has no
	 * exit status available. */
	sleep_ms(200);
	CHECK(waitpid(pid, &status, WNOHANG) == 0);
	CHECK(kill(pid, SIGCONT) == 0);
	CHECK(waitpid(pid, &status, WCONTINUED) == pid);
	CHECK(WIFCONTINUED(status));
	CHECK(kill(pid, SIGKILL) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	describe("self-stop cleanup", status);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void test_sigsuspend_mask_and_wakeup(const char *self)
{
	pid_t pid;
	int status;

	if (spawn_child(self, "--child-sigsuspend", &pid) < 0) {
		CHECK(0 && "spawn failed");
		return;
	}
	sleep_ms(STARTUP_GRACE_MS);
	CHECK(kill(pid, SIGUSR2) == 0);
	/* No grace between packets: kill() must not return from the first
	 * request until the listener has published its replacement instance. */
	CHECK(kill(pid, SIGUSR1) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	describe("sigsuspend mask/restore", status);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
}

static void test_remote_wait_interface(const char *self, const char *mode,
				       int sig, const char *description)
{
	pid_t pid;
	int status;

	if (spawn_child(self, mode, &pid) < 0) {
		CHECK(0 && "spawn failed");
		return;
	}
	sleep_ms(STARTUP_GRACE_MS);
	CHECK(kill(pid, sig) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	describe(description, status);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
}

/* No hang for a target that has no listener yet -- __sig_try_deliver_remote()
 * (src/signal/sigdelivery.c) must fail fast on NtOpenFile rather than
 * wait for one to appear (that function's own comment cites the NT
 * mechanics; this is the runtime check). Sent with NO grace period at
 * all, racing __sig_delivery_init() in the just-spawned child on
 * purpose, so this genuinely exercises "no listener yet" rather than
 * "no listener ever" on at least some runs.
 *
 * Deliberately does NOT assert what happens to the child. Whichever
 * side of the race this lands on, kill() takes the same action for a
 * signal whose target it cannot reach: fall through to the
 * unconditional NtTerminateProcess path -- and that path terminates the
 * child outright even for a signal like SIGWINCH whose default_action()
 * (src/signal/signal.c) is "ignore", a separate, pre-existing gap
 * (kill() to a process with no listener has never consulted
 * default_action() at all, only ever assumed "terminate") outside this
 * file's scope. The only property under test here is that reaching for
 * a listener that is not there yet costs milliseconds, not a hang. */
static void test_no_listener_does_not_hang(const char *self)
{
	pid_t pid;
	int status;
	long long t0, t1;

	if (spawn_child(self, "--child-ignore", &pid) < 0) { CHECK(0 && "spawn failed"); return; }

	t0 = now_ms();
	CHECK(kill(pid, SIGWINCH) == 0);
	t1 = now_ms();
	printf("    kill() racing startup: %lldms\n", t1 - t0);
	CHECK(t1 - t0 < 3000);

	/* Whatever that first kill() did to it, this reaps it either way:
	 * SIGUSR2 is ignored if the child is still alive (its own --child-ignore
	 * body), and waitpid() on an already-dead child just as readily
	 * reports how it died. */
	kill(pid, SIGUSR2);
	CHECK(waitpid(pid, &status, 0) == pid);
	describe("post-race child", status);
}

#ifdef __linux__
/* /proc/pid/stat's state field: 'Z' once a process has actually
 * terminated but not yet been reaped (its new parent, after
 * reparenting off the process that orphaned it, may take a while to
 * get around to that -- unlike kill(pid, 0), which a lingering zombie
 * still answers success for, this tells "genuinely dead" apart from
 * "still running" without waiting on that). A pid /proc no longer has
 * an entry for at all counts the same as 'Z': reaped is also dead. The
 * comm field is skipped past its own closing ')' rather than assumed
 * to start at a fixed column, because it can itself contain spaces or
 * parentheses (proc(5)). */
static int pid_is_dead(pid_t pid)
{
	char path[64], buf[256], *p;
	FILE *f;

	snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
	f = fopen(path, "r");
	if (!f) return 1;
	if (!fgets(buf, sizeof buf, f)) { fclose(f); return 1; }
	fclose(f);
	p = strrchr(buf, ')');
	if (!p) return 0;
	p++;
	while (*p == ' ') p++;
	return *p == 'Z';
}

/* exit.html CONSEQUENCES OF PROCESS TERMINATION: a stopped child left
 * behind by an exiting process must get SIGHUP before SIGCONT.  Only
 * Linux delivers that SIGHUP as a real signal, applying the child's own
 * kernel-level disposition, instead of being forced through the
 * destroy-the-child NT fallback -- see src/process/children.c's own
 * comment and __plat_sig_deliverable_to_other_process() (src/internal/
 * plat_signal.h) -- so this only means anything, and only runs, here.
 *
 * Three processes deep, all via __spawn(): this process spawns
 * child_stop_and_orphan() (M), which spawns and stops
 * child_hup_target() (G) and then exits without resuming it, orphaning
 * a stopped G exactly as the clause describes. G is never this
 * process's own child (M's is the pid table __child_resume_stopped()
 * acts on), so it cannot be waitpid()'d here: it reports its own pid
 * back over M's stdout instead (redirected to a file before M was
 * spawned -- see child_stop_and_orphan()'s own comment), and the
 * assertion below is pid_is_dead() on that pid rather than a wait
 * status. G installs no handler for anything (see child_hup_target()'s
 * own comment on why that, not a caught signal, is what this platform
 * can actually prove today): a real SIGHUP's default action (Term) is
 * what should end it. Before this fix, only SIGCONT ever reached a
 * stopped child on the way out, and G would still be sitting in its own
 * sleep_ms() loop, never stopped from running by anything. */
#define SIGHUP_MARKER_FILE "posix-signal-crossproc-sighup.txt"
static void test_orphaned_stop_gets_real_sighup(const char *self)
{
	char *argv[3];
	pid_t pid;
	pid_t gpid = 0;
	int status, out, saved_out;
	FILE *f;

	unlink(SIGHUP_MARKER_FILE);
	out = open(SIGHUP_MARKER_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0) { CHECK(0 && "marker file open failed"); return; }
	saved_out = dup(STDOUT_FILENO);
	dup2(out, STDOUT_FILENO);
	close(out);

	argv[0] = (char *)self;
	argv[1] = (char *)"--child-stop-and-orphan";
	argv[2] = NULL;
	pid = __spawn(self, argv, environ);

	dup2(saved_out, STDOUT_FILENO);
	close(saved_out);

	if (pid <= 0) { CHECK(0 && "spawn failed"); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
	describe("stop-and-orphan middle process", status);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	f = fopen(SIGHUP_MARKER_FILE, "r");
	if (f) { if (fscanf(f, "%d", &gpid) != 1) gpid = 0; fclose(f); }
	unlink(SIGHUP_MARKER_FILE);
	CHECK(gpid > 0);
	if (gpid <= 0) return;

	/* Real SIGHUP delivery races this process's own scheduling, same as
	 * every other STARTUP_GRACE_MS wait in this file -- it happens only
	 * after M has already exited and been reaped above, not before. */
	sleep_ms(500);

	CHECK(pid_is_dead(gpid));

	/* Best-effort cleanup for the case just above that failed: leave
	 * nothing running past this test either way. Not this process's own
	 * child, so there is no corresponding waitpid() to reap it with;
	 * the same tolerance test/posix-realtime-linux.c's own banner
	 * documents for a leaked, reparented process. */
	kill(gpid, SIGKILL);
}
#endif

int main(int argc, char **argv)
{
	if (argc > 1) {
		if (!strcmp(argv[1], "--child-handler")) return child_handler();
		if (!strcmp(argv[1], "--child-ignore")) return child_ignore();
		if (!strcmp(argv[1], "--child-blocked")) return child_blocked();
		if (!strcmp(argv[1], "--child-select-eintr")) return child_select_eintr();
		if (!strcmp(argv[1], "--child-sigcont")) return child_job_signal_eintr(SIGCONT);
		if (!strcmp(argv[1], "--child-sigtstp")) return child_job_signal_eintr(SIGTSTP);
		if (!strcmp(argv[1], "--child-sigttin")) return child_job_signal_eintr(SIGTTIN);
		if (!strcmp(argv[1], "--child-sigttou")) return child_job_signal_eintr(SIGTTOU);
		if (!strcmp(argv[1], "--child-self-stop")) return child_self_stop();
		if (!strcmp(argv[1], "--child-hup-target")) return child_hup_target();
		if (!strcmp(argv[1], "--child-stop-and-orphan")) return child_stop_and_orphan(argv[0]);
		if (!strcmp(argv[1], "--child-sigsuspend")) return child_sigsuspend();
		if (!strcmp(argv[1], "--child-sigwait")) return child_sigwait();
		if (!strcmp(argv[1], "--child-nanosleep")) return child_nanosleep();
		if (!strcmp(argv[1], "--child-clock-nanosleep")) return child_clock_nanosleep();
	}

	test_handler_runs_for_remote_kill(argv[0]);
	test_sig_ign_survives_remote_kill(argv[0]);
	test_blocked_signal_goes_pending(argv[0]);
	test_select_returns_eintr(argv[0]);
	test_job_signal_handler(argv[0], "--child-sigcont", SIGCONT,
	                        "remote SIGCONT handler");
	test_job_signal_handler(argv[0], "--child-sigtstp", SIGTSTP,
	                        "remote SIGTSTP handler");
	test_job_signal_handler(argv[0], "--child-sigttin", SIGTTIN,
	                        "remote SIGTTIN handler");
	test_job_signal_handler(argv[0], "--child-sigttou", SIGTTOU,
	                        "remote SIGTTOU handler");
	test_self_stop_is_waitable(argv[0]);
	test_sigsuspend_mask_and_wakeup(argv[0]);
	test_remote_wait_interface(argv[0], "--child-sigwait", SIGUSR1,
	                           "remote sigwait");
	test_remote_wait_interface(argv[0], "--child-nanosleep", SIGABRT,
	                           "remote nanosleep EINTR");
	test_remote_wait_interface(argv[0], "--child-clock-nanosleep", SIGABRT,
	                           "remote clock_nanosleep EINTR");
	test_no_listener_does_not_hang(argv[0]);
#ifdef __linux__
	test_orphaned_stop_gets_real_sighup(argv[0]);
#endif

	if (fails) printf("posix-signal-crossproc: %d failure(s)\n", fails);
	else printf("posix-signal-crossproc: ok\n");
	return fails != 0;
}
