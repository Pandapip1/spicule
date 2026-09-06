/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * timeout: `timeout [-s signal] [-k duration] duration utility
 * [argument...]` -- runs utility, and if it is still running after
 * duration, signals it; if it is still running duration-after-that
 * (when -k is given), escalates to SIGKILL.
 *
 * NOT an XCU utility: checked directly against the real POSIX.1-2017
 * alphabetical utility index (the "t" entries there run tabs, tail,
 * talk, tee, test, time, touch, tput, tr, true, tsort, tty, type --
 * no timeout(1p) page exists at all) before writing a single line of
 * this file. It is implemented anyway because this project's own
 * POSIX-utilities plan names it explicitly as part of this tier
 * alongside time(1p), not because it is secretly standard. Everything
 * below instead follows the real, common GNU-heritage `timeout(1)`
 * every BSD/GNU implementation agrees on (checked against the actual
 * GNU Coreutils manual and the timeout(1) manual page, not
 * reconstructed from memory), with the exact subset implemented and
 * the exact wording cited spelled out below.
 *
 * OPTIONS implemented (this tree's usual "-xVALUE or -x VALUE, never
 * -x -- VALUE" attachment convention -- see e.g. src/util/uniq.c's
 * -f/-s -- no bundled short options, no getopt(3), no long options;
 * consistent with every other *.c file in src/util/):
 *
 *  -s signal   Send this signal instead of the default SIGTERM.
 *              Accepts a name (with or without a leading "SIG",
 *              matched case-insensitively against a fixed table of
 *              the signals include/signal.h actually defines -- not a
 *              full sys_siglist-driven enumeration, since this
 *              platform's own signal set is itself fixed and small)
 *              or a plain decimal number.
 *  -k duration Send SIGKILL if utility is still running duration after
 *              the first signal was sent. "Has no effect if the main
 *              duration or this duration is 0" -- both zero cases are
 *              implemented as documented below.
 *
 * NOT implemented (real, deliberate scope narrowing, not oversights):
 * -f/--foreground (process-group/TTY-foregrounding semantics this
 * project's own job-control model does not have a matching concept
 * for), -p/--preserve-status (this file always uses the fixed 124/137
 * timeout exit codes below -- see EXIT STATUS), -v/--verbose (no
 * "sending signal N to command" diagnostic), and every GNU long-option
 * spelling (--signal=, --kill-after=, ...) -- none of the short
 * options above have a long-option twin here for the same reason no
 * other *.c file in src/util/ does.
 *
 * DURATION grammar: GNU's own -- "a floating point number with an
 * optional suffix: 's' for seconds (the default), 'm' for minutes,
 * 'h' for hours or 'd' for days" -- implemented via strtod() plus one
 * optional trailing unit character; GNU's additional hex-float-with-
 * 'd'-suffix wrinkle ("0x1p0d") is not implemented (never documented
 * as more than an obscure corner even in GNU's own manual, and no
 * other numeric operand anywhere in this tree accepts hex float
 * syntax either). "A duration of 0 disables the associated timeout"
 * (GNU Coreutils manual, timeout-invocation) is implemented for both
 * the main duration (runs utility to completion with no deadline at
 * all, exactly like this tree's own time(1p) does) and for -k's
 * duration (treated exactly as if -k had not been given).
 *
 * WAITING MECHANISM: this platform has no "block on a child with a
 * timeout" primitive this tree already uses anywhere (checked before
 * writing this file: no existing deadline/alarm-based child
 * supervision precedent exists in src/sh/ or elsewhere), so a bounded
 * wait is a plain poll loop -- waitpid(WNOHANG) against a
 * CLOCK_MONOTONIC deadline, sleeping POLL_INTERVAL_NS (20ms) between
 * checks via nanosleep() when neither has resolved yet. 20ms bounds
 * this file's own CPU use to something negligible while keeping the
 * signal-delivery/reap latency well under any duration granularity a
 * real caller would notice. Once a deadline has genuinely passed (or
 * once -k is not in play, or once SIGKILL has just been sent), the
 * final wait for the child to actually go away is a single ordinary
 * blocking waitpid() -- there is nothing left to bound.
 *
 * EXIT STATUS: this file follows the exact convention the timeout(1)
 * manual page states (verified directly, not reconstructed): "124 if
 * COMMAND times out ... 125 if the timeout command itself fails; 126
 * if COMMAND is found but cannot be invoked; 127 if COMMAND cannot be
 * found; 137 if COMMAND (or timeout itself) is sent the KILL(9)
 * signal (128+9); [otherwise] the exit status of COMMAND". "Sent the
 * KILL(9) signal" is read literally here, not as "escalation via -k
 * happened": if -s KILL is given explicitly as the *first* signal and
 * it is what actually fires, that is 137 too, exactly as reported
 * whenever this file itself calls kill(pid, SIGKILL) for any reason.
 * 125 covers every "timeout itself fails" case this file has --
 * option/duration/signal parsing errors, and a waitpid() failure this
 * file cannot otherwise attribute to the child. 126/127 follow
 * __spawn()/__find_program() failing, the same convention
 * src/util/find.c's and src/util/xargs.c's own spawn_and_wait()
 * helpers already use elsewhere in this tree.
 *
 * Like every other __util_<name>_main(), this never calls exit()/
 * _exit(): as the `timeout` shell builtin (src/sh/builtin.c's
 * bi_timeout()) it runs in-process with no fork, so an error path that
 * replaced the calling shell process would be a real bug -- see
 * src/internal/util.h's own header comment and src/util/dd.c's for the
 * established reasoning. Like src/util/util_time.c's own bi_time(),
 * both callers always resolve `utility` via __find_program() and run
 * it as a real, separate process via __spawn(); neither has any path
 * to invoke a shell builtin in-process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "util.h"
#include "libc.h" /* __find_program()/__spawn() -- src/process/, the same primitives sh's own execute.c uses */

#define POLL_INTERVAL_NS 20000000L /* 20ms -- see this file's header comment */

struct signame { const char *name; int sig; };

/* Every signal include/signal.h actually defines (checked against
 * that header directly), named without the "SIG" prefix -- parse_signal()
 * below strips an optional "SIG"/"sig" before matching. */
static const struct signame g_signames[] = {
	{ "HUP", SIGHUP }, { "INT", SIGINT }, { "QUIT", SIGQUIT },
	{ "ILL", SIGILL }, { "TRAP", SIGTRAP }, { "ABRT", SIGABRT },
	{ "IOT", SIGIOT }, { "BUS", SIGBUS }, { "FPE", SIGFPE },
	{ "KILL", SIGKILL }, { "USR1", SIGUSR1 }, { "SEGV", SIGSEGV },
	{ "USR2", SIGUSR2 }, { "PIPE", SIGPIPE }, { "ALRM", SIGALRM },
	{ "TERM", SIGTERM }, { "STKFLT", SIGSTKFLT }, { "CHLD", SIGCHLD },
	{ "CONT", SIGCONT }, { "STOP", SIGSTOP }, { "TSTP", SIGTSTP },
	{ "TTIN", SIGTTIN }, { "TTOU", SIGTTOU }, { "URG", SIGURG },
	{ "XCPU", SIGXCPU }, { "XFSZ", SIGXFSZ }, { "VTALRM", SIGVTALRM },
	{ "PROF", SIGPROF }, { "WINCH", SIGWINCH }, { "IO", SIGIO },
	{ "PWR", SIGPWR }, { "SYS", SIGSYS },
};

/* Returns the signal number, or -1 for anything not recognized. */
static int parse_signal(const char *s)
{
	size_t i;
	char *end;
	long n;

	if (!strncasecmp(s, "SIG", 3) && s[3]) s += 3;
	for (i = 0; i < sizeof g_signames / sizeof *g_signames; i++)
		if (!strcasecmp(s, g_signames[i].name)) return g_signames[i].sig;

	if (!*s) return -1;
	n = strtol(s, &end, 10);
	/* _NSIG, not NSIG: the latter is gated behind _XOPEN_SOURCE/
	 * _BSD_SOURCE/_GNU_SOURCE (include/signal.h), none of which this
	 * file defines -- _NSIG is the same value, unconditionally
	 * visible, and already this tree's own convention for exactly
	 * this bound (e.g. src/signal/signal.c's sig_valid()). */
	if (*end || n <= 0 || n >= _NSIG) return -1;
	return (int)n;
}

/* Comfortably above any real caller's duration (~31.7 million years)
 * yet comfortably below time_t's own 64-bit range (include/alltypes.h.
 * gen: `typedef _Int64 time_t;`, on every platform this tree targets)
 * with enormous margin left over for deadline_after()'s tv_sec
 * addition against a live CLOCK_MONOTONIC base. See parse_duration()'s
 * use below for why this bound has to exist at all. */
#define MAX_DURATION_SECS 1e15

/* Returns 0 and sets *out (seconds) on success, -1 on a malformed
 * duration -- see this file's header comment for the exact grammar. */
static int parse_duration(const char *s, double *out)
{
	char *end;
	double v;

	if (!*s) return -1;
	v = strtod(s, &end);
	if (end == s || v < 0) return -1;
	switch (*end) {
	case 0: break;
	case 's': if (end[1]) return -1; break;
	case 'm': if (end[1]) return -1; v *= 60; break;
	case 'h': if (end[1]) return -1; v *= 3600; break;
	case 'd': if (end[1]) return -1; v *= 86400; break;
	default: return -1;
	}
	/* Reject non-finite and unrepresentable durations here, before
	 * they ever reach deadline_after()'s "(time_t)secs" narrowing.
	 * This libc's own strtod() (src/stdlib/strtod.c) accepts the
	 * C99 "inf"/"infinity"/"nan" spellings and silently saturates to
	 * HUGE_VAL on plain numeric overflow (e.g. "1e400"); the 'm'/'h'/
	 * 'd' multiplies just above can themselves push an already-huge
	 * finite value to infinity (e.g. "3e304d"). "-inf" is already
	 * caught by the "v < 0" check above, but +inf and NaN both pass
	 * it (a NaN comparison is always false, and +inf is not < 0), and
	 * either one reaching a float-to-integer cast whose target can't
	 * hold the value is undefined behavior per C11 6.3.1.4 -- not a
	 * mere truncation. The comparison below is written so a NaN `v`
	 * (which compares false against everything, including itself)
	 * fails it and is rejected too, with no separate isnan() needed. */
	if (!(v <= MAX_DURATION_SECS)) return -1;
	*out = v;
	return 0;
}

static struct timespec deadline_after(struct timespec base, double secs)
{
	struct timespec r = base;
	time_t whole = (time_t)secs;
	long nsec = (long)((secs - (double)whole) * 1e9 + 0.5);

	r.tv_sec += whole;
	r.tv_nsec += nsec;
	if (r.tv_nsec >= 1000000000L) { r.tv_nsec -= 1000000000L; r.tv_sec += 1; }
	return r;
}

static int deadline_passed(struct timespec deadline)
{
	struct timespec now;
	(void)clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec > deadline.tv_sec ||
	       (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
}

/* Polls for pid to exit, bounded by deadline. Returns 1 (status set)
 * if the child was reaped, 0 if the deadline passed first, -1 on a
 * genuine waitpid() failure (errno set). */
static int wait_bounded(int pid, int *status, struct timespec deadline)
{
	for (;;) {
		int r = waitpid(pid, status, WNOHANG);
		if (r == pid) return 1;
		if (r < 0 && errno != EINTR) return -1;
		if (deadline_passed(deadline)) return 0;
		{
			struct timespec nap = { 0, POLL_INTERVAL_NS };
			(void)nanosleep(&nap, 0);
		}
	}
}

int __util_timeout_main(int argc, char **argv)
{
	int i = 1;
	int sig = SIGTERM;
	int have_k = 0, sent_kill = 0;
	double duration = 0, kduration = 0;
	char *resolved;
	int pid, status, spawn_errno;
	struct timespec deadline;

	for (; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		if (!strcmp(arg, "-s") || !strncmp(arg, "-s", 2)) {
			const char *val;
			int parsed;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("timeout: -s: option requires an argument\n"); return 125; } val = argv[i]; }
			parsed = parse_signal(val);
			if (parsed < 0) { __util_diagf("timeout: -s: %s: invalid signal\n", val); return 125; }
			sig = parsed;
			continue;
		}
		if (!strcmp(arg, "-k") || !strncmp(arg, "-k", 2)) {
			const char *val;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("timeout: -k: option requires an argument\n"); return 125; } val = argv[i]; }
			if (parse_duration(val, &kduration) < 0) { __util_diagf("timeout: -k: %s: invalid duration\n", val); return 125; }
			have_k = 1;
			continue;
		}
		__util_diagf("timeout: %s: invalid option\n", arg);
		return 125;
	}

	if (i >= argc) { __util_diagf("timeout: missing operand\n"); return 125; }
	if (parse_duration(argv[i], &duration) < 0) {
		__util_diagf("timeout: %s: invalid duration\n", argv[i]);
		return 125;
	}
	i++;
	if (i >= argc) { __util_diagf("timeout: missing utility operand\n"); return 125; }

	/* "A duration of 0 disables the associated timeout" (see this
	 * file's header comment) -- have_k stays authoritative for -k's
	 * own zero case below, but disabling it here up front keeps the
	 * rest of this function from needing a special zero case of its
	 * own for -k. */
	if (have_k && kduration == 0) have_k = 0;

	resolved = __find_program(argv[i], 1);
	if (!resolved) {
		__util_diagf("timeout: %s: command not found\n", argv[i]);
		return 127;
	}

	pid = __spawn(resolved, &argv[i], environ);
	/* Captured before free(): see src/util/util_time.c's identical
	 * check for why the ENOENT-vs-everything-else distinction has to
	 * come from __spawn()'s own errno, read right away, rather than
	 * from __find_program() having already succeeded. */
	spawn_errno = errno;
	free(resolved);
	if (pid < 0) {
		__util_diagf("timeout: %s: %s\n", argv[i], strerror(spawn_errno));
		return spawn_errno == ENOENT ? 127 : 126;
	}

	if (duration == 0) {
		/* No timeout at all -- just run it to completion, same as
		 * src/util/util_time.c's own unconditional wait. */
		if (waitpid(pid, &status, 0) < 0) {
			__util_diagf("timeout: %s\n", strerror(errno));
			return 125;
		}
		return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	}

	{
		struct timespec now;
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		deadline = deadline_after(now, duration);
	}
	switch (wait_bounded(pid, &status, deadline)) {
	case 1:
		return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	case -1:
		__util_diagf("timeout: %s\n", strerror(errno));
		return 125;
	default:
		break; /* deadline passed; fall through to the signal/escalate path below */
	}

	/* The deadline has passed. A benign, unavoidable race lives here:
	 * the child may have exited in the instant between the last
	 * WNOHANG poll and this kill() -- kill() then simply fails ESRCH,
	 * which changes nothing below, since a timeout genuinely did
	 * occur from this file's own point of view either way. */
	(void)kill(pid, sig);
	if (sig == SIGKILL) sent_kill = 1;

	if (have_k) {
		struct timespec now;
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		deadline = deadline_after(now, kduration);
		switch (wait_bounded(pid, &status, deadline)) {
		case 1:
			break; /* reaped within the grace period */
		case -1:
			__util_diagf("timeout: %s\n", strerror(errno));
			return 125;
		default:
			(void)kill(pid, SIGKILL);
			sent_kill = 1;
			if (waitpid(pid, &status, 0) < 0) {
				__util_diagf("timeout: %s\n", strerror(errno));
				return 125;
			}
			break;
		}
	} else {
		if (waitpid(pid, &status, 0) < 0) {
			__util_diagf("timeout: %s\n", strerror(errno));
			return 125;
		}
	}

	return sent_kill ? 137 : 124;
}
