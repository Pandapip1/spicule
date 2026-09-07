/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * timeout: `timeout [-s signal] [-k duration] duration utility
 * [argument...]` -- runs utility, and if it is still running after
 * duration, signals it; if it is still running duration-after-that
 * (when -k is given), escalates to SIGKILL.
 *
 * Not a POSIX.1-2017 XCU utility (no timeout(1p) page exists); this
 * project's own utilities plan names it explicitly alongside time(1p),
 * so it follows the common GNU-heritage `timeout(1)` instead.
 *
 * OPTIONS (this tree's usual "-xVALUE or -x VALUE" attachment
 * convention -- no bundled short options, no getopt(3), no long
 * options, consistent with the rest of src/util/):
 *  -s signal   Send this signal instead of the default SIGTERM.
 *              Accepts a name (with or without "SIG", matched
 *              case-insensitively against the signals
 *              include/signal.h defines) or a decimal number.
 *  -k duration Send SIGKILL if utility is still running duration after
 *              the first signal. A duration of 0 disables it, same as
 *              the main duration below.
 *
 * Deliberately not implemented: -f/--foreground (no matching
 * process-group/TTY-foregrounding concept in this project's job-control
 * model), -p/--preserve-status (always uses the fixed 124/137 codes
 * below), -v/--verbose, and every GNU long-option spelling.
 *
 * DURATION: GNU's grammar -- a floating point number with an optional
 * trailing 's'/'m'/'h'/'d' unit (seconds by default) -- via strtod()
 * plus one trailing unit character; GNU's hex-float-with-'d' wrinkle
 * ("0x1p0d") is not implemented. A duration of 0 disables the
 * associated timeout, for both the main duration (runs utility to
 * completion, like this tree's own time(1p)) and -k's.
 *
 * WAITING: this platform has no "block on a child with a timeout"
 * primitive, so a bounded wait is a plain poll loop -- waitpid(WNOHANG)
 * against a CLOCK_MONOTONIC deadline, napping POLL_INTERVAL_NS (20ms)
 * between checks. Once a deadline has passed (or there is nothing left
 * to bound), the final wait for the child to go away is a single
 * ordinary blocking waitpid().
 *
 * EXIT STATUS (timeout(1) manual page, read literally): 124 if utility
 * times out; 125 if timeout itself fails (bad option/duration/signal,
 * or an unattributable waitpid() failure); 126/127 if utility could not
 * be invoked/found (__spawn()/__find_program(), same convention as
 * src/util/find.c and src/util/xargs.c); 137 if utility or timeout
 * itself was sent SIGKILL -- including an explicit `-s KILL` that
 * actually fires, not just a -k escalation; otherwise utility's own
 * exit status.
 *
 * Like every __util_<name>_main(), this never calls exit()/_exit():
 * as the `timeout` shell builtin it runs in-process with no fork, so
 * an error path that replaced the calling shell would be a real bug
 * (see src/internal/util.h). `utility` is always resolved via
 * __find_program() and run as a real, separate process via __spawn().
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

/* Every signal include/signal.h defines, named without the "SIG"
 * prefix -- parse_signal() below strips an optional "SIG"/"sig". */
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
	/* _NSIG, not NSIG: NSIG is gated behind _XOPEN_SOURCE/_BSD_SOURCE/
	 * _GNU_SOURCE, none of which this file defines. */
	if (*end || n <= 0 || n >= _NSIG) return -1;
	return (int)n;
}

/* ~31.7 million years -- comfortably above any real duration, yet
 * comfortably below time_t's 64-bit range with margin left for
 * deadline_after()'s tv_sec addition against a live clock base. */
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
	/* strtod() accepts "inf"/"nan" and saturates to HUGE_VAL on plain
	 * overflow (e.g. "1e400"), and the unit multiplies above can push
	 * an already-huge value to infinity (e.g. "3e304d"); either reaching
	 * the float-to-integer cast in deadline_after() would be undefined
	 * behavior. Written as "!(v <= MAX)" rather than "v > MAX" so a NaN
	 * `v` (false against everything) is rejected too, without isnan(). */
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

int __util_timeout_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
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

	/* A duration of 0 disables -k -- fold that in here so nothing
	 * below needs its own zero case for -k. */
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

	/* Benign race: the child may exit between the last WNOHANG poll and
	 * this kill(), which then just fails ESRCH -- harmless either way. */
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
