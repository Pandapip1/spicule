/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * time(1p): `time [-p] utility [argument...]` -- runs utility, then
 * writes its elapsed real/user/system time to standard error.
 *
 * Named src/util/util_time.c, not src/util/time.c: src/internal/util.h's
 * own header comment documents why (tcc's `ar` truncates archive member
 * names to basename only, so a second time.c anywhere in src/ would
 * silently collide with src/time/time.c's own ar member in lib/libc.a
 * -- a real, confirmed collision, not a theoretical one -- the same
 * reason src/util/util_printf.c isn't src/util/printf.c).
 *
 * SYNOPSIS/OPERANDS/EXIT STATUS below are XCU time(1p), fetched and
 * checked against directly rather than reconstructed from familiarity
 * with the unrelated ksh/bash `time` reserved-word or GNU
 * /usr/bin/time, both of which use their own, different output
 * formats.
 *
 * OUTPUT FORMAT: time(1p) STDOUT is explicitly "Not used" -- the
 * timing report goes to stderr. The only format the standard actually
 * pins down is -p's: "the following format shall be used for the
 * timing statistics in the POSIX locale: 'real %f\nuser %f\nsys
 * %f\n'" (one digit after the radix character, minimum). The
 * unqualified default format is explicitly left unspecified by the
 * standard's own RATIONALE ("[t]he default output format has been
 * left unspecified because historical implementations differ
 * greatly"), so there is no "more correct" default to reconstruct.
 * This implementation always emits the -p format, whether or not -p
 * is given on the command line: it is the one format XCU actually
 * commits to, so using it unconditionally is honest rather than
 * inventing a second, arbitrary "default" format to sit alongside it.
 * -p is still accepted (as SYNOPSIS requires) purely so a script that
 * passes it does not fail on an "invalid option".
 *
 * TIMING SOURCES (both real, both actually available on this
 * platform -- see include/time.h and include/sys/resource.h, checked
 * before writing this file rather than assumed):
 *  - real: clock_gettime(CLOCK_MONOTONIC) immediately before __spawn()
 *    and immediately after waitpid() reaps the child. CLOCK_MONOTONIC
 *    rather than CLOCK_REALTIME specifically so a concurrent wall-
 *    clock step (NTP, DST, a manual clock change) during the run
 *    cannot produce a negative or inflated "real" reading -- a real
 *    utility contract violation CLOCK_REALTIME would risk, not a
 *    hypothetical one.
 *  - user/sys: getrusage(RUSAGE_CHILDREN) before and after, subtracted.
 *    RUSAGE_CHILDREN is a running total this process's own reaped
 *    children accumulate into at every waitpid() call
 *    (src/process/wait.c's own "for RUSAGE_CHILDREN" comment), so
 *    bracketing the one __spawn()/waitpid() pair below with a before/
 *    after read isolates exactly this child's own contribution,
 *    regardless of what any earlier child already added to the
 *    running total in this same process (relevant when this runs as
 *    the `time` shell builtin in a long-lived shell session that has
 *    already reaped other children).
 *
 * Like every other __util_<name>_main(), this never calls exit()/
 * _exit(): as the `time` shell builtin (src/sh/builtin.c's bi_time())
 * it runs in-process with no fork, so replacing the calling shell
 * process on an error path would be a real bug, not a shortcut -- see
 * src/internal/util.h's own header comment and src/util/dd.c's for the
 * established reasoning this file follows.
 *
 * EXIT STATUS: XCU time(1p) only buckets this -- "1-125: An error
 * occurred in the time utility", 126 utility found but could not be
 * invoked, 127 utility not found, otherwise the utility's own exit
 * status. This implementation uses 1 for every "error occurred in
 * time itself" case (missing operand, an invalid option, waitpid()
 * failing) -- the exact value within 1-125 is left to the
 * implementation by the standard, and 1 is this tree's usual choice
 * for that bucket (e.g. src/util/ln.c, src/util/rmdir.c). 126/127
 * follow __spawn()/__find_program() failing, the same convention
 * src/util/find.c's and src/util/xargs.c's own spawn_and_wait()
 * helpers already use elsewhere in this tree for "ran a command found
 * via PATH and waited on it". A child that dies from a signal is
 * reported as 128+signal, the same convention those two files already
 * use for their own spawned children.
 *
 * "utility cannot be a special built-in" (OPERANDS): satisfied by
 * construction rather than by an explicit check. Unlike a shell's own
 * `time` reserved word (which ntlibc's sh does not implement -- only
 * this builtin), both callers of __util_time_main() -- bin/time.exe
 * and the `time` shell builtin -- always resolve `utility` via
 * __find_program() and run it as a real, separate process via
 * __spawn(); neither has any path to invoke another shell builtin
 * in-process (that dispatch lives in src/sh/execute.c, not here), so
 * there is no way for a special built-in to reach this code as
 * `utility` in the first place.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "util.h"
#include "libc.h" /* __find_program()/__spawn() -- src/process/, the same primitives sh's own execute.c uses */

static double ts_diff(struct timespec a, struct timespec b)
{
	return (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}

static double tv_diff(struct timeval a, struct timeval b)
{
	return (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_usec - a.tv_usec) / 1e6;
}

int __util_time_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 1;
	char *resolved;
	int pid, status, rc, spawn_errno;
	struct timespec real0, real1;
	struct rusage ru0, ru1;

	/* Only -p is defined by SYNOPSIS; "--" lets a utility whose own
	 * name happens to start with '-' still be named unambiguously,
	 * the same escape hatch src/util/uniq.c's own option loop offers. */
	for (; i < argc; i++) {
		char *arg = argv[i];
		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;
		if (!strcmp(arg, "-p")) continue;
		__util_diagf("time: %s: invalid option\n", arg);
		return 1;
	}

	if (i >= argc) {
		__util_diagf("time: missing operand\n");
		return 1;
	}

	resolved = __find_program(argv[i], 1);
	if (!resolved) {
		__util_diagf("time: %s: command not found\n", argv[i]);
		return 127;
	}

	/* Bracket the actual spawn/wait as tightly as possible so neither
	 * reading includes this file's own option-parsing/PATH-search
	 * overhead. */
	(void)getrusage(RUSAGE_CHILDREN, &ru0);
	(void)clock_gettime(CLOCK_MONOTONIC, &real0);
	pid = __spawn(resolved, &argv[i], environ);
	/* Captured before free(): __spawn()'s own errno is the only thing
	 * that distinguishes "found but not executable" (126) from "not
	 * really found after all" (127, e.g. a race, or -- as here --
	 * __find_program() taking an explicit path/drive-letter name on
	 * faith without itself checking existence, see find_program.c's
	 * has_dir() branch) -- and nothing between here and the check below
	 * is documented not to disturb errno on the success path, so the
	 * read has to happen immediately. */
	spawn_errno = errno;
	free(resolved);
	if (pid < 0) {
		__util_diagf("time: %s: %s\n", argv[i], strerror(spawn_errno));
		return spawn_errno == ENOENT ? 127 : 126;
	}
	if (waitpid(pid, &status, 0) < 0) {
		__util_diagf("time: %s\n", strerror(errno));
		return 1;
	}
	(void)clock_gettime(CLOCK_MONOTONIC, &real1);
	(void)getrusage(RUSAGE_CHILDREN, &ru1);

	rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);

	/* XCU time(1p)'s own pinned -p format, applied unconditionally --
	 * see this file's header comment for why. Bare %f (six digits
	 * after the radix character by default) comfortably satisfies "at
	 * least one digit", the standard's only floor. */
	if (fprintf(stderr, "real %f\nuser %f\nsys %f\n",
		    ts_diff(real0, real1),
		    tv_diff(ru0.ru_utime, ru1.ru_utime),
		    tv_diff(ru0.ru_stime, ru1.ru_stime)) < 0) {
		/* A diagnostic failing here has no more useful status to
		 * report than the utility's own real exit status, already
		 * computed above -- the same "the primary outcome remains
		 * authoritative" reasoning __util_diagf() itself documents. */
	}

	return rc;
}
