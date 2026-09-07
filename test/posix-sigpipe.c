/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * SIGPIPE on a broken pipe: the disposition, and the shape of the death.
 *
 * https://pubs.opengroup.org/onlinepubs/9799919799/functions/write.html
 * https://pubs.opengroup.org/onlinepubs/9799919799/functions/fflush.html
 * https://pubs.opengroup.org/onlinepubs/9799919799/functions/_Exit.html
 * https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html
 *
 * WHY THIS FILE EXISTS, which is a specific bug and not a survey.
 *
 * write.html ERRORS: "[EPIPE] An attempt is made to write to a pipe or
 * FIFO that is not open for reading by any process, or that has only one
 * end open. A SIGPIPE signal shall also be sent to the thread."  spicule
 * implements both halves -- src/unistd/write.c turns STATUS_PIPE_BROKEN
 * (0xC00000B1, read directly out of NtWriteFile, not inferred back
 * through the many-to-one map in src/internal/errno.c) into
 * __raise_internal(SIGPIPE) and then [EPIPE].
 *
 * The bug this file fences was in what happened NEXT.  SIGPIPE's default
 * action is to terminate (src/signal/signal.c's default_action()), and
 * that path called __stdio_exit() to flush before dying.  When the
 * stream being flushed WAS the broken pipe, the flush re-entered:
 *
 *     fflush(f) -> write() -> STATUS_PIPE_BROKEN -> __raise_internal(SIGPIPE)
 *               -> terminate -> __stdio_exit() -> fflush(f) -> ...
 *
 * because the buffer the second pass tried to drain had never been
 * drained -- the write that would have emptied it did not return.  That
 * is unbounded recursion.  Measured: ~1 MB of stack, then
 * EXCEPTION_STACK_OVERFLOW (0xC00000FD).
 *
 * THE ASSERTION THAT MATTERS IS THE EXIT STATUS, NOT THE DEATH.  Both
 * the broken and the fixed library end the process here; a test that
 * only checked "the child died" passes on the broken build.  What the
 * overflow destroyed was the __ENCODE_SIGNAL_EXIT(SIGPIPE) the child should
 * have exited with, so the parent saw a *clean exit 0* -- a crashed
 * program reporting success to whatever built it.  So every case below
 * asserts the decoded status exactly, and the two failure shapes that
 * were actually observed (exited-0, and death by SIGSEGV) are called out
 * by name rather than left to a bare inequality.
 *
 * Note EXCEPTION_STACK_OVERFLOW is one of the codes
 * src/process/wait.c's __wait_encode_status() decodes to SIGSEGV.  If
 * the overflow ever does reach the parent as the child's exit code --
 * it did not under Wine, which is itself a divergence worth knowing --
 * waitpid() reports this as a segmentation fault.  That is the shape a
 * `cc1 | as` pipeline under gcc -pipe would present as "cc1 segfaulted".
 *
 * THE SIG_IGN CONTROL IS PART OF THE TEST, deliberately.  It is what
 * isolates the disposition as the cause rather than pipes-in-general:
 * the identical fflush() with SIGPIPE ignored must return -1/[EPIPE] and
 * the process must survive.  Without it a future change could break the
 * re-entrancy guard while every "it died correctly" case stayed green.
 *
 * Not a *-win.c file: __spawn() works under Wine (only
 * RtlCloneUserProcess/fork does not), so all of this runs on the Wine
 * leg as well as the real-Windows one.
 */
/* fdopen() is feature-test gated in include/stdio.h; same define most
 * other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

extern char **environ;
extern int __spawn(const char *, char *const *, char *const *);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* An exit code no path below produces on purpose, so "the child ran off
 * the end of a case that should not have returned" is distinguishable
 * from every real outcome instead of looking like a pass. */
#define SURVIVED_EXIT 70

/* ------------------------------------------------------------------ *
 * Child scenarios.  Each is entered by re-executing this same binary
 * with a marker argument; the parent adjudicates the exit status.
 * ------------------------------------------------------------------ */

/* Unbuffered: write() straight at a pipe with no reader.  This path
 * never recursed -- there is no buffered stream for __stdio_exit() to
 * re-flush -- so it is the control for "an orderly SIGPIPE death", and
 * it must keep working after the fix. */
static int child_write_default(void)
{
	int p[2];
	if (pipe(p) < 0) return 71;
	if (close(p[0]) < 0) return 72;
	(void)write(p[1], "hello", 5);
	return SURVIVED_EXIT;      /* must not be reached */
}

/* Buffered: the regression case.  Nothing reaches the pipe until the
 * flush, so the flush is what takes STATUS_PIPE_BROKEN, and the stream
 * it is inside of is the one __stdio_exit() then tries to flush again. */
static int child_flush_default(void)
{
	int p[2];
	FILE *f;
	int i;

	if (pipe(p) < 0) return 71;
	f = fdopen(p[1], "w");
	if (!f) return 73;
	if (setvbuf(f, 0, _IOFBF, 4096) != 0) return 74;
	for (i = 0; i < 200; i++) fputs("0123456789", f);
	if (close(p[0]) < 0) return 72;
	(void)fflush(f);
	return SURVIVED_EXIT;      /* must not be reached */
}

/* The control: same buffered flush, SIGPIPE ignored.  write.html's
 * [EPIPE] is what is left once the signal is not fatal, and fflush.html
 * RETURN VALUE gives EOF with errno set for a write error. */
static int child_flush_ignored(void)
{
	int p[2];
	FILE *f;
	int i, rc;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 75;
	if (pipe(p) < 0) return 71;
	f = fdopen(p[1], "w");
	if (!f) return 73;
	if (setvbuf(f, 0, _IOFBF, 4096) != 0) return 74;
	for (i = 0; i < 200; i++) fputs("0123456789", f);
	if (close(p[0]) < 0) return 72;

	errno = 0;
	rc = fflush(f);
	if (rc != EOF) return 76;
	if (errno != EPIPE) return 77;
	return 0;                  /* survived, which is the point */
}

/* ------------------------------------------------------------------ *
 * Parent side.
 * ------------------------------------------------------------------ */

static int run_child(const char *self, const char *mode, int *status)
{
	char *argv[3];
	int pid;

	argv[0] = (char *)self;
	argv[1] = (char *)mode;
	argv[2] = 0;
	pid = __spawn(self, argv, environ);
	if (pid < 0) return -1;
	if (waitpid(pid, status, 0) != pid) return -1;
	return 0;
}

/* Report the status in words, so a failure says what actually happened
 * rather than only that an assertion did not hold. */
static void describe(const char *what, int status)
{
	if (WIFEXITED(status))
		printf("    %s: exited %d\n", what, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("    %s: killed by signal %d\n", what, WTERMSIG(status));
	else
		printf("    %s: raw status 0x%x\n", what, (unsigned)status);
}

static void expect_sigpipe_death(const char *self, const char *mode, const char *what)
{
	int status = 0;

	if (run_child(self, mode, &status) < 0) { CHECK(0 && "spawn/waitpid failed"); return; }
	describe(what, status);

	/* The clause: 2.4.3 Signal Actions -- "the process is terminated as
	 * if by a call to _exit(), except that the status made available to
	 * wait(), waitid(), and waitpid() indicates abnormal termination by
	 * the signal." */
	CHECK(WIFSIGNALED(status));
	if (WIFSIGNALED(status)) CHECK(WTERMSIG(status) == SIGPIPE);

	/* The two shapes the broken library actually produced, named so a
	 * regression reads as itself instead of as a generic mismatch. */
	CHECK(!(WIFEXITED(status) && WEXITSTATUS(status) == 0));       /* crash reported success */
	CHECK(!(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV));  /* stack overflow */
	CHECK(!(WIFEXITED(status) && WEXITSTATUS(status) == SURVIVED_EXIT));
}

static void test_write_default_disposition_kills(const char *self)
{
	expect_sigpipe_death(self, "--child-write-default", "unbuffered write()");
}

static void test_flush_default_disposition_kills_without_recursing(const char *self)
{
	expect_sigpipe_death(self, "--child-flush-default", "buffered fflush()");
}

static void test_flush_with_sigpipe_ignored_reports_epipe(const char *self)
{
	int status = 0;

	if (run_child(self, "--child-flush-ignored", &status) < 0) { CHECK(0 && "spawn/waitpid failed"); return; }
	describe("buffered fflush(), SIGPIPE ignored", status);

	CHECK(WIFEXITED(status));
	if (WIFEXITED(status)) CHECK(WEXITSTATUS(status) == 0);
}

/* In-process, no spawn: the [EPIPE] half of write.html's clause, which
 * is only observable once the signal is not fatal. */
static void test_write_epipe_when_ignored(void)
{
	int p[2];
	ssize_t n;
	void (*old)(int);

	old = signal(SIGPIPE, SIG_IGN);
	CHECK(old != SIG_ERR);
	CHECK(pipe(p) == 0);
	if (p[0] < 0) { signal(SIGPIPE, old); return; }
	CHECK(close(p[0]) == 0);

	errno = 0;
	n = write(p[1], "hello", 5);
	CHECK(n == -1);
	CHECK(errno == EPIPE);

	close(p[1]);
	signal(SIGPIPE, old);
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		if (!strcmp(argv[1], "--child-write-default")) return child_write_default();
		if (!strcmp(argv[1], "--child-flush-default")) return child_flush_default();
		if (!strcmp(argv[1], "--child-flush-ignored")) return child_flush_ignored();
	}

	test_write_epipe_when_ignored();
	test_write_default_disposition_kills(argv[0]);
	test_flush_default_disposition_kills_without_recursing(argv[0]);
	test_flush_with_sigpipe_ignored_reports_epipe(argv[0]);

	if (fails) printf("posix-sigpipe: %d failure(s)\n", fails);
	else printf("posix-sigpipe: ok\n");
	return fails != 0;
}
