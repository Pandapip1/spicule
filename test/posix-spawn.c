/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <spawn.h> -- the _POSIX_SPAWN (SPN) option group.
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/spawn.h.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawn.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawn_file_actions_addclose.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawn_file_actions_addopen.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawn_file_actions_adddup2.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_init.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getflags.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getsigmask.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getpgroup.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getschedparam.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getschedpolicy.html
 *
 * This file is its own child: every spawn below re-runs this executable
 * with a command word, and the child reports what its inherited
 * descriptor table looks like down a pipe.  That is the only way to
 * check a file action at all -- the whole observable content of
 * posix_spawn_file_actions_t is what the *child* sees, so a test that
 * only inspected the object would be checking a struct, not a spawn.
 *
 * Two properties get more attention than the rest because they are the
 * two that are easy to get wrong and impossible to notice:
 *
 *   - Order.  DESCRIPTION: "The file actions ... shall be performed in
 *     the order in which they were added."  A replay that iterates the
 *     list backwards, or that resolves every source descriptor against
 *     the *original* table instead of the running one, passes any test
 *     with a single action in it.  test_order_two_targets() and
 *     test_order_chained() are built so that the reversed replay
 *     produces a *different, specific* answer rather than a broken one.
 *
 *   - errno.  RETURN VALUE: posix_spawn() and every accessor here
 *     "shall return zero; otherwise, an error number shall be returned
 *     to indicate the error" -- the error is the return value and errno
 *     is not written.  An implementation built on functions that all
 *     report through errno slips into returning -1, or into leaving
 *     errno set, almost by default, so errno is stamped with a sentinel
 *     before each failing call and checked afterwards.
 *
 * Nothing here forks: posix_spawn() is specified in terms of fork() but
 * is not required to use one, and __spawn() (src/process/spawn.c) never
 * does -- so, unlike test/fork*.c, this file runs under a stock Wine
 * with no RtlCloneUserProcess.  If the very first self-spawn fails
 * anyway, main() prints one SKIP line naming the mechanism and the
 * observed errno and exits 77 rather than reporting a pass over
 * assertions that never ran.
 */
/* setenv() and the sigprocmask()/sigemptyset()/sigaddset() family are
 * feature-test gated in include/stdlib.h and include/signal.h; same
 * define most other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include "test-policy.h"
#include <spawn.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>

extern char **environ;

static int fails;
/* Assertion groups this run could not exercise at all; see main(). */
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* A value errno is never set to by anything here, stamped in before a
 * call that must not touch it. */
#define ERRNO_SENTINEL 0x5eed

/* ---------------------------------------------------------------- */
/* The child half.                                                    */
/* ---------------------------------------------------------------- */

static void wr(int fd, const char *s) { (void)!write(fd, s, strlen(s)); }

/* argv[1] is the command word; the child exits 0 having done exactly
 * what it says, so a nonzero child status is itself an assertion
 * failure in the parent. */
static int child_main(int argc, char **argv)
{
	const char *cmd = argv[1];

	if (!strcmp(cmd, "w1")) { wr(1, argv[2]); return 0; }
	if (!strcmp(cmd, "w2")) { wr(2, argv[2]); return 0; }
	if (!strcmp(cmd, "both")) { wr(1, argv[2]); wr(2, argv[3]); return 0; }
	if (!strcmp(cmd, "probe")) {
		/* fcntl(F_GETFD) is the cheapest "is this descriptor open"
		 * question there is, and unlike a read or a write it neither
		 * consumes anything nor cares which way the descriptor faces. */
		int fd = atoi(argv[2]);
		wr(1, fcntl(fd, F_GETFD) >= 0 ? "open" : "closed");
		return 0;
	}
	if (!strcmp(cmd, "wfd")) {
		/* Writes through argv[2]'s OWN fd number, not through 1 or 2 --
		 * unlike "probe" (open/closed only), this is the only child
		 * command that proves a specific requested descriptor NUMBER is
		 * genuinely wired to the right open file description, not just
		 * present in the table -- see test_adddup2_above_two_real_fd(). */
		int fd = atoi(argv[2]);
		wr(fd, argv[3]);
		return 0;
	}
	if (!strcmp(cmd, "wfd2")) {
		/* Same idea as "wfd", but two independent above-2 targets in
		 * the same child -- see test_adddup2_two_above_two(), the case
		 * that actually exercises the generalized staging's own
		 * collision-avoidance pass (src/process/linux/plat_process.c's
		 * __plat_process_spawn()), which a single target can never
		 * reach. */
		int fda = atoi(argv[2]), fdb = atoi(argv[4]);
		wr(fda, argv[3]);
		wr(fdb, argv[5]);
		return 0;
	}
	if (!strcmp(cmd, "cat")) {
		char b[256];
		ssize_t n;
		while ((n = read(0, b, sizeof b)) > 0) (void)!write(1, b, (size_t)n);
		return 0;
	}
	if (!strcmp(cmd, "argv")) {
		int i;
		for (i = 2; i < argc; i++) { wr(1, argv[i]); wr(1, "|"); }
		return 0;
	}
	if (!strcmp(cmd, "sigmask")) {
		/* test_setsigmask_nonempty_is_delivered()'s own child: reports
		 * whether SIGINT is blocked from *inside* the process the mask
		 * was supposedly delivered to, rather than only inferring
		 * delivery from posix_spawn()'s own return value.  CHECK()
		 * would be pointless here -- this process's own `fails` is
		 * never read by anything, and child_main()'s return value,
		 * not `fails`, becomes the exit status the parent inspects
		 * (this file's own banner comment on child_main) -- so a
		 * query failure is reported the same way every other child
		 * failure here is, through that exit status. */
		sigset_t got;
		if (sigprocmask(SIG_BLOCK, 0, &got) != 0) return 1;
		wr(1, sigismember(&got, SIGINT) ? "blocked" : "unblocked");
		return 0;
	}
	if (!strcmp(cmd, "noop")) return 0;
	wr(2, "child: unknown command\n");
	return 1;
}

/* ---------------------------------------------------------------- */
/* Parent-side helpers.                                               */
/* ---------------------------------------------------------------- */

static const char *self;

/* Spawn self with up to three extra words, wait for it, and return the
 * bytes the child wrote to `readfd` (a pipe read end the caller has
 * already wired up through file actions).  `*rc` receives posix_spawn()'s
 * own return value.  `wend` is the pipe write end in the *parent*, which
 * must be closed before reading or the read never sees EOF. */
static void spawn_and_collect(int *rc, const posix_spawn_file_actions_t *fa,
                              const posix_spawnattr_t *at,
                              const char *a1, const char *a2, const char *a3,
                              int wend, int readfd, char *out, size_t outlen)
{
	char *argv[5];
	pid_t pid = -1;
	int status = -1, n = 0;
	ssize_t r;

	argv[n++] = (char *)self;
	argv[n++] = (char *)a1;
	if (a2) argv[n++] = (char *)a2;
	if (a3) argv[n++] = (char *)a3;
	argv[n] = 0;

	out[0] = 0;
	*rc = posix_spawn(&pid, self, fa, at, argv, environ);
	if (*rc != 0) { if (wend >= 0) close(wend); return; }
	if (wend >= 0) close(wend);
	if (readfd >= 0) {
		size_t got = 0;
		while (got + 1 < outlen && (r = read(readfd, out + got, outlen - 1 - got)) > 0)
			got += (size_t)r;
		out[got] = 0;
	}
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ---------------------------------------------------------------- */
/* posix_spawn_file_actions_* -- the recording half.                  */
/* ---------------------------------------------------------------- */

/* posix_spawn_file_actions_init.html RETURN VALUE, and each add*'s
 * ERRORS: "[EBADF] The value specified by fildes is negative or greater
 * than or equal to {OPEN_MAX}." */
static void test_file_actions_object(void)
{
	posix_spawn_file_actions_t fa;
	long openmax = sysconf(_SC_OPEN_MAX);
	int e;

	CHECK(posix_spawn_file_actions_init(&fa) == 0);

	errno = ERRNO_SENTINEL;
	CHECK(posix_spawn_file_actions_addclose(&fa, -1) == EBADF);
	CHECK(posix_spawn_file_actions_adddup2(&fa, -1, 1) == EBADF);
	CHECK(posix_spawn_file_actions_adddup2(&fa, 1, -1) == EBADF);
	CHECK(posix_spawn_file_actions_addopen(&fa, -1, "x", O_RDONLY, 0) == EBADF);
	if (openmax > 0 && openmax < 1000000L) {
		int too_big = (int)openmax;
		CHECK(posix_spawn_file_actions_addclose(&fa, too_big) == EBADF);
		CHECK(posix_spawn_file_actions_adddup2(&fa, 1, too_big) == EBADF);
		CHECK(posix_spawn_file_actions_addopen(&fa, too_big, "x", O_RDONLY, 0) == EBADF);
	}
	/* "an error number shall be returned to indicate the error" -- in
	 * the return value, so errno is left exactly as the caller had it. */
	e = errno;
	CHECK(e == ERRNO_SENTINEL);

	/* Valid additions, well past the initial capacity, to make sure the
	 * list actually grows instead of overwriting its last entry. */
	{
		int i;
		for (i = 0; i < 64; i++)
			CHECK(posix_spawn_file_actions_addclose(&fa, 3 + (i % 5)) == 0);
	}
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
	/* Destroy then re-init is how a caller reuses one object; a destroy
	 * that left the array pointer behind would double-free here. */
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_addopen(&fa, 3, "x", O_RDONLY, 0) == 0);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* posix_spawn_file_actions_addopen.html DESCRIPTION: "The string
 * described by path shall be copied by the
 * posix_spawn_file_actions_addopen() function" -- so overwriting the
 * caller's buffer afterwards must not change what gets opened. */
static void test_addopen_copies_path(void)
{
	posix_spawn_file_actions_t fa;
	char path[64];
	char got[64];
	int p[2], rc = -1, fd;

	fd = open("spawn-copy.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0);
	if (fd < 0) return;
	(void)!write(fd, "COPIED", 6);
	close(fd);

	strcpy(path, "spawn-copy.txt");
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_addopen(&fa, 0, path, O_RDONLY, 0) == 0);
	memset(path, 'Z', sizeof path - 1);   /* clobber the caller's buffer */
	path[sizeof path - 1] = 0;

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	spawn_and_collect(&rc, &fa, 0, "cat", 0, 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "COPIED"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
	unlink("spawn-copy.txt");
}

/* ---------------------------------------------------------------- */
/* posix_spawn() acting on file actions.                              */
/* ---------------------------------------------------------------- */

/* The common case, and the one GNU make's USE_POSIX_SPAWN path is built
 * on: adddup2() of a pipe end onto a standard descriptor. */
static void test_adddup2_stdout(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1;

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	spawn_and_collect(&rc, &fa, 0, "w1", "hello", 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "hello"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

static void test_adddup2_stderr(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1;

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 2) == 0);
	spawn_and_collect(&rc, &fa, 0, "w2", "onerr", 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "onerr"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* Regression test for a genuine Linux-backend bug in
 * src/process/linux/plat_process.c's __plat_process_spawn(): the raw
 * Linux fd number backing this process's OWN fd 0/1/2 is a completely
 * separate namespace from the small integer 0/1/2 a std[] slot is being
 * moved TO, and nothing kept those apart. The do_action() __SPAWN_DUP2
 * case (src/process/posix_spawn.c) creates the child's future fd 2 via
 * a plain dup(2) on the pipe's write end -- a NEW raw fd the kernel
 * hands back as the lowest currently free one. If the caller's own fd 0
 * happens to be closed right before the spawn, that lowest-free slot is
 * fd 0 itself, so the new descriptor backing (future) fd 2 could be raw
 * fd 0. The (once-buggy) child-side loop then processed target index 0
 * first -- std[0] is closed, so it issued a raw close(0) -- destroying
 * the very raw fd that target index 2 still needed as ITS OWN source;
 * dup3()'s return value was never checked, so that failure was silent:
 * execve() ran anyway and the child's real fd 2 came up as whatever it
 * already was (this test's own inherited stderr), not the pipe.
 *
 * This is exactly stderr redirection, closing fd 0 first is a common
 * and unremarkable thing for a real caller to do (e.g. a daemon or a
 * build tool feeding a child no stdin at all), and the resulting
 * failure was completely silent -- posix_spawn() itself still returned
 * 0. Confirmed against the unfixed backend with a standalone
 * reproducer before this test was added; confirmed fixed after. */
static void test_stderr_survives_closed_stdin(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1, saved_stdin;

	/* pipe() first, while fd 0 is still open, so p[0]/p[1] land above
	 * it as usual; fd 0 is freed only right before the spawn, so it is
	 * the lowest free raw fd exactly when the dup2 file action's own
	 * internal dup(2) runs. */
	CHECK(pipe(p) == 0);

	saved_stdin = dup(0);
	CHECK(saved_stdin >= 0);
	if (saved_stdin < 0) { close(p[0]); close(p[1]); return; }

	CHECK(close(0) == 0);

	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 2) == 0);
	spawn_and_collect(&rc, &fa, 0, "w2", "onerr", 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "onerr"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* Put the caller's own fd 0 back -- every test after this one in
	 * the same process still expects a real stdin. */
	CHECK(dup2(saved_stdin, 0) == 0);
	close(saved_stdin);
}

/* Order, part 1: two actions with the *same target*.  Whichever ran last
 * wins, so a replay in the wrong order sends the output down the other
 * pipe -- a specific wrong answer, not a crash. */
static void test_order_two_targets(void)
{
	posix_spawn_file_actions_t fa;
	char got[64], other[64];
	int p[2], q[2], rc = -1;
	ssize_t n;

	CHECK(pipe(p) == 0);
	CHECK(pipe(q) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, q[1], 1) == 0);
	/* q was added second, so the child's fd 1 is q's write end.  p[1]
	 * stays open here until the spawn is done: the recorded action
	 * names the descriptor by number and the replay resolves it at
	 * spawn time, so closing it first would fail the call with EBADF. */
	spawn_and_collect(&rc, &fa, 0, "w1", "LAST", 0, q[1], q[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "LAST"));
	/* ...and nothing at all went to p.  With both write ends now gone
	 * (the parent's here, the child's when it exited) this read returns
	 * 0 at EOF rather than blocking. */
	close(p[1]);
	other[0] = 0;
	n = read(p[0], other, sizeof other - 1);
	CHECK(n == 0);
	close(p[0]);
	close(q[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* Order, part 2: the second action's *source* is the first action's
 * target.  This is the one that separates "replay in order against the
 * running table" from "resolve every source against the original
 * table": only the former puts the child's fd 2 on the pipe. */
static void test_order_chained(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1;

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, 1, 2) == 0);
	spawn_and_collect(&rc, &fa, 0, "both", "A", "B", p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "AB"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* addclose of an ordinary inherited descriptor, and of fd 0.
 *
 * The fd 0 half is the one that touches src/process/spawn.c's banner:
 * a *closed* standard descriptor cannot be handed to the child as NULL
 * or as -1 (both were measured on real Windows to come back as a live
 * descriptor), so __spawn() passes a duplicated process pseudohandle
 * that the child's install_std() then refuses.  "closed" here is that
 * mechanism working end to end. */
static void test_addclose(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1, extra;

	extra = open("spawn-extra.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(extra >= 0);
	if (extra < 0) return;

	/* Baseline: with no addclose, `extra` is inherited and open. */
	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	{
		char num[16];
		sprintf(num, "%d", extra);
		spawn_and_collect(&rc, &fa, 0, "probe", num, 0, p[1], p[0], got, sizeof got);
		CHECK(rc == 0);
		CHECK(!strcmp(got, "open"));
		close(p[0]);
		CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

		/* Now the same spawn with the descriptor closed by an action. */
		CHECK(pipe(p) == 0);
		CHECK(posix_spawn_file_actions_init(&fa) == 0);
		CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
		CHECK(posix_spawn_file_actions_addclose(&fa, extra) == 0);
		spawn_and_collect(&rc, &fa, 0, "probe", num, 0, p[1], p[0], got, sizeof got);
		CHECK(rc == 0);
		CHECK(!strcmp(got, "closed"));
		close(p[0]);
		CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
	}

	/* And the standard-descriptor case. */
	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	CHECK(posix_spawn_file_actions_addclose(&fa, 0) == 0);
	spawn_and_collect(&rc, &fa, 0, "probe", "0", 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "closed"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* The parent's own descriptor is untouched by all of that: the
	 * actions were replayed on this table and undone again. */
	CHECK(fcntl(extra, F_GETFD) >= 0);
	close(extra);
	unlink("spawn-extra.txt");

	/* "as if close(fildes) had been called": closing a descriptor that
	 * is already closed leaves the child's postcondition already true,
	 * and is not reported as an error (glibc agrees).  fd 400 is used
	 * rather than the index just closed above, which the pipe() below
	 * would be entitled to hand straight back. */
	CHECK(fcntl(400, F_GETFD) < 0);
	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	CHECK(posix_spawn_file_actions_addclose(&fa, 400) == 0);
	spawn_and_collect(&rc, &fa, 0, "w1", "still-here", 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "still-here"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* addopen, both directions. */
static void test_addopen(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1, fd;
	int fd0_before, fd0_after;
	ssize_t n;

	/* fd 0 is borrowed as an action target twice below; whatever this
	 * process has there must be exactly the same afterwards. */
	fd0_before = fcntl(0, F_GETFD);

	fd = open("spawn-in.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0);
	if (fd < 0) return;
	(void)!write(fd, "FROMFILE", 8);
	close(fd);

	/* Read side: the child's fd 0 is the file. */
	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_addopen(&fa, 0, "spawn-in.txt", O_RDONLY, 0) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	spawn_and_collect(&rc, &fa, 0, "cat", 0, 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "FROMFILE"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* Write side: the child's fd 1 is a file it creates. */
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_addopen(&fa, 1, "spawn-out.txt",
	                                       O_WRONLY | O_CREAT | O_TRUNC, 0666) == 0);
	spawn_and_collect(&rc, &fa, 0, "w1", "TOFILE", 0, -1, -1, got, sizeof got);
	CHECK(rc == 0);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
	fd = open("spawn-out.txt", O_RDONLY);
	CHECK(fd >= 0);
	if (fd >= 0) {
		n = read(fd, got, sizeof got - 1);
		CHECK(n == 6);
		if (n > 0) { got[n] = 0; CHECK(!strcmp(got, "TOFILE")); }
		close(fd);
	}

	/* ERRORS: "an error value shall be returned as described by ...
	 * open()" -- a file action that cannot be performed fails the whole
	 * call, and no process is created. */
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_addopen(&fa, 0, "spawn-no-such-dir/x",
	                                       O_RDONLY, 0) == 0);
	{
		pid_t pid = (pid_t)-999;
		char *argv[3];
		argv[0] = (char *)self; argv[1] = (char *)"w1"; argv[2] = 0;
		errno = ERRNO_SENTINEL;
		rc = posix_spawn(&pid, self, &fa, 0, argv, environ);
		CHECK(rc == ENOENT);
		CHECK(errno == ERRNO_SENTINEL);
		CHECK(pid == (pid_t)-999);   /* untouched on failure */
	}
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* The parent's fd 0 survived being borrowed as an action target
	 * twice -- once successfully, once by a spawn that failed partway
	 * through the action list and still had to put it back. */
	fd0_after = fcntl(0, F_GETFD);
	CHECK(fd0_after == fd0_before);

	unlink("spawn-in.txt");
	unlink("spawn-out.txt");
}

/* adddup2(fd, fd): the descriptor stays open across the exec.  POSIX.1-2017
 * does not spell this case out, but its step 4 ("any file descriptor
 * that has its FD_CLOEXEC flag set shall be closed") is what makes
 * naming a descriptor as its own dup2 target mean anything at all, and
 * it is what glibc does with it. */
static void test_adddup2_self(void)
{
	posix_spawn_file_actions_t fa;
	char got[64], num[16];
	int p[2], rc = -1, cl;

	cl = open("spawn-cloexec.txt", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
	CHECK(cl >= 0);
	if (cl < 0) return;
	CHECK((fcntl(cl, F_GETFD) & FD_CLOEXEC) != 0);
	sprintf(num, "%d", cl);

	/* Baseline: a close-on-exec descriptor is not inherited. */
	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	spawn_and_collect(&rc, &fa, 0, "probe", num, 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "closed"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* Naming it as its own dup2 target clears that. */
	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, cl, cl) == 0);
	spawn_and_collect(&rc, &fa, 0, "probe", num, 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "open"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* ...in the child only. The parent's descriptor is still
	 * close-on-exec afterwards, which is the visible half of "the
	 * actions are replayed on this table and then undone". */
	CHECK((fcntl(cl, F_GETFD) & FD_CLOEXEC) != 0);
	close(cl);
	unlink("spawn-cloexec.txt");
}

/* An action naming a descriptor that is not open fails the call with
 * dup2()'s own error, and leaves the parent's table alone. */
static void test_adddup2_badfd(void)
{
	posix_spawn_file_actions_t fa;
	pid_t pid = (pid_t)-999;
	char *argv[3];
	int rc, spare;

	spare = open("spawn-spare.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(spare >= 0);
	if (spare < 0) return;
	close(spare);            /* now a valid index with nothing in it */

	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, spare, 1) == 0);
	argv[0] = (char *)self; argv[1] = (char *)"w1"; argv[2] = 0;
	errno = ERRNO_SENTINEL;
	rc = posix_spawn(&pid, self, &fa, 0, argv, environ);
	CHECK(rc == EBADF);
	CHECK(errno == ERRNO_SENTINEL);
	CHECK(pid == (pid_t)-999);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
	unlink("spawn-spare.txt");
}

/* The parent's descriptor table is byte-for-byte what it was: a
 * descriptor borrowed as a dup2 target still refers to the same open
 * file description, at the same offset, afterwards. */
static void test_parent_table_restored(void)
{
	posix_spawn_file_actions_t fa;
	char got[64];
	int p[2], rc = -1, keep;
	ssize_t n;

	keep = open("spawn-keep.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(keep >= 0);
	if (keep < 0) return;
	CHECK(write(keep, "ABCDEFGH", 8) == 8);
	CHECK(lseek(keep, 3, SEEK_SET) == 3);

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], keep) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	spawn_and_collect(&rc, &fa, 0, "w1", "ok", 0, p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "ok"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* Same descriptor, same file, same offset. */
	CHECK(lseek(keep, 0, SEEK_CUR) == 3);
	n = read(keep, got, 5);
	CHECK(n == 5);
	if (n == 5) { got[5] = 0; CHECK(!strcmp(got, "DEFGH")); }
	close(keep);
	unlink("spawn-keep.txt");
}

/* adddup2() to a target well above 2: not just "some fd is open" (every
 * other test above only ever checks fd 0/1/2, or -- test_parent_table_
 * restored()'s own "keep" -- that the PARENT's table survives, never
 * that the CHILD actually got the requested number) but genuinely wired
 * to the right open file description at EXACTLY the requested number.
 * This is the specific gap src/internal/linux/plat_fd_init.c's own
 * banner used to document by name: on Linux, a child inherits real
 * kernel descriptor NUMBERS, and do_action()'s own __plat_dup()
 * (posix_spawn.c) makes its duplicate at an arbitrary one, not
 * necessarily `newfd` -- so a test that only asked "is fd 5 open"
 * could pass by accident, on whatever real descriptor happened to
 * already occupy that number, without the redirect having reached the
 * child at all. Writing through it and reading the specific bytes back
 * on the parent's own pipe end is what rules that out. */
static void test_adddup2_above_two_real_fd(void)
{
	posix_spawn_file_actions_t fa;
	pid_t pid = (pid_t)-999;
	char *argv[5];
	int p[2], status = -1;
	char got[32];
	ssize_t n;

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 5) == 0);

	argv[0] = (char *)self; argv[1] = (char *)"wfd";
	argv[2] = (char *)"5"; argv[3] = (char *)"hello-fd5"; argv[4] = 0;
	CHECK(posix_spawn(&pid, self, &fa, 0, argv, environ) == 0);
	close(p[1]);

	n = read(p[0], got, sizeof got - 1);
	CHECK(n > 0);
	if (n > 0) { got[n] = 0; CHECK(!strcmp(got, "hello-fd5")); }

	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* Two independent above-2 targets in the SAME spawn -- a single target
 * can never exercise the generalized staging's own collision-avoidance
 * pass (src/process/linux/plat_process.c's __plat_process_spawn():
 * every live source at or below the highest target is staged out of
 * the target zone before any target is touched), since there is only
 * ever one source and one target to collide with each other.  Two
 * targets, each a fresh pipe, make a source/target collision at least
 * possible for the platform code to get wrong even if this particular
 * run does not happen to land on one -- what this test actually proves
 * either way is that both requested numbers work, independently and
 * simultaneously. */
static void test_adddup2_two_above_two(void)
{
	posix_spawn_file_actions_t fa;
	pid_t pid = (pid_t)-999;
	char *argv[7];
	int p[2], q[2], status = -1;
	char gp[32], gq[32];
	ssize_t n;

	/* Targets picked well clear of anything pipe() itself could have
	 * just handed back for p/q: a target that coincided with q[1]'s OWN
	 * real number would make the SECOND adddup2() below resolve its
	 * source against whatever the FIRST adddup2() had already
	 * overwritten that same table slot with -- correct per-action
	 * replay-order semantics (this file's own banner), not the
	 * collision this test means to exercise. */
	CHECK(pipe(p) == 0);
	CHECK(pipe(q) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 20) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, q[1], 30) == 0);

	argv[0] = (char *)self; argv[1] = (char *)"wfd2";
	argv[2] = (char *)"20"; argv[3] = (char *)"six";
	argv[4] = (char *)"30"; argv[5] = (char *)"nine";
	argv[6] = 0;
	CHECK(posix_spawn(&pid, self, &fa, 0, argv, environ) == 0);
	close(p[1]);
	close(q[1]);

	n = read(p[0], gp, sizeof gp - 1);
	CHECK(n > 0);
	if (n > 0) { gp[n] = 0; CHECK(!strcmp(gp, "six")); }
	n = read(q[0], gq, sizeof gq - 1);
	CHECK(n > 0);
	if (n > 0) { gq[n] = 0; CHECK(!strcmp(gq, "nine")); }

	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(p[0]);
	close(q[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);
}

/* ---------------------------------------------------------------- */
/* posix_spawnattr_*                                                  */
/* ---------------------------------------------------------------- */

/* Every accessor is storage: what went in comes back out.  Values are
 * deliberately ones this platform cannot act on, because that is
 * exactly what the accessors are still required to keep. */
static void test_attr_roundtrip(void)
{
	posix_spawnattr_t at;
	short flags = -1;
	pid_t pg = -1;
	sigset_t set, back;
	struct sched_param par, parback;
	int pol = -1, e;

	CHECK(posix_spawnattr_init(&at) == 0);

	/* posix_spawnattr_init.html: the object gets "the default values",
	 * and the default spawn-flags is no flag set -- nothing else in the
	 * object is consulted unless a flag says so. */
	CHECK(posix_spawnattr_getflags(&at, &flags) == 0);
	CHECK(flags == 0);

	errno = ERRNO_SENTINEL;
	CHECK(posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF) == 0);
	CHECK(posix_spawnattr_getflags(&at, &flags) == 0);
	CHECK(flags == (POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF));

	CHECK(posix_spawnattr_setpgroup(&at, 12345) == 0);
	CHECK(posix_spawnattr_getpgroup(&at, &pg) == 0);
	CHECK(pg == 12345);

	CHECK(sigemptyset(&set) == 0);
	CHECK(sigaddset(&set, SIGINT) == 0);
	CHECK(sigaddset(&set, SIGTERM) == 0);
	CHECK(posix_spawnattr_setsigmask(&at, &set) == 0);
	CHECK(posix_spawnattr_getsigmask(&at, &back) == 0);
	CHECK(sigismember(&back, SIGINT) == 1);
	CHECK(sigismember(&back, SIGTERM) == 1);
	CHECK(sigismember(&back, SIGUSR1) == 0);

	CHECK(sigemptyset(&set) == 0);
	CHECK(sigaddset(&set, SIGUSR1) == 0);
	CHECK(posix_spawnattr_setsigdefault(&at, &set) == 0);
	CHECK(posix_spawnattr_getsigdefault(&at, &back) == 0);
	CHECK(sigismember(&back, SIGUSR1) == 1);
	CHECK(sigismember(&back, SIGINT) == 0);
	/* ...and setting sigdefault did not disturb sigmask. */
	CHECK(posix_spawnattr_getsigmask(&at, &back) == 0);
	CHECK(sigismember(&back, SIGINT) == 1);

	/* Scheduling: stored faithfully even though posix_spawn() will
	 * refuse to act on it (see the flag tests below).  A setter that
	 * refused the value would break a caller that only reads it back,
	 * and POSIX gives it no error to refuse with. */
	par.sched_priority = 42;
	CHECK(posix_spawnattr_setschedparam(&at, &par) == 0);
	parback.sched_priority = -1;
	CHECK(posix_spawnattr_getschedparam(&at, &parback) == 0);
	CHECK(parback.sched_priority == 42);

	CHECK(posix_spawnattr_setschedpolicy(&at, 7) == 0);
	CHECK(posix_spawnattr_getschedpolicy(&at, &pol) == 0);
	CHECK(pol == 7);

	/* None of that touched errno: every one of these returns an error
	 * number, and none of them failed. */
	e = errno;
	CHECK(e == ERRNO_SENTINEL);

	CHECK(posix_spawnattr_destroy(&at) == 0);
}

/* Spawn with `flags` (and optionally a signal set / pgroup) set, and
 * hand back posix_spawn()'s return value.  Reaps the child when one was
 * made, so a flag that is honoured does not leave a process behind. */
static int spawn_with_flags(short flags, const sigset_t *mask, const pid_t *pgroup)
{
	posix_spawnattr_t at;
	posix_spawn_file_actions_t fa;
	pid_t pid = (pid_t)-999;
	char *argv[4];
	int rc, p[2], status;
	char buf[16];

	if (pipe(p) != 0) return -1;
	posix_spawnattr_init(&at);
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, p[1], 1);
	if (mask) posix_spawnattr_setsigmask(&at, mask);
	if (pgroup) posix_spawnattr_setpgroup(&at, *pgroup);
	posix_spawnattr_setflags(&at, flags);

	argv[0] = (char *)self; argv[1] = (char *)"w1"; argv[2] = (char *)"f"; argv[3] = 0;
	errno = ERRNO_SENTINEL;
	rc = posix_spawn(&pid, self, &fa, &at, argv, environ);
	/* Whether it succeeded or was refused, the answer came back in the
	 * return value and errno was left alone. */
	CHECK(errno == ERRNO_SENTINEL);
	close(p[1]);
	if (rc == 0) {
		(void)!read(p[0], buf, sizeof buf);
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	} else {
		CHECK(pid == (pid_t)-999);
	}
	close(p[0]);
	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&at);
	return rc;
}

/* Which spawn-flags posix_spawn() can act on, and what it does with the
 * ones it cannot.  Each rejection is checked against the error POSIX's
 * own ERRORS section routes that flag to -- not merely against
 * "nonzero" -- because the point is that a portable caller gets the
 * failure it is already written to handle. */
static void test_attr_flags_acted_on(void)
{
	sigset_t empty, one;
	pid_t pg;

	CHECK(sigemptyset(&empty) == 0);
	CHECK(sigemptyset(&one) == 0);
	CHECK(sigaddset(&one, SIGINT) == 0);

	/* Honoured, and satisfied by construction: a fresh NT process runs
	 * its own crt1, whose signal state (src/signal/signal.c statics) is
	 * an empty mask and SIG_DFL everywhere. */
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSIGDEF, 0, 0) == 0);
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSIGMASK, &empty, 0) == 0);
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK, &empty, 0) == 0);
	/* RESETIDS: an NT token has no real/effective/saved triple to
	 * reset, so the postcondition holds unconditionally. */
	CHECK(spawn_with_flags(POSIX_SPAWN_RESETIDS, 0, 0) == 0);
	/* USEVFORK is not POSIX; __spawn() never copies the parent's
	 * address space, which is the whole of what it asks for. */
	CHECK(spawn_with_flags(POSIX_SPAWN_USEVFORK, 0, 0) == 0);

	/* A mask that is not empty: delivered for real on NT, through the
	 * RuntimeData trailer __spawn_set_pending_sigmask()'s own comment
	 * (src/internal/libc.h) describes -- test_setsigmask_nonempty_is_
	 * delivered() below exercises the same flag/mask pair and is the
	 * fence for that mechanism, not this baseline. Still refused on
	 * Linux, where nothing has built or verified an equivalent: ERRORS'
	 * "[EINVAL] The value specified by file_actions or attrp is
	 * invalid" is the only channel POSIX gives this flag to refuse
	 * through. */
#if defined(__linux__)
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSIGMASK, &one, 0) == EINVAL);
#else
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSIGMASK, &one, 0) == 0);
#endif

	/* SETSCHEDPARAM/SETSCHEDULER: applied on NT (best-effort, via the
	 * same suspended-process window, see
	 * __spawn_set_pending_priority()'s own comment) since NT's own
	 * lack of a POSIX scheduling policy no longer means nothing can be
	 * done with sched_priority, only that nothing has a specified
	 * mapping onto it -- see nice_from_sched_priority() (posix_spawn.c)
	 * for the one used.  Still refused on Linux with ERRORS' "[EINVAL]
	 * The value of the policy parameter is invalid", which -- unlike
	 * NT -- is not an honest answer to a real POSIX scheduling policy
	 * existing there; it just is not one this platform's own posix_
	 * spawn() has built or verified applying yet.  (Issue 6 deleted
	 * [ENOSYS] from sched_setscheduler(), so EINVAL is the specified
	 * shape where refused at all.) */
#if defined(__linux__)
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSCHEDPARAM, 0, 0) == EINVAL);
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSCHEDULER, 0, 0) == EINVAL);
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER, 0, 0) == EINVAL);
#else
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSCHEDPARAM, 0, 0) == 0);
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSCHEDULER, 0, 0) == 0);
	CHECK(spawn_with_flags(POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER, 0, 0) == 0);
#endif

	/* SETPGROUP: the only process group this platform can put a child
	 * in is the one every process is born into (src/unistd/ids.c's
	 * banner), so asking for the caller's own group -- which this
	 * process has not moved out of -- is already true of the child, and
	 * asking for any other -- 0 included, which means "a new group of
	 * the child's own" -- is refused with setpgid()'s "[EINVAL] ... not
	 * a value supported by the implementation". */
	pg = getpgrp();
	CHECK(spawn_with_flags(POSIX_SPAWN_SETPGROUP, 0, &pg) == 0);
	pg = 0;
	CHECK(spawn_with_flags(POSIX_SPAWN_SETPGROUP, 0, &pg) == EINVAL);
	pg = 999;
	CHECK(spawn_with_flags(POSIX_SPAWN_SETPGROUP, 0, &pg) == EINVAL);

	/* A bit that is not a flag at all. */
	CHECK(spawn_with_flags((short)0x1000, 0, 0) == EINVAL);
}

/* ---------------------------------------------------------------- */
/* posix_spawn vs posix_spawnp                                        */
/* ---------------------------------------------------------------- */

/* "The posix_spawnp() function shall be equivalent to posix_spawn()
 * except that ... the file parameter shall be used to construct a
 * pathname that identifies the new process image file ... using the
 * PATH environment variable"; posix_spawn() never searches. */
static void test_spawnp_path_search(void)
{
	char dir[512], base[256];
	const char *slash;
	posix_spawn_file_actions_t fa;
	pid_t pid = (pid_t)-999;
	char *argv[4];
	char got[64];
	int p[2], rc, status;
	size_t n;

	{
		const char *fs = strrchr(self, '/'), *bs = strrchr(self, '\\');
		slash = fs > bs ? fs : bs;   /* NULL sorts lowest */
	}
	if (!slash) {
		printf("SKIP posix-spawn PATH-search tests (argv[0]=\"%s\" has no "
		       "directory part, so this executable's directory is unknown "
		       "and there is nothing to put on PATH)\n", self);
		unverified++;
		return;
	}
	n = (size_t)(slash - self);
	if (n >= sizeof dir) { unverified++; return; }
	memcpy(dir, self, n);
	dir[n] = 0;
	if (strlen(slash + 1) >= sizeof base) { unverified++; return; }
	strcpy(base, slash + 1);

	/* src/process/find_program.c splits PATH on ';', not ':' -- an
	 * absolute Windows entry contains a colon of its own. */
	CHECK(setenv("PATH", dir, 1) == 0);

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	argv[0] = base; argv[1] = (char *)"w1"; argv[2] = (char *)"viaPATH"; argv[3] = 0;
	rc = posix_spawnp(&pid, base, &fa, 0, argv, environ);
	CHECK(rc == 0);
	close(p[1]);
	got[0] = 0;
	if (rc == 0) {
		ssize_t r = read(p[0], got, sizeof got - 1);
		if (r > 0) got[r] = 0;
		CHECK(!strcmp(got, "viaPATH"));
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* The same bare name through posix_spawn(), which does no search:
	 * the file is on PATH and nowhere near the working directory, so
	 * this must fail. */
	pid = (pid_t)-999;
	errno = ERRNO_SENTINEL;
	rc = posix_spawn(&pid, base, 0, 0, argv, environ);
	CHECK(rc == ENOENT);
	CHECK(errno == ERRNO_SENTINEL);

	/* posix_spawnp() with a name that has a directory part does not
	 * search either, and a name that is nowhere on PATH fails. */
	pid = (pid_t)-999;
	errno = ERRNO_SENTINEL;
	rc = posix_spawnp(&pid, "no-such-program-anywhere", 0, 0, argv, environ);
	CHECK(rc == ENOENT);
	CHECK(errno == ERRNO_SENTINEL);
}

/* ERRORS, plus the errno rule, on the plainest failure there is. */
static void test_enoent_and_errno(void)
{
	pid_t pid = (pid_t)-999;
	char *argv[2];
	int rc;

	argv[0] = (char *)"no-such-program"; argv[1] = 0;
	errno = ERRNO_SENTINEL;
	rc = posix_spawn(&pid, "spawn-no-such-dir/no-such-program", 0, 0, argv, environ);
	CHECK(rc == ENOENT);
	/* "an error number shall be returned as the function value to
	 * indicate the error" -- posix_spawn() reports through the return
	 * value only, and does not set errno. */
	CHECK(errno == ERRNO_SENTINEL);
	CHECK(pid == (pid_t)-999);
}

/* argv reaches the child intact, and a NULL file_actions/attrp pair is
 * the documented "no actions, default attributes" case. */
static void test_null_actions_and_argv(void)
{
	posix_spawn_file_actions_t fa;
	char got[128];
	int p[2], rc = -1;

	CHECK(pipe(p) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	spawn_and_collect(&rc, &fa, 0, "argv", "one two", "three\"four", p[1], p[0], got, sizeof got);
	CHECK(rc == 0);
	CHECK(!strcmp(got, "one two|three\"four|"));
	close(p[0]);
	CHECK(posix_spawn_file_actions_destroy(&fa) == 0);

	/* Both objects NULL: no actions, default attributes.  The child
	 * inherits this process's stdout, so it is told to write nothing. */
	{
		pid_t pid = (pid_t)-1;
		char *argv[4];
		int status;
		argv[0] = (char *)self; argv[1] = (char *)"w1"; argv[2] = (char *)""; argv[3] = 0;
		CHECK(posix_spawn(&pid, self, 0, 0, argv, environ) == 0);
		CHECK(pid > 0);
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
}

/* ---------------------------------------------------------------- */

#if SPICULE_TEST(PASS, posix_spawn_setsigmask_nonempty_is_delivered) /* was BUG (formerly UNIMPL): posix_spawn.html DESCRIPTION -- POSIX_SPAWN_SETSIGMASK
	with a *non-empty* mask.  Needs the parent to hand initial signal
	state to a child that has not executed an instruction yet.

	test/posix-dl.c's fence for this pair used to say there was "no
	channel to hand a chosen initial mask/disposition to a child".
	That was already half wrong when this fence was still UNIMPL:
	RTL_USER_PROCESS_PARAMETERS' RuntimeData *is* such a channel, it is
	packed into the parameters block by RtlCreateProcessParametersEx
	(src/process/spawn.c) and read back by __fd_init before main(), and
	test/spawn-runtimedata-stress.c exercises it hard enough to have
	caught a dangling-pointer bug in it.

	What was missing was a format and a reader -- now built:
	src/internal/nt/plat_fd_init.c appends an spicule-specific trailer
	(SIG_RUNTIME_MAGIC) past the msvcrt-compatible osfile/osfhnd table
	and its own optional VFS trailer, carrying the mask
	src/process/posix_spawn.c's spawn_common() staged through
	__spawn_set_pending_sigmask() (src/internal/libc.h) immediately
	before calling __spawn().  __fd_init() decodes it and calls
	__sig_current_mask_install() before __signal_init() or main() ever
	run, so the mask is live before the child's first instruction that
	could observe it.

	Still not equivalent to POSIX's promise in the one respect
	src/process/posix_spawn.c's own banner records: on POSIX the kernel
	carries the mask across exec, so it applies to *any* image; this
	trailer reaches an spicule-built child only.  That does not matter
	to this fence -- self is always spicule-built -- but is why
	POSIX_SPAWN_SETSIGMASK is still refused with EINVAL on the Linux
	backend rather than given a from-scratch equivalent nothing here
	has verified (test_attr_flags_acted_on's own #if defined(__linux__)
	split, above).

	VERIFICATION: code-reviewed, not run.  This project's Wine is
	broken in the sandbox that produced this fix, so the NT test binary
	this fence lives in could not be executed; the trailer's byte
	offsets were hand-traced against __fd_runtime_data()'s writer and
	__fd_init()'s reader (src/internal/nt/plat_fd_init.c) rather than
	confirmed by running either. */
static void test_setsigmask_nonempty_is_delivered(void)
{
	posix_spawnattr_t at;
	posix_spawn_file_actions_t fa;
	sigset_t m;
	pid_t pid;
	int p[2], status;
	char buf[16];
	size_t got = 0;
	ssize_t r;

	CHECK(sigemptyset(&m) == 0);
	CHECK(sigaddset(&m, SIGINT) == 0);
	CHECK(pipe(p) == 0);
	CHECK(posix_spawnattr_init(&at) == 0);
	CHECK(posix_spawn_file_actions_init(&fa) == 0);
	CHECK(posix_spawn_file_actions_adddup2(&fa, p[1], 1) == 0);
	CHECK(posix_spawnattr_setsigmask(&at, &m) == 0);
	CHECK(posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK) == 0);

	{
		char *argv[3];
		argv[0] = (char *)self; argv[1] = (char *)"sigmask"; argv[2] = 0;
		CHECK(posix_spawn(&pid, self, &fa, &at, argv, environ) == 0);
	}
	close(p[1]);
	buf[0] = 0;
	while (got + 1 < sizeof buf && (r = read(p[0], buf + got, sizeof buf - 1 - got)) > 0)
		got += (size_t)r;
	buf[got] = 0;
	close(p[0]);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* The mechanism this fence is about: a mask observed from *inside*
	 * the child itself, not merely inferred from posix_spawn()'s own
	 * success. */
	CHECK(!strcmp(buf, "blocked"));

	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&at);
}
#endif

#if SPICULE_TEST(NA, posix_spawn_setpgroup_other_group) /* N/A: posix_spawn.html DESCRIPTION -- POSIX_SPAWN_SETPGROUP with
	a spawn-pgroup naming some *other* process's group.
	
	The mechanism previously recorded here -- "NT has no process-group
	object in the POSIX sense: a job object groups processes for
	resource limits, not for job-control signal delivery" -- is false,
	and job objects are the wrong object to compare against.  NT does
	have process groups, and they exist for exactly the purpose the
	old reason said they did not: console process groups.  Per
	GenerateConsoleCtrlEvent (learn.microsoft.com/en-us/windows/
	console/generateconsolectrlevent, "Parameters"): "A process group
	is created when the CREATE_NEW_PROCESS_GROUP flag is specified in
	a call to the CreateProcess function.  The process identifier of
	the new process is also the process group identifier of a new
	process group", and CTRL_BREAK_EVENT is delivered to a named
	dwProcessGroupId -- job-control signal delivery to a group,
	precisely.

	The verdict survives on the *correct* mechanism, which is a
	narrower and more specific fact: console process-group membership
	is fixed by descent from the group root at creation time.  The
	same page: "The process group includes all processes that are
	descendants of the root process."  There is no NT call that places
	a process into a pre-existing group it is not a descendant of, and
	no group id is chooseable -- it is always the root process's own
	pid.  So a child cannot be spawned into some *other* process's
	group, and there is nothing to observe a placement against.

	Note what this does NOT excuse: spicule's own group model
	(src/unistd/ids.c answers getpgrp()/getpgid() with a fixed 1 for
	every process, setpgid() is a no-op) is a choice, not a
	consequence of the platform, since a group concept does exist to
	be modelled on.  Only the join-another-group clause fenced here is
	genuinely unreachable.  posix_spawn() refuses any spawn-pgroup but
	the one group it models (asserted above).

	INFERRED from Microsoft's documented console API, not measured: the
	blocker is the shape of the API surface (no call takes a target
	group id at process creation other than "make me a new root"), so
	no run of any binary could refute it. */
static void test_setpgroup_other_group(void)
{
	posix_spawnattr_t at;
	pid_t pid;
	char *argv[2];
	posix_spawnattr_init(&at);
	posix_spawnattr_setpgroup(&at, 4242);
	posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP);
	argv[0] = (char *)self; argv[1] = 0;
	CHECK(posix_spawn(&pid, self, 0, &at, argv, environ) == 0);
	CHECK(getpgid(pid) == 4242);
}
#endif

#if SPICULE_TEST(PASS, posix_spawn_setschedparam_applied) /* was BUG (formerly UNIMPL): posix_spawn.html DESCRIPTION --
	POSIX_SPAWN_SETSCHEDULER/POSIX_SPAWN_SETSCHEDPARAM actually being
	applied.  NT mechanism, already half-built by accident: __spawn()
	creates the process *suspended* (RtlCreateUserProcess followed by a
	separate NtResumeThread, src/process/nt/plat_process.c), so there
	was already a real window before the child's first instruction in
	which a priority could be set on info.Process -- no kernel32
	needed.  Now used: __plat_priority_set(info.Process, 0, nice_value)
	in that window, the identical call src/misc/resource.c's own
	setpriority() makes for a non-self target, driven by a value
	spawn_common() stages through __spawn_set_pending_priority()
	(src/internal/libc.h) immediately before __spawn().

	The POSIX shape still does not survive the translation, and that
	part of the old UNIMPL reasoning was never wrong: NT has priorities
	but no SCHED_FIFO/SCHED_RR/SCHED_OTHER policy distinction, so
	sched_setscheduler()'s policy argument has no valid value here and
	<sched.h> deliberately does not claim the
	_POSIX_PRIORITY_SCHEDULING option group at all.  Mapping
	sched_priority onto an NT priority class is still an invention with
	a POSIX name on it -- nice_from_sched_priority() (posix_spawn.c)
	admits as much -- but an admitted, applied invention is what this
	fence asks for now (test-policy.py's own compiles-and-fails-vs-
	does-not-compile split leaves no UNIMPL disposition for a present,
	acted-on interface), not a rejection.  `policy` itself is still
	accepted unconditionally, whatever value it holds; only
	sched_priority is mapped and applied.

	VERIFICATION: code-reviewed, not run -- this project's Wine is
	broken in the sandbox that produced this fix, so this fence's NT
	test binary could not be executed.  Checked by reading
	src/process/nt/plat_process.c's suspended-window ordering (the
	priority is set before NtResumeThread, never after) and
	src/misc/resource.c's own __plat_priority_get() path for a non-self
	pid, which this test's own assertion below reuses to observe the
	real NT priority class rather than the self_nice cache
	getpriority(PRIO_PROCESS, 0) would report for a target that is not
	self.

	A later real Wine-hosted `make check` run reported this fence
	STALE (PASS produced TIMEOUT), diagnosed from source as a bug in
	this TEST, not in posix_spawn(): the child below used to be spawned
	with argv = {self, NULL}, giving it argc == 1 -- missing
	child_main()'s `argc > 1` dispatch and falling into main()'s
	top-level flow instead, which tools/test-policy.py's isolated-probe
	transform makes call this very function again before its own final
	verdict, regardless of argc.  Each such child spawned another just
	like it: unbounded recursive self-spawning, each level paying real
	Wine process-creation cost, is what timed out.  Fixed by giving the
	child a "noop" argv[1] so it dispatches into child_main() and exits
	at once, like every other child in this file.

	A later CI run (this fence's Wine still unavailable to run locally)
	reported this fence STALE (PASS produced FAIL), again a bug in this
	TEST rather than in posix_spawn(): it asserted sched_priority 5
	round-tripped through getpriority() unchanged, but a non-self
	getpriority() query goes through the real NT priority class rather
	than the self_nice cache (see the assertion's own comment, below),
	and src/misc/nt/plat_misc.c's priorityclass_from_nice() only
	distinguishes three classes -- every nice value in [1,9] applies as
	BELOW_NORMAL and reads back as that class's one representative nice
	value, 2, not the value that was asked for.  Fixed by asserting with
	2, the one value in that bucket the round trip actually preserves,
	instead of 5. */
static void test_setschedparam_applied(void)
{
	posix_spawnattr_t at;
	struct sched_param par;
	pid_t pid;
	int status;
	char *argv[3];

	/* 2, not some other value in setpriority()'s always-allowed
	 * [0, NZERO-1] range: the readback below queries a pid that is not
	 * self, which -- unlike the self_nice cache getpriority() returns
	 * for self (src/misc/resource.c) -- goes through the real NT
	 * priority class and back, and that round trip is lossy by design.
	 * src/misc/nt/plat_misc.c's priorityclass_from_nice() only ever
	 * reaches the three priority classes an unprivileged caller can
	 * set (NORMAL/BELOW_NORMAL/IDLE), so any nice value in [1,9] is
	 * indistinguishable from any other once applied; its inverse,
	 * nice_from_baseprio(), maps back to one representative nice value
	 * per class (0, 2, 4). 2 is BELOW_NORMAL's representative, so it is
	 * the one value in that bucket the round trip actually preserves --
	 * an arbitrary value like 5 would apply fine but read back as 2,
	 * which is a fact about this mapping's granularity, not a defect in
	 * posix_spawn(). */
	par.sched_priority = 2;
	CHECK(posix_spawnattr_init(&at) == 0);
	CHECK(posix_spawnattr_setschedparam(&at, &par) == 0);
	CHECK(posix_spawnattr_setschedpolicy(&at, 0) == 0);
	CHECK(posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSCHEDULER) == 0);
	/* "noop", not a bare argv[0]: see this fence's own VERIFICATION
	 * addendum above for why a child with no distinguishing argv[1]
	 * recurses instead of exiting. */
	argv[0] = (char *)self; argv[1] = (char *)"noop"; argv[2] = 0;
	CHECK(posix_spawn(&pid, self, 0, &at, argv, environ) == 0);
	/* getpriority() for a pid that is not self queries the child's real
	 * NT priority class directly (src/misc/resource.c); read before
	 * waitpid() reaps it, since __child_remove() closes the handle that
	 * query needs. */
	CHECK(getpriority(PRIO_PROCESS, (id_t)pid) == 2);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	posix_spawnattr_destroy(&at);
}
#endif

#if SPICULE_TEST(NA, posix_spawn_resetids) /* N/A: posix_spawn.html DESCRIPTION -- POSIX_SPAWN_RESETIDS,
	"reset the effective user ID of the child process to the real user
	ID of the parent process".  An NT access token carries a set of
	SIDs and privileges; it has no real/effective/saved-set-id triple,
	so there is no state in which a child's effective id *differs* from
	its real one for this flag to collapse.  test/POSIX-COVERAGE.md and
	test/posix-dl.c already fence it on exactly that mechanism.  The
	flag is accepted by posix_spawn() (asserted above) because its
	postcondition is unconditionally true, not because it is ignored. */
static void test_resetids(void)
{
	posix_spawnattr_t at;
	posix_spawnattr_init(&at);
	posix_spawnattr_setflags(&at, POSIX_SPAWN_RESETIDS);
	CHECK(geteuid() == getuid());
}
#endif

/* ---------------------------------------------------------------- */

int main(int argc, char **argv)
{
	pid_t probe = -1;
	char *pargv[4];
	int status;

	if (argc > 1) return child_main(argc, argv);

	self = argv[0];

	/* The environment probe: one complete round trip of the machinery
	 * every assertion below depends on -- spawn this executable, hand
	 * its fd 1 to a pipe with the one file action, reap it, and read
	 * back what it wrote.  If any part of that does not work, every
	 * assertion below would fail for a single environmental reason,
	 * which is not a result.  Exit 77 with one SKIP line naming the
	 * mechanism instead, the way test/posix-socket.c does for a missing
	 * network stack.
	 *
	 * The known environment where this fires is the native
	 * (Linux/ELF) `make asan` build: fuzz/ntstubs.c stands in for
	 * RtlCreateUserProcess by execve()ing a real host binary, and the
	 * fresh child's __ntshim_init wires up only StandardInput/Output/
	 * Error before calling __fd_init -- there is no process-parameters
	 * copy carrying a RuntimeData descriptor table across that execve
	 * the way real NT's does.  This test is covered by `make check`
	 * under Wine, and by the real-Windows CI leg, where
	 * RtlCreateUserProcess is the real thing.
	 *
	 * The child is reaped before the pipe is read, rather than after,
	 * so that a child that never runs cannot turn this probe into a
	 * hang. */
	{
		posix_spawn_file_actions_t fa;
		char got[32];
		int p[2], rc = -1;
		ssize_t n = -1;
		const char *why = 0;

		pargv[0] = (char *)self;
		pargv[1] = (char *)"w1";
		pargv[2] = (char *)"PROBE";
		pargv[3] = 0;

		if (pipe(p) != 0) {
			why = "pipe() failed";
		} else {
			posix_spawn_file_actions_init(&fa);
			posix_spawn_file_actions_adddup2(&fa, p[1], 1);
			rc = posix_spawn(&probe, self, &fa, 0, pargv, environ);
			posix_spawn_file_actions_destroy(&fa);
			close(p[1]);
			if (rc != 0) why = "posix_spawn() failed";
			else if (waitpid(probe, &status, 0) != probe) why = "waitpid() did not reap the child";
			else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) why = "the child did not exit 0";
			else if ((n = read(p[0], got, sizeof got - 1)) <= 0) why = "nothing came back down the pipe";
			else { got[n] = 0; if (strcmp(got, "PROBE")) why = "the wrong bytes came back down the pipe"; }
			close(p[0]);
		}
		if (why) {
			printf("SKIP posix-spawn (%s; rc=%d, errno=%d): this "
			       "environment cannot spawn a child of this "
			       "executable and hand it a descriptor, which every "
			       "assertion here needs.  Real NT does that through "
			       "RtlCreateUserProcess plus the RuntimeData "
			       "descriptor table (src/process/spawn.c, "
			       "src/internal/fd.c)\n", why, rc, errno);
			printf("posix-spawn: 0 assertion(s) ran\n");
			return 77;
		}
	}

	test_file_actions_object();
	test_addopen_copies_path();
	test_adddup2_stdout();
	test_adddup2_stderr();
	test_stderr_survives_closed_stdin();
	test_order_two_targets();
	test_order_chained();
	test_addclose();
	test_addopen();
	test_adddup2_self();
	test_adddup2_badfd();
	test_parent_table_restored();
	test_adddup2_above_two_real_fd();
	test_adddup2_two_above_two();
	test_attr_roundtrip();
	test_attr_flags_acted_on();
	test_spawnp_path_search();
	test_enoent_and_errno();
	test_null_actions_and_argv();

	if (fails) { printf("posix-spawn: failures: %d\n", fails); return 1; }
	if (unverified) {
		/* `unverified` only ever comes from test_spawnp_path_search()
		 * above, which is unconditional and unrelated to either of this
		 * file's two SPICULE_TEST-fenced cases.  A tools/test-policy.py
		 * probe recompiles this whole file to validate ONE fenced case in
		 * isolation, and test_spawnp_path_search() still runs alongside
		 * it; without this guard, its argv[0]-shape environment gap would
		 * report the OTHER fenced case's probe UNRESOLVED too, regardless
		 * of that case's own result.  (The environment round-trip gate at
		 * the top of main() is a real precondition of both fenced cases
		 * themselves -- they call posix_spawn()/posix_spawnp() too -- so
		 * its own `return 77` stays unconditional.) */
		printf("posix-spawn: %d assertion group(s) unverified in this "
		       "environment (see SKIP lines above); no failures in what "
		       "did run\n", unverified);
		if (!SPICULE_TEST_POLICY_PROBE) return 77;
	}
	printf("posix-spawn: all ok\n");
	return 0;
}
