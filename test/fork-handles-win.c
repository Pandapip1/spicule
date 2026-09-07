/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Pins down what fork() does with the process handles of children that
 * already existed before the fork (see the "What does not carry over
 * cleanly" paragraph at the top of src/process/fork.c).
 *
 * The parent starts child A (a fork that sleeps, then exits 7; exec is
 * not used because exec.c still references an undefined __find_program,
 * and a fork child's table entry, fork.c's info.Process, is exactly as
 * non-inheritable as __spawn's), then forks B.  B inherits the
 * parent's __children table as plain memory, but the process handle in
 * it was never marked inheritable, so in B that handle value is either
 * empty or -- worse -- recycled for some unrelated object B opened.
 * B reports what waitpid(A) did through its exit code:
 *
 *   0  failed cleanly (ECHILD / EINVAL / EBADF)        -- acceptable
 *   1  worked and reported A's real status (7)        -- acceptable
 *   2  "succeeded" with a status that is not A's      -- a lie, FAIL
 *   4  failed with some other errno                   -- FAIL
 *   5  B's own fds (a pipe from before the fork) broke -- FAIL
 *   6  a child B spawned *after* fork was not waitable -- FAIL
 *
 * and the parent turns 3 into "hung past the timeout".  spicule has no
 * alarm() (it is a stub) and no threads, so the timeout is implemented
 * on the parent side: it polls B with WNOHANG and kills it if it is
 * still alive after TIMEOUT_S seconds.
 *
 * Needs a real fork() and so, like fork-win.c, only runs on Windows CI.
 */
/* kill() is feature-test gated in include/signal.h; same define most
 * other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TIMEOUT_S 20

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; write(1, "FAIL: " #cond "\n", sizeof("FAIL: " #cond "\n") - 1); } } while (0)

static void say(const char *s) { write(1, s, strlen(s)); }

/* Runs in B.  Returns the exit code described above. */
static int child_b(pid_t a, int wfd)
{
	int st = -1, r1, r2, e1 = 0, e2 = 0;
	pid_t c;

	/* fds opened before fork() must still work in the child. */
	if (write(wfd, "ok", 2) != 2) return 5;
	close(wfd);

	errno = 0;
	r1 = waitpid(a, &st, WNOHANG);
	e1 = errno;
	errno = 0;
	r2 = waitpid(a, &st, 0);
	e2 = errno;

	/* A child spawned *after* the fork must be waitable as normal. */
	c = fork();
	if (c == 0) _exit(5);
	if (c < 0) return 6;
	{
		int cst = -1;
		if (waitpid(c, &cst, 0) != c || !WIFEXITED(cst) || WEXITSTATUS(cst) != 5) return 6;
	}

	if (r2 == a || r1 == a) {
		/* waitpid claims A is reaped; is that A's real status? */
		if (WIFEXITED(st) && WEXITSTATUS(st) == 7) return 1;
		return 2;
	}
	if (r2 == -1 && (r1 == -1 || r1 == 0)) {
		int e = r1 == -1 ? e1 : e2;
		if (e == ECHILD || e == EINVAL || e == EBADF) return 0;
		(void)e2;
		return 4;
	}
	return 4;
}

int main(int argc, char **argv)
{
	int pfd[2], status = -1, code, i;
	char buf[2];
	pid_t a, b, r;

	(void)argc; (void)argv;

	CHECK(pipe(pfd) == 0);

	/* Child A: a child that exists before the fork under test. */
	a = fork();
	CHECK(a >= 0);
	if (a == 0) { sleep(2); _exit(7); }

	/* Child B: the fork that inherits a table entry for A. */
	b = fork();
	CHECK(b >= 0);
	if (b == 0) _exit(child_b(a, pfd[1]));

	close(pfd[1]);
	CHECK(read(pfd[0], buf, 2) == 2 && buf[0] == 'o' && buf[1] == 'k');
	close(pfd[0]);

	/* Parent-side timeout for B. */
	code = 3;
	for (i = 0; i < TIMEOUT_S; i++) {
		r = waitpid(b, &status, WNOHANG);
		if (r == b) { code = WIFEXITED(status) ? WEXITSTATUS(status) : 4; break; }
		if (r < 0) { code = 4; break; }
		sleep(1);
	}
	if (code == 3) { kill(b, SIGKILL); waitpid(b, &status, 0); }

	switch (code) {
	case 0: say("fork-handles: B got a clean error for the pre-fork child\n"); break;
	case 1: say("fork-handles: B waited the pre-fork child successfully\n"); break;
	case 2: say("fork-handles: B reported a WRONG status for the pre-fork child\n"); break;
	case 3: say("fork-handles: B hung waiting for the pre-fork child\n"); break;
	case 5: say("fork-handles: B's pre-fork pipe fd broke\n"); break;
	case 6: say("fork-handles: B could not wait its own post-fork child\n"); break;
	default: say("fork-handles: B failed with an unexpected errno\n"); break;
	}
	CHECK(code != 2);                  /* must never lie */
	CHECK(code == 0 || code == 1);     /* fail cleanly or work */

	/* The parent's own handle for A is fine regardless. */
	CHECK(waitpid(a, &status, 0) == a);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);

	if (!fails) say("fork-handles: all tests passed\n");
	return fails != 0;
}
