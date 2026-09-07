/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Process creation and reaping: fork(), the exec family, waitpid() and
 * wait().  Like fork-win.c this needs RtlCloneUserProcess, which Wine
 * does not implement, so it is built but not run by "make check".
 *
 * The binary re-executes itself: a first argument starting with "--"
 * selects a child role (see child_main) so that exec can be tested
 * without depending on any other program being present.
 */
/* setenv()/wait3()/wait4() are feature-test gated in include/stdlib.h
 * and include/sys/wait.h; same define most other tests in test/
 * already carry for the same reason (see test/posix-glob.c's comment on this
 * exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* src/internal/libc.h: CHILD_MAX_, the static seed size of the child
 * table.  The table grows past it, so this is not a limit any more --
 * NCHILDREN is deliberately well beyond it so that a regression to a
 * fixed-size table shows up as unreapable children. */
#define CHILD_TABLE 256
#define NCHILDREN (CHILD_TABLE + 64)

/* Arguments that exercise every quoting rule spawn.c's append_arg
 * implements and crt1.c's split_cmdline undoes. */
static const char *const tricky[] = {
	"plain",
	"two words",
	"",
	"say \"hi\"",
	"trailing\\",
	"two\\\\backslashes",
	"\\\"escaped quote",
	"tab\there",
	"c:\\dir with space\\",
	"\"",
	"end\\\\\"",
	0
};

/* Exit codes used by child roles, distinct from anything a test below
 * deliberately asks for. */
#define RC_ARGV_MISMATCH 7
#define RC_ENV_MISMATCH 8
#define RC_EXEC_RETURNED 99

/* stdout is shared with every child; never let a clone carry a
 * half-filled buffer away and print it twice. */
static pid_t do_fork(void)
{
	fflush(stdout);
	return fork();
}

static pid_t fork_exit(int code)
{
	pid_t pid = do_fork();
	if (pid == 0) _exit(code);
	return pid;
}

/* Child roles. */
static int child_main(int argc, char **argv)
{
	if (!strcmp(argv[1], "--exit")) {
		_exit(atoi(argv[2]));
	}
	if (!strcmp(argv[1], "--sleep-exit")) {
		sleep(2);
		_exit(atoi(argv[2]));
	}
	if (!strcmp(argv[1], "--argv") || !strcmp(argv[1], "--argv-env")) {
		int i;
		for (i = 0; tricky[i]; i++) {
			if (i + 2 >= argc || strcmp(argv[i + 2], tricky[i])) {
				printf("child: argv[%d] = \"%s\", wanted \"%s\"\n", i + 2,
				       i + 2 < argc ? argv[i + 2] : "(missing)", tricky[i]);
				_exit(RC_ARGV_MISMATCH);
			}
		}
		if (i + 2 != argc) {
			printf("child: argc %d, wanted %d\n", argc, i + 2);
			_exit(RC_ARGV_MISMATCH);
		}
		if (!strcmp(argv[1], "--argv-env")) {
			const char *v = getenv("SPICULE_TEST_ENV");
			if (!v || strcmp(v, "hello world")) {
				printf("child: SPICULE_TEST_ENV = %s\n", v ? v : "(unset)");
				_exit(RC_ENV_MISMATCH);
			}
			if (getenv("SPICULE_TEST_ABSENT")) _exit(RC_ENV_MISMATCH);
		}
		_exit(0);
	}
	printf("child: unknown role %s\n", argv[1]);
	_exit(100);
	return 100;
}

static int global_seen_by_child = 111;

static void test_fork_basics(void)
{
	pid_t parent = getpid(), pid;
	int status = -1;

	pid = do_fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		if (getpid() == parent) _exit(3);
		if (getppid() != parent) _exit(4);
		global_seen_by_child = 999;
		_exit(42);
	}
	CHECK(pid > 0);
	CHECK(pid != parent);
	CHECK(global_seen_by_child == 111);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 42);
}

static void test_wait_semantics(void)
{
	static const int codes[] = { 0, 1, 42, 255 };
	pid_t pid, r;
	int status, i;

	/* Exit codes round-trip through the wait status. */
	for (i = 0; i < 4; i++) {
		pid = fork_exit(codes[i]);
		CHECK(pid > 0);
		status = -1;
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status));
		CHECK(!WIFSIGNALED(status));
		CHECK(WEXITSTATUS(status) == codes[i]);
	}

	/* waitpid(-1) reaps whichever child there is. */
	pid = fork_exit(3);
	CHECK(pid > 0);
	status = -1;
	r = waitpid(-1, &status, 0);
	CHECK(r == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 3);

	/* A pid that is not our child. */
	errno = 0;
	CHECK(waitpid(1, &status, 0) == -1);
	CHECK(errno == ECHILD);
	errno = 0;
	CHECK(waitpid(getpid(), &status, WNOHANG) == -1);
	CHECK(errno == ECHILD);

	/* WNOHANG on a child that is still running returns 0, and the
	 * later blocking wait still gets the real status. */
	pid = do_fork();
	CHECK(pid >= 0);
	if (pid == 0) { sleep(2); _exit(5); }
	status = 0x7777;
	CHECK(waitpid(pid, &status, WNOHANG) == 0);
	CHECK(status == 0x7777);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 5);

	/* Nothing left: wait() and waitpid(-1, WNOHANG) both say ECHILD. */
	errno = 0;
	CHECK(wait(&status) == -1);
	CHECK(errno == ECHILD);
	errno = 0;
	CHECK(waitpid(-1, &status, WNOHANG) == -1);
	CHECK(errno == ECHILD);
}

/* wait3()/wait4(): same reaping as waitpid(), plus a struct rusage for
 * the child just reaped, and getrusage(RUSAGE_CHILDREN)'s running total
 * grows to match. */
/* See test/exec.c's copy: a whole timeval as microseconds, so the
 * monotonicity check is one comparison on the real quantity. */
static long long timeval_usec(const struct timeval *tv)
{
	return (long long)tv->tv_sec * 1000000 + (long long)tv->tv_usec;
}

static void test_wait_rusage(void)
{
	struct rusage ru_before, ru_after, ru_child;
	pid_t pid, r;
	int status;

	memset(&ru_before, 0, sizeof ru_before);
	CHECK(getrusage(RUSAGE_CHILDREN, &ru_before) == 0);

	pid = fork_exit(7);
	CHECK(pid > 0);
	status = -1;
	memset(&ru_child, 0xff, sizeof ru_child);
	r = wait4(pid, &status, 0, &ru_child);
	CHECK(r == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	CHECK(ru_child.ru_utime.tv_sec >= 0 && ru_child.ru_stime.tv_sec >= 0);

	/* Same repair as test/exec.c's test_wait_rusage(): the old form
	 * OR'd four half-timeval comparisons together, one of which
	 * (`ru_after.ru_utime.tv_usec >= ru_before.ru_utime.tv_usec`) is
	 * satisfied by the two structs simply being equal -- which they
	 * are, at zero, on any platform whose ProcessTimes for an exited
	 * child reads back 0.  So it passed with getrusage(RUSAGE_CHILDREN)
	 * doing nothing whatsoever.  Poisoning ru_after makes a
	 * never-written struct fail, and comparing whole timevals makes the
	 * "running total never shrinks" claim (getrusage.html DESCRIPTION,
	 * RUSAGE_CHILDREN) the thing actually being checked. */
	memset(&ru_after, 0xff, sizeof ru_after);
	CHECK(getrusage(RUSAGE_CHILDREN, &ru_after) == 0);
	CHECK(timeval_usec(&ru_after.ru_utime) >= timeval_usec(&ru_before.ru_utime));
	CHECK(timeval_usec(&ru_after.ru_stime) >= timeval_usec(&ru_before.ru_stime));

	/* wait3() is the (-1, ...) shape of the same call. */
	pid = fork_exit(8);
	CHECK(pid > 0);
	status = -1;
	r = wait3(&status, 0, 0);   /* rusage is optional, like waitpid()'s ru == NULL path */
	CHECK(r == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 8);
}

/* Encoded result of the forked child's waitpid on its elder sibling. */
#define PF_RUNNING 10
#define PF_REAPED_OK 11
#define PF_REAPED_BAD 12
#define PF_ERR_BASE 20
#define PF_ERR_OTHER 20
#define PF_ERR_ECHILD 21
#define PF_ERR_EINVAL 22
#define PF_ERR_EBADF 23
#define PF_STATUS_CLOBBERED 30

/* fork.c's header documents that a child started before a fork() is not
 * necessarily reachable from the clone: its handle in __children was not
 * created inheritable.  Whatever the clone sees must be a clean outcome
 * -- a reap, "still running", or -1 with a sensible errno -- never a
 * hang, a crash, or a made-up status. */
static void test_prefork_handle(void)
{
	pid_t a, b;
	int status = -1;

	a = do_fork();
	CHECK(a >= 0);
	if (a == 0) { sleep(2); _exit(5); }

	b = do_fork();
	CHECK(b >= 0);
	if (b == 0) {
		int st = 0x7777, code;
		pid_t r;
		errno = 0;
		r = waitpid(a, &st, WNOHANG);
		if (r == a) code = (WIFEXITED(st) && WEXITSTATUS(st) == 5) ? PF_REAPED_OK : PF_REAPED_BAD;
		else if (r == 0) code = st == 0x7777 ? PF_RUNNING : PF_STATUS_CLOBBERED;
		else if (r == -1) {
			code = errno == ECHILD ? PF_ERR_ECHILD : errno == EINVAL ? PF_ERR_EINVAL
			     : errno == EBADF ? PF_ERR_EBADF : PF_ERR_OTHER;
			if (st != 0x7777) code = PF_STATUS_CLOBBERED;
		} else code = PF_REAPED_BAD;
		_exit(code);
	}

	CHECK(waitpid(b, &status, 0) == b);
	CHECK(WIFEXITED(status));
	printf("prefork: clone's waitpid(elder sibling, WNOHANG) -> code %d "
	       "(10 running, 11 reaped, 21 ECHILD, 22 EINVAL, 23 EBADF)\n", WEXITSTATUS(status));
	CHECK(WEXITSTATUS(status) == PF_RUNNING || WEXITSTATUS(status) == PF_REAPED_OK ||
	      WEXITSTATUS(status) == PF_ERR_ECHILD || WEXITSTATUS(status) == PF_ERR_EINVAL ||
	      WEXITSTATUS(status) == PF_ERR_EBADF);

	/* The parent's own handle to A is unaffected by B's attempt. */
	CHECK(waitpid(a, &status, 0) == a);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 5);
}

static char **build_argv(const char *self, const char *role)
{
	static char *v[32];
	int i, n = 0;
	v[n++] = (char *)self;
	v[n++] = (char *)role;
	for (i = 0; tricky[i]; i++) v[n++] = (char *)tricky[i];
	v[n] = 0;
	return v;
}

/* execve never returns on success: it runs the program as a child and
 * exits with its status.  So exec from a forked child and read the
 * result back through that child's exit code. */
static void test_exec(const char *self)
{
	pid_t pid;
	int status;
	char *envp[4];
	char sysroot[512];
	const char *sr = getenv("SystemRoot");

	/* execv */
	pid = do_fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		execv(self, build_argv(self, "--argv"));
		_exit(RC_EXEC_RETURNED);
	}
	status = -1;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 0);

	/* execvp: self contains a slash, so it is used as-is, not searched */
	pid = do_fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		execvp(self, build_argv(self, "--argv"));
		_exit(RC_EXEC_RETURNED);
	}
	status = -1;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 0);

	/* execve with an explicit environment */
	envp[0] = (char *)"SPICULE_TEST_ENV=hello world";
	if (sr) { snprintf(sysroot, sizeof sysroot, "SystemRoot=%s", sr); envp[1] = sysroot; }
	else envp[1] = (char *)"SystemRoot=C:\\Windows";
	envp[2] = 0;
	setenv("SPICULE_TEST_ABSENT", "1", 1);   /* must not leak past an explicit envp */
	pid = do_fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		execve(self, build_argv(self, "--argv-env"), envp);
		_exit(RC_EXEC_RETURNED);
	}
	status = -1;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 0);

	/* An exit code from the exec'd image is what exec's caller exits with. */
	{
		char *v[4];
		v[0] = (char *)self; v[1] = (char *)"--exit"; v[2] = (char *)"200"; v[3] = 0;
		pid = do_fork();
		CHECK(pid >= 0);
		if (pid == 0) { execv(self, v); _exit(RC_EXEC_RETURNED); }
		status = -1;
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 200);
	}

	/* A missing program fails with ENOENT and exec returns. */
	errno = 0;
	CHECK(execv("./no-such-program-here.exe", build_argv(self, "--argv")) == -1);
	CHECK(errno == ENOENT);
}

/* More children than the child table's static seed holds, none reaped
 * until all exist: the table has to grow, and every child stays reapable
 * with the right status. */
static void test_child_table_growth(void)
{
	static pid_t pids[NCHILDREN];
	int i, status;

	for (i = 0; i < NCHILDREN; i++) {
		pids[i] = fork_exit(i % 250 + 1);
		CHECK(pids[i] > 0);
		if (pids[i] <= 0) break;
	}

	for (i = 0; i < NCHILDREN && pids[i] > 0; i++) {
		pid_t r;
		status = -1;
		errno = 0;
		r = waitpid(pids[i], &status, 0);
		CHECK(r == pids[i]);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == i % 250 + 1);
	}

	/* The table is empty again. */
	errno = 0;
	CHECK(waitpid(-1, &status, WNOHANG) == -1);
	CHECK(errno == ECHILD);
}

int main(int argc, char **argv)
{
	int status;

	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == '-') return child_main(argc, argv);

	/* No children yet. */
	errno = 0;
	CHECK(wait(&status) == -1);
	CHECK(errno == ECHILD);

	test_fork_basics();
	test_wait_semantics();
	test_wait_rusage();
	test_prefork_handle();
	test_exec(argv[0]);
	test_child_table_growth();

	if (!fails) printf("process: all tests passed\n");
	return fails != 0;
}
