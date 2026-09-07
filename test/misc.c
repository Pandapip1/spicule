/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
/* setenv() is feature-test gated in include/stdlib.h; same define most
 * other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <libgen.h>
#include <locale.h>
#include <assert.h>
#include <unistd.h>
#include <sched.h>
#include <semaphore.h>
#include <mqueue.h>
#include <aio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

extern char **environ;
/* Internal: spawn a program as a child, return its pid (see src/process/spawn.c).
 * fork() needs RtlCloneUserProcess, which wine lacks, so this is used to
 * run abort() in a child. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

/* ---- env ---- */
static int env_has(const char *prefix)
{
	char **e;
	size_t l = strlen(prefix);
	for (e = environ; e && *e; e++) if (!strncmp(*e, prefix, l)) return 1;
	return 0;
}

static void test_env(void)
{
	static char pe[] = "SPICULE_PUTENV=pv";

	CHECK(getenv("SPICULE_NO_SUCH_VAR_XYZ") == NULL);
	CHECK(getenv("") == NULL);
	CHECK(getenv("A=B") == NULL);

	CHECK(setenv("SPICULE_T1", "one", 1) == 0);
	CHECK(getenv("SPICULE_T1") && !strcmp(getenv("SPICULE_T1"), "one"));
	CHECK(env_has("SPICULE_T1=one"));
	CHECK(setenv("SPICULE_T1", "two", 0) == 0);
	CHECK(getenv("SPICULE_T1") && !strcmp(getenv("SPICULE_T1"), "one"));
	CHECK(setenv("SPICULE_T1", "two", 1) == 0);
	CHECK(getenv("SPICULE_T1") && !strcmp(getenv("SPICULE_T1"), "two"));
	CHECK(env_has("SPICULE_T1=two"));
	CHECK(!env_has("SPICULE_T1=one"));
	CHECK(setenv("SPICULE_EMPTY", "", 1) == 0);
	CHECK(getenv("SPICULE_EMPTY") && !*getenv("SPICULE_EMPTY"));
	CHECK(unsetenv("SPICULE_T1") == 0);
	CHECK(getenv("SPICULE_T1") == NULL);
	CHECK(!env_has("SPICULE_T1="));
	CHECK(unsetenv("SPICULE_T1") == 0);  /* not present: still success */

	errno = 0;
	CHECK(setenv("A=B", "x", 1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(setenv("", "x", 1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(unsetenv("") == -1 && errno == EINVAL);
	errno = 0;
	CHECK(unsetenv("A=B") == -1 && errno == EINVAL);

	CHECK(putenv(pe) == 0);
	CHECK(getenv("SPICULE_PUTENV") && !strcmp(getenv("SPICULE_PUTENV"), "pv"));
	CHECK(env_has("SPICULE_PUTENV=pv"));
	pe[14] = 'q';  /* putenv strings are referenced, not copied */
	CHECK(getenv("SPICULE_PUTENV") && !strcmp(getenv("SPICULE_PUTENV"), "qv"));
	CHECK(unsetenv("SPICULE_PUTENV") == 0);
	CHECK(getenv("SPICULE_PUTENV") == NULL);
	CHECK(!env_has("SPICULE_PUTENV="));
}

/* ---- process scheduling ---- */
static void test_sched(void)
{
	struct sched_param param;
	struct timespec interval;
	int min = sched_get_priority_min(SCHED_FIFO);
	int max = sched_get_priority_max(SCHED_FIFO);

	CHECK(min >= 0 && max >= min);
	CHECK(sched_getscheduler(0) == SCHED_OTHER);
	CHECK(sched_getparam(0, &param) == 0);
	param.sched_priority = min;
	/* SCHED_RR, not SCHED_FIFO: the kernel's own rt_sched_class only fills
	 * in a real round-robin quantum for SCHED_RR tasks; sched_rr_get_interval()
	 * on a SCHED_FIFO task legitimately reports an all-zero interval, since
	 * FIFO has no time slice to report. */
	CHECK(sched_setscheduler(0, SCHED_RR, &param) == 0);
	CHECK(sched_getscheduler(0) == SCHED_RR);
	param.sched_priority = max;
	CHECK(sched_setparam(0, &param) == 0);
	param.sched_priority = -1;
	CHECK(sched_getparam(0, &param) == 0 && param.sched_priority == max);
	CHECK(sched_rr_get_interval(0, &interval) == 0);
	CHECK(interval.tv_sec == 0 && interval.tv_nsec > 0);
	errno = 0;
	CHECK(sched_get_priority_max(-1) == -1 && errno == EINVAL);
	param.sched_priority = 0;
	CHECK(sched_setscheduler(0, SCHED_OTHER, &param) == 0);
}

/* ---- whole-process memory locking ---- */
static void test_mlockall(void)
{
	CHECK(mlockall(MCL_FUTURE) == 0);
	CHECK(munlockall() == 0);
	errno = 0;
	CHECK(mlockall(0) == -1 && errno == EINVAL);
}

/* ---- semaphores ---- */
static void test_semaphore(void)
{
	sem_t sem;
	sem_t *named;
	struct timespec past;
	int value;
	CHECK(sem_init(&sem, 0, 1) == 0);
	CHECK(sem_wait(&sem) == 0);
	CHECK(sem_trywait(&sem) == -1 && errno == EAGAIN);
	CHECK(clock_gettime(CLOCK_REALTIME, &past) == 0);
	past.tv_sec--;
	CHECK(sem_timedwait(&sem, &past) == -1 && errno == ETIMEDOUT);
	CHECK(sem_post(&sem) == 0);
	CHECK(sem_getvalue(&sem, &value) == 0 && value == 1);
	CHECK(sem_destroy(&sem) == 0);
	sem_unlink("/spicule_misc_sem");
	named = sem_open("/spicule_misc_sem", O_CREAT | O_EXCL, 0600, 1);
	CHECK(named != SEM_FAILED);
	if (named != SEM_FAILED) CHECK(sem_close(named) == 0);
	CHECK(sem_unlink("/spicule_misc_sem") == 0);
}

/* ---- message queues ---- */
static void test_mqueue(void)
{
	struct mq_attr attr = {0}, got, old;
	struct sigevent event = {0};
	struct timespec deadline;
	mqd_t q;
	char buf[8];
	unsigned prio;

	attr.mq_maxmsg = 2;
	attr.mq_msgsize = sizeof buf;
	mq_unlink("/spicule_misc_mq");
	q = mq_open("/spicule_misc_mq", O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
	CHECK(q != (mqd_t)-1);
	if (q == (mqd_t)-1) return;
	event.sigev_notify = SIGEV_NONE;
	CHECK(mq_notify(q, &event) == 0);
	CHECK(mq_notify(q, NULL) == 0);
	CHECK(mq_send(q, "low", 3, 1) == 0);
	CHECK(mq_getattr(q, &got) == 0 && got.mq_curmsgs == 1);
	got.mq_flags = O_NONBLOCK;
	CHECK(mq_setattr(q, &got, &old) == 0 && old.mq_flags == 0);
	CHECK(mq_receive(q, buf, sizeof buf, &prio) == 3 && prio == 1 &&
	      !memcmp(buf, "low", 3));
	CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	deadline.tv_sec++;
	CHECK(mq_timedsend(q, "high", 4, 9, &deadline) == 0);
	CHECK(mq_timedreceive(q, buf, sizeof buf, &prio, &deadline) == 4 &&
	      prio == 9 && !memcmp(buf, "high", 4));
	CHECK(mq_close(q) == 0);
	CHECK(mq_unlink("/spicule_misc_mq") == 0);
}

/* ---- asynchronous I/O ---- */
static void test_aio(void)
{
	struct aiocb cb, first, second;
	struct aiocb *lio[2];
	const struct aiocb *wait[1];
	char out[8] = "aio-data";
	char in[8] = {0};
	int fd, canceled;

	fd = open("spicule-misc-aio.tmp", O_CREAT | O_TRUNC | O_RDWR, 0600);
	CHECK(fd >= 0);
	if (fd < 0) return;

	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_buf = out;
	cb.aio_nbytes = sizeof out;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_write(&cb) == 0);
	wait[0] = &cb;
	CHECK(aio_suspend(wait, 1, NULL) == 0);
	CHECK(aio_error(&cb) == 0);
	CHECK(aio_return(&cb) == (ssize_t)sizeof out);

	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_fsync(O_SYNC, &cb) == 0);
	wait[0] = &cb;
	CHECK(aio_suspend(wait, 1, NULL) == 0);
	CHECK(aio_return(&cb) == 0);

	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_buf = in;
	cb.aio_nbytes = sizeof in;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_read(&cb) == 0);
	wait[0] = &cb;
	CHECK(aio_suspend(wait, 1, NULL) == 0);
	CHECK(aio_return(&cb) == (ssize_t)sizeof in);
	CHECK(!memcmp(in, out, sizeof out));

	memset(&first, 0, sizeof first);
	first.aio_fildes = fd;
	first.aio_buf = "one";
	first.aio_nbytes = 3;
	first.aio_offset = 0;
	first.aio_lio_opcode = LIO_WRITE;
	first.aio_sigevent.sigev_notify = SIGEV_NONE;
	memset(&second, 0, sizeof second);
	second.aio_fildes = fd;
	second.aio_buf = "two";
	second.aio_nbytes = 3;
	second.aio_offset = 3;
	second.aio_lio_opcode = LIO_WRITE;
	second.aio_sigevent.sigev_notify = SIGEV_NONE;
	lio[0] = &first;
	lio[1] = &second;
	CHECK(lio_listio(LIO_WAIT, lio, 2, NULL) == 0);
	CHECK(aio_return(&first) == 3);
	CHECK(aio_return(&second) == 3);

	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_buf = out;
	cb.aio_nbytes = sizeof out;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_write(&cb) == 0);
	canceled = aio_cancel(fd, &cb);
	CHECK(canceled == AIO_CANCELED || canceled == AIO_NOTCANCELED ||
	      canceled == AIO_ALLDONE);
	wait[0] = &cb;
	CHECK(aio_suspend(wait, 1, NULL) == 0);
	CHECK(aio_error(&cb) == 0 || aio_error(&cb) == ECANCELED);
	(void)aio_return(&cb);

	CHECK(close(fd) == 0);
	CHECK(unlink("spicule-misc-aio.tmp") == 0);
}

/* ---- system() ---- */
static void test_system(void)
{
	int status;

	/* A command processor must be available on any real Windows/Wine
	 * host this runs on (cmd.exe always exists); see
	 * src/stdlib/system.c.  The native asan build (tools/asan-build.sh)
	 * compiles this same source against NT stubs that emulate files,
	 * pipes and processes but not a shell -- there is genuinely no
	 * ComSpec and no "cmd.exe" on PATH there, so system(NULL) reporting
	 * 0 is the *correct* answer in that environment, not a bug.  Treat
	 * that as "nothing further to exercise here" rather than a
	 * failure. */
	if (system(NULL) == 0) return;

	status = system("exit 3");
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 3);

	status = system("exit 0");
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 0);

#if defined(__linux__)
	/* A command containing a space still reaches sh(1p) byte-for-byte
	 * on Linux: __spawn's Linux backend execve(2)s argv[] directly, so
	 * there is no cmd.exe-style command-line re-lexing here needing a
	 * quoting layer at all (see system.c's header comment).  "true;
	 * exit 7" exercises that same "space in the command" shape while
	 * staying sh(1p) syntax, in place of the nested-cmd.exe form below. */
	status = system("true; exit 7");
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 7);
#else
	/* A command containing a space exercises append_arg's quoting of
	 * the "/c" argument -- see the design comment in system.c for why
	 * this, and not an embedded quote or trailing backslash, is the
	 * case this is expected to round-trip through cmd.exe correctly. */
	status = system("cmd /c exit 7");
	CHECK(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 7);
#endif
}

/* ---- setjmp/longjmp ---- */
static jmp_buf jb_outer, jb_inner;

static void jump_from_frames(int depth, int val)
{
	volatile char pad[64];
	pad[0] = (char)depth;
	if (depth == 0) longjmp(jb_outer, val);
	jump_from_frames(depth - 1, val + pad[0] - depth);
}

static int recurse(int n)
{
	if (n == 0) longjmp(jb_outer, 100);
	return recurse(n - 1) + 1;
}

static void test_setjmp(void)
{
	volatile int v = 1, count = 0;
	int r;

	r = setjmp(jb_outer);
	if (r == 0) {
		v = 2;
		longjmp(jb_outer, 7);
		CHECK(0);
	}
	CHECK(r == 7);
	CHECK(v == 2);

	/* longjmp(env, 0) returns 1 */
	r = setjmp(jb_outer);
	if (r == 0) longjmp(jb_outer, 0);
	CHECK(r == 1);

	/* multiple returns through the same buffer */
	r = setjmp(jb_outer);
	count++;
	if (count < 5) longjmp(jb_outer, count);
	CHECK(count == 5);
	CHECK(r == 4);

	/* nested */
	r = setjmp(jb_outer);
	if (r == 0) {
		int s = setjmp(jb_inner);
		if (s == 0) longjmp(jb_inner, 3);
		CHECK(s == 3);
		longjmp(jb_outer, 4);
	}
	CHECK(r == 4);

	/* across several stack frames */
	r = setjmp(jb_outer);
	if (r == 0) { jump_from_frames(10, 42); CHECK(0); }
	CHECK(r == 42);

	/* out of a recursion 100 deep */
	r = setjmp(jb_outer);
	if (r == 0) { (void)recurse(100); CHECK(0); }
	CHECK(r == 100);

	/* the buffer must be usable again after all this */
	r = setjmp(jb_outer);
	if (r == 0) longjmp(jb_outer, 99);
	CHECK(r == 99);
}

/* ---- signal ---- */
static volatile sig_atomic_t got_sig, sig_calls;
static void on_sig(int s) { got_sig = s; sig_calls++; }

static void test_signal(void)
{
	void (*old)(int);

	old = signal(SIGINT, on_sig);
	CHECK(old == SIG_DFL);
	old = signal(SIGINT, SIG_DFL);
	CHECK(old == on_sig);

	CHECK(signal(SIGUSR1, on_sig) == SIG_DFL);
	got_sig = 0; sig_calls = 0;
	CHECK(raise(SIGUSR1) == 0);
	CHECK(got_sig == SIGUSR1);
	CHECK(sig_calls == 1);
	CHECK(raise(SIGUSR1) == 0);   /* handler stays installed */
	CHECK(sig_calls == 2);

	CHECK(signal(SIGUSR1, SIG_IGN) == on_sig);
	CHECK(raise(SIGUSR1) == 0);
	CHECK(sig_calls == 2);
	CHECK(signal(SIGUSR1, SIG_DFL) == SIG_IGN);

	/* kill(getpid(), sig) is raise() */
	CHECK(signal(SIGUSR2, on_sig) == SIG_DFL);
	CHECK(kill(getpid(), SIGUSR2) == 0);
	CHECK(got_sig == SIGUSR2);
	CHECK(kill(getpid(), 0) == 0);

	/* blocking defers delivery */
	{
		sigset_t s, pend;
		sigemptyset(&s);
		sigaddset(&s, SIGUSR2);
		sig_calls = 0;
		CHECK(sigprocmask(SIG_BLOCK, &s, NULL) == 0);
		CHECK(raise(SIGUSR2) == 0);
		CHECK(sig_calls == 0);
		CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR2) == 1);
		CHECK(sigprocmask(SIG_UNBLOCK, &s, NULL) == 0);
		CHECK(sig_calls == 1);
	}

	errno = 0;
	CHECK(signal(0, on_sig) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(signal(_NSIG, on_sig) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(signal(-1, on_sig) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(signal(SIGKILL, on_sig) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(raise(0) == -1 && errno == EINVAL);

	/* abort() in the main process would fail the test; see test_abort_child */
}

/* ---- basename/dirname ---- */
static void check_base(const char *in, const char *base, const char *dir)
{
	char buf[64], *r;
	strcpy(buf, in);
	r = basename(buf);
	if (strcmp(r, base)) { fails++; printf("FAIL %s:%d: basename(\"%s\") = \"%s\", want \"%s\"\n", __FILE__, __LINE__, in, r, base); }
	strcpy(buf, in);
	r = dirname(buf);
	if (strcmp(r, dir)) { fails++; printf("FAIL %s:%d: dirname(\"%s\") = \"%s\", want \"%s\"\n", __FILE__, __LINE__, in, r, dir); }
}

static void test_libgen(void)
{
	check_base("/a/b/c", "c", "/a/b");
	check_base("/a/b/c/", "c", "/a/b");
	check_base("/a/b//c//", "c", "/a/b");
	check_base("a", "a", ".");
	check_base("", ".", ".");
	check_base("/", "/", "/");
	check_base("//", "/", "/");
	check_base("///", "/", "/");
	check_base("a/b", "b", "a");
	check_base("/a", "a", "/");
	check_base("a/", "a", ".");
	check_base("/usr/", "usr", "/");
	CHECK(!strcmp(basename(NULL), "."));
	CHECK(!strcmp(dirname(NULL), "."));
	/* Windows flavours */
	check_base("C:\\x\\y", "y", "C:\\x");
	check_base("C:\\", "\\", "C:\\");
	check_base("C:/foo", "foo", "C:/");
}

/* ---- locale ---- */
static void test_locale(void)
{
	char *l;
	struct lconv *lc;
	l = setlocale(LC_ALL, "C");
	CHECK(l && !strcmp(l, "C"));
	l = setlocale(LC_ALL, "");
	CHECK(l != NULL);
	l = setlocale(LC_ALL, NULL);
	CHECK(l && !strcmp(l, "C"));
	l = setlocale(LC_ALL, "POSIX");
	CHECK(l && !strcmp(l, "C"));
	l = setlocale(LC_NUMERIC, "C");
	CHECK(l && !strcmp(l, "C"));
	CHECK(setlocale(LC_ALL, "xx_YY.UTF-8") == NULL);
	errno = 0;
	CHECK(setlocale(LC_ALL + 1, "C") == NULL && errno == EINVAL);
	lc = localeconv();
	CHECK(lc != NULL);
	CHECK(lc && !strcmp(lc->decimal_point, "."));
	CHECK(lc && !strcmp(lc->thousands_sep, ""));
	CHECK(lc && lc->frac_digits == 127);
}

/* ---- exit/atexit ---- */
static int order[4];
static int norder;
static void h1(void) { order[norder++] = 1; }
static void h2(void) { order[norder++] = 2; }
static void h3(void)
{
	order[norder++] = 3;
	/* main has returned: nothing else can report a failure, so do it here */
	if (norder != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3) {
		printf("FAIL %s:%d: atexit order %d %d %d\n", __FILE__, __LINE__, order[0], order[1], order[2]);
		fflush(stdout);
		_Exit(1);
	}
}

/* ---- abort() in a child ---- */
static void test_abort_child(const char *self)
{
	char *argv[3];
	int pid, status;
	argv[0] = (char *)self;
	argv[1] = (char *)"--abort-child";
	argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) {
		printf("note: cannot spawn \"%s\" (errno %d); abort() child test skipped\n", self, errno);
		return;
	}
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) ? WEXITSTATUS(status) != 0 : WIFSIGNALED(status));

	argv[1] = (char *)"--assert-child";
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	if (pid > 0) {
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) ? WEXITSTATUS(status) != 0 : WIFSIGNALED(status));
	}

	argv[1] = (char *)"--exit-child";
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	if (pid > 0) {
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 23);
	}
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--abort-child")) {
		signal(SIGABRT, SIG_IGN);  /* abort() must still die */
		abort();
	}
	if (argc > 1 && !strcmp(argv[1], "--assert-child")) {
		volatile int zero = 0;
		/* prints "Assertion failed: ..." to stderr: expected noise */
		assert(zero == 1);
		return 0;  /* assert did not fire: child "succeeds" -> parent fails */
	}
	if (argc > 1 && !strcmp(argv[1], "--exit-child")) {
		atexit(h1);
		exit(23);
	}

	unlink("misc-exit-flush.tmp");
	test_env();
	test_sched();
	test_mlockall();
	test_semaphore();
	test_mqueue();
	test_aio();
	test_system();
	test_setjmp();
	test_signal();
	test_libgen();
	test_locale();
	test_abort_child(argv[0]);

	/* exit flushes stdio: write without fclose and let exit() do it */
	{
		FILE *f = fopen("misc-exit-flush.tmp", "w");
		if (f) fputs("flushed by exit\n", f);
		/* left for exit() to flush; removed on the next run */
	}

	CHECK(atexit(h3) == 0);
	CHECK(atexit(h2) == 0);
	CHECK(atexit(h1) == 0);
	/* registered h3, h2, h1: they run in reverse, h1 h2 h3; h3 checks the order */

	if (!fails) printf("misc: all tests passed\n");
	return fails != 0;
}
