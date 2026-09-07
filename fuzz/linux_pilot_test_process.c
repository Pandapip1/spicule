/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux process/fork/wait pilot smoke test -- NOT part of spicule, same
 * standing as fuzz/ntstubs.c's own native-build scaffolding and
 * fuzz/linux_pilot_test.c's for the mman/unistd-fd-ops pilot this one
 * sits alongside.
 *
 * Exercises the REAL spicule public entry points fork()/waitpid() (from
 * the real src/process/fork.c and src/process/wait.c, statically linked
 * here) and close()/read()/write() (from the already-proven mman/
 * unistd-fd-ops pilot's own front doors) against the new
 * src/process/linux/plat_process.c backend, running as a real, native
 * aarch64 Linux process on this host -- no Wine, no emulation.
 *
 * Three things this test does NOT go through spicule for, each raw-
 * syscall scaffolding standing in for a subsystem this pilot deliberately
 * does not port: pipe(2) itself (src/unistd/pipe.c
 * still calls the NT-only __pipe_handles(), never ported here -- a raw
 * pipe2(2) stands in, exactly the way linux_pilot_test.c's raw openat(2)
 * stands in for open()); _exit() (src/exit/exit.c, another unported
 * subsystem -- a raw exit_group(2) stands in); and the WUNTRACED
 * stopped-child synchronization __plat_process_resume()'s own test needs
 * (the real mechanism is signal.c's self-stop-marker machinery, entirely
 * unported here -- see fuzz/linux_pilot_harness_process.c's own stub for
 * __sig_consume_child_stop() -- so a raw wait4(WUNTRACED) poll, done
 * directly in this test file rather than through the backend under test,
 * confirms the child really is stopped before __plat_process_resume()
 * -- the real function this test is proving -- is ever called).
 */
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include "libc.h"
#include "plat_process.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern int memcmp(const void *, const void *, size_t);

#define SYS_pipe2      59
#define SYS_kill       129
#define SYS_getpid     172
#define SYS_exit_group 94
#define SYS_wait4      260
#define SYS_openat     56
#define SYS_close      57
#define SYS_nanosleep  101

#define AT_FDCWD_LX  (-100)
#define SIGSTOP_LX   19
#define WUNTRACED_LX 2
#define WNOHANG_LX   1

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

/* Raw pipe2(2), installed into spicule's OWN fd table the same way
 * linux_pilot_test.c installs its raw openat() fd -- see this file's
 * banner for why pipe() itself is out of scope. */
static void make_pipe(int *fd_r, int *fd_w)
{
	int fds[2];
	long ret = syscall(SYS_pipe2, (long)fds, 0L);
	if (ret < 0) { printf("FAIL - raw pipe2() setup (errno=%ld)\n", -ret); failures++; *fd_r = *fd_w = -1; return; }
	*fd_r = __fd_install((HANDLE)(long)(fds[0] + 1), O_RDONLY, __FD_FILE);
	*fd_w = __fd_install((HANDLE)(long)(fds[1] + 1), O_WRONLY, __FD_FILE);
}

/* ---- Test 1: fork() + waitpid() over a real child, through the real -- */
/* ---- front doors, with the child's own write() proven by content ----- */
static void test_fork_wait(void)
{
	const char msg[] = "hello from a real fork()ed spicule child on linux";
	int fd_r, fd_w;
	pid_t pid;

	printf("\n-- test 1: fork()/waitpid() through the real front door --\n");
	make_pipe(&fd_r, &fd_w);
	if (fd_r < 0 || fd_w < 0) return;

	pid = fork();   /* the real front door: src/process/fork.c -> */
	                /* __plat_process_fork() (this pilot's own backend) */
	CHECK(pid >= 0, "fork() succeeded");
	if (pid < 0) return;

	if (pid == 0) {
		/* Child. */
		close(fd_r);
		write(fd_w, msg, sizeof msg - 1);
		close(fd_w);
		/* Bypass the (unported) exit subsystem deliberately -- see this
		 * file's banner -- with a distinctive, easy-to-mistake-for-
		 * nothing-else exit code. */
		syscall(SYS_exit_group, 77L);
		return; /* unreachable */
	}

	/* Parent. */
	{
		char buf[128];
		ssize_t n;
		int status = 0;
		pid_t wpid;

		close(fd_w);
		n = read(fd_r, buf, sizeof buf - 1);
		CHECK(n == (ssize_t)(sizeof msg - 1), "read() got the child's full write()");
		if (n > 0) CHECK(memcmp(buf, msg, (size_t)n) == 0, "child's write() content matches exactly");
		close(fd_r);

		wpid = waitpid(pid, &status, 0);   /* the real front door: */
		                                    /* src/process/wait.c -> */
		                                    /* __plat_process_wait()/ */
		                                    /* __plat_process_exit_code() */
		CHECK(wpid == pid, "waitpid() reaped the right pid");
		CHECK(WIFEXITED(status) != 0, "waitpid() reports normal exit (WIFEXITED)");
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77, "waitpid() reports the exact exit code (77)");
	}
}

/* ---- Test 2: __plat_process_resume(), proven through a real --------- */
/* ---- SIGSTOP/SIGCONT cycle on a real child --------------------------- */
static void test_resume(void)
{
	const char msg[] = "resumed-ok";
	int fd_r, fd_w;
	pid_t pid;

	printf("\n-- test 2: __plat_process_resume() over a really-stopped child --\n");
	make_pipe(&fd_r, &fd_w);
	if (fd_r < 0 || fd_w < 0) return;

	pid = fork();
	CHECK(pid >= 0, "fork() for the resume test succeeded");
	if (pid < 0) return;

	if (pid == 0) {
		long mypid = syscall(SYS_getpid);
		close(fd_r);
		/* Stop this process for real -- the kernel, not this library,
		 * suspends it right here until a SIGCONT arrives. */
		syscall(SYS_kill, mypid, (long)SIGSTOP_LX);
		/* Execution only reaches here after the parent's
		 * __plat_process_resume() call below actually delivers
		 * SIGCONT -- there is no other way past the line above. */
		write(fd_w, msg, sizeof msg - 1);
		close(fd_w);
		syscall(SYS_exit_group, 55L);
		return; /* unreachable */
	}

	/* Parent: confirm -- via a raw wait4(WUNTRACED) probe of our own,
	 * NOT through the backend under test -- that the child has really
	 * reached the kernel's stopped state before calling
	 * __plat_process_resume(), so a pass here cannot be a no-op race
	 * (see this file's banner). Bounded retries: this reports a test
	 * failure rather than hanging the whole build forever if something
	 * is wrong. */
	{
		int stopped = 0;
		int tries;
		close(fd_w);
		for (tries = 0; tries < 200 && !stopped; tries++) {
			int status = 0;
			long wr = syscall(SYS_wait4, (long)pid, (long)&status,
			                  (long)(WUNTRACED_LX | WNOHANG_LX), 0L);
			if (wr == pid && WIFSTOPPED(status)) { stopped = 1; break; }
			{
				struct { long tv_sec; long tv_nsec; } ts;
				ts.tv_sec = 0; ts.tv_nsec = 5000000L; /* 5ms */
				syscall(SYS_nanosleep, (long)&ts, 0L);
			}
		}
		CHECK(stopped, "child really reached the kernel's stopped state (raw wait4/WUNTRACED)");

		if (stopped) {
			int rc = __plat_process_resume((__plat_handle_t)(long)pid);
			CHECK(rc == 0, "__plat_process_resume() reported success");
		}

		{
			char buf[64];
			ssize_t n = read(fd_r, buf, sizeof buf - 1);
			CHECK(n == (ssize_t)(sizeof msg - 1), "child resumed and wrote its post-resume message");
			if (n > 0) CHECK(memcmp(buf, msg, (size_t)n) == 0, "post-resume message content matches");
			close(fd_r);
		}

		{
			int status = 0;
			pid_t wpid = waitpid(pid, &status, 0);
			CHECK(wpid == pid, "waitpid() reaped the resumed child");
			CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 55, "resumed child's exit code is exact (55)");
		}
	}
}

/* ---- Test 3: __plat_is_program() ------------------------------------- */
static void make_file(const char *path, long mode)
{
	long fd = syscall(SYS_openat, (long)AT_FDCWD_LX, path,
	                  (long)(O_CREAT | O_TRUNC | O_WRONLY), mode);
	if (fd >= 0) syscall(SYS_close, fd);
}

static void test_is_program(void)
{
	printf("\n-- test 3: __plat_is_program() --\n");
	make_file("/tmp/spicule-linux-pilot-process-exec", 0755L);
	make_file("/tmp/spicule-linux-pilot-process-noexec", 0644L);

	CHECK(__plat_is_program("/tmp/spicule-linux-pilot-process-exec") == 1,
	      "a regular file with an execute bit is a program");
	CHECK(__plat_is_program("/tmp/spicule-linux-pilot-process-noexec") == 0,
	      "a regular file with no execute bit is not a program");
	CHECK(__plat_is_program("/tmp/spicule-linux-pilot-process-does-not-exist") == 0,
	      "a nonexistent path is not a program");

	syscall(35 /* unlinkat */, (long)AT_FDCWD_LX, "/tmp/spicule-linux-pilot-process-exec", 0L);
	syscall(35 /* unlinkat */, (long)AT_FDCWD_LX, "/tmp/spicule-linux-pilot-process-noexec", 0L);
}

int main(void)
{
	test_fork_wait();
	test_resume();
	test_is_program();

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
