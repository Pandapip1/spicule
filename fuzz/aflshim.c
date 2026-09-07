/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Built only for ENGINE=afl (see fuzz/Makefile). AFL++'s runtime object,
 * afl-compiler-rt.o, calls open/read/write/close/shmat/shmdt/getenv/
 * fork/waitpid/sigaction/signal to talk to afl-fuzz and run its
 * persistent-mode forkserver. Every one of those names is also a strong
 * symbol in spicule, and spicule's wins the ordinary ELF override (the
 * same class of bug STATRENAME fixes for stat()) -- so unpatched,
 * afl-compiler-rt.o reaches spicule's versions instead of the host's.
 * Six failure modes were found by measurement, not anticipated:
 *
 *   1. read/write/close look fds up in spicule's own table (which never
 *      heard of FORKSRV_FD), getenv() searches spicule's environ (emptied
 *      by ntstubs.c for every native test), shmat/shmdt would attach
 *      spicule's simulated address space. Measured: afl-showmap showed the
 *      harness never touching FORKSRV_FD, exiting 0 silently.
 *   2. fork(), once fixed, turned out to be RtlCloneUserProcess, cloning
 *      an entire simulated NT process per test case -- slow enough to
 *      look like a hang (fuzz_string.c took over a second, tripping
 *      afl-fuzz's dry-run timeout).
 *   3. The forkserver child never exits on SIGTERM: spicule's SIGTERM
 *      handler (layered on simulated-NT signal delivery) does a couple
 *      of close()s and returns straight back into the blocking
 *      read(FORKSRV_FD) (measured with strace) -- so shutdown hangs.
 *      __real_sigaction()/signal() below are deliberate no-ops rather
 *      than raw-syscall reimplementations: they report success without
 *      installing anything, leaving SIGTERM's kernel default ("terminate
 *      the process") in effect. This loses AFL++'s own crash diagnostics
 *      message (the crash itself is still seen via wait4()) and an
 *      in-process SIGALRM timeout (every caller already wraps `timeout`
 *      around the whole run) -- both already covered elsewhere, a better
 *      trade than a hand-rolled kernel ABI shim with no way to be sure
 *      it's right (kernel sigset_t is 8 bytes, not glibc's 128, and a
 *      real handler needs a correct SA_RESTORER trampoline).
 *   4. Once (1)-(3) were fixed, fork() succeeded and reported to
 *      afl-fuzz, then waitpid() on the new child hit spicule's own
 *      process table, which knew nothing about a bare-syscall child and
 *      answered ECHILD -- afl-compiler-rt.o's error path then exit()s,
 *      which afl-fuzz sees as "Unable to communicate with fork server"
 *      (measured with strace: fork() and write() both succeed, then
 *      waitpid() ECHILD and exit_group).
 *   5-6. Two failures sharing one cause, in two objects, costliest to
 *      find because the symptom (afl-fuzz's dry run timing out) looked
 *      like a performance problem: once the persistent loop started,
 *      the forked child did nothing until the watchdog SIGKILLed it.
 *      AFL++'s testcase shared-memory transfer is gated by
 *      `__afl_sharedmem_fuzzing`, cleared whenever a check calls
 *      fcntl(FORKSRV_FD, F_GETFD) unredirected: fuzz/Makefile's
 *      AFL_RTDIR loop redirected getenv/fork/sigaction but not fcntl,
 *      and aflpp_driver.o (a separate archive, needing its own
 *      copy-and-patch step) does the identical check a second time and
 *      also needed getenv redirected, since its `||` chain
 *      short-circuited before reaching fcntl().
 *
 * The fix mirrors STATRENAME: local, objcopied copies of the two objects
 * that need it, redirecting exactly the undefined references below to
 * the __real_* names here, so only those two objects reach the host's
 * real kernel/environment (or a real no-op, for sigaction/signal). pipe
 * is left alone -- the forkserver reaches this point through spicule's
 * version without issue. Patch what measurement shows is broken, not
 * everything that could plausibly be: kill() was reasoned safe right up
 * until the SIGCONT hang showed it wasn't.
 *
 * Raw syscall()s throughout, for the same reason ntstubs.c uses them: a
 * plain read()/write()/... call here would hit the spicule symbol this
 * file exists to route around. syscall() itself isn't redirected, so it
 * still reaches glibc's thin ABI-stable wrapper.
 *
 * __real_getenv() reads /proc/self/environ rather than taking a saved
 * envp pointer from ntstubs.c (tried first): ntstubs.c's constructor
 * runs at priority 200, but AFL++'s own coverage-bitmap constructor
 * needs __AFL_SHM_ID before that (implementation-reserved priorities
 * 0-100, which a user constructor can't request). Measured: with a saved
 * envp pointer, afl-showmap still reported "No instrumentation detected"
 * because AFL++'s constructor ran first and found spicule's still-empty
 * environ. /proc/self/environ has no such ordering dependency -- the
 * kernel populates it before any constructor runs.
 */
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int __real_open(const char *path, int flags, ...);
long __real_read(int fd, void *buf, unsigned long n);
int __real_close(int fd);

#define ENVBUF_SIZE 65536
#define ENVPTR_MAX  1024
static char envbuf[ENVBUF_SIZE];
static char *envptr[ENVPTR_MAX];
static int env_loaded;

static void load_real_environ(void)
{
	int fd, n, total = 0, i, count = 0;
	char *p;

	if (env_loaded) return;
	env_loaded = 1;

	fd = __real_open("/proc/self/environ", O_RDONLY);
	if (fd < 0) return;
	while (total < (int)sizeof(envbuf) - 1) {
		n = (int)__real_read(fd, envbuf + total, sizeof(envbuf) - 1 - total);
		if (n <= 0) break;
		total += n;
	}
	__real_close(fd);
	envbuf[total] = 0;

	for (p = envbuf, i = 0; p < envbuf + total && count < ENVPTR_MAX - 1; p += i + 1) {
		i = (int)strlen(p);
		envptr[count++] = p;
	}
	envptr[count] = 0;
}

long __real_read(int fd, void *buf, unsigned long n)
{
	return syscall(SYS_read, fd, buf, n);
}

long __real_write(int fd, const void *buf, unsigned long n)
{
	return syscall(SYS_write, fd, buf, n);
}

int __real_close(int fd)
{
	return (int)syscall(SYS_close, fd);
}

/* The classic fork(2) syscall, not glibc's wrapper (which does its own
 * pthread_atfork/tid bookkeeping this file has no business touching) and
 * not spicule's (see the file comment above for why that one is wrong
 * here specifically, not just unneeded). */
int __real_fork(void)
{
	return (int)syscall(SYS_fork);
}

/* wait4(2) directly: a real child of a real fork() needs the kernel's
 * own accounting, not spicule's process table, which has no entry for a
 * child __real_fork() created -- see the file comment's fourth failure
 * for what asking spicule's waitpid() about it produces instead
 * (ECHILD, immediately, every time). */
#define SYS_wait4 61
int __real_waitpid(int pid, int *status, int options)
{
	return (int)syscall(SYS_wait4, pid, status, options, 0);
}

/* fcntl(2), for aflpp_driver.o (libAFLDriver.a) -- see this file's
 * banner for the fifth failure this one is.  Only ever called here with
 * F_GETFD/F_SETFD/F_GETFL/F_SETFL, none of which read the third argument
 * as anything but an integer, so a plain va_arg(long) covers every
 * caller without needing to know which command was passed -- the same
 * simplification musl's own fcntl() makes internally. */
#define SYS_fcntl 72
int __real_fcntl(int fd, int cmd, ...)
{
	long arg;
	va_list ap;
	va_start(ap, cmd);
	arg = va_arg(ap, long);
	va_end(ap);
	return (int)syscall(SYS_fcntl, fd, cmd, arg);
}

/* raise(SIGSTOP), from __afl_persistent_loop() -- see this file's
 * banner for the sixth failure, the one that took longest to find
 * because the symptom (a silent, syscall-free hang) looked nothing like
 * its cause.  AFL++'s persistent loop synchronises with the forkserver
 * parent by stopping itself: the parent's wait4(..., WUNTRACED) detects
 * the real kernel STOPPED state, refills the shared testcase buffer in
 * place (the same memory, inherited by fork()), and SIGCONTs the child.
 * spicule's raise() -- layered on this codebase's own simulated signal
 * delivery, the same machinery the sigaction()/signal() no-ops above
 * exist to route around -- does not put the process into that real
 * kernel state, so the parent's wait4() never returns and the child
 * never resumes: exactly the "closes 198/199, then nothing, for a full
 * second" hang strace showed, with no syscall to explain it because
 * spicule's raise() never reached one. raise(sig) is POSIX sugar for
 * kill(getpid(), sig); this spells that out directly with two raw
 * syscalls rather than also redirecting kill() and getpid() themselves,
 * since nothing else here calls either of those under names this file
 * would otherwise have to chase down. */
#define SYS_getpid 39
#define SYS_kill   62
int __real_raise(int sig)
{
	return (int)syscall(SYS_kill, syscall(SYS_getpid), sig);
}

/* kill(2), for the other half of the same mechanism: after detecting a
 * persistent-mode child's real SIGSTOP (via __real_waitpid's WUNTRACED,
 * itself only meaningful because raise() above delivers a real one),
 * afl-compiler-rt.o's forkserver loop resumes it for the next iteration
 * with kill(child_pid, SIGCONT) rather than forking again -- and that
 * call needs the same redirection raise() did, for the same reason:
 * spicule's kill() does not deliver a real SIGCONT to a real stopped
 * process, so the child never wakes and the loop hangs on its next
 * wait4() until afl-fuzz's own watchdog SIGKILLs everything a second
 * later.  Measured with strace: the first SIGSTOP and its WIFSTOPPED
 * detection both work (raise() already fixed), and the very next thing
 * in the trace is the parent's second wait4() never returning -- no
 * SIGCONT delivered in between, anywhere. */
int __real_kill(int pid, int sig)
{
	return (int)syscall(SYS_kill, pid, sig);
}

/* afl-compiler-rt.o only ever opens existing files (its own coverage
 * bitmap's control paths, when present), never O_CREAT, but open() is
 * variadic in the real prototype and this has to link against calls
 * built expecting that ABI. */
int __real_open(const char *path, int flags, ...)
{
	unsigned mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, unsigned);
		va_end(ap);
	}
	return (int)syscall(SYS_open, path, flags, mode);
}

void *__real_shmat(int shmid, const void *shmaddr, int shmflg)
{
	return (void *)syscall(SYS_shmat, shmid, shmaddr, shmflg);
}

int __real_shmdt(const void *shmaddr)
{
	return (int)syscall(SYS_shmdt, shmaddr);
}

char *__real_getenv(const char *name)
{
	size_t len;
	int i;
	if (!name) return 0;
	load_real_environ();
	len = strlen(name);
	for (i = 0; envptr[i]; i++)
		if (!strncmp(envptr[i], name, len) && envptr[i][len] == '=')
			return envptr[i] + len + 1;
	return 0;
}

/* Deliberate no-ops -- see the file comment's third section for why a
 * raw-syscall reimplementation is not worth the ABI risk here.  Report
 * success, install nothing, so SIGTERM (and anything else AFL++ wanted
 * to catch) keeps the kernel's own default disposition. */
int __real_sigaction(int signum, const void *act, void *oldact)
{
	(void)signum; (void)act; (void)oldact;
	return 0;
}

void *__real_signal(int signum, void *handler)
{
	(void)signum; (void)handler;
	return 0;
}
