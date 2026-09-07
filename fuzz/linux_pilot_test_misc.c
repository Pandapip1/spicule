/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux platform pilot smoke test for the exit/misc/select/signal
 * extension -- NOT part of spicule, same standing as fuzz/
 * linux_pilot_test.c (the mman/unistd pilot this extends) and
 * fuzz/ntstubs.c.
 *
 * Exercises:
 *   - src/exit/linux/plat_exit.c's __plat_terminate(), directly (see
 *     "exit-test" mode below: exit.c's own front door, __exit_internal(),
 *     pulls in __child_resume_stopped() (src/process/children.c) and
 *     __stdio_exit(), both from subsystems no Linux backend exists for
 *     yet in this tree, so this calls the platform function itself --
 *     the one syscall plat_exit.h actually contracts for).
 *   - src/misc/linux/plat_misc.c via the REAL src/misc/sched.c and
 *     src/misc/resource.c front doors (sched_yield(), getrusage(),
 *     getpriority()/setpriority() against a real foreign pid --  this
 *     process's own parent -- getrlimit()/setrlimit()), and
 *     __plat_write_start_offset() directly (a leaf lseek(2) wrapper
 *     with no meaningful front door of its own to speak of beyond
 *     src/misc/resource.c's RLIMIT_FSIZE machinery, which this test
 *     does not need to pull in just to prove the wrapper works).
 *   - src/select/linux/plat_select.c's functions directly, against
 *     real kernel objects (a pipe, a socketpair, an eventfd via this
 *     session's own __plat_sigevent_create()) set up with raw
 *     syscalls -- select()/poll()'s own front doors (src/select/
 *     select.c, poll.c) pull in src/signal/'s lock machinery and the
 *     real fd table, well beyond plat_select.h's own scope to stand up
 *     just for this; see tools/linux-build-misc.sh's own note.
 *   - src/signal/linux/plat_signal.c's implemented functions directly:
 *     event create/wait/peek against a real eventfd, and
 *     __plat_kill_open()/__plat_process_suspend()/__plat_kill_terminate()
 *     against a REAL, independent OS process (a `sleep` the build
 *     script backgrounds for this purpose -- see "signal-test" mode
 *     below) so this never has to SIGSTOP the test binary's own
 *     process, which would deadlock it with nothing left running to
 *     send the SIGCONT this session does not own
 *     (__plat_process_resume() is the process subsystem's).
 */
#include <sched.h>
#include <sys/resource.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "libc.h"
#include "plat_exit.h"
#include "plat_misc.h"
#include "plat_select.h"
#include "plat_signal.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int fflush(void *stream);

/* __plat_terminate() (src/exit/linux/plat_exit.c) is a raw exit_group(2)
 * syscall with no libc runtime involved at all -- correct, and exactly
 * what it should be, but it means the host glibc this test binary is
 * otherwise linked against (for printf() etc., same as fuzz/
 * linux_pilot_test.c already relies on) never gets a chance to flush
 * stdout's userspace buffer the way returning from main() normally
 * would. fflush(NULL) (flushes every open stream, ISO C, no need to
 * name stdout specifically) before every __plat_terminate() call below
 * is this test's own bookkeeping, not part of what is being proven. */
#define TERMINATE(code) do { fflush(0); __plat_terminate(code); } while (0)

#define SYS_openat     56
#define SYS_unlinkat   35
#define SYS_close      57
#define SYS_read       63
#define SYS_write      64
#define SYS_pipe2      59
#define SYS_socketpair 199
#define SYS_prlimit64  261
#define SYS_clock_gettime 113
#define AT_FDCWD (-100)

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

static long atoi_l(const char *s)
{
	long v = 0;
	int neg = 0;
	if (*s == '-') { neg = 1; s++; }
	while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
	return neg ? -v : v;
}

static long long now_ms(void)
{
	struct timespec ts;
	syscall(SYS_clock_gettime, 1L /* CLOCK_MONOTONIC */, &ts);
	return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

/* ---- src/misc/linux/plat_misc.c, via the real sched.c/resource.c front
 * doors, plus __plat_write_start_offset() directly ------------------- */
static void test_misc(void)
{
	pid_t ppid;
	int nice_value;
	struct rusage ru;
	struct rlimit rl, rl2;

	CHECK(sched_yield() == 0, "sched_yield() (src/misc/sched.c -> __plat_yield())");

	memset(&ru, 0, sizeof ru);
	CHECK(getrusage(RUSAGE_SELF, &ru) == 0,
	      "getrusage(RUSAGE_SELF) (-> __plat_process_times_self(), real getrusage(2))");

	/* A real, independent, foreign process -- this test's own parent
	 * (the shell tools/linux-build-misc.sh runs it from) -- to actually
	 * exercise __plat_process_open()/__plat_priority_get() rather than
	 * resource.c's self fast path, which never reaches this session's
	 * backend at all. */
	ppid = getppid();
	errno = 0;
	nice_value = getpriority(PRIO_PROCESS, (id_t)ppid);
	CHECK(errno == 0 && nice_value >= -20 && nice_value <= 19,
	      "getpriority(PRIO_PROCESS, parent pid) (-> __plat_process_open()+__plat_priority_get(), real pidfd_open(2)+getpriority(2))");

	/* setpriority() on a real foreign (non-child) pid is refused by
	 * src/misc/resource.c's own front-door logic unconditionally
	 * (EPERM, "this library did not spawn it") -- see that file's own
	 * comment -- but reaching that refusal still round-trips through
	 * __plat_process_open() and plat_fd.h's __plat_close() on the
	 * pidfd it opens, which is exactly the integration point this
	 * session's pidfd-based handle redesign exists to prove: a process
	 * handle __plat_process_open() vends really is safely closeable by
	 * the SAME close function unistd's Linux backend already owns. */
	errno = 0;
	CHECK(setpriority(PRIO_PROCESS, (id_t)ppid, 5) == -1 && errno == EPERM,
	      "setpriority() on a foreign non-child pid is EPERM (front door's own policy; exercises __plat_process_open()+__plat_close() round-trip)");

	/* RLIMIT_NPROC: safe to lower on this process (no forking happens
	 * here), and independently re-read via a raw prlimit64(2) syscall
	 * afterward -- not through any spicule call -- to prove
	 * __plat_job_apply_limits() actually reached the real kernel limit,
	 * the same "verified through an independent read(), not just
	 * through the mapping that wrote it" standard fuzz/
	 * linux_pilot_test.c's own msync() check already set. */
	CHECK(getrlimit(RLIMIT_NPROC, &rl) == 0, "getrlimit(RLIMIT_NPROC)");
	rl2 = rl;
	rl2.rlim_cur = 123;
	CHECK(setrlimit(RLIMIT_NPROC, &rl2) == 0, "setrlimit(RLIMIT_NPROC, 123) (-> __plat_job_apply_limits(), real prlimit64(2))");
	{
		unsigned long long lim[2];
		long ret = syscall(SYS_prlimit64, 0L, 6L /* RLIMIT_NPROC */, 0L, lim);
		CHECK(ret == 0 && lim[0] == 123ULL,
		      "raw prlimit64(2) read-back confirms the kernel's own RLIMIT_NPROC.rlim_cur is now 123");
	}
	CHECK(getrlimit(RLIMIT_NPROC, &rl) == 0 && rl.rlim_cur == 123,
	      "getrlimit(RLIMIT_NPROC) reports back the value setrlimit() just recorded");

	/* __plat_write_start_offset(): a leaf lseek(2) wrapper, tested
	 * directly against a real file set up with raw openat/write (the
	 * same "raw syscall stands in for an out-of-scope front door"
	 * pattern fuzz/linux_pilot_test.c's own use of raw openat()
	 * already established -- open()'s own front door is NT-path-only
	 * and out of scope here too, see this file's own banner). */
	{
		long rawfd = syscall(SYS_openat, AT_FDCWD, "/tmp/spicule-linux-pilot-misc-test",
		                     0101 /* O_CREAT|O_WRONLY */ | 01000 /* O_TRUNC */, 0644L);
		__plat_handle_t h;
		long long off;

		CHECK(rawfd >= 0, "raw openat() setup for __plat_write_start_offset() test");
		h = (__plat_handle_t)(rawfd + 1);
		syscall(SYS_write, rawfd, "hello", 5L);
		CHECK(__plat_write_start_offset(h, 0, &off) == 0 && off == 5,
		      "__plat_write_start_offset(append=0) reports the current (post-write) position via SEEK_CUR");
		syscall(SYS_write, rawfd, "world!!!", 8L); /* cursor was already at 5; file is now 13 bytes */
		CHECK(__plat_write_start_offset(h, 1, &off) == 0 && off == 13,
		      "__plat_write_start_offset(append=1) reports the file's real end via SEEK_END");
		syscall(SYS_close, rawfd);
		syscall(SYS_unlinkat, AT_FDCWD, "/tmp/spicule-linux-pilot-misc-test", 0L);
	}
}

/* ---- src/select/linux/plat_select.c, directly, against real kernel
 * objects ------------------------------------------------------------- */
static void test_select(void)
{
	int pfd[2], sv[2];
	unsigned long ravail, wquota;
	__plat_handle_t rh, wh, s0, ev;
	long long t0, t1;

	CHECK(syscall(SYS_pipe2, pfd, 0L) == 0, "raw pipe2() setup for __plat_pipe_probe() test");
	rh = (__plat_handle_t)(long)(pfd[0] + 1);
	wh = (__plat_handle_t)(long)(pfd[1] + 1);

	CHECK(__plat_pipe_probe(wh, &ravail, &wquota) == 1 && wquota > 0,
	      "__plat_pipe_probe() on an empty pipe's write end reports connected and writable");
	CHECK(__plat_pipe_probe(rh, &ravail, &wquota) == 1 && ravail == 0,
	      "__plat_pipe_probe() on an empty pipe's read end reports 0 bytes available");
	CHECK(__plat_wait_ready(rh) == 0, "__plat_wait_ready() on an empty pipe's read end is not ready");

	syscall(SYS_write, pfd[1], "hi", 2L);
	CHECK(__plat_pipe_probe(rh, &ravail, &wquota) == 1 && ravail == 2,
	      "__plat_pipe_probe() sees the 2 bytes just written (real read(2)/ioctl(FIONREAD) round-trip)");
	CHECK(__plat_wait_ready(rh) == 1, "__plat_wait_ready() on the now-readable pipe end reports ready");

	syscall(SYS_close, pfd[1]);
	CHECK(__plat_pipe_probe(rh, &ravail, &wquota) == 0,
	      "__plat_pipe_probe() reports 'disconnected' (0) once the peer end is closed, per its own contract");
	syscall(SYS_close, pfd[0]);

	CHECK(__plat_pipe_wqa_trustworthy() == 1, "__plat_pipe_wqa_trustworthy() is unconditionally 1 on this backend");

	CHECK(syscall(SYS_socketpair, 1L /* AF_UNIX */, 1L /* SOCK_STREAM */, 0L, sv) == 0,
	      "raw socketpair() setup for __plat_socket_probe() test");
	s0 = (__plat_handle_t)(long)(sv[0] + 1);
	{
		int cr, cw, hup;
		__plat_socket_probe(s0, &cr, &cw, &hup);
		CHECK(cw == 1 && cr == 0 && hup == 0, "__plat_socket_probe() on a fresh socketpair end: writable, not readable, not hung up");
		syscall(SYS_write, sv[1], "hey", 3L);
		__plat_socket_probe(s0, &cr, &cw, &hup);
		CHECK(cr == 1, "__plat_socket_probe() sees data written from the peer end");
		syscall(SYS_close, sv[1]);
		__plat_socket_probe(s0, &cr, &cw, &hup);
		CHECK(hup == 1 && cr == 1 && cw == 1, "__plat_socket_probe() reports hup once the peer closes");
	}
	syscall(SYS_close, sv[0]);

	ev = __plat_sigevent_create(0);
	CHECK(ev != __PLAT_HANDLE_NULL, "__plat_sigevent_create(0) for __plat_wait_multiple() test");
	{
		unsigned long long one = 1;
		syscall(SYS_write, (long)((long)ev - 1), &one, 8L);
	}
	t0 = now_ms();
	__plat_wait_multiple(&ev, 1, 50000000LL /* 5s, should return immediately */, 0);
	t1 = now_ms();
	CHECK(t1 - t0 < 2000, "__plat_wait_multiple() returns promptly when the handle is already signalled, not after the full 5s budget");
	/* __plat_event_peek() is NOT this check any more (src/signal/linux/
	 * plat_signal.c's own banner on it): it was redesigned to take a
	 * struct spicule_linux_sync* from the sync-object domain
	 * (src/thread/linux/plat_thread.c's __plat_event_set()), not this
	 * file's box()/unbox() eventfd domain `ev` is in here.
	 * __plat_wait_ready() (src/select/linux/plat_select.c) is that
	 * domain's own nonblocking, non-consuming poll() check -- the same
	 * one this test already uses on pipes/sockets above. */
	CHECK(__plat_wait_ready(ev) == 1, "the eventfd is still readable after __plat_wait_multiple() (poll() does not consume it)");
	/* The real close() front door (src/unistd/close.c), not a raw
	 * syscall: __plat_sigevent_create() registers this eventfd's real
	 * kernel fd in the real __fds[] table via __fd_install() (see
	 * main()'s own __fd_init() comment above), so a raw
	 * syscall(SYS_close, ...) here would free the real descriptor but
	 * leave that table slot marked occupied forever -- the next
	 * __fd_alloc(0) would then skip it and hand back a HIGHER slot than
	 * the kernel's own reused (now lower) fd number for the next
	 * eventfd, breaking the same box()/unbox() "same number" invariant
	 * all over again. Every other raw close() in this file targets a
	 * fd that was never installed in the table to begin with (this
	 * pilot's pipe/socketpair/openat setup is deliberately raw syscalls
	 * only -- see this file's own banner), so those stay raw. */
	close((int)((long)ev - 1));

	t0 = now_ms();
	__plat_delay(500000LL /* 50ms, 100ns ticks */, 0);
	t1 = now_ms();
	CHECK(t1 - t0 >= 30, "__plat_delay(50ms) actually blocks for a real, measurable interval");

	t0 = __plat_now_100ns();
	t1 = __plat_now_100ns();
	CHECK(t1 >= t0, "__plat_now_100ns() is monotonically non-decreasing across two immediate calls");
}

/* ---- src/signal/linux/plat_signal.c, directly ----------------------- */
static void test_signal_events(void)
{
	__plat_handle_t ev;
	long long t0, t1;

	ev = __plat_sigevent_create(1);
	CHECK(ev != __PLAT_HANDLE_NULL, "__plat_sigevent_create(1) (initially signalled)");
	/* __plat_event_peek() no longer applies to this eventfd domain --
	 * see the identical note above, test_select(). __plat_wait_ready()
	 * (non-consuming) plus a real, direct consuming read(2) reproduces
	 * the same "peek, then auto-reset" check this used to make through
	 * __plat_event_peek(), using the EFD_SEMAPHORE counter's own real
	 * semantics (one unit consumed per successful read(2), the same
	 * primitive src/signal/linux/plat_signal.c's own __plat_signal_wait()
	 * uses to consume this domain's handle). */
	CHECK(__plat_wait_ready(ev) == 1, "the initial signal is visible before anything reads it");
	{
		unsigned long long val = 0;
		long n = syscall(SYS_read, (long)((long)ev - 1), &val, 8L);
		CHECK(n == 8 && val == 1, "a real read(2) consumes exactly the one initial signal");
	}
	CHECK(__plat_wait_ready(ev) == 0, "auto-reset: after that read, nothing is left to see");
	close((int)((long)ev - 1)); /* real close() -- see test_select()'s own comment on why */

	ev = __plat_sigevent_create(0);
	CHECK(ev != __PLAT_HANDLE_NULL, "__plat_sigevent_create(0) (not initially signalled)");

	t0 = now_ms();
	__plat_signal_wait(ev, 1 /* has_timeout */, 300000LL /* 30ms, 100ns ticks */);
	t1 = now_ms();
	CHECK(t1 - t0 >= 15, "__plat_signal_wait() on an unset event actually waits out its timeout (real ppoll(2))");

	{
		unsigned long long one = 1;
		syscall(SYS_write, (long)((long)ev - 1), &one, 8L);
	}
	t0 = now_ms();
	__plat_signal_wait(ev, 1 /* has_timeout */, 50000000LL /* 5s */);
	t1 = now_ms();
	CHECK(t1 - t0 < 2000, "__plat_signal_wait() wakes promptly once the event is signalled, not after the full 5s budget");

	close((int)((long)ev - 1)); /* real close() -- see test_select()'s own comment on why */

	CHECK(__plat_segv_code((void *)&failures) == SEGV_ACCERR,
	      "__plat_segv_code() on this process's own mapped .bss reports SEGV_ACCERR (mapped, real msync(2) probe)");
	CHECK(__plat_segv_code((void *)0x1) == SEGV_MAPERR,
	      "__plat_segv_code() on an address with no real mapping reports SEGV_MAPERR");
}

/* Against a REAL, independent OS process -- tools/linux-build-misc.sh
 * backgrounds a `sleep` for this purpose and passes its pid here, so
 * this test never has to SIGSTOP its own process (see this file's own
 * banner). */
static void test_signal_process(pid_t target)
{
	__plat_handle_t h = __PLAT_HANDLE_NULL;
	__plat_handle_t h2 = __PLAT_HANDLE_NULL;
	__plat_handle_t process = __PLAT_HANDLE_NULL;

	CHECK(__plat_kill_open(target, 1, &h) == 0,
	      "__plat_kill_open() on the real background `sleep` process (real kill(pid,0) probe)");
	if (h == __PLAT_HANDLE_NULL) return;

	CHECK(__plat_process_open_checked(target, &process) == 0,
	      "__plat_process_open_checked() opens a pidfd for the sleep process");
	if (process != __PLAT_HANDLE_NULL) {
		CHECK(__plat_process_alive(process) == 1,
		      "__plat_process_alive() reports the sleep process alive via its pidfd");
		syscall(SYS_close, (long)((long)process - 1));
	}

	CHECK(__plat_process_suspend(h) == 0,
	      "__plat_process_suspend() (real pidfd_send_signal(SIGSTOP)) on the sleep process");

	/* Give the kernel a moment to actually apply the stop before
	 * checking /proc for it. */
	__plat_delay(500000LL /* 50ms */, 0);
	{
		char path[64], buf[512];
		int i = 0, fd;
		const char prefix[] = "/proc/";
		long n;
		for (; prefix[i]; i++) path[i] = prefix[i];
		{
			pid_t p = target;
			char digits[16];
			int nd = 0;
			if (p == 0) digits[nd++] = '0';
			while (p > 0) { digits[nd++] = (char)('0' + p % 10); p /= 10; }
			while (nd > 0) path[i++] = digits[--nd];
		}
		{
			const char suffix[] = "/stat";
			int j = 0;
			for (; suffix[j]; j++) path[i++] = suffix[j];
			path[i] = 0;
		}
		fd = (int)syscall(SYS_openat, AT_FDCWD, path, 0L /* O_RDONLY */, 0L);
		CHECK(fd >= 0, "opened /proc/<sleep pid>/stat to independently verify the stop");
		if (fd >= 0) {
			n = syscall(SYS_read, (long)fd, buf, 511L);
			if (n > 0) buf[n] = 0; else buf[0] = 0;
			syscall(SYS_close, fd);
			{
				/* Field 3 of /proc/pid/stat is the single-character
				 * process state; 'T' is "stopped (on a signal)" -- the
				 * kernel's own independent confirmation that
				 * __plat_process_suspend()'s SIGSTOP really landed,
				 * not just that the syscall returned 0. */
				int paren = 0, field = 1, k;
				char state = 0;
				for (k = 0; buf[k]; k++) {
					if (buf[k] == ')' && paren) { field = 2; continue; }
					if (buf[k] == '(') paren = 1;
					if (field == 2 && buf[k] == ' ') { state = buf[k + 1]; break; }
				}
				CHECK(state == 'T', "/proc/<pid>/stat independently confirms the process is really stopped ('T')");
			}
		}
	}

	CHECK(__plat_kill_open(target, 0, &h2) == 0, "__plat_kill_open() a second handle to the same (stopped) process");
	CHECK(__plat_kill_terminate(h2, 0) == 0,
	      "__plat_kill_terminate() (real pidfd_send_signal(SIGKILL)) succeeds even against a stopped process");
	syscall(SYS_close, (long)((long)h2 - 1));
	syscall(SYS_close, (long)((long)h - 1));
}

int main(int argc, char **argv)
{
	/* __plat_sigevent_create() (src/signal/linux/plat_signal.c) now
	 * registers its eventfd through the REAL src/internal/fd.c
	 * __fd_install() (see that file's own commit message: "wake_event's
	 * eventfd is now registered through __fd_install()"), and box()es
	 * the SLOT __fd_install() hands back, not the raw kernel fd
	 * eventfd2(2) returned -- every other plat_signal.c/plat_select.c
	 * function that unbox()es an event handle then uses that number
	 * directly in a real syscall, so the two must be the same number.
	 * They only are if the __fds[] table's own "lowest free slot"
	 * bookkeeping is in lockstep with the kernel's own lowest-free-fd
	 * allocator, which requires __fd_init() to have already registered
	 * whatever this process inherited (0/1/2) -- exactly what
	 * crt/linux/crt1.c's real startup now does before __signal_init()
	 * (same commit). This pilot has no crt1.c/_start of its own, so
	 * nothing called __fd_init() until this line: without it, __fds[]
	 * starts believing slot 0 is free, __fd_alloc(0) hands the eventfd
	 * table slot 0 while the kernel's own eventfd2(2) returned a
	 * different, already-in-use real fd, and every later raw syscall
	 * this file or plat_signal.c makes against the wrong "same" number
	 * hits some unrelated real descriptor instead -- reproduced
	 * directly as a raw `write(0, ...)` landing on this process's own
	 * stdin. Every temporary fd this test opens for its own setup
	 * (below) is always closed before the next __plat_sigevent_create()
	 * call, so the kernel's own reused low numbers keep matching the
	 * table's after this. */
	__fd_init();

	if (argc >= 2 && streq(argv[1], "exit-test")) {
		/* __plat_terminate() directly -- see this file's own banner for
		 * why exit.c's front door is not used here. tools/
		 * linux-build-misc.sh checks this process's real exit status is
		 * exactly 42, proving the `code` argument really becomes the
		 * kernel's own view of this process's exit status, not just
		 * that the syscall was issued. */
		__plat_terminate(42);
	}

	if (argc >= 3 && streq(argv[1], "signal-test")) {
		test_signal_process((pid_t)atoi_l(argv[2]));
		printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
		TERMINATE(failures ? 1 : 0);
	}

	test_misc();
	test_select();
	test_signal_events();

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	TERMINATE(failures ? 1 : 0);
}
