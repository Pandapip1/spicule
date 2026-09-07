/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_signal.h -- see src/mman/
 * linux/plat_mem.c's own banner for the raw-syscall discipline this file
 * follows too.
 *
 * NOT implemented here: the named-pipe-plus-mutant RPC transport
 * (__plat_signal_pipe_*(), __plat_signal_mutant_create()/
 * __plat_wait_acquire()/__plat_mutant_release()) and __plat_thread_start(),
 * NT-only machinery whose real job is participating in NT's own invented
 * cross-process wire protocol -- src/signal/linux/sigdelivery.c uses real
 * kernel signal delivery instead and needs none of it.
 *
 * What IS implemented: event create/wait/peek, kill()-adjacent job control
 * (__plat_process_suspend{,_self}(), __plat_kill_{open,terminate}(),
 * __plat_segv_code()), and named stop-events under /tmp (shared like NT's
 * \BaseNamedObjects, using O_CREAT|O_EXCL for atomic create-vs-open and a
 * MAP_SHARED backing file so every opener sees the same futex word -- see
 * src/thread/linux/plat_thread.c's matching technique for the one
 * disclosed race, a second opener's mmap racing the creator's ftruncate()).
 *
 * __plat_kill_open(), __plat_process_suspend(), and __plat_kill_terminate()
 * box their handle as the BARE PID (matching plat_process.c's box_pid()),
 * not this file's own fd+1 event-handle convention -- getting this wrong
 * once caused a real hang (an orphaned child spinning in sigsuspend()
 * forever because the wake signal, sent through a bare pid misread as
 * fd+1, hit pidfd_send_signal(2) with a garbage descriptor and failed
 * EBADF). See __plat_process_suspend()'s own comment for the one hazard
 * this convention reopens.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include "libc.h"       /* struct _UNICODE_STRING's real definition (nt.h) --
                         * a type-only use across a still-NT-shaped seam. */
#include "plat_signal.h"
#include "linux/sync.h"
#include "unsafe_pointer.h"

/* Linux syscall numbers -- aarch64 confirmed via a throwaway host
 * program printing the SYS_* macros from <sys/syscall.h>, the same
 * oracle technique src/mman/linux/plat_mem.c's banner describes; x86_64/
 * i386 confirmed against a real x86_64-linux-gnu glibc's own asm/
 * unistd_64.h/unistd_32.h, genuinely different tables from aarch64's
 * (e.g. SYS_read is 63 on aarch64, 0 on x86_64) rather than a fixed
 * offset. */
#if defined(__aarch64__)
#define SYS_eventfd2          19
#define SYS_ppoll             73
#define SYS_read              63
#define SYS_write             64
#define SYS_close             57
#define SYS_kill              129
#define SYS_rt_sigaction      134
#define SYS_rt_sigprocmask    135
#define SYS_nanosleep         101
#define SYS_msync             227
#define SYS_getpid            172
#define SYS_pidfd_open        434
#define SYS_pidfd_send_signal 424
#define SYS_mmap_ps           222
#elif defined(__x86_64__)
#define SYS_eventfd2          290
#define SYS_ppoll             271
#define SYS_read              0
#define SYS_write             1
#define SYS_close             3
#define SYS_kill              62
#define SYS_rt_sigaction      13
#define SYS_rt_sigprocmask    14
#define SYS_nanosleep         35
#define SYS_msync             26
#define SYS_getpid            39
#define SYS_pidfd_open        434 /* shares this number with aarch64/i386:
                                    * recent enough to be added to every
                                    * arch's table at once. */
#define SYS_pidfd_send_signal 424
#define SYS_mmap_ps           9
#elif defined(__i386__)
#define SYS_eventfd2          328
#define SYS_ppoll             309
#define SYS_read                3
#define SYS_write               4
#define SYS_close               6
#define SYS_kill               37
#define SYS_rt_sigaction      174
#define SYS_rt_sigprocmask    175
#define SYS_nanosleep         162
#define SYS_msync             144
#define SYS_getpid              20
#define SYS_pidfd_open        434
#define SYS_pidfd_send_signal 424
#define SYS_mmap_ps            192 /* SYS_mmap2, matching crt/linux/crt1.c's
                                    * own i386 choice: offset is in PAGE
                                    * units, moot here since every mmap
                                    * call site below passes offset 0. */
#else
#error "plat_signal.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif
#define PROT_READ_PS          0x1
#define PROT_WRITE_PS         0x2

/* Raw syscall trampoline, not glibc's syscall(2) wrapper: glibc
 * translates a kernel failure into -1 plus its OWN errno storage,
 * distinct from spicule's -nostdinc <errno.h>, so `errno = (int)-ret`
 * below needs the raw kernel [-4095,-1]-encodes-errno value directly,
 * whichever arch's raw instruction below provides it. */
#include <stdarg.h>
#if defined(__aarch64__)
static long syscall(long number, ...)
{
	va_list ap;
	long a1, a2, a3, a4, a5, a6;
	register long x8 __asm__("x8");
	register long x0 __asm__("x0");
	register long x1 __asm__("x1");
	register long x2 __asm__("x2");
	register long x3 __asm__("x3");
	register long x4 __asm__("x4");
	register long x5 __asm__("x5");

	va_start(ap, number);
	a1 = va_arg(ap, long); a2 = va_arg(ap, long); a3 = va_arg(ap, long);
	a4 = va_arg(ap, long); a5 = va_arg(ap, long); a6 = va_arg(ap, long);
	va_end(ap);

	x8 = number; x0 = a1; x1 = a2; x2 = a3; x3 = a4; x4 = a5; x5 = a6;
	__asm__ volatile("svc #0"
	                 : "+r"(x0)
	                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
	                 : "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long syscall(long number, ...)
{
	va_list ap;
	long a1, a2, a3, a4, a5, a6, ret;
	register long r10 __asm__("r10");
	register long r8  __asm__("r8");
	register long r9  __asm__("r9");

	va_start(ap, number);
	a1 = va_arg(ap, long); a2 = va_arg(ap, long); a3 = va_arg(ap, long);
	a4 = va_arg(ap, long); a5 = va_arg(ap, long); a6 = va_arg(ap, long);
	va_end(ap);

	r10 = a4; r8 = a5; r9 = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(number), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
static long syscall(long number, ...)
{
	va_list ap;
	long args[7];
	long ret;

	va_start(ap, number);
	args[0] = number;
	args[1] = va_arg(ap, long); args[2] = va_arg(ap, long); args[3] = va_arg(ap, long);
	args[4] = va_arg(ap, long); args[5] = va_arg(ap, long); args[6] = va_arg(ap, long);
	va_end(ap);

	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

/* ---- event create/wait/peek -----------------------------------------
 *
 * NT's SynchronizationEvent ("wakes one waiting thread, then
 * automatically resets") maps directly onto a Linux eventfd(2) created
 * with EFD_SEMAPHORE: each successful read() consumes exactly one unit,
 * returning immediately if the counter is nonzero or blocking until it
 * becomes nonzero. Boxed the same way src/unistd/linux/plat_fd.c boxes any
 * other small Linux fd (+1, so __PLAT_HANDLE_NULL never collides with
 * eventfd 0).
 */
#define EFD_SEMAPHORE_LX 1
#define EFD_CLOEXEC_LX   02000000

static int unbox(__plat_handle_t h) { return (int)((long)h - 1); }
/* __plat_handle_t is an opaque one-word carrier shared with the NT
 * backend; the real payload here is the plain fd number, boxed +1 so 0
 * stays free for __PLAT_HANDLE_NULL, never dereferenced. */
static __plat_handle_t box(int fd) { return unsafe_assume_valid_pointer((__plat_handle_t)(long)(fd + 1)); }

/* This process's __fds[] table (src/internal/fd.c) and the kernel's real fd
 * numbering must stay in sync: __fd_alloc(0) assumes every real, long-lived
 * fd is registered via __fd_install(). This eventfd is long-lived but
 * created via a raw syscall that bypasses __fd_install() by default; left
 * unregistered, __fd_alloc(0) can later hand out the same number the
 * kernel gave this eventfd, and the next open()/dup() landing there closes
 * the real fd out from under wake_event without this library knowing.
 * Confirmed as a real bug via strace: a later dup3() silently clobbering
 * this eventfd's fd. __fd_install() below closes that gap. */
__plat_handle_t __plat_sigevent_create(int initially_signalled)
{
	long ret = syscall(SYS_eventfd2, (long)(initially_signalled ? 1 : 0),
	                   (long)(EFD_SEMAPHORE_LX | EFD_CLOEXEC_LX));
	int fd;
	if (is_sys_error(ret)) return __PLAT_HANDLE_NULL;
	/* ret is the eventfd2(2) syscall's own return-register value, just
	 * proven a real success (not an encoded -errno) by is_sys_error()
	 * immediately above; a successful eventfd2(2) returns a small
	 * nonnegative file descriptor number by the Linux syscall ABI's own
	 * contract. HANDLE is void* only because this internal
	 * __fd_install() signature is still NT-shaped (this file's own
	 * banner above); on this backend it carries the plain descriptor
	 * number, never dereferenced. */
	fd = __fd_install(unsafe_assume_valid_pointer((HANDLE)(long)ret), O_CLOEXEC, 0);
	if (fd < 0) { syscall(SYS_close, ret, 0L, 0L, 0L, 0L, 0L); return __PLAT_HANDLE_NULL; }
	return box(fd);
}

/* wake_event's "post" operation -- __plat_event_set() (a different
 * __plat_handle_t domain on this platform) is NOT it. Writing an 8-byte
 * counter value to an EFD_SEMAPHORE eventfd increments its counter and
 * never blocks: write(2) only fails EAGAIN near UINT64_MAX overflow, never
 * because nothing is waiting to read it. */
int __plat_sigevent_set(__plat_handle_t ev)
{
	unsigned long long one = 1;
	long ret = syscall(SYS_write, (long)unbox(ev), (long)&one, 8L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* __plat_event_set() is declared in plat_signal.h but defined in
 * src/thread/'s Linux backend, to avoid a duplicate ODR definition. */

void __plat_signal_wait(__plat_handle_t wake_event, int has_timeout, long long ticks) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; timeout flag and duration have distinct roles
{
	struct timespec ts, *tsp;
	long long magnitude, ns;

	/* `ticks` carries NT's relative/absolute LARGE_INTEGER encoding:
	 * negative means "relative, this many 100ns units from now", positive
	 * means absolute NT time. Every real caller here only ever constructs a
	 * relative (negative) value; a genuinely absolute `ticks` has no
	 * Linux-native handling built here yet. The magnitude computation below
	 * guards a real, confirmed bug: passing `ticks` straight through to
	 * `ns = ticks * 100L` with no sign handling produces a negative
	 * ts.tv_sec/tv_nsec that nanosleep(2)/ppoll(2) reject with EINVAL
	 * (unchecked below), turning every timed wait into a zero-duration
	 * busy-spin -- the root cause of a cluster of conformance-suite TIMEOUT
	 * failures across fork, pthread_atfork, sem_*, mqueue, sigsuspend and
	 * sigwait. */
	magnitude = ticks < 0 ? -ticks : ticks;

	if (wake_event) {
		int fd = unbox(wake_event);
		struct pollfd pfd;
		unsigned long long val;

		pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
		if (has_timeout) {
			ns = magnitude * 100LL;
			ts.tv_sec = (time_t)(ns / 1000000000LL); ts.tv_nsec = (long)(ns % 1000000000LL);
			tsp = &ts;
		} else {
			tsp = 0;
		}
		if (syscall(SYS_ppoll, &pfd, 1L, tsp, 0L, 0L) > 0 && (pfd.revents & POLLIN))
			syscall(SYS_read, (long)fd, &val, 8L); /* consume one unit -- auto-reset */
		return;
	}
	if (has_timeout) {
		ns = magnitude * 100LL;
		ts.tv_sec = (time_t)(ns / 1000000000LL); ts.tv_nsec = (long)(ns % 1000000000LL);
		syscall(SYS_nanosleep, &ts, 0L);
		return;
	}
	/* Neither a timeout nor an event: the same fixed 100ms fallback the
	 * NT backend uses (src/signal/nt/plat_signal.c). */
	ts.tv_sec = 0; ts.tv_nsec = 100000000L;
	syscall(SYS_nanosleep, &ts, 0L);
}

/* Both real call sites (signal.c's stop-event handling) hand this a
 * struct spicule_linux_sync* from __plat_stop_event_create()/
 * __plat_stop_event_probe() -- the SAME domain __plat_event_set() uses,
 * NOT this file's own box()/unbox() eventfd domain __plat_signal_wait()
 * uses for `wake_event`. Decoding it as `fd+1` used to hand ppoll()/read()
 * a garbage descriptor, causing a real confirmed hang (self-stop never
 * observed, waitpid(WUNTRACED) spinning forever).
 *
 * This platform's only event kind is manual-reset, unlike NT's auto-reset
 * SynchronizationEvent this handle represents, so "peek and consume" is
 * implemented here as an atomic compare-exchange from 1 to 0 across the
 * MAP_SHARED word, rather than inherited from the kernel primitive the
 * way ppoll()+read() gets it for free from EFD_SEMAPHORE. */
int __plat_event_peek(__plat_handle_t ev)
{
	struct spicule_linux_sync *obj = (struct spicule_linux_sync *)ev;
	int expected = 1;

	return __atomic_compare_exchange_n(&obj->futex, &expected, 0, 0,
	                                   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

/* ---- signal.c's kill()-adjacent job control and fault classification */

int __plat_process_suspend_self(void)
{
	/* Cannot be kill(0, SIGSTOP): pid 0 as a kill(2) target means "every
	 * process in my process group", not "myself", so the real pid is
	 * needed. */
	long pid = syscall(SYS_getpid);
	long ret = syscall(SYS_kill, pid, (long)SIGSTOP);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* `h` is the bare pid (see this file's banner), NOT this file's own
 * box()/unbox() fd+1 domain used for event handles.
 *
 * A pidfd is opened here, used once, and closed: pidfd_send_signal(2)
 * keeps the same pid-reuse-immunity __plat_kill_open()'s existence probe
 * relies on, rather than downgrading to plain kill(2). */
int __plat_process_suspend(__plat_handle_t h)
{
	long pid = (long)(int)(long)h;
	long fd = syscall(SYS_pidfd_open, pid, 0L);
	long ret;
	if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	ret = syscall(SYS_pidfd_send_signal, fd, (long)SIGSTOP, 0L, 0L);
	syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* __plat_process_resume() is declared in plat_signal.h but defined in
 * src/process/linux/plat_process.c, to avoid a duplicate ODR definition. */

int __plat_kill_open(pid_t pid, int want_suspend_resume, __plat_handle_t *out) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; process ID and capability flag have distinct roles
{
	/* Linux has no "open a process object" step for most per-process
	 * syscalls; `h` is the bare pid (this file's banner). That reopens one
	 * hazard: a bare pid handed to plat_fd.h's fd-domain close() reads
	 * pid-1 as an fd number and closes whatever real descriptor happens to
	 * have that value -- accepted because real pids on this host run past
	 * a million, so pid-1 reliably lands on an fd number this process
	 * never opened and the close fails silently EBADF.
	 *
	 * kill(pid, 0) is the existence-and-permission probe wanted here: its
	 * real errno IS the [EPERM]-vs-[ESRCH] distinction this contract
	 * needs. `want_suspend_resume` has nothing to translate: unlike NT's
	 * PROCESS_SUSPEND_RESUME access right, signalling a pid this process
	 * can already signal needs no separate right. */
	long ret;
	(void)want_suspend_resume;
	ret = syscall(SYS_kill, (long)pid, 0L);
	if (is_sys_error(ret)) {
		errno = ((int)-ret == EPERM) ? EPERM : ESRCH;
		return -1;
	}
	/* __plat_handle_t is an opaque one-word carrier shared with the NT
	 * backend; this backend's real payload is the bare Linux pid,
	 * never dereferenced (see this function's own comment above). */
	*out = unsafe_assume_valid_pointer((__plat_handle_t)(long)pid);
	return 0;
}

int __plat_kill_terminate(__plat_handle_t h, int exitcode)
{
	/* exitcode carries the originally-requested signal via
	 * __ENCODE_SIGNAL_EXIT(sig), decoded back out below. Sending THAT
	 * signal, not an unconditional SIGKILL, matters because a raw kernel
	 * signal with no handler installed still runs the kernel's own default
	 * action -- Term for most signals, but Ignore for SIGCHLD/SIGWINCH/
	 * SIGURG, and forcing SIGKILL for those would turn an intended no-op
	 * into an unconditional kill. SIGKILL is kept as the defensive
	 * fallback for a non-__ENCODE_SIGNAL_EXIT()-shaped exitcode, though
	 * this is the only call site and that never happens today.
	 *
	 * No special-casing needed for a target already exiting:
	 * pidfd_send_signal() to an unreaped zombie still succeeds, and ESRCH
	 * comes back only once the process is genuinely gone.
	 *
	 * `h` is the bare pid, same as __plat_process_suspend() above. */
	long pid = (long)(int)(long)h;
	long fd = syscall(SYS_pidfd_open, pid, 0L);
	long ret;
	int sig = __IS_SIGNAL_EXIT(exitcode) ? (exitcode & 0x7f) : SIGKILL;
	if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	ret = syscall(SYS_pidfd_send_signal, fd, (long)sig, 0L, 0L);
	syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_segv_code(void *addr)
{
	/* Linux's real SIGSEGV siginfo_t already carries the true si_code
	 * natively, so a full port would read it off the handler's siginfo_t
	 * directly and never call this. Until then: msync(2) on the containing
	 * page reports ENOMEM specifically when the memory isn't mapped at all,
	 * and otherwise succeeds regardless of protection -- an indirect probe
	 * needing no /proc/self/maps parsing. Page size hardcoded to 4096
	 * (this project's other target architectures' default); a non-default
	 * page size would only over-round the address, never misclassify past
	 * the actual boundary. */
	unsigned long page = (unsigned long)addr & ~(unsigned long)0xFFF;
	long ret = syscall(SYS_msync, (void *)page, (unsigned long)4096, 4 /* MS_ASYNC */);
	if (is_sys_error(ret) && (int)-ret == ENOMEM) return SEGV_MAPERR;
	return SEGV_ACCERR;
}

/* rt_sigaction(2)'s kernel-ABI struct: handler, flags, restorer, then a
 * sigset_t sized for exactly _NSIG (64) kernel signals -- NOT this
 * file's own larger <signal.h> sigset_t, hence sigsetsize below being
 * RT_SIGSETSIZE, not sizeof(sigset_t). k_restorer is left null and
 * SA_RESTORER unset since the only handlers this function ever installs
 * are SIG_IGN and SIG_DFL, which never call back through
 * rt_sigreturn(2).
 *
 * Fields are named k_* rather than sa_*: <signal.h>'s sa_handler is a
 * macro over a union, and this struct's kernel ABI layout has no union
 * to expand it into.
 *
 * The kernel's own sigset_t is always exactly 8 bytes (64 signal bits)
 * on every Linux arch, regardless of native word size. A plain
 * `unsigned long k_mask` is 8 bytes on aarch64/x86_64 (LP64) but only 4
 * on i386 (ILP32) -- too narrow, and it would pass sigsetsize=4 instead
 * of the 8 the kernel strictly validates against (EINVAL otherwise) --
 * so i386 gets a real two-word array instead. sigsetsize is a fixed
 * RT_SIGSETSIZE (8) on every arch below, never sizeof(unsigned long), so
 * it stays correct regardless of native word width. */
#define RT_SIGSETSIZE 8
#if defined(__i386__)
struct kernel_sigaction {
	void (*k_handler)(int);
	unsigned long k_flags;
	void (*k_restorer)(void);
	unsigned long k_mask[2];
};
#else
struct kernel_sigaction {
	void (*k_handler)(int);
	unsigned long k_flags;
	void (*k_restorer)(void);
	unsigned long k_mask;
};
#endif

/* Zeroes k_mask regardless of its per-arch shape above (a single word on
 * aarch64/x86_64, a two-word array on i386) -- one small helper instead
 * of duplicating an #if at each of this file's three real call sites. */
static void kernel_sigaction_zero_mask(struct kernel_sigaction *act)
{
#if defined(__i386__)
	act->k_mask[0] = 0;
	act->k_mask[1] = 0;
#else
	act->k_mask = 0;
#endif
}

void __plat_sig_sync_kernel(int sig, int ignore)
{
	struct kernel_sigaction act;
	act.k_handler = ignore ? SIG_IGN : SIG_DFL;
	act.k_flags = 0;
	act.k_restorer = 0;
	kernel_sigaction_zero_mask(&act);
	syscall(SYS_rt_sigaction, (long)sig, &act, 0L, (long)RT_SIGSETSIZE);
}

void __plat_sig_default_terminate(int sig)
{
	/* Forces the kernel-level disposition to SIG_DFL rather than trusting
	 * __plat_sig_sync_kernel() to have already done it: abort()'s override
	 * of a blocked/ignored/caught-and-returned SIGABRT can reach here with
	 * the kernel still set to SIG_IGN, and termination is required
	 * regardless.
	 *
	 * kill(2) to this process's own pid, not tgkill(2): a fatal signal's
	 * default action ends the whole process regardless of which thread
	 * raised it.
	 *
	 * The rt_sigprocmask(2) unblock right before kill(2) is load-bearing,
	 * not optional: __plat_sig_install_fault_handlers()'s own real_dispatch()
	 * below runs without SA_NODEFER, so the kernel auto-blocks `sig` for
	 * its whole duration, and __raise_internal_info()'s default-terminate
	 * branch can call through to this function from INSIDE that same
	 * handler, for the exact signal still blocked. kill(2) of a
	 * currently-blocked signal just queues it pending instead of forcing
	 * default action, so without this unblock the kill() below is a
	 * silent no-op and __exit_internal() falls through to its
	 * exit_group(2) fallback, producing WIFEXITED instead of the real
	 * WIFSIGNALED/WTERMSIG(sig) this function exists to guarantee --
	 * confirmed as a real bug via test/posix-signal-fault-linux.c.
	 * Unblocking unconditionally is still correct for every other caller
	 * (abort(), the exec() stand-in's re-raise), since none of them can
	 * ever be running as the kernel handler for `sig` itself.
	 *
	 * Neither syscall's result is checked past the unblock: a failure of
	 * any of the three just falls through to __exit_internal()'s own
	 * fallback. */
	struct kernel_sigaction act;
	/* A raw byte view of the kernel's own RT_SIGSETSIZE-byte sigset --
	 * NOT `unsigned long mask = 1UL << (sig - 1)` (correct on aarch64/
	 * x86_64, where a single 8-byte word IS the whole kernel sigset, but
	 * a real bug on i386's 4-byte `unsigned long`, which both misses
	 * signals above 32 and passes the wrong sigsetsize). Setting bit
	 * (sig-1) by byte index instead is correct on every little-endian
	 * arch this file targets. */
	unsigned char mask[RT_SIGSETSIZE];
	long pid;
	int i;

	act.k_handler = SIG_DFL;
	act.k_flags = 0;
	act.k_restorer = 0;
	kernel_sigaction_zero_mask(&act);
	syscall(SYS_rt_sigaction, (long)sig, &act, 0L, (long)RT_SIGSETSIZE);

	for (i = 0; i < RT_SIGSETSIZE; i++) mask[i] = 0;
	mask[(sig - 1) / 8] = (unsigned char)(1U << ((sig - 1) % 8));
	syscall(SYS_rt_sigprocmask, (long)SIG_UNBLOCK, (long)mask, 0L, (long)RT_SIGSETSIZE);

	pid = syscall(SYS_getpid);
	syscall(SYS_kill, pid, (long)sig);
}

/* arch/aarch64/src/sigreturn_trampoline.S has the real SA_RESTORER ABI
 * contract. Declared as a plain function so `act.k_restorer =
 * __spicule_sigreturn_trampoline` below needs no cast. */
void __spicule_sigreturn_trampoline(void); // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

/* The one real kernel-level entry point installed below, for both real
 * hardware faults (the fixed five __plat_sig_install_fault_handlers()
 * installs at startup) and, as of Tier 2, any other signal a real
 * catchable disposition was installed for (__plat_sig_install_real_handler()
 * below). `info` is the kernel's own siginfo_t, not synthesized: si_code
 * for a real SIGSEGV/SIGBUS/SIGILL/SIGFPE already arrives correctly from
 * the kernel, unlike NT's exception_handler() which has to reverse-engineer
 * it from a raw exception code.
 *
 * Routes into __raise_internal_info(), the same portable entry point every
 * other signal source uses. Locked via __sig_lock(), a recursive lock keyed
 * by gettid(): a fault that interrupts code on a thread already holding the
 * lock re-enters without blocking, while a fault on a different thread
 * blocks on the semaphore normally.
 *
 * Audited for async-signal-safety: no malloc on the path a fault with no
 * installed handler takes (child_grow() only runs past 256 concurrently-
 * unreaped children via __child_add(), which this path never reaches). A
 * caught handler this library dispatches to inherits the same
 * async-signal-safety obligation any POSIX handler has.
 *
 * A signal whose disposition later changes back to SIG_IGN/SIG_DFL needs no
 * matching "uninstall": __raise_internal_info() re-reads handlers[sig]
 * itself on every call, so leaving this installed is simply the honest
 * state. SA_ONSTACK is honored via signal.c's sig_dispatch() calling
 * __sig_call_on_altstack() (src/signal/aarch64/altstack.S). */
static void real_dispatch(int sig, siginfo_t *info, void *ucontext)
{
	(void)ucontext;
	__sig_lock();
	__raise_internal_info(sig, info);
	__sig_unlock();
}

/* SA_NODEFER deliberately NOT set: leaving the kernel's auto-block of `sig`
 * in place means a second real delivery during real_dispatch() forces the
 * kernel's default action (process death) instead of recursing into
 * real_dispatch() again on a stack that, for a stack-overflow SIGSEGV, is
 * already exhausted. */
void __plat_sig_install_real_handler(int sig)
{
	struct kernel_sigaction act;

	act.k_handler = (void (*)(int))(void *)real_dispatch; // NOLINT(bugprone-casting-through-void) -- same sigaction union-slot recovery signal.c's own SA_SIGINFO cast documents
	act.k_flags = SA_SIGINFO | SA_RESTORER;
	act.k_restorer = __spicule_sigreturn_trampoline;
	kernel_sigaction_zero_mask(&act);
	syscall(SYS_rt_sigaction, (long)sig, &act, 0L, (long)RT_SIGSETSIZE);
}

void __plat_sig_install_fault_handlers(void)
{
	static const int fault_sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP };
	int i, n = (int)(sizeof fault_sigs / sizeof fault_sigs[0]);

	for (i = 0; i < n; i++) __plat_sig_install_real_handler(fault_sigs[i]);
}

/* Linux has a real per-signal kernel default action and a real
 * pidfd_send_signal(2): __plat_kill_terminate() delivers to whatever the
 * target process last synced as its own real kernel-level disposition. */
int __plat_sig_deliverable_to_other_process(void)
{
	return 1;
}

/* ---- named stop-events, keyed by the filesystem namespace ----------------
 * See this file's own banner. `name`'s wide chars are ASCII by
 * construction (signal.c's own stop_event_name() builds them from a
 * fixed prefix plus hex digits), so narrowing byte-by-byte is exact,
 * not an approximation. */
#if defined(__aarch64__)
#define SYS_openat_ps    56
#define SYS_ftruncate_ps 46
#elif defined(__x86_64__)
#define SYS_openat_ps    257
#define SYS_ftruncate_ps 77
#elif defined(__i386__)
#define SYS_openat_ps    295
#define SYS_ftruncate_ps 93
#else
#error "plat_signal.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif
#define AT_FDCWD_PS      (-100)
#define O_RDWR_PS        02
#define O_CREAT_PS       0100
#define O_EXCL_PS        0200
#define MAP_SHARED_PS    0x01

/* name is required: name->Length is dereferenced unconditionally with no
 * guard. buf writes are bounds-checked via `j < bufsz - 1` at every step. */
static void stop_event_path(const struct _UNICODE_STRING *name, char *buf, size_t bufsz)
    __attribute__((nonnull(1)));
static void stop_event_path(const struct _UNICODE_STRING *name, char *buf, size_t bufsz)
{
	static const char prefix[] = "/tmp/.spicule-stopev.";
	size_t plen = sizeof(prefix) - 1, i, j = 0;
	size_t n = name->Length / sizeof(unsigned short);
	for (i = 0; i < plen && j < bufsz - 1; i++) buf[j++] = prefix[i];
	for (i = 0; i < n && j < bufsz - 1; i++) {
		unsigned short c = name->Buffer[i];
		buf[j++] = (c == '\\' || c == 0) ? '_' : (char)c;
	}
	buf[j] = 0;
}

/* Opens-or-creates the backing file for `name` and hands back its
 * MAP_SHARED mapping plus whether THIS call created it. */
static int open_shared_stop_event(const struct _UNICODE_STRING *name, int *created,
                                  struct spicule_linux_sync **out)
{
	char path[128];
	long fd, r;

	stop_event_path(name, path, sizeof path);
	fd = syscall(SYS_openat_ps, (long)AT_FDCWD_PS, (long)path,
	            (long)(O_RDWR_PS | O_CREAT_PS | O_EXCL_PS), 0600L, 0L, 0L);
	if (is_sys_error(fd)) {
		*created = 0;
		fd = syscall(SYS_openat_ps, (long)AT_FDCWD_PS, (long)path, (long)O_RDWR_PS, 0L, 0L, 0L);
		if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	} else {
		*created = 1;
		syscall(SYS_ftruncate_ps, fd, (long)sizeof(struct spicule_linux_sync), 0L, 0L, 0L, 0L);
	}
	r = syscall(SYS_mmap_ps, 0L, (long)sizeof(struct spicule_linux_sync),
	           (long)(PROT_READ_PS | PROT_WRITE_PS), (long)MAP_SHARED_PS, fd, 0L);
	syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(r)) { errno = (int)-r; return -1; }
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register; this backing store's whole point is being
	 * reinterpreted as struct spicule_linux_sync. */
	*out = unsafe_assume_valid_pointer((struct spicule_linux_sync *)r);
	if (*created) { (*out)->futex = 0; (*out)->max = 0; (*out)->kind = 2 /* SPICULE_LX_SYNC_EVENT */; }
	return 0;
}

__plat_handle_t __plat_stop_event_create(const struct _UNICODE_STRING *name)
{
	struct spicule_linux_sync *obj;
	int created;
	if (open_shared_stop_event(name, &created, &obj) < 0) return __PLAT_HANDLE_NULL;
	return (__plat_handle_t)obj;
}

int __plat_stop_event_probe(const struct _UNICODE_STRING *name, __plat_handle_t *out,
                            int *already_existed)
{
	struct spicule_linux_sync *obj;
	int created;
	if (open_shared_stop_event(name, &created, &obj) < 0) return -1;
	*out = (__plat_handle_t)obj;
	*already_existed = !created;
	return 0;
}

/* ---- remote-disposition probe -----------------------------------------
 * Reuses SYS_openat_ps/AT_FDCWD_PS from the stop-event section above. */

/* Builds "/proc/<pid>/status" into buf. pid is always a real, positive
 * pid_t here: kill()'s pid<=0 arms are handled before this is reached. */
static void proc_status_path(pid_t pid, char *buf, size_t bufsz)
{
	static const char prefix[] = "/proc/";
	static const char suffix[] = "/status";
	size_t plen = sizeof prefix - 1, slen = sizeof suffix - 1;
	unsigned long v = (unsigned long)pid;
	char digits[20];
	size_t nd = 0, i, j = 0;

	if (v == 0) digits[nd++] = '0';
	while (v > 0 && nd < sizeof digits) {
		digits[nd++] = (char)('0' + (v % 10));
		v /= 10;
	}
	for (i = 0; i < plen && j < bufsz - 1; i++) buf[j++] = prefix[i];
	for (i = 0; i < nd && j < bufsz - 1; i++) buf[j++] = digits[nd - 1 - i];
	for (i = 0; i < slen && j < bufsz - 1; i++) buf[j++] = suffix[i];
	buf[j] = 0;
}

/* Scans `buf` (the first `n` bytes read from /proc/pid/status) for a line
 * beginning with `field` ("SigCgt:" or "SigIgn:", proc(5)) and reports bit
 * (sig-1) of the hex bitmask that follows. Returns 0 (safe default: "not
 * proven nondefault") if `field` is never found. */
static int status_field_bit(const char *buf, long n, const char *field, int sig)
{
	long flen = 0, i;

	while (field[flen]) flen++;

	for (i = 0; i + flen <= n; i++) {
		int match = 1, k;
		long j;
		unsigned long long mask = 0;

		if (i != 0 && buf[i - 1] != '\n') continue;
		for (k = 0; k < flen; k++)
			if (buf[i + k] != field[k]) { match = 0; break; }
		if (!match) continue;

		j = i + flen;
		while (j < n && (buf[j] == ' ' || buf[j] == '\t')) j++;
		while (j < n && buf[j] != '\n') {
			char c = buf[j];
			int digit;
			if (c >= '0' && c <= '9') digit = c - '0';
			else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
			else break;
			mask = (mask << 4) | (unsigned long long)digit;
			j++;
		}
		return (int)((mask >> (sig - 1)) & 1ULL);
	}
	return 0;
}

int __plat_sig_remote_disposition_nondefault(pid_t pid, int sig)
{
	char path[40];
	char buf[4096];
	long fd, got = 0, r;

	if (pid <= 0 || sig < 1 || sig > 64) return 0;

	proc_status_path(pid, path, sizeof path);
	fd = syscall(SYS_openat_ps, (long)AT_FDCWD_PS, (long)path, 0L, 0L, 0L, 0L);
	if (is_sys_error(fd)) return 0;

	while (got < (long)sizeof buf) {
		r = syscall(SYS_read, fd, (long)&buf[got], (long)(sizeof buf - (size_t)got), 0L, 0L, 0L);
		if (is_sys_error(r) || r == 0) break;
		got += r;
	}
	syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);

	if (status_field_bit(buf, got, "SigCgt:", sig)) return 1;
	return status_field_bit(buf, got, "SigIgn:", sig);
}

// NOLINTEND(misc-include-cleaner)
