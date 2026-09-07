/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_misc.h -- see src/mman/linux/
 * plat_mem.c's own banner for the raw-syscall discipline this file
 * follows too.
 *
 * Process handle encoding: __plat_close() (plat_fd.h) is the SAME close
 * function every front door here calls on a handle this file vends,
 * boxed the same fd+1 way as any other Linux fd. That constrains this
 * backend's choice: a process handle must actually BE something close(2)
 * can correctly close, so this backend's __plat_handle_t for a process is
 * a boxed pidfd (Linux 5.3+ pidfd_open(2)) -- a real, closeable,
 * kernel-refcounted reference immune to pid reuse, making __plat_close()
 * correct here for free.
 *
 * getpriority(2)/setpriority(2) are the one place this still needs a bare
 * pid_t rather than a pidfd -- no pidfd-taking priority syscall exists. A
 * small fixed side table (pidfd_pid_table[] below) records the pid each
 * pidfd this file opens actually belongs to.
 *
 * A handle can also reach this file as struct __child's own `h` field. If
 * that process handle is NOT a boxed pidfd the same way, a foreign
 * child's handle handed here fails (ESRCH) rather than silently
 * misinterpreting an arbitrary integer as a pidfd.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include "plat_misc.h"
#include "plat_fd.h"
#include "unsafe_pointer.h"

/* aarch64 Linux syscall numbers, confirmed against this host's own
 * <sys/syscall.h>. */
#if defined(__aarch64__)
#define SYS_uname                   160
#define SYS_sched_yield             124
#define SYS_kill                    129
#define SYS_setpriority             140
#define SYS_getpriority             141
#define SYS_getrusage               165
#define SYS_lseek                   62
#define SYS_prlimit64               261
#define SYS_pidfd_open              434
#define SYS_pidfd_send_signal       424
#define SYS_sched_setparam          118
#define SYS_sched_setscheduler      119
#define SYS_sched_getscheduler      120
#define SYS_sched_getparam          121
#define SYS_sched_rr_get_interval   127
#elif defined(__x86_64__)
#define SYS_uname                   63
#define SYS_sched_yield             24
#define SYS_kill                    62
#define SYS_setpriority             141
#define SYS_getpriority             140
#define SYS_getrusage               98
#define SYS_lseek                   8
#define SYS_prlimit64               302
#define SYS_pidfd_open              434
#define SYS_pidfd_send_signal       424
/* This backend's Linux platform target is aarch64 only; this __x86_64__
 * branch exists solely so this file also compiles and runs as the
 * native-ELF pilot/fuzz test harness on an x86_64 CI host. The five
 * numbers below are taken from the stable x86_64 syscall table
 * (arch/x86/entry/syscalls/syscall_64.tbl), adjacent to the already-
 * verified SYS_getpriority=140/SYS_setpriority=141 above. */
#define SYS_sched_setparam          142
#define SYS_sched_getparam          143
#define SYS_sched_setscheduler      144
#define SYS_sched_getscheduler      145
#define SYS_sched_rr_get_interval   148
#elif defined(__i386__)
/* i386 Linux syscall numbers, confirmed against this host's own
 * /nix/store linux-headers asm/unistd_32.h (the pre-"generic table"
 * legacy i386 numbering -- pidfd_open/pidfd_send_signal are the two
 * exceptions, added long after i386 adopted the shared cross-arch
 * numbering scheme, so they match the aarch64/x86_64 values above). */
#define SYS_uname                   122
#define SYS_sched_yield             158
#define SYS_kill                    37
#define SYS_setpriority             97
#define SYS_getpriority             96
#define SYS_getrusage               77
#define SYS_lseek                   19
#define SYS_prlimit64               340
#define SYS_pidfd_open              434
#define SYS_pidfd_send_signal       424
#define SYS_sched_setparam          154
#define SYS_sched_getparam          155
#define SYS_sched_setscheduler      156
#define SYS_sched_getscheduler      157
#define SYS_sched_rr_get_interval   161
#else
#error "plat_misc.c: unsupported architecture"
#endif

/* A genuine raw syscall trampoline, NOT a call through the host's own
 * glibc syscall(2) wrapper: glibc's OWN syscall() translates a kernel
 * failure into the ISO C convention (-1, with the real code left in
 * GLIBC's own errno, a different storage location from spicule's own
 * <errno.h>), so `errno = (int)-ret` below would misdecode any failure
 * as EPERM regardless. This function issues the raw `svc #0`/`syscall`
 * instruction directly, so `ret` really is the kernel's own
 * [-4095,-1]-encodes-errno value everywhere below.
 *
 * Reads six va_arg(long)s regardless of how many a caller actually
 * supplied for a given syscall number -- harmless in practice on this
 * ABI, since the callee's own calling convention always passes the first
 * several integer arguments in registers regardless of parameter count. */
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
/* Same variadic-capture trick as the aarch64 version above, just this
 * arch's own `syscall` register convention. */
static long syscall(long number, ...)
{
	va_list ap;
	long a1, a2, a3, a4, a5, a6;
	long ret;
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
/* i386 has no spare general register left for a 6th syscall argument
 * (unlike aarch64/x86_64's register-passing ABI) -- same "point %eax at
 * an explicit args array, int $0x80" technique as src/unistd/linux/
 * plat_fd.c's own i386 raw_syscall(), just wrapped in a variadic
 * function to match this file's own syscall(number, ...) call sites. */
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

static int unbox_fd(__plat_handle_t h) { return (int)((long)h - 1); }
/* __plat_handle_t is an opaque one-word carrier shared with the NT
 * backend; the real payload here is the plain fd number, boxed +1 so 0
 * stays free for __PLAT_HANDLE_NULL, never dereferenced. */
static __plat_handle_t box_fd(int fd) { return unsafe_assume_valid_pointer((__plat_handle_t)(long)(fd + 1)); }

/* pidfd -> pid side table for __plat_priority_get()/_set(): fixed size,
 * round-robin overwrite when full. Bounded rather than dynamic since this
 * backend never has more than a handful of foreign-process handles open
 * at once in practice, and a stale, overwritten entry only ever produces
 * a safe ESRCH-on-lookup-miss, never a wrong answer for the wrong pid. */
#define PIDFD_TABLE_MAX 32
static struct { int pidfd; pid_t pid; int used; } pidfd_pid_table[PIDFD_TABLE_MAX];
static int pidfd_table_next;

static void record_pidfd_pid(int pidfd, pid_t pid) // NOLINT(bugprone-easily-swappable-parameters) -- descriptor and process ID have distinct bookkeeping roles
{
	pidfd_pid_table[pidfd_table_next].pidfd = pidfd;
	pidfd_pid_table[pidfd_table_next].pid = pid;
	pidfd_pid_table[pidfd_table_next].used = 1;
	pidfd_table_next = (pidfd_table_next + 1) % PIDFD_TABLE_MAX;
}

/* -1 if `pidfd` was never recorded (or its slot has since been
 * overwritten) -- a safe "not found" rather than a wrong pid. */
static pid_t pid_for_pidfd(int pidfd)
{
	int i;
	for (i = 0; i < PIDFD_TABLE_MAX; i++)
		if (pidfd_pid_table[i].used && pidfd_pid_table[i].pidfd == pidfd)
			return pidfd_pid_table[i].pid;
	return (pid_t)-1;
}

/* kill(pid, 0): existence/permission checked, no signal sent -- the
 * [EPERM]-vs-[ESRCH] distinction sched.c's process_exists() wants.
 * pidfd_open(2) does NOT perform this same up-front permission check (a
 * real check happens later, at signal-send time), so this probe is still
 * needed even once the caller goes on to open a pidfd. */
static int probe_pid(pid_t pid)
{
	long ret = syscall(SYS_kill, (long)pid, 0L);
	if (is_sys_error(ret)) return ((int)-ret == EPERM) ? EPERM : ESRCH;
	return 0;
}

void __plat_yield(void)
{
	syscall(SYS_sched_yield);
}

/* Common to both open functions: probe (when `checked`), then
 * pidfd_open(2) for a real, closeable handle, boxed fd+1 like any other
 * Linux fd and recorded in the pid side table for the priority functions
 * below. */
static int open_process(pid_t pid, int checked, __plat_handle_t *out)
    __attribute__((nonnull(3)));
static int open_process(pid_t pid, int checked, __plat_handle_t *out) // NOLINT(bugprone-easily-swappable-parameters) -- process ID and validation flag have distinct roles
{
	long fd;
	if (checked) {
		int e = probe_pid(pid);
		if (e) { errno = e; return -1; }
	}
	fd = syscall(SYS_pidfd_open, (long)pid, 0L);
	if (is_sys_error(fd)) { errno = checked ? (int)-fd : ESRCH; return -1; }
	record_pidfd_pid((int)fd, pid);
	*out = box_fd((int)fd);
	return 0;
}

int __plat_process_open_checked(pid_t pid, __plat_handle_t *out)
{
	return open_process(pid, 1, out);
}

int __plat_process_open(pid_t pid, __plat_handle_t *out)
{
	/* Not checked with a separate kill(pid, 0) probe first: this contract
	 * reports [ESRCH] uniformly for every failure anyway, and
	 * pidfd_open(2)'s own failure already gives exactly that answer. */
	if (open_process(pid, 0, out) < 0) { errno = ESRCH; return -1; }
	return 0;
}

int __plat_process_alive(__plat_handle_t h)
{
	/* Unlike NT's check (which excludes a reaped-but-still-openable
	 * process object), Linux has no equivalent state to exclude: a pidfd
	 * still valid for pidfd_send_signal(fd, 0, ...) is either a live
	 * process or a not-yet-reaped zombie, and POSIX process_exists()
	 * means "does this pid still name something in the process table",
	 * which a zombie still does. pidfd_send_signal (not kill(pid, 0)) is
	 * immune to the original pid having been recycled meanwhile. */
	long ret = syscall(SYS_pidfd_send_signal, (long)unbox_fd(h), 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = ESRCH; return 0; }
	return 1;
}

int __plat_process_times_self(unsigned long long *user100ns, unsigned long long *kernel100ns) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; user and kernel outputs have distinct roles
{
	/* struct rusage's timeval fields (usec resolution) are this file's
	 * portable stand-in for KERNEL_USER_TIMES's 100ns fields, so this only
	 * needs to scale usec up by 10. spicule's own struct rusage is
	 * bit-identical to the raw getrusage(2) kernel ABI's own layout, so it
	 * can be handed straight to the syscall with no translation struct. */
	struct rusage ru;
	long ret = syscall(SYS_getrusage, 0L /* RUSAGE_SELF */, &ru);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	*user100ns = (unsigned long long)ru.ru_utime.tv_sec * 10000000ULL +
	             (unsigned long long)ru.ru_utime.tv_usec * 10ULL;
	*kernel100ns = (unsigned long long)ru.ru_stime.tv_sec * 10000000ULL +
	               (unsigned long long)ru.ru_stime.tv_usec * 10ULL;
	return 0;
}

int __plat_priority_get(__plat_handle_t h, int *nice_out)
{
	/* getpriority(2)'s raw kernel ABI returns 20-nice (range [1,40]) on
	 * success, never negative, so it cannot be confused with this
	 * syscall's [-4095,-1] error window: the kernel deliberately biases
	 * the result up by 20 for exactly this reason. Unlike NT, this needs
	 * no base-priority-class mapping; it just needs a bare pid, not this
	 * handle's own pidfd, hence the side-table lookup. */
	long ret;
	pid_t pid = pid_for_pidfd(unbox_fd(h));
	if (pid < 0) { errno = ESRCH; return -1; }
	ret = syscall(SYS_getpriority, (long)0 /* PRIO_PROCESS */, (long)pid);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	*nice_out = 20 - (int)ret;
	return 0;
}

int __plat_priority_set(__plat_handle_t h, int foreground, int nice_value) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; foreground mode and nice value have distinct roles
{
	long ret;
	pid_t pid;
	/* `foreground` is an NT-only concept (foreground-boost scheduling)
	 * with no Linux nice-value analog; src/misc/resource.c always passes
	 * 0 anyway, so there is nothing to translate. */
	(void)foreground;
	pid = pid_for_pidfd(unbox_fd(h));
	if (pid < 0) { errno = ESRCH; return -1; }
	ret = syscall(SYS_setpriority, (long)0 /* PRIO_PROCESS */, (long)pid, (long)nice_value);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_priority_set_self(int foreground, int nice_value) // NOLINT(bugprone-easily-swappable-parameters) -- foreground mode and nice value have distinct roles
{
	(void)foreground;
	{
		long ret = syscall(SYS_setpriority, (long)0 /* PRIO_PROCESS */, 0L /* self */, (long)nice_value);
		if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	}
	return 0;
}

int __plat_write_start_offset(__plat_handle_t h, int append, long long *out)
{
	/* `h` here is an fd handle (fd+1 boxing), NOT a process handle. This
	 * must never touch errno, so it does not reuse plat_fd.h's
	 * __plat_seek_query(); the fd+1 boxing convention is fixed by
	 * src/internal/libc.h's struct __fd across every backend, so
	 * re-deriving it here is not a guess. */
	int fd = (int)((long)h - 1);
	long ret = syscall(SYS_lseek, (long)fd, 0L, append ? 2L /* SEEK_END */ : 1L /* SEEK_CUR */);
	if (is_sys_error(ret)) return -1;
	*out = (long long)ret;
	return 0;
}

/* NT's lazily-created job object exists purely to give NT -- which
 * otherwise has no notion of "this process's own resource limits" --
 * something to attach RLIMIT_{NPROC,CPU,AS,DATA} to. Linux already has
 * real, kernel-enforced per-process rlimits: prlimit64(2) on pid 0 (self)
 * sets them directly. RLIM_INFINITY and RLIMIT_{CPU,DATA,NPROC,AS} are
 * already the real Linux kernel ABI's own values, so no translation is
 * needed for either. */
#define RLIMIT_CPU_LX   0
#define RLIMIT_DATA_LX  2
#define RLIMIT_NPROC_LX 6
#define RLIMIT_AS_LX    9

static void apply_one(int resource, rlim_t cur) // NOLINT(bugprone-easily-swappable-parameters) -- resource selector and limit value have distinct roles
{
	unsigned long long lim[2]; /* struct rlimit64 { rlim64_t cur, max; } */
	lim[0] = (unsigned long long)cur;
	lim[1] = (unsigned long long)cur; /* soft==hard: this backend only ever
	                                    * pushes the current soft value. */
	syscall(SYS_prlimit64, 0L /* self */, (long)resource, lim, 0L);
}

void __plat_job_apply_limits(rlim_t nproc_cur, rlim_t cpu_cur, rlim_t as_cur, rlim_t data_cur)
{
	/* Best-effort, like the NT backend: prlimit64(2) can only ever LOWER
	 * these hard limits here (both cur and max pushed to the same value),
	 * and an unprivileged process cannot raise its own hard limit back up
	 * -- matching real Linux setrlimit() semantics for an unprivileged
	 * caller. Failure is silently ignored: getrlimit() never asks the
	 * kernel to confirm what was actually accepted. */
	if (nproc_cur != RLIM_INFINITY) apply_one(RLIMIT_NPROC_LX, nproc_cur);
	if (cpu_cur != RLIM_INFINITY) apply_one(RLIMIT_CPU_LX, cpu_cur);
	if (as_cur != RLIM_INFINITY) apply_one(RLIMIT_AS_LX, as_cur);
	if (data_cur != RLIM_INFINITY) apply_one(RLIMIT_DATA_LX, data_cur);
}

/* RLIMIT_STACK/CORE/RSS/MEMLOCK are, like the four above, already the
 * real Linux kernel ABI's own numbering, so apply_one() above is reused
 * directly with spicule's own public RLIMIT_* constants. */
void __plat_rlimit_apply_extra(rlim_t stack_cur, rlim_t core_cur, rlim_t rss_cur, rlim_t memlock_cur)
{
	if (stack_cur != RLIM_INFINITY) apply_one(RLIMIT_STACK, stack_cur);
	if (core_cur != RLIM_INFINITY) apply_one(RLIMIT_CORE, core_cur);
	if (rss_cur != RLIM_INFINITY) apply_one(RLIMIT_RSS, rss_cur);
	if (memlock_cur != RLIM_INFINITY) apply_one(RLIMIT_MEMLOCK, memlock_cur);
}

/* ======================================================================
 * sched.c: real sched_setscheduler(2)/sched_getscheduler(2)/
 * sched_setparam(2)/sched_getparam(2)/sched_rr_get_interval(2). struct
 * sched_param is a single `int sched_priority` on both spicule's own ABI
 * and the raw kernel one, so it is handed straight to/from the syscall
 * with no translation struct.
 * ====================================================================== */

int __plat_sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
	long ret = syscall(SYS_sched_setscheduler, (long)pid, (long)policy, param);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_sched_getscheduler(pid_t pid)
{
	long ret = syscall(SYS_sched_getscheduler, (long)pid);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (int)ret;
}

int __plat_sched_setparam(pid_t pid, const struct sched_param *param)
{
	long ret = syscall(SYS_sched_setparam, (long)pid, param);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_sched_getparam(pid_t pid, struct sched_param *param)
{
	long ret = syscall(SYS_sched_getparam, (long)pid, param);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_sched_rr_get_interval(pid_t pid, struct timespec *interval)
{
	long ret = syscall(SYS_sched_rr_get_interval, (long)pid, interval);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ======================================================================
 * uname.c: Linux's own real uname(2) already answers every field of the
 * POSIX contract directly, unlike NT (which has to reconstruct each
 * field by hand). One syscall answers the whole struct.
 * ====================================================================== */

/* The raw kernel ABI's own struct new_utsname: six 65-byte NUL-terminated
 * fields, confirmed against this host's own <sys/utsname.h>. spicule's own
 * struct utsname is a different, wider shape (256-byte fields, no
 * domainname), so the raw syscall cannot write directly into the
 * caller's own `u` and needs this local buffer as an intermediate. */
struct linux_new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

static void copy_field(char *dst, size_t dstsz, const char *src, size_t srcsz)
{
	size_t n = strnlen(src, srcsz);
	if (n >= dstsz) n = dstsz - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

int __plat_uname(struct utsname *u)
{
	struct linux_new_utsname raw;
	long ret = syscall(SYS_uname, &raw);
	/* uname(2)'s only failure is EFAULT for a bad buffer, already ruled
	 * out by the front door's NULL check on `u`, so in practice this
	 * never fails, but the real -errno is still surfaced rather than
	 * assumed away. */
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	copy_field(u->sysname, sizeof u->sysname, raw.sysname, sizeof raw.sysname);
	copy_field(u->nodename, sizeof u->nodename, raw.nodename, sizeof raw.nodename);
	copy_field(u->release, sizeof u->release, raw.release, sizeof raw.release);
	copy_field(u->version, sizeof u->version, raw.version, sizeof raw.version);
	copy_field(u->machine, sizeof u->machine, raw.machine, sizeof raw.machine);
	/* spicule's own struct utsname has no domainname member at all, so
	 * raw.domainname is read by the syscall but has nowhere to go here. */
	return 0;
}

// NOLINTEND(misc-include-cleaner)
