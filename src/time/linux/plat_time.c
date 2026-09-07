/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_time.h -- see src/mman/linux/
 * plat_mem.c's own banner for the general discipline every Linux backend
 * file keeps (raw syscall(2), no host libc, -nostdinc against spicule's
 * OWN generated headers, aarch64 syscall numbers confirmed against this
 * host's real glibc rather than assumed).
 *
 * The interface this backend implements is expressed entirely in NT's
 * own units (100ns ticks since 1601-01-01 -- see plat_time.h's banner:
 * "the epoch conversion ... stay[s] exactly where [it] already was ...
 * and [is] NOT part of this interface"). That is not NT leaking into a
 * platform-neutral seam by accident: every front door under src/time/
 * already calls the shared, portable src/internal/libc.h helpers
 * (__ticks_to_unix_sec/__ticks_to_unix_nsec/__unix_to_ticks) to cross between
 * that unit and a POSIX timespec, so this backend reuses those same
 * helpers rather than inventing a second, parallel conversion -- the
 * NT-tick representation is just this seam's chosen wire format, the
 * same way __plat_mem_map_file()'s prot/flags bits are already POSIX
 * values on both backends (see plat_mem.c's own banner) rather than
 * each backend picking its own vocabulary.
 *
 * spicule's own CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1)
 * (include/time.h) are confirmed, not assumed, to already match the
 * Linux kernel's own clockid_t values for clock_gettime(2)/
 * clock_settime(2) -- verified against this build host's real
 * <time.h> (POSIX/Linux both fix these at 0 and 1) -- so
 * this file passes them straight through with no translation table,
 * unlike a backend for a platform whose clock IDs did not already
 * line up. spicule's own struct timespec (include/alltypes.h.in:
 * "STRUCT timespec { time_t tv_sec; long tv_nsec; }", both 8-byte
 * fields, no padding) was likewise confirmed field-order- and width-
 * compatible with the raw 16-byte structure the Linux clock_gettime(2)
 * syscall itself writes on both this build's generated-header
 * convention (x86_64, always LP64 regardless of host --
 * tools/linux-build.sh's own banner) and this host's actual aarch64
 * kernel ABI (also LP64) before being relied on below -- a raw syscall
 * writes bytes with no type-checking to catch a mismatch, so this was
 * confirmed with a throwaway host oracle program rather than assumed
 * from "it's just seconds and nanoseconds".
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <time.h>
#include <sys/resource.h>
#include <errno.h>
#include "libc.h"
#include "plat_time.h"

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * <sys/syscall.h>/<time.h>/<sys/resource.h> via a throwaway host-glibc
 * oracle program (see src/mman/linux/plat_mem.c's banner for why they
 * cannot come from a host header in this file itself: this build is
 * -nostdinc against spicule's own generated headers, never glibc's).
 * Oracle output on this host: SYS_clock_gettime=113, SYS_clock_settime=112,
 * SYS_getrusage=165, CLOCK_REALTIME=0, CLOCK_MONOTONIC=1,
 * sizeof(struct timespec)=16, sizeof(time_t)=sizeof(long)=8,
 * sizeof(struct rusage)=144 (matching include/sys/resource.h's own
 * layout exactly -- see below). x86_64 confirmed against this host's
 * own /nix/store linux-headers asm/unistd_64.h; also LP64, same
 * bit-for-bit-compatible situation as aarch64.
 *
 * i386 is genuinely different, not just a number swap: its plain
 * SYS_clock_gettime/_settime (265/264) are the LEGACY Y2038-unsafe
 * 32-bit-time_t syscalls, writing an 8-byte kernel struct, while
 * spicule's own struct timespec always carries a 64-bit time_t
 * (include/alltypes.h.in's own `TYPEDEF _Int64 time_t`, the same
 * Y2038-safe choice as off_t) -- handing that wider struct's address
 * to the narrow legacy syscall would only let the kernel fill the
 * first 8 of its 12 bytes, leaving stale/uninitialized high bits and a
 * garbage tv_nsec. This file instead uses the real Y2038-safe *64
 * syscalls on i386 (403/404), matching spicule's own 64-bit time_t
 * choice, decoded through the __lx_timespec64/__lx_rusage32 kernel-ABI
 * mirrors below rather than spicule's own wider structs. i386's
 * SYS_getrusage (77) has no such split -- getrusage(2)'s own struct
 * rusage was never widened for Y2038 on ANY arch (its timeval fields
 * stay the kernel's native `long` width, 32-bit on i386 to this day),
 * so it is spicule's own struct rusage (always 64-bit `time_t
 * tv_sec`/`suseconds_t tv_usec` in its embedded timevals) that
 * mismatches the raw i386 ABI here, the same shape of gap as
 * clock_gettime's, addressed the same way (see __lx_rusage32 below). */
#if defined(__aarch64__)
#define SYS_clock_gettime 113
#define SYS_clock_settime 112
#define SYS_getrusage     165
#elif defined(__x86_64__)
#define SYS_clock_gettime 228
#define SYS_clock_settime 227
#define SYS_getrusage     98
#elif defined(__i386__)
#define SYS_clock_gettime64 403
#define SYS_clock_settime64 404
#define SYS_getrusage       77
#else
#error "plat_time.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

#if defined(__i386__)
/* Raw i386 kernel ABI mirrors -- see this file's own banner above for
 * why spicule's own struct timespec/struct rusage cannot be used
 * directly here the way they can on the two LP64 arches. Sizes
 * confirmed against the real kernel uapi shapes (struct
 * __kernel_timespec: two 8-byte fields, no gap regardless of i386's
 * own 4-byte natural alignment for `long long`, since 8 is already a
 * multiple of 4; struct __kernel_old_timeval/struct rusage: every
 * field the kernel's native 32-bit `long`, matching this arch's own
 * `long` exactly), sanity-checked below rather than trusted by
 * inspection alone -- same discipline as src/dirent/linux/
 * plat_dirent.c's own __lx_dirent64 _Static_assert. */
struct __lx_timespec64 { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	long long tv_sec;
	long long tv_nsec;
};
_Static_assert(sizeof(struct __lx_timespec64) == 16,
               "__lx_timespec64 layout mismatch for i386");

struct __lx_timeval32 { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	long tv_sec;
	long tv_usec;
};
struct __lx_rusage32 { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	struct __lx_timeval32 ru_utime;
	struct __lx_timeval32 ru_stime;
	long ru_maxrss, ru_ixrss, ru_idrss, ru_isrss, ru_minflt, ru_majflt; // NOLINT(readability-isolate-declaration) -- mirrors the kernel's own flat field-list ABI shape
	long ru_nswap, ru_inblock, ru_oublock, ru_msgsnd, ru_msgrcv; // NOLINT(readability-isolate-declaration) -- mirrors the kernel's own flat field-list ABI shape
	long ru_nsignals, ru_nvcsw, ru_nivcsw; // NOLINT(readability-isolate-declaration) -- mirrors the kernel's own flat field-list ABI shape
};
_Static_assert(sizeof(struct __lx_rusage32) == 72,
               "__lx_rusage32 layout mismatch for i386");
#endif

/* A minimal 6-argument raw syscall: no host libc in the call path at
 * all. NOT `extern long syscall(long, ...)`: that symbol is satisfied
 * by the HOST's real glibc at link time (this build is -nostdinc, not
 * -nostdlib -- only compiling avoids the host headers, the final link
 * step still pulls in host libc), and glibc's syscall() performs its
 * own error translation: on failure it returns exactly -1 and sets
 * glibc's OWN errno (a different memory location than spicule's own
 * errno global, src/internal/errno.c) to the real code -- it does NOT
 * hand back the raw kernel -errno in [-4095,-1] this file's
 * is_sys_error()/`errno = (int)-ret` translation requires. Confirmed
 * both by inspecting the linked pilot binary (nm -D shows an undefined
 * `syscall@GLIBC_*`, resolved by ld-linux at runtime) and independently
 * by src/thread/linux/plat_thread.c's own port, which hit the identical
 * bug and is this fix's model. Three per-arch bodies, same "own syscall
 * table per file" discipline this tree already uses (see
 * src/dirent/linux/plat_dirent.c's own raw_syscall()): aarch64's
 * `svc #0`, x86_64's `syscall`, i386's register-starved `int $0x80`. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
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
#else
#error "plat_time.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A raw Linux syscall returns the result on success, or -errno (as an
 * unsigned value in [-4095, -1]) on failure -- see plat_mem.c's own
 * comment on this same helper. */
static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

void __plat_realtime_get(long long *nt_ticks)
{
	/* Zero-initialized so a (realistically unreachable -- clock_gettime()
	 * with a valid stack address and CLOCK_REALTIME has no failure mode
	 * on a running kernel) syscall failure still leaves a well-defined
	 * timespec behind rather than reading an uninitialized local, the
	 * same "no documented failure mode ... never checked" contract
	 * plat_time.h's own comment describes for this function. */
#if defined(__i386__)
	struct __lx_timespec64 raw = {0, 0};
	raw_syscall(SYS_clock_gettime64, (long)CLOCK_REALTIME, (long)&raw, 0L, 0L, 0L, 0L);
	__unix_to_ticks((time_t)raw.tv_sec, (long)raw.tv_nsec, nt_ticks);
#else
	struct timespec ts = {0, 0};
	raw_syscall(SYS_clock_gettime, (long)CLOCK_REALTIME, (long)&ts, 0L, 0L, 0L, 0L);
	/* __unix_to_ticks() can only reject an out-of-range input (a `sec` many
	 * millennia from now); *nt_ticks is left at whatever it already held
	 * in that unreachable case, matching this function's own "never
	 * checked" contract -- there is no error channel to report through. */
	__unix_to_ticks(ts.tv_sec, ts.tv_nsec, nt_ticks);
#endif
}

int __plat_realtime_set(long long nt_ticks)
{
	long ret;
#if defined(__i386__)
	struct __lx_timespec64 raw;
	raw.tv_sec = (long long)__ticks_to_unix_sec(nt_ticks);
	raw.tv_nsec = (long long)__ticks_to_unix_nsec(nt_ticks);
	ret = raw_syscall(SYS_clock_settime64, (long)CLOCK_REALTIME, (long)&raw, 0L, 0L, 0L, 0L);
#else
	struct timespec ts;
	ts.tv_sec = (time_t)__ticks_to_unix_sec(nt_ticks);
	ts.tv_nsec = __ticks_to_unix_nsec(nt_ticks);
	ret = raw_syscall(SYS_clock_settime, (long)CLOCK_REALTIME, (long)&ts, 0L, 0L, 0L, 0L);
#endif
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_perfcounter_get(long long *count, long long *freq) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; counter and frequency outputs have distinct roles
{
	long long sec, nsec;
#if defined(__i386__)
	struct __lx_timespec64 raw = {0, 0};
	long ret = raw_syscall(SYS_clock_gettime64, (long)CLOCK_MONOTONIC, (long)&raw, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	sec = raw.tv_sec;
	nsec = raw.tv_nsec;
#else
	struct timespec ts = {0, 0};
	long ret = raw_syscall(SYS_clock_gettime, (long)CLOCK_MONOTONIC, (long)&ts, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	sec = ts.tv_sec;
	nsec = ts.tv_nsec;
#endif
	/* Express CLOCK_MONOTONIC as a nanosecond counter running at a fixed
	 * 1e9 Hz "frequency": src/internal/libc.h's __clock_qpc_to_timespec()
	 * (sec = count/freq, nsec = (count%freq) scaled to a ns fraction)
	 * reduces exactly to sec=ts.tv_sec, nsec=ts.tv_nsec for this choice
	 * of freq, so the front door (src/time/clock_gettime.c's
	 * monotonic_get()) recovers the original timespec bit-for-bit with
	 * no translation loss, the same contract NT's QPC pair already
	 * promises with its own arbitrary frequency. */
	if (sec < 0 || sec > (INT64_MAX - nsec) / 1000000000LL) {
		errno = EOVERFLOW;
		return -1;
	}
	*count = sec * 1000000000LL + nsec;
	*freq = 1000000000LL;
	return 0;
}

int __plat_process_cpu_ticks(long long *kernel, long long *user) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; kernel and user outputs have distinct roles
{
	/* include/sys/resource.h's own struct rusage banner already commits
	 * to reporting exactly the raw kernel ABI's fields, in the kernel's
	 * own order, with no trailing padding (a deliberate choice recorded
	 * there for the native-build symbol-preemption reason its comment
	 * describes) -- so on the two LP64 arches (unlike plat_fd.c's
	 * SEEK_END comment, which had to hand-roll a local struct because
	 * spicule's own headers had nothing to reuse), this backend can and
	 * does use spicule's own sys/resource.h struct rusage/getrusage()
	 * prototype directly. Its 144-byte size was confirmed to match this
	 * host's raw SYS_getrusage output exactly via the same oracle
	 * program. i386 is the one arch where that no longer holds -- see
	 * this file's own banner -- so it decodes through the raw
	 * __lx_rusage32 kernel-ABI mirror above instead. */
	long long user_us, kernel_us;
#if defined(__i386__)
	struct __lx_rusage32 ru = {{0, 0}, {0, 0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	long ret = raw_syscall(SYS_getrusage, (long)RUSAGE_SELF, (long)&ru, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	user_us = (long long)ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec;
	kernel_us = (long long)ru.ru_stime.tv_sec * 1000000LL + ru.ru_stime.tv_usec;
#else
	struct rusage ru = {0};
	long ret = raw_syscall(SYS_getrusage, (long)RUSAGE_SELF, (long)&ru, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	user_us = (long long)ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec;
	kernel_us = (long long)ru.ru_stime.tv_sec * 1000000LL + ru.ru_stime.tv_usec;
#endif
	/* getrusage() reports microsecond resolution; the interface wants
	 * 100ns ticks (__TICKS_PER_SEC == 1e7), so scale by 10 -- the same
	 * "no extra validation, __clock_combine_cpu_ticks() is the trust
	 * boundary every front door already applies" division of
	 * responsibility src/time/nt/plat_time.c's own
	 * __plat_process_cpu_ticks() keeps toward KERNEL_USER_TIMES. */
	*user = user_us * 10;
	*kernel = kernel_us * 10;
	return 0;
}

/* --- timer.c's per-process manager thread: deliberately unimplemented --
 *
 * The clock-query functions above are the part of this interface that
 * genuinely simplifies on Linux (no reservation table, no EOF/zero-fill
 * workaround -- see plat_mem.c's banner for the analogous story on the
 * mman side). The manager thread is the opposite: a correct
 * implementation needs real thread creation plus a real cross-thread
 * wake primitive, and this file deliberately does not attempt either,
 * for a specific reason beyond "out of scope":
 *
 *   1. Thread creation via clone(2) (CLONE_VM|CLONE_FS|CLONE_FILES|
 *      CLONE_THREAD|CLONE_SIGHAND|CLONE_SETTLS|CLONE_PARENT_SETTID|
 *      CLONE_CHILD_CLEARTID, ...) needs this backend to own a stack
 *      allocation (an mmap()'d region -- clone() takes a bare stack
 *      pointer, unlike NtCreateThreadEx, which manages the new thread's
 *      stack itself) and to reap or reset that allocation across
 *      timer.c's __timer_reinit_after_fork() path.
 *   2. The manager thread needs a wake primitive the caller thread can
 *      signal without a race: futex(2) (FUTEX_WAIT/FUTEX_WAKE on a
 *      shared word) or an eventfd(2) read()/write() pair. Either is a
 *      small surface on its own, but the property NT's auto-reset event
 *      gives for free -- see __plat_timer_manager_wait's own doc
 *      comment in plat_time.h: "auto-reset wake closes the scan/wait
 *      race" -- has to be rebuilt by hand on Linux: the futex word's
 *      value has to distinguish "a wake was requested before I started
 *      waiting" from "no wake yet", or a timer_settime()/timer_delete()
 *      landing in the manager's narrow scan-then-wait window is missed
 *      silently until the next unrelated wakeup happens to occur. That
 *      is not a hang and not a crash -- it is a timer that fires late,
 *      exactly the shape of bug a short smoke test does not reliably
 *      catch, and the accuracy bar this port holds itself to elsewhere
 *      (fuzz/linux_pilot_test.c's msync()-through-a-real-fd round trip,
 *      not just "the mapping that wrote it") is not one a rushed
 *      attempt at both (1) and (2) together would clear with
 *      confidence.
 *   3. Both of the above have to work with no libc runtime underneath
 *      them at all (this file's own -nostdinc, no-host-libc discipline):
 *      clone()'s child begins executing with a valid CLONE_VM
 *      environment from its very first instruction, with nothing to
 *      fall back on if that setup is subtly wrong.
 *
 * Returning failure here costs less than it might look like: timer.c's
 * start_manager() is only reached for a timer_create() whose event is
 * either omitted (defaults to SIGEV_SIGNAL/SIGALRM) or explicitly
 * SIGEV_SIGNAL -- a caller who passes SIGEV_NONE skips it entirely, and
 * timer_settime()/timer_gettime() for a SIGEV_NONE timer derive
 * remaining time purely from clock_gettime() (see timer.c's
 * timer_value()/clock_ticks()), which this backend already serves
 * correctly above. Only SIGEV_SIGNAL notification -- the manager thread
 * actually firing a signal on a deadline -- is unavailable here, exactly
 * mirroring the native (non-NT) sanitizer shim's own EAGAIN path in
 * src/time/nt/plat_time.c's #ifdef _SPICULE_NATIVE_BUILD branch, which
 * has the identical "no thread/signal-delivery transport" limitation
 * for a different reason. */
int __plat_timer_manager_start(void (*loop)(void), __plat_handle_t *wake_out)
{
	(void)loop;
	(void)wake_out;
	errno = EAGAIN;
	return -1;
}

/* Unreachable on this backend: __plat_timer_manager_start() above always
 * fails, so timer.c's manager_wake is never nonzero and neither of these
 * is ever called (timer_settime()/timer_delete() both guard their call
 * with `if (manager_wake)`, and timer_manager() -- the only caller of
 * __plat_timer_manager_wait() -- never runs since no thread was ever
 * created to run it on). Real, harmless bodies are still required so the
 * link succeeds: timer.c calls both unconditionally in source, and this
 * backend's -nostdinc build has no way to prove either call statically
 * dead. */
void __plat_timer_wake(__plat_handle_t wake)
{
	(void)wake;
}

void __plat_timer_manager_wait(__plat_handle_t wake, long long ticks, int has_deadline) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; duration and deadline flag have distinct roles
{
	(void)wake;
	(void)ticks;
	(void)has_deadline;
}

// NOLINTEND(misc-include-cleaner)
