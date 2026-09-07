/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_unistd.h -- see src/mman/
 * linux/plat_mem.c's own banner for the raw-syscall discipline this file
 * follows too.
 *
 * UNLIKE plat_fcntl.h's __plat_create_file(), which takes a `struct
 * __ntpath *` already resolved through NT-only machinery, every
 * path-taking function plat_unistd.h declares takes a plain `const char
 * *path` and, where relevant, a plain `int dirfd` -- so this whole family
 * ports directly onto Linux's own *at() syscalls, which take the
 * identical (dirfd, path) shape POSIX already gives them.
 *
 * __plat_chdir() and __plat_readlink() need no __vfs_resolve_at()
 * (src/internal/vfs.c) pre-check at all here, unlike on NT: Linux has
 * real native devices and a real native root, so __plat_chdir() always
 * reports __VFS_NONE, and Linux's own readlinkat(2) already answers
 * ENOENT/EINVAL correctly on its own.
 *
 * `dirfd` here may be spicule's own AT_FDCWD sentinel or an spicule fd-table
 * index, never a raw Linux fd on its own. resolve_dirfd() below turns
 * either into what the raw *at() syscalls need: AT_FDCWD passed straight
 * through (numerically identical to Linux's own), or the fd table's boxed
 * handle unboxed back into the real fd it names.
 *
 * spicule's own <fcntl.h> AT_FDCWD/AT_SYMLINK_NOFOLLOW/AT_REMOVEDIR/
 * AT_SYMLINK_FOLLOW/O_CLOEXEC values are numerically identical to the
 * kernel ABI's own, so they are used directly below rather than
 * reintroduced under an _LX suffix.
 *
 * SCOPED OUT, deliberately: __plat_alarm_arm()'s SIGALRM/timer machinery.
 * alarm()'s real semantics need a raw signal handler wired through
 * src/signal/linux/plat_signal.c's signal-delivery machinery, not this
 * file. __plat_alarm_arm() below always returns -1 ("could not arm"),
 * the exact degraded mode sleep.c's own alarm() already tolerates.
 *
 * getpid()/gettid() are implemented here too, via __plat_getpid()/
 * __plat_gettid() below, giving pthread_mutex.c's own port a working
 * getpid() reachable on this backend.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>   /* syscall()'s own public prototype (-Wmissing-prototypes) */
#include "libc.h"
#include "plat_unistd.h"
#include "unsafe_pointer.h"

/* Linux syscall numbers, confirmed against this host's own
 * <sys/syscall.h> (aarch64) / a real x86_64-linux-gnu glibc's asm/
 * unistd_64.h and unistd_32.h (x86_64, i386) -- three genuinely
 * different tables, not derived from each other by a fixed offset.
 * SYS_newfstatat has no i386 arm: it's unused in this file, and i386's
 * own fstatat syscall is a differently-shaped fstatat64 rather than a
 * same-shaped newfstatat under a different number. */
#if defined(__aarch64__)
#define SYS_getcwd              17
#define SYS_uname              160
#define SYS_chdir              49
#define SYS_unlinkat           35
#define SYS_linkat             37
#define SYS_readlinkat         78
#define SYS_symlinkat          36
#define SYS_newfstatat         79
#define SYS_fchownat           54
#define SYS_fchown             55
#define SYS_ftruncate          46
#define SYS_fsync              82
#define SYS_pipe2              59
#define SYS_getppid           173
#define SYS_getpid            172
#define SYS_gettid            178
#define SYS_getuid            174
#define SYS_getgid            176
#define SYS_clock_gettime     113
#define SYS_sched_getaffinity 123
#define SYS_sysinfo           179
#define SYS_kill              129
#define SYS_setpgid           154
#define SYS_getpgid           155
#define SYS_syncfs            267
#define SYS_acct               89
#define SYS_getrandom         278
#elif defined(__x86_64__)
#define SYS_getcwd              79
#define SYS_uname               63
#define SYS_chdir               80
#define SYS_unlinkat           263
#define SYS_linkat             265
#define SYS_readlinkat         267
#define SYS_symlinkat          266
#define SYS_newfstatat         262
#define SYS_fchownat           260
#define SYS_fchown              93
#define SYS_ftruncate           77
#define SYS_fsync               74
#define SYS_pipe2              293
#define SYS_getppid            110
#define SYS_getpid              39
#define SYS_gettid             186
#define SYS_getuid             102
#define SYS_getgid             104
#define SYS_clock_gettime      228
#define SYS_sched_getaffinity  204
#define SYS_sysinfo             99
#define SYS_kill                62
#define SYS_setpgid            109
#define SYS_getpgid            121
#define SYS_syncfs             306
#define SYS_acct               163
#define SYS_getrandom          318
#elif defined(__i386__)
#define SYS_getcwd             183
#define SYS_uname              122
#define SYS_chdir                12
#define SYS_unlinkat           301
#define SYS_linkat             303
#define SYS_readlinkat         305
#define SYS_symlinkat          304
#define SYS_newfstatat           0 /* unused on this arch -- see banner above */
#define SYS_fchownat           298
#define SYS_fchown               95
#define SYS_ftruncate            93
#define SYS_fsync               118
#define SYS_pipe2              331
#define SYS_getppid              64
#define SYS_getpid               20
#define SYS_gettid              224
#define SYS_getuid               24
#define SYS_getgid               47
#define SYS_clock_gettime      265
#define SYS_sched_getaffinity  242
#define SYS_sysinfo            116
#define SYS_kill                 37
#define SYS_setpgid              57
#define SYS_getpgid            132
#define SYS_syncfs             344
#define SYS_acct                 51
#define SYS_getrandom          355
#else
#error "plat_unistd.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A minimal 6-argument raw syscall, one calling convention per arch
 * below. NOT `extern long syscall(long, ...)`: that symbol resolves to
 * the HOST's real glibc at link time, which sets glibc's OWN errno on
 * failure rather than the raw kernel -errno this file's translation
 * requires -- and __plat_process_exists() below reads `-ret` directly
 * and compares it to EPERM, so under a glibc-wrapped syscall() every
 * kill(2) failure would collapse to ret==-1 and every nonexistent pid
 * would report as existing. */
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
#error "plat_unistd.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A raw Linux syscall returns the result on success, or -errno (an
 * unsigned value in [-4095, -1]) on failure -- see plat_mem.c's banner
 * for the full statement of this convention. */
static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

/* syscall(): unlike the rest of this file, which exists to satisfy
 * plat_unistd.h's own __plat_*() seam, this is the plain POSIX front door
 * itself, since Linux (unlike NT) has a real stable syscall ABI. Every
 * argument's count is unknown ("..."), so all six slots raw_syscall()
 * always takes are read regardless of how many the caller actually
 * passed; a kernel syscall taking fewer than six simply ignores the
 * extras, so this is harmless in practice. */
long syscall(long number, ...)
{
	va_list ap;
	long a1, a2, a3, a4, a5, a6, ret;

	va_start(ap, number);
	a1 = va_arg(ap, long);
	a2 = va_arg(ap, long);
	a3 = va_arg(ap, long);
	a4 = va_arg(ap, long);
	a5 = va_arg(ap, long);
	a6 = va_arg(ap, long);
	va_end(ap);

	ret = raw_syscall(number, a1, a2, a3, a4, a5, a6);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return ret;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* syncfs(): NT has no per-volume sync primitive, so this is a plain POSIX
 * front door, not a __plat_* seam -- just a direct syscall(2) (sync every
 * dirty inode/buffer for the filesystem `fd` is on, unlike fsync(2)'s
 * single-descriptor scope). */
int syncfs(int fd)
{
	struct __fd *f = __fd_get(fd);
	long ret;
	if (!f) return -1;
	ret = raw_syscall(SYS_syncfs, (long)unbox(f->h), 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* acct(): same "plain POSIX front door" shape as syncfs() just above; a
 * kernel built without CONFIG_BSD_PROCESS_ACCT answers ENOSYS honestly. */
int acct(const char *filename)
{
	long ret = raw_syscall(SYS_acct, (long)filename, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* Turns spicule's own AT_FDCWD sentinel or fd-table index into what the
 * raw *at() syscalls need. Returns -1 with errno already set only on a
 * bad table index -- never a legitimate result otherwise, since AT_FDCWD
 * is -100 and every unboxed real fd is >= 0. */
static int resolve_dirfd(int dirfd)
{
	struct __fd *f;
	if (dirfd == AT_FDCWD) return AT_FDCWD;
	f = __fd_get(dirfd);
	if (!f) return -1;
	return unbox(f->h);
}

/* ======================================================================
 * sleep.c: the realtime clock alarm()/__alertable_delay() share, and the
 * (deliberately unimplemented -- see this file's banner) alarm timer.
 * ====================================================================== */

long long __plat_time_now(void)
{
	/* Raw kernel struct timespec: two `long`s on every 64-bit Linux
	 * ABI (tv_sec, tv_nsec), unlike struct stat/sysinfo there is no
	 * historical 32-bit padding tail to worry about. */
	struct { long tv_sec; long tv_nsec; } ts = {0, 0};
	long long nt;
	long ret = raw_syscall(SYS_clock_gettime, 0L /* CLOCK_REALTIME */, (long)&ts, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) return __TICKS_1601_TO_1970; /* the epoch: never actually fails on Linux */
	/* __unix_to_ticks() (src/internal/libc.h) is the same NT-epoch/100ns-
	 * tick conversion src/time/clock_gettime.c and every other clock
	 * reader in this library already shares -- reused rather than
	 * reinvented so this backend's answer cannot drift from theirs. */
	if (!__unix_to_ticks(ts.tv_sec, ts.tv_nsec, &nt)) return __TICKS_1601_TO_1970;
	return nt;
}

int __plat_alarm_arm(long long due, unsigned long seq, __plat_alarm_fn deliver) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; due time and sequence have distinct roles
{
	(void)due; (void)seq; (void)deliver;
	return -1; /* see this file's banner: SIGALRM/timer machinery, deliberately out of scope */
}

void __plat_alarm_cancel(void)
{
	/* Nothing was ever armed (see __plat_alarm_arm() above); alarm.html
	 * gives this no error to report one with regardless. */
}

void __plat_alarm_reset_after_fork(void)
{
	/* Nothing to reset: __plat_alarm_arm() never creates a timer. */
}

/* ======================================================================
 * getpid.c: getpid()/gettid() are implemented here (see this file's own
 * banner) -- neither can fail on Linux any more than getppid(2) below
 * can, so neither checks is_sys_error() at all.
 * ====================================================================== */

pid_t __plat_getpid(void)
{
	return (pid_t)raw_syscall(SYS_getpid, 0L, 0L, 0L, 0L, 0L, 0L);
}

pid_t __plat_gettid(void)
{
	return (pid_t)raw_syscall(SYS_gettid, 0L, 0L, 0L, 0L, 0L, 0L);
}

pid_t __plat_getppid(void)
{
	long ret = raw_syscall(SYS_getppid, 0L, 0L, 0L, 0L, 0L, 0L);
	/* getppid(2) cannot fail on Linux (getppid.html reserves no error
	 * return either); init's conventional pid is the only sane
	 * fallback if it somehow did. */
	return is_sys_error(ret) ? (pid_t)1 : (pid_t)ret;
}

/* ======================================================================
 * ftruncate.c
 * ====================================================================== */

int __plat_ftruncate(__plat_handle_t h, off_t len)
{
	long ret = raw_syscall(SYS_ftruncate, (long)unbox(h), (long)len, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ======================================================================
 * fsync.c
 * ====================================================================== */

int __plat_fsync(__plat_handle_t h)
{
	long ret = raw_syscall(SYS_fsync, (long)unbox(h), 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ======================================================================
 * pipe.c
 * ====================================================================== */

int __plat_pipe(__plat_handle_t *rp, __plat_handle_t *wp, int inheritable)
{
	int fds[2] = {-1, -1};
	long ret = raw_syscall(SYS_pipe2, (long)fds, (long)(inheritable ? 0 : O_CLOEXEC), 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	/* __plat_handle_t is an opaque one-word carrier shared with the NT
	 * backend; the real payload here is the plain fd number, boxed +1
	 * so 0 stays free for __PLAT_HANDLE_NULL, never dereferenced. */
	*rp = unsafe_assume_valid_pointer((__plat_handle_t)(long)(fds[0] + 1));
	*wp = unsafe_assume_valid_pointer((__plat_handle_t)(long)(fds[1] + 1));
	return 0;
}

/* ======================================================================
 * sysconf.c
 * ====================================================================== */

long __plat_nprocessors(void)
{
	/* sched_getaffinity(2)'s return is the number of bytes of mask it
	 * actually wrote (the kernel's own cpumask_t size), which may be
	 * less than the buffer offered; counting set bits over exactly
	 * that many bytes, rather than the whole buffer, is what makes
	 * this correct for any core count the buffer is large enough to
	 * hold. */
	unsigned char mask[128];
	long ret, i, count = 0;
	for (i = 0; i < (long)sizeof mask; i++) mask[i] = 0;
	ret = raw_syscall(SYS_sched_getaffinity, 0L, (long)sizeof mask, (long)mask, 0L, 0L, 0L);
	if (is_sys_error(ret) || ret <= 0) return 1;
	for (i = 0; i < ret; i++) {
		unsigned char b = mask[i];
		while (b) { count += (b & 1); b = (unsigned char)(b >> 1); }
	}
	return count ? count : 1;
}

long __plat_phys_pages(void)
{
	/* Raw uapi struct sysinfo layout on a 64-bit Linux kernel
	 * (offsetof(totalram)==32, offsetof(mem_unit)==104), read by fixed
	 * byte offset out of a plain buffer rather than a locally-declared
	 * struct: struct sysinfo's historical `char _f[]` padding tail would
	 * otherwise silently drift between what this file assumes and what
	 * the kernel writes. */
	unsigned char raw[128];
	unsigned long long totalram;
	unsigned int mem_unit;
	long ret, i;
	for (i = 0; i < (long)sizeof raw; i++) raw[i] = 0;
	ret = raw_syscall(SYS_sysinfo, (long)raw, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) return -1;
	totalram = 0;
	for (i = 7; i >= 0; i--) totalram = (totalram << 8) | raw[32 + i];
	mem_unit = 0;
	for (i = 3; i >= 0; i--) mem_unit = (mem_unit << 8) | raw[104 + i];
	if (!mem_unit) mem_unit = 1;
	return (long)((totalram * mem_unit) / 4096);
}

/* ======================================================================
 * unlink.c
 * ====================================================================== */

int __plat_unlink(int dirfd, const char *path, int isdir)
{
	int rd = resolve_dirfd(dirfd);
	long ret;
	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */
	ret = raw_syscall(SYS_unlinkat, (long)rd, (long)path, (long)(isdir ? AT_REMOVEDIR : 0), 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ======================================================================
 * getcwd.c: Linux's own getcwd(2) already answers exactly the plat_
 * unistd.h contract wants (a NUL-terminated, forward-slash, absolute
 * path, since a Linux pathname is just bytes), far simpler than the NT
 * backend's UTF-16 DOS-form fetch-and-convert.
 *
 * getcwd(2)'s own return is the number of bytes written INCLUDING the
 * terminating NUL -- one less than that is the length plat_unistd.h's
 * contract asks for. */
ssize_t __plat_getcwd(char *buf, size_t bufsz)
{
	long ret = raw_syscall(SYS_getcwd, (long)buf, (long)bufsz, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)(ret - 1);
}

/* ======================================================================
 * gethostname.c: Linux has no standalone gethostname(2) syscall on the
 * modern generic ABI, so this backend answers the same hostname
 * __plat_uname() (src/misc/linux/plat_misc.c) already reports as struct
 * utsname's nodename field, via the identical raw uname(2) call, rather
 * than NT's environment-variable indirection. test/posix-tail.c's
 * uname()/gethostname() cross-check depends on the two calls agreeing.
 * ====================================================================== */

void __plat_hostname(char *buf, size_t bufsz)
{
	/* Raw kernel struct new_utsname: six 65-byte NUL-terminated fields,
	 * nodename second (see src/misc/linux/plat_misc.c's __plat_uname()). */
	struct { char sysname[65]; char nodename[65]; char release[65];
	         char version[65]; char machine[65]; char domainname[65]; } raw;
	const char *h;
	size_t n, i;
	long ret = raw_syscall(SYS_uname, (long)&raw, 0L, 0L, 0L, 0L, 0L);
	h = is_sys_error(ret) ? "localhost" : raw.nodename;
	n = strlen(h);
	if (!bufsz) return;
	if (n >= bufsz) n = bufsz - 1;
	for (i = 0; i < n; i++) buf[i] = h[i];
	buf[n] = '\0';
}

/* ======================================================================
 * chdir.c
 * ====================================================================== */

int __plat_chdir(const char *path, int *vfsout)
{
	long ret = raw_syscall(SYS_chdir, (long)path, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	/* No overlay on this backend at all -- see this file's own banner --
	 * so nothing to report beyond the plat_unistd.h contract's own
	 * "__VFS_NONE, always" for a backend with no overlay concept. */
	*vfsout = __VFS_NONE;
	return 0;
}

/* ======================================================================
 * link.c
 * ====================================================================== */

int __plat_link(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int followsym)
{
	int rold = resolve_dirfd(olddirfd);
	int rnew;
	long ret;
	if (rold == -1 && olddirfd != AT_FDCWD) return -1;
	rnew = resolve_dirfd(newdirfd);
	if (rnew == -1 && newdirfd != AT_FDCWD) return -1;
	ret = raw_syscall(SYS_linkat, (long)rold, (long)oldpath, (long)rnew, (long)newpath,
	                 (long)(followsym ? AT_SYMLINK_FOLLOW : 0), 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

ssize_t __plat_readlink(int dirfd, const char *path, char *buf, size_t bufsz)
{
	int rd = resolve_dirfd(dirfd);
	long ret;
	if (rd == -1 && dirfd != AT_FDCWD) return -1;
	/* readlinkat(2)'s own truncate-silently behaviour already IS
	 * readlink.html's contract verbatim, unlike the NT backend which has
	 * to build it out of a reparse-point buffer by hand. */
	ret = raw_syscall(SYS_readlinkat, (long)rd, (long)path, (long)buf, (long)bufsz, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

int __plat_symlink(const char *target, int newdirfd, const char *linkpath)
{
	int rd = resolve_dirfd(newdirfd);
	long ret;
	if (rd == -1 && newdirfd != AT_FDCWD) return -1;
	ret = raw_syscall(SYS_symlinkat, (long)target, (long)rd, (long)linkpath, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ======================================================================
 * ids.c: Linux has real process groups and a real uid, unlike NT, so
 * this whole section is a much shorter story than src/unistd/nt/
 * plat_unistd.c's Cygwin-style SID-to-uid mapping and named-event pgrp
 * trick -- it just asks the kernel.
 * ====================================================================== */

uid_t __plat_detect_uid(void)
{
	/* getuid(2) cannot fail on Linux, and getuid.html reserves no
	 * error return either -- the raw return is always the real uid,
	 * never in is_sys_error()'s [-4095,-1] failure window. */
	return (uid_t)raw_syscall(SYS_getuid, 0L, 0L, 0L, 0L, 0L, 0L);
}

/* getgid(2), same "cannot fail" contract as getuid(2) just above. */
gid_t __plat_detect_gid(void)
{
	return (gid_t)raw_syscall(SYS_getgid, 0L, 0L, 0L, 0L, 0L, 0L);
}

void __plat_pgrp_publish_self(pid_t self)
{
	/* The NT backend publishes a named event because NT has nothing else
	 * to hang "this process is a group leader" on; Linux actually has the
	 * process group setpgid(0,0) asks for, superseding the event trick
	 * entirely. Best-effort and silent on failure, matching setpgrp.html's
	 * "no errors are defined". */
	(void)self;
	raw_syscall(SYS_setpgid, 0L, 0L, 0L, 0L, 0L, 0L);
}

int __plat_pgrp_is_leader(pid_t pid)
{
	long ret = raw_syscall(SYS_getpgid, (long)pid, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) return 0;
	return ret == (long)pid;
}

int __plat_process_exists(pid_t pid)
{
	/* kill(pid, 0) is the standard POSIX existence probe: 0 means the
	 * process exists and is signalable, EPERM means it exists but isn't
	 * ours to signal, and anything else (ESRCH first) means it doesn't. */
	long ret = raw_syscall(SYS_kill, (long)pid, 0L, 0L, 0L, 0L, 0L);
	if (!is_sys_error(ret)) return 1;
	return (int)-ret == EPERM;
}

/* There is real ownership to set on Linux (unlike NT, whose __plat_chown()
 * stays a path-resolving probe): fchownat(2) already takes the identical
 * (dirfd, path, uid, gid, flags) shape the front door hands down, the
 * (uid_t)-1/(gid_t)-1 "leave unchanged" sentinel included.
 *
 * `flags` is masked to AT_SYMLINK_NOFOLLOW before the syscall: classic
 * fchownat(2) validates its flags word strictly (an unrecognised bit is a
 * real EINVAL), and the front door treats an unrecognised bit as a
 * may-fail it chooses not to fail, so only the one bit chown.html defines
 * is ever forwarded. */
int __plat_chown(int dirfd, const char *path, uid_t uid, gid_t gid, int flags) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; uid/gid/flags have distinct roles
{
	int rd = resolve_dirfd(dirfd);
	long ret;
	if (rd == -1 && dirfd != AT_FDCWD) return -1;
	ret = raw_syscall(SYS_fchownat, (long)rd, (long)path, (long)uid, (long)gid,
	                 (long)(flags & AT_SYMLINK_NOFOLLOW), 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* fchown(2): the handle-taking sibling, no path or dirfd resolution
 * needed -- `h` already names an open Linux fd via this file's fd+1
 * boxing. */
int __plat_fchown(__plat_handle_t h, uid_t uid, gid_t gid)
{
	long ret = raw_syscall(SYS_fchown, (long)unbox(h), (long)uid, (long)gid, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ======================================================================
 * getentropy.c
 * ====================================================================== */

/* getrandom(2), always with flags == 0: no GRND_NONBLOCK (getentropy() has
 * no non-blocking mode) and no GRND_RANDOM (that selects the legacy
 * /dev/random-equivalent behaviour, which can block for a long time on
 * boot entropy; the default source blocks only until the kernel considers
 * itself seeded, which is what getentropy() wants). A short return is
 * looped rather than surfaced, same as elsewhere in this tree. */
int __plat_getentropy(void *buf, size_t buflen)
{
	unsigned char *p = buf;
	size_t left = buflen;
	while (left) {
		long ret = raw_syscall(SYS_getrandom, (long)p, (long)left, 0L, 0L, 0L, 0L);
		if (is_sys_error(ret)) {
			if ((int)-ret == EINTR) continue;
			errno = (int)-ret;
			return -1;
		}
		p += ret;
		left -= (size_t)ret;
	}
	return 0;
}

// NOLINTEND(misc-include-cleaner)
