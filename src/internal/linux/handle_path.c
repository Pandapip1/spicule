/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux's half of the src/internal/nt/handle_path.c split -- called
 * unconditionally from portable front doors (fchmod()'s EACCES retry,
 * fchdir(), exec.c, realpath.c), so a Linux build needs a real body here.
 *
 * NT has no reverse mapping from a HANDLE back to a path, hence that
 * file's device-name-plus-drive-letter search. Linux does not need any
 * of that: the kernel already publishes this mapping for every open
 * descriptor as the symlink target of /proc/self/fd/<fd> (proc(5)), and
 * readlinkat(2) reads it directly.
 *
 * One honest gap, inherited from /proc/self/fd itself: if the
 * descriptor's file was unlink()ed while still open, the kernel appends
 * " (deleted)" to the symlink target, so the string returned is not a
 * path that can be reopened -- matching glibc's own realpath() behaviour
 * on a deleted-but-open fd.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include "libc.h"

/* Same 6-argument raw syscall trampoline every Linux backend defines
 * for itself. File-scoped by convention, not shared, the same as every
 * other Linux backend in this tree. Three per-arch bodies, same "own
 * syscall table per file" discipline this tree already uses (see
 * src/dirent/linux/plat_dirent.c's own raw_syscall()): aarch64's
 * `svc #0`, x86_64's `syscall`, i386's register-starved `int $0x80`. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc #0"
	                 : "+r"(x0)
	                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
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
#error "handle_path.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* Linux syscall number -- aarch64 confirmed against this host's own
 * <sys/syscall.h>; x86_64/i386 confirmed against this host's own
 * /nix/store linux-headers asm/unistd_64.h / asm/unistd_32.h. */
#if defined(__aarch64__)
#define SYS_readlinkat 78
#elif defined(__x86_64__)
#define SYS_readlinkat 267
#elif defined(__i386__)
#define SYS_readlinkat 305
#else
#error "handle_path.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

/* HANDLE here is always this backend's own boxed (fd + 1) encoding
 * (src/unistd/linux/plat_fd.c's banner) -- every caller of this function
 * already holds a __plat_handle_t this backend itself produced. */
static int unbox(HANDLE h)
{
	return (int)((long)h - 1);
}

/* "/proc/self/fd/" plus up to 10 decimal digits (a 32-bit fd never needs
 * more) plus the terminator. Written by hand rather than through
 * snprintf() to avoid pulling in the stdio subsystem for this alone. */
static void fd_path(int fd, char *out)
{
	static const char prefix[] = "/proc/self/fd/";
	char digits[10];
	int nd = 0;
	size_t i;

	for (i = 0; prefix[i]; i++) out[i] = prefix[i];
	if (fd == 0) {
		digits[nd++] = '0';
	} else {
		unsigned u = (unsigned)fd; /* fd is never negative here: unbox()'s
		                            * caller already rejected that case. */
		while (u) { digits[nd++] = (char)('0' + u % 10); u /= 10; }
	}
	while (nd) out[i++] = digits[--nd];
	out[i] = 0;
}

withtok(internal_heap_allocated)
char *__handle_path(HANDLE h)
{
	int fd = unbox(h);
	char path[32];
	char buf[PATH_MAX];
	char *r;
	long n;
	size_t bytes;

	if (fd < 0) { errno = EBADF; return 0; }
	fd_path(fd, path);
	n = raw_syscall(SYS_readlinkat, (long)AT_FDCWD, (long)path, (long)buf, (long)sizeof buf, 0L, 0L);
	if (is_sys_error(n)) { errno = (int)-n; return 0; }
	/* readlinkat(2) never NUL-terminates; it fills up to n bytes and
	 * reports the count, exactly like the POSIX readlink() this mirrors
	 * (see __plat_readlink()'s own comment on the same call). */
	if (!__size_add_checked((size_t)n, 1, &bytes)) { errno = ENOMEM; return 0; }
	r = __malloc(bytes);
	if (!r) return 0;
	if (n) {
		size_t i;
		for (i = 0; i < (size_t)n; i++) r[i] = buf[i];
	}
	r[n] = 0;
	return r;
}

// NOLINTEND(misc-include-cleaner)
