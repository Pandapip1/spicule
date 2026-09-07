/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_fd.h -- see src/mman/linux/
 * plat_mem.c's own banner for the raw-syscall discipline this file
 * follows too.
 *
 * __plat_handle_t encoding: a Linux fd is a small int, and fd 0 (stdin)
 * is perfectly valid, while every front door treats a NULL/zero
 * __plat_handle_t as "no handle, empty slot". This file boxes a real fd
 * as (fd + 1) and unboxes by subtracting 1, so __PLAT_HANDLE_NULL (0)
 * never collides with any real fd.
 *
 * Every NT-specific interpretation step plat_fd.h describes -- STATUS_
 * PENDING waits, broken-pipe-as-EOF, EFBIG's offset-maximum query,
 * SIGPIPE's status disambiguation -- collapses to nothing here: a Linux
 * read()/write() syscall already returns 0 at EOF and already delivers
 * SIGPIPE via the kernel's own default disposition on a broken pipe.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include "plat_fd.h"
#include "unsafe_pointer.h"

/* Linux syscall numbers, confirmed against arch/x86/entry/syscalls/
 * syscall_{64,32}.tbl (x86_64/i386) and this host's own headers
 * (aarch64). Only pread64/pwrite64 differ in ARGUMENT SHAPE on i386 (see
 * __plat_pread()/__plat_pwrite() below), not in having a syscall number. */
#if defined(__aarch64__)
#define SYS_close  57
#define SYS_lseek  62
#define SYS_read   63
#define SYS_write  64
#define SYS_pread64  67
#define SYS_pwrite64 68
#define SYS_dup    23
#define SYS_dup3   24
#define SYS_fcntl  25
#elif defined(__x86_64__)
#define SYS_close  3
#define SYS_lseek  8
#define SYS_read   0
#define SYS_write  1
#define SYS_pread64  17
#define SYS_pwrite64 18
#define SYS_dup    32
#define SYS_dup3   292
#define SYS_fcntl  72
#elif defined(__i386__)
#define SYS_close  6
/* Plain lseek(2) (19), not _llseek(140): i386's lseek(2) takes and
 * returns a 32-bit offset directly, a disclosed limitation -- seeking
 * past 2 GiB fails/wraps on i386 specifically, unlike aarch64/x86_64
 * where lseek(2) already takes a native 64-bit offset. A real fix is
 * _llseek(2), future work if a 32-bit-Linux consumer needs it. */
#define SYS_lseek  19
#define SYS_read   3
#define SYS_write  4
#define SYS_pread64  180
#define SYS_pwrite64 181
#define SYS_dup    41
#define SYS_dup3   330
#define SYS_fcntl  55
#else
#error "plat_fd.c: unsupported architecture"
#endif

#define F_SETFD_LX   2
#define FD_CLOEXEC_LX 1
#define O_CLOEXEC_LX  0x80000

/* A minimal 6-argument raw syscall, one body per arch's own calling
 * convention -- no host libc in the call path. NOT `extern long
 * syscall(long, ...)`: that symbol resolves to the HOST's real glibc at
 * link time, which sets glibc's OWN errno on failure rather than handing
 * back the raw kernel -errno this file's `errno = (int)-ret` translation
 * requires. See crt/linux/crt1.c's own raw_syscall() banner for the
 * per-arch calling-convention rationale. */
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
/* Same "point eax at an explicit args array" technique as crt/linux/
 * crt1.c's own i386 raw_syscall() -- see that file's banner (ebp is both
 * cdecl's frame-pointer register and the only place left for a 6th arg). */
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
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

int __plat_close(__plat_handle_t h)
{
	long ret = raw_syscall(SYS_close, (long)unbox(h), 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

ssize_t __plat_read(__plat_handle_t h, void *buf, size_t count)
{
	long ret = raw_syscall(SYS_read, (long)unbox(h), (long)buf, (long)count, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

ssize_t __plat_pread(__plat_handle_t h, void *buf, size_t count, off_t off)
{
	long ret;
#if defined(__i386__)
	/* i386's pread64(2) takes a 64-bit offset as two SEPARATE 32-bit
	 * argument registers (pos_low, pos_high), not one `long`: `(long)off`
	 * alone would silently truncate off_t (always 64-bit) to its low
	 * 32 bits. */
	unsigned long long uoff = (unsigned long long)off;
	ret = raw_syscall(SYS_pread64, (long)unbox(h), (long)buf, (long)count,
	                  (long)(unsigned long)(uoff & 0xffffffffu),
	                  (long)(unsigned long)(uoff >> 32), 0L);
#else
	ret = raw_syscall(SYS_pread64, (long)unbox(h), (long)buf, (long)count, (long)off, 0L, 0L);
#endif
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

ssize_t __plat_write(__plat_handle_t h, const void *buf, size_t count, int append) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; byte count and append flag have distinct roles
{
	long ret;
	/* `append` needs nothing here: on Linux, whether a write() goes to the
	 * file's current end is decided by the fd's own O_APPEND bit, not by
	 * any per-call argument the way NT's FILE_WRITE_TO_END_OF_FILE needs. */
	(void)append;
	ret = raw_syscall(SYS_write, (long)unbox(h), (long)buf, (long)count, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

ssize_t __plat_pwrite(__plat_handle_t h, const void *buf, size_t count, off_t off)
{
	long ret;
#if defined(__i386__)
	/* See __plat_pread()'s identical comment just above -- same split. */
	unsigned long long uoff = (unsigned long long)off;
	ret = raw_syscall(SYS_pwrite64, (long)unbox(h), (long)buf, (long)count,
	                  (long)(unsigned long)(uoff & 0xffffffffu),
	                  (long)(unsigned long)(uoff >> 32), 0L);
#else
	ret = raw_syscall(SYS_pwrite64, (long)unbox(h), (long)buf, (long)count, (long)off, 0L, 0L);
#endif
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

long long __plat_seek_query(__plat_handle_t h, int at_eof)
{
	int fd = unbox(h);
	long cur, ret;

	if (!at_eof) {
		/* SEEK_CUR with a zero offset is a pure query: it reports the
		 * position without moving it, exactly this contract's promise. */
		ret = raw_syscall(SYS_lseek, (long)fd, 0L, 1L /* SEEK_CUR */, 0L, 0L, 0L);
		if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
		return ret;
	}
	/* SEEK_END, unlike SEEK_CUR, WOULD move the descriptor's position as a
	 * side effect -- something this "just a query" contract must not do.
	 * Save and restore around it. A pure fstat(2) query would avoid the
	 * extra two syscalls, at the cost of hardcoding the raw kernel `struct
	 * stat` layout; not worth it for a pilot backend. */
	cur = raw_syscall(SYS_lseek, (long)fd, 0L, 1L /* SEEK_CUR */, 0L, 0L, 0L);
	if (is_sys_error(cur)) { errno = (int)-cur; return -1; }
	ret = raw_syscall(SYS_lseek, (long)fd, 0L, 2L /* SEEK_END */, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	raw_syscall(SYS_lseek, (long)fd, cur, 0L /* SEEK_SET */, 0L, 0L, 0L);
	return ret;
}

int __plat_seek_set(__plat_handle_t h, long long target)
{
	long ret = raw_syscall(SYS_lseek, (long)unbox(h), (long)target, 0L /* SEEK_SET */, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_dup(__plat_handle_t h, int inheritable, __plat_handle_t *out)
{
	long newfd = raw_syscall(SYS_dup, (long)unbox(h), 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(newfd)) { errno = (int)-newfd; return -1; }
	if (!inheritable) {
		/* dup(2) never sets O_CLOEXEC on the new descriptor (matching
		 * `inheritable` true); ask for it explicitly otherwise. */
		long fc = raw_syscall(SYS_fcntl, newfd, (long)F_SETFD_LX, (long)FD_CLOEXEC_LX, 0L, 0L, 0L);
		if (is_sys_error(fc)) {
			int e = (int)-fc;
			raw_syscall(SYS_close, newfd, 0L, 0L, 0L, 0L, 0L);
			errno = e;
			return -1;
		}
	}
	/* Boxing, not dereference -- see __plat_dup_to()'s own comment
	 * below on the identical +1 encoding. */
	*out = unsafe_assume_valid_pointer((__plat_handle_t)(newfd + 1));
	return 0;
}

int __plat_dup_to(__plat_handle_t h, int newfd, __plat_handle_t old, int inheritable, __plat_handle_t *out)
{
	int oldfd = unbox(h);
	long ret;

	/* `old` needs no handling of its own here on purpose: dup3(2) below
	 * already replaces whatever real descriptor NUMBER newfd previously
	 * held, atomically -- a separate close here would, after dup3(2)
	 * returns, actually close the brand new duplicate this call just made. */
	(void)old;

	if (oldfd == newfd) {
		/* dup3(2) refuses this outright (EINVAL) where dup(2) simply
		 * would not apply: this case means
		 * posix_spawn_file_actions_adddup2(fd, fd)'s "keep this
		 * descriptor across the child's exec" -- clear close-on-exec on
		 * the SAME real fd, not duplicate it onto itself. */
		long fc = raw_syscall(SYS_fcntl, (long)oldfd, (long)F_SETFD_LX,
		                      inheritable ? 0L : (long)FD_CLOEXEC_LX, 0L, 0L, 0L);
		if (is_sys_error(fc)) { errno = (int)-fc; return -1; }
		*out = h;
		return 0;
	}

	/* dup3(2), unlike the dup(2) __plat_dup() above uses, forces the new
	 * descriptor to be exactly `newfd`, closing whatever was already there
	 * first, atomically -- the entire reason this function exists. */
	ret = raw_syscall(SYS_dup3, (long)oldfd, (long)newfd,
	                  inheritable ? 0L : (long)O_CLOEXEC_LX, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	/* ret is dup3(2)'s own return-register value, just proven a real
	 * success (not an encoded -errno) by is_sys_error() immediately
	 * above; the Linux syscall ABI's dup3(2) contract guarantees a
	 * successful call returns the new descriptor number, which by
	 * dup3(2)'s own semantics equals `newfd`. Boxed +1 into
	 * __plat_handle_t the same way box_fd()/box() (both already exempt
	 * below) box every other real Linux fd this library hands out as an
	 * opaque handle -- see plat_handle.h -- never dereferenced. */
	*out = unsafe_assume_valid_pointer((__plat_handle_t)(ret + 1));
	return 0;
}

void __plat_set_cloexec(__plat_handle_t h, int cloexec)
{
	/* A plain in-place fcntl(F_SETFD): never creates a new descriptor or
	 * changes which real fd number `h` names. Failure is not reported:
	 * F_SETFD on a fd this process still has open does not fail in
	 * practice. */
	raw_syscall(SYS_fcntl, (long)unbox(h), (long)F_SETFD_LX,
	           cloexec ? (long)FD_CLOEXEC_LX : 0L, 0L, 0L, 0L);
}

// NOLINTEND(misc-include-cleaner)
