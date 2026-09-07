/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux filesystem-subsystem pilot --
 * NOT part of spicule, same as fuzz/linux_pilot_harness.c. Its own file
 * (not shared with linux_pilot_harness.c) because it backs a separate
 * binary, linux_pilot_test_fs -- see tools/linux-build-fs.sh.
 *
 * The fd table is reimplemented here because linking the real
 * src/internal/fd.c would still require NT-only syscalls this pilot has
 * no Linux backend for. The rest of this file is stand-ins for symbols
 * that src/fcntl/fcntl.c, fadvise.c, src/stat/chmod.c, and stat.c
 * reference from branches this test never actually takes at runtime but
 * that the linker still needs resolved.
 *
 * syscall() is a REAL raw syscall trampoline (aarch64 `svc #0`), not a
 * stub, and its presence here fixed a real bug: every plat_*.c backend
 * is written against the raw kernel ABI (`errno = (int)-ret` on a
 * negative return), but this pilot previously borrowed glibc's exported
 * syscall(), which itself translates that convention -- returning bare
 * -1 with the real errno already set. `(int)-(-1)` is always EPERM, so
 * every failure was silently misreported as EPERM regardless of the
 * real error. Invisible on success-only checks; caught only when a
 * fork()-based fcntl()/flock() conflict test needed a specific EAGAIN
 * and got EPERM instead (confirmed via strace that the kernel itself
 * returned EAGAIN correctly). Defining a real syscall() here, which a
 * directly-linked object's symbol shadows over glibc's same-named
 * export, gives every plat_*.c file the raw ABI it expects.
 */
#include <stdarg.h>

long syscall(long number, ...)
{
	va_list ap;
	long a1, a2, a3, a4, a5, a6;
	register long x0 __asm__("x0");
	register long x1 __asm__("x1");
	register long x2 __asm__("x2");
	register long x3 __asm__("x3");
	register long x4 __asm__("x4");
	register long x5 __asm__("x5");
	register long x8 __asm__("x8");

	va_start(ap, number);
	a1 = va_arg(ap, long);
	a2 = va_arg(ap, long);
	a3 = va_arg(ap, long);
	a4 = va_arg(ap, long);
	a5 = va_arg(ap, long);
	a6 = va_arg(ap, long);
	va_end(ap);

	x0 = a1; x1 = a2; x2 = a3; x3 = a4; x4 = a5; x5 = a6; x8 = number;
	__asm__ volatile("svc #0"
	                : "+r"(x0)
	                : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
	                : "memory", "cc");
	return x0;
}

/* Remaining stand-ins: getpid() is answered for real (raw getpid(2), not
 * a stub) because record_lock()'s per-fd lock-ownership bookkeeping
 * needs the true owning pid across this test's fork()-based lock-
 * conflict check -- a fake constant would silently break that check.
 * Everything else below is a dead-branch symbol GNU ld still needs
 * resolved (an object linked directly, not pulled from a .a archive by
 * need, has every reference resolved regardless of --gc-sections):
 * __mq_fd_replaced() (no mqueue fds exist here to remap), __fsize_allow()
 * and friends (report "no limit", so RLIMIT_FSIZE paths stay
 * unreachable), __vfs_stat() (this pilot's fd table never sets `vfs`),
 * __fd_pos_save/_restore, __vfs_resolve_at, __ntpath (NT-only path
 * handling this pilot's calls never reach), and __handle_path() /
 * __ntpath_at() / __ntpath_free() / free() (fchmod()'s EACCES fallback
 * path, never hit since this test chmods a file it just created --
 * __handle_path() returning NULL here matches its real "no reopenable
 * name" contract, so the other three are linked but never called).
 */
#include <string.h>
#include <unistd.h>
#include "libc.h"

struct __fd __fds[FD_MAX];
int __fd_limit = FD_MAX;

int __fd_alloc(int lowest)
{
	int i;
	if (lowest < 0) lowest = 0;
	for (i = lowest; i < __fd_limit; i++)
		if (!__fds[i].h) return i;
	errno = EMFILE;
	return -1;
}

/* No-op: this pilot never links getdents.c, so f->dbuf is always NULL;
 * present only to satisfy close.c's call to it. */
void __fd_release_dynamic(struct __fd *f) { (void)f; }

int __fd_install_at(int fd, HANDLE h, unsigned flags, int type)
{
	struct __fd *f = &__fds[fd];
	__fd_release_dynamic(f);
	memset(f, 0, sizeof *f);
	f->h = h;
	f->flags = flags;
	f->type = (unsigned char)type; /* always nonzero in this pilot */
	f->pos = -1;
	return fd;
}

int __fd_install(HANDLE h, unsigned flags, int type)
{
	int fd = __fd_alloc(0);
	if (fd < 0) return -1;
	return __fd_install_at(fd, h, flags, type);
}

struct __fd *__fd_get(int fd)
{
	if (fd < 0 || fd >= FD_MAX || !__fds[fd].h) { errno = EBADF; return 0; }
	return &__fds[fd];
}

void __mq_fd_closed(int fd)
{
	(void)fd;
}

void __mq_fd_replaced(int fd, __plat_handle_t h)
{
	(void)fd; (void)h;
}

int __fsize_limited(void) { return 0; }
long long __fsize_clamp(__plat_handle_t h, int append, size_t count)
{
	(void)h; (void)append;
	return (long long)count;
}
long long __fsize_room_at(long long off) { (void)off; return 0x7fffffffffffffffLL; }
int __fsize_exceeded(void) { return -1; }
int __fsize_allow(long long size) { (void)size; return 0; }

int __vfs_stat(int kind, struct stat *st)
{
	(void)kind; (void)st;
	errno = ENOSYS;
	return -1;
}

int __fd_pos_save(HANDLE h, long long *pos)
{
	(void)h;
	*pos = 0;
	return 0;
}

void __fd_pos_restore(HANDLE h, long long pos)
{
	(void)h; (void)pos;
}

int __vfs_resolve_at(int dirfd, const char *path)
{
	(void)dirfd; (void)path;
	errno = ENOSYS;
	return -1;
}

int __ntpath(const char *path, struct __ntpath *out, ULONG attributes)
{
	(void)path; (void)out; (void)attributes;
	errno = ENOSYS;
	return -1;
}

char *__handle_path(HANDLE h)
{
	(void)h;
	return 0;
}

int __ntpath_at(int dirfd, const char *path, struct __ntpath *np, ULONG attributes)
{
	(void)dirfd; (void)path; (void)np; (void)attributes;
	errno = ENOSYS;
	return -1;
}

void __ntpath_free(struct __ntpath *np)
{
	(void)np;
}

void free(void *p)
{
	(void)p;
}

#define SYS_getpid 172
pid_t getpid(void)
{
	return (pid_t)syscall(SYS_getpid);
}
