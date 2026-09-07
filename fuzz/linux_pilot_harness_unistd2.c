/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the "rest of src/unistd" Linux pilot --
 * NOT part of spicule, same standing as fuzz/linux_pilot_harness.c, which
 * this file mirrors (fd table, __fd_pos_save/restore, __mq_fd_closed,
 * __fsize_* copied verbatim) since src/unistd/{close,read,write,lseek,
 * dup}.c are linked again here to round-trip data through pipe()s.
 *
 * Each stand-in exists for a different reason: the fd table, because
 * real __fd_install_at() unconditionally calls the NT-only
 * __handle_type() on a branch the compiler can't prove dead here.
 * __environ, because crt1.c's NT-only process-parameter parsing would
 * normally fill it before main() -- an empty environment is a faithful
 * "no USERNAME/USER set" for getlogin(). getpid() is not a __plat_*
 * seam function at all (the real one reads NT's TEB directly, which
 * doesn't exist in a Linux ELF process) -- answered here with a real
 * getpid(2) syscall so ids.c's pid_exists()/setpgrp()/setsid()/
 * getpgid() still exercise real front-door code. __child_find() and
 * __fsize_allow() each have a real, portable definition, but their
 * translation units also pull in another parallel session's Linux
 * backend (__plat_process_resume()/__plat_process_times_self()) --
 * linking them to get one function would risk the duplicate-__plat_*
 * collision this project's NT migration already hit twice, so each
 * answers with its own defined "nothing special" case instead (no known
 * child; RLIMIT_FSIZE never lowered).
 *
 * __vfs_cwd_set() has a portable one-line real definition too, but lives
 * in the same translation unit as genuinely NT-only __vfs_resolve_at()
 * (HANDLE, NTSTATUS, OBJECT_ATTRIBUTES types), so it's a bare store here
 * with no reader -- nothing this pilot calls ever reads cwd_kind back.
 * __handle_path() and __free() are pulled in by chdir.c's fchdir()
 * fallback branch, dead at runtime (this pilot's fd table never sets
 * vfs) but still needed by the linker; same NULL stand-in as
 * fuzz/linux_pilot_harness_fs.c's own __handle_path().
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

void __fd_release_dynamic(struct __fd *f)
{
	if (f->dbuf) { __free(f->dbuf); f->dbuf = 0; }
}

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

int __fd_pos_save(HANDLE h, long long *pos)
{
	(void)h;
	*pos = 0;
	return 0;
}

void __fd_pos_restore(HANDLE h, long long pos)
{
	(void)h;
	(void)pos;
}

void __mq_fd_closed(int fd)
{
	(void)fd;
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

struct __child *__child_find(int pid) { (void)pid; return 0; }

extern long syscall(long number, ...);
#define SYS_getpid_LX 172 /* aarch64 */
pid_t getpid(void)
{
	return (pid_t)syscall(SYS_getpid_LX);
}

/* libc.h's `#define __environ environ` means the symbol to define here
 * is `environ` itself, declared in <unistd.h>. */
char **environ;

void __vfs_cwd_set(int kind) { (void)kind; }

char *__handle_path(HANDLE h)
{
	(void)h;
	return 0;
}

void __free(void *p)
{
	(void)p;
}
