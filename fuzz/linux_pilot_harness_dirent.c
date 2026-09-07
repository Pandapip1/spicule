/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux dirent pilot -- NOT part of
 * spicule. A separate file rather than a reuse of
 * linux_pilot_harness_fs.c: this pilot's link set is much smaller (no
 * fcntl()/flock()/ioctl()/stat() front doors at all), and needs one
 * symbol none of the existing harnesses provide: __fd_handle()
 * (src/dirent/readdir.c's __dirstream_next() is the first Linux-pilot
 * front door to call it).
 *
 * The fd table (__fds[]/__fd_limit/__fd_alloc/__fd_install/
 * __fd_install_at/__fd_get/__fd_handle) is reimplemented here for the
 * same reason every other pilot harness gives: linking the real
 * src/internal/fd.c would still require satisfying NT-only syscalls this
 * pilot has no Linux backend for.
 *
 * __mq_fd_closed(): src/unistd/close.c calls it unconditionally at the
 * top of close(); this pilot installs no mqueue descriptors, so it's a
 * no-op.
 *
 * __malloc()/__free(): src/dirent/opendir.c allocates the DIR and its
 * __DIRBUF_SIZE record buffer through these, and closedir.c frees them
 * -- but the real implementation (src/malloc/malloc.c) is
 * RtlAllocateHeap on NT's own process heap, as NT-specific as fd.c and
 * equally out of scope here. A trivial bump allocator stands in: this
 * test opens one directory, reads its entries, and closes it, so a
 * static arena with a no-op __free() (a deliberate, bounded leak) is
 * sufficient.
 */
#include <string.h>
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

/* Real fd.c's version frees getdents()'s lazily-allocated continuation
 * buffer before a slot is wiped and reused. __free() below is already a
 * no-op stand-in for this pilot, so this is too. */
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
	f->type = (unsigned char)type; /* always nonzero: __plat_open()
	                                * always names a real __FD_* via
	                                * statx(). */
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

HANDLE __fd_handle(int fd)
{
	struct __fd *f = __fd_get(fd);
	return f ? f->h : 0;
}

void __mq_fd_closed(int fd)
{
	(void)fd;
}

/* A bump allocator over a static arena. 1 MiB is far more than this
 * test's few DIR/__DIRBUF_SIZE (32768-byte) allocations need. */
static unsigned char arena[1 << 20];
static size_t arena_used;

void *__malloc(size_t n)
{
	void *p;
	/* 16-byte alignment, matching malloc.c's own real x86_64 alignment;
	 * enough for any type this pilot allocates. */
	size_t aligned = (arena_used + 15u) & ~(size_t)15u;
	if (n == 0) n = 1;
	if (aligned + n > sizeof arena) { errno = ENOMEM; return 0; }
	p = arena + aligned;
	arena_used = aligned + n;
	return p;
}

void __free(void *p)
{
	(void)p; /* deliberate leak -- see this file's header comment */
}
