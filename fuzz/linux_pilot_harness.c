/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux platform pilot -- NOT part of
 * spicule, exactly like fuzz/ntstubs.c is "not part of spicule" for the
 * native ASan build. Stands in for the handful of internal helpers the
 * pilot's front-door files (close.c, read.c, write.c) reference but that
 * this pilot deliberately does not port:
 *
 *   __fd_pos_save/__fd_pos_restore (src/internal/fdpos.c) -- purely an
 *     NT quirk workaround (a synchronous NT handle's position moves
 *     during a positioned pread/pwrite transfer, which POSIX forbids);
 *     Linux's pread64/pwrite64 never move the descriptor's position at
 *     all, so the real fix is "this pair becomes a no-op on this
 *     backend". Declared HANDLE (not __plat_handle_t) in libc.h because
 *     it was never brought into the platform-abstraction interface at
 *     all -- a real gap this pilot surfaces rather than silently works
 *     around.
 *
 *   __mq_fd_closed (src/thread/mqueue.c) -- releases a POSIX message
 *     queue's fd-side bookkeeping on close(); this pilot exercises no
 *     mqueue descriptors, so there is nothing for it to release.
 *
 * The fd table itself (__fds[], __fd_limit, __fd_alloc, __fd_install
 * and __fd_install_at, __fd_get) is also reimplemented here, minimally,
 * rather than linking the real src/internal/fd.c: that file's
 * __handle_type() (NT device-type classification) is unconditionally
 * called by the real __fd_install_at() whenever type==0 -- a runtime
 * branch on a function argument the compiler cannot statically prove
 * dead even though this pilot always passes a nonzero type. This
 * reimplementation covers only what the mman/unistd-fd-ops pilot's
 * front doors actually call; it is not a Linux port of fd.c's real
 * responsibilities (cwd tracking, runtime-data serialization for spawn,
 * handle classification by device type), which stay real, open, future
 * work.
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

/* Real fd.c's own version (src/internal/fd.c) frees getdents()'s
 * lazily-allocated continuation buffer here; this pilot never links
 * src/dirent/getdents.c, so f->dbuf can never be anything but NULL --
 * a no-op stand-in, only present to satisfy src/unistd/close.c's own
 * call to it, same shape as this file's other reimplemented fd-table
 * primitives. */
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

/* src/misc/resource.c's RLIMIT_FSIZE machinery -- write.c calls
 * __fsize_limited() unconditionally to decide whether to enforce a
 * size limit at all; reporting "no limit" here means the other three
 * are unreachable at runtime for this pilot (no rlimit is ever set),
 * but the linker still needs real bodies for them since the call site
 * in write.c is not statically dead code. */
int __fsize_limited(void) { return 0; }
long long __fsize_clamp(__plat_handle_t h, int append, size_t count)
{
	(void)h; (void)append;
	return (long long)count;
}
long long __fsize_room_at(long long off) { (void)off; return 0x7fffffffffffffffLL; }
int __fsize_exceeded(void) { return -1; }
