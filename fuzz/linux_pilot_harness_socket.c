/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux socket-backend pilot -- NOT
 * part of spicule, same standing as fuzz/linux_pilot_harness.c (the
 * mman/unistd pilot's own harness) and fuzz/ntstubs.c before it.
 *
 * src/socket/sendrecv.c's real recv()/send() front doors need only
 * __fd_get() (to look up struct __fd by descriptor) from the fd-table
 * machinery -- unlike the mman/unistd pilot, nothing here ever installs
 * a NEW descriptor through this file's own code (the test program does
 * that itself, directly against __fds[]/__fd_alloc(), so it can also
 * poke the AFD_ST_CONNECTED bit into the freshly installed slot's `pad`
 * field -- see the test file's own comment on why: no front door this
 * pilot links ever sets that bit itself, since bind()/connect()/
 * accept() -- the only real code that normally would -- are out of
 * scope, exactly as much raw NT AFD machinery as socket() itself; see
 * src/socket/linux/plat_socket.c's own banner).
 *
 * __fd_alloc()/__fd_get() are reimplemented here, minimally, rather than
 * linking the real src/internal/fd.c, for the exact same reason
 * fuzz/linux_pilot_harness.c gives for its own from-scratch fd table:
 * fd.c's __handle_type() unconditionally calls two NT-only syscalls
 * whenever __fd_install_at()'s type argument is 0, a runtime branch the
 * compiler cannot prove dead even though this pilot never passes 0.
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

struct __fd *__fd_get(int fd)
{
	if (fd < 0 || fd >= FD_MAX || !__fds[fd].h) { errno = EBADF; return 0; }
	return &__fds[fd];
}
