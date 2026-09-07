/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * An anonymous pipe is a named pipe with a name nobody else will guess,
 * same as kernel32's CreatePipe: the read end is the server side
 * (NtCreateNamedPipeFile), the write end an ordinary NtOpenFile of the
 * same name. Both are synchronous byte-stream, so read/write behave as
 * on a file. See src/unistd/nt/plat_unistd.c's __plat_pipe().
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "libc.h"
#include "plat_fd.h"
#include "plat_unistd.h"

int pipe2(int fds[2], int flags)
{
	__plat_handle_t r, w;
	int rfd, wfd;

	if (__plat_pipe(&r, &w, !(flags & O_CLOEXEC)) < 0) return -1;

	rfd = __fd_install(r, O_RDONLY | (flags & (O_CLOEXEC | O_NONBLOCK)), __FD_PIPE);
	if (rfd < 0) { __plat_close(r); __plat_close(w); return -1; }
	wfd = __fd_install(w, O_WRONLY | (flags & (O_CLOEXEC | O_NONBLOCK)), __FD_PIPE);
	if (wfd < 0) {
		int saved = errno;
		(void)close(rfd);
		__plat_close(w);
		errno = saved;
		return -1;
	}
	fds[0] = rfd;
	fds[1] = wfd;
	return 0;
}

int pipe(int fds[2])
{
	return pipe2(fds, 0);
}

// NOLINTEND(misc-include-cleaner)
