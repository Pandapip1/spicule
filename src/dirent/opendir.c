/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * opendir/fdopendir: ask open() for an O_DIRECTORY descriptor and wrap it
 * in a DIR. For the fixed POSIX namespace (/, /dev), the handle exists
 * only as a lifetime/inheritance carrier; readdir() enumerates those
 * entries without asking NT. fdopendir() does not duplicate its argument
 * fd, it just starts using it, exactly as glibc's does — the caller must
 * not touch that fd afterward, and closedir() closes it.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "dirent_internal.h"

withtok(directory_stream_open)
static DIR *alloc_dir(int fd)
{
	DIR *dp;
	size_t bytes;
	if (!__size_add_checked(sizeof *dp, __DIRBUF_SIZE, &bytes)) {
		errno = ENOMEM;
		return 0;
	}
	dp = __malloc(bytes);
	if (!dp) { errno = ENOMEM; return 0; }
	memset(dp, 0, sizeof *dp);
	dp->buf = (unsigned char *)(dp + 1);
	dp->fd = fd;
	dp->restart = 1;
	return dp;
}

withtok(directory_stream_open)
DIR *fdopendir(int fd)
{
	struct __fd *f = __fd_get(fd);
	if (!f) return 0;
	if (f->type != __FD_DIR) { errno = ENOTDIR; return 0; }
	return alloc_dir(fd);
}

withtok(directory_stream_open)
DIR *opendir(const char *path)
{
	int fd;
	DIR *dp;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) return 0;

	dp = alloc_dir(fd);
	if (!dp) {
		int saved = errno;
		(void)close(fd);
		errno = saved;
		return 0;
	}
	return dp;
}

// NOLINTEND(misc-include-cleaner)
