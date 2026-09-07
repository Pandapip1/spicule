/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include <sys/stat.h>
#include <sys/time.h>
#include <utime.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "libc.h"
#include "plat_stat.h"

int futimens(int fd, const struct timespec ts[2])
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;
	if (f->vfs && !f->vfs_native) { errno = EROFS; return -1; }
	return __plat_set_times(f->h, ts);
}

int utimensat(int dirfd, const char *path, const struct timespec ts[2], int flags)
{
	return __plat_set_times_at(dirfd, path, flags, ts);
}

int utimes(const char *path, const struct timeval tv[2])
{
	struct timespec ts[2];
	if (!tv) return utimensat(AT_FDCWD, path, 0, 0);
	if (tv[0].tv_usec < 0 || tv[0].tv_usec >= 1000000 ||
	    tv[1].tv_usec < 0 || tv[1].tv_usec >= 1000000) {
		errno = EINVAL;
		return -1;
	}
	/* The validation above bounds each product to [0, 999999000]. */
	ts[0].tv_sec = tv[0].tv_sec; ts[0].tv_nsec = (long)(tv[0].tv_usec * 1000);
	ts[1].tv_sec = tv[1].tv_sec; ts[1].tv_nsec = (long)(tv[1].tv_usec * 1000);
	return utimensat(AT_FDCWD, path, ts, 0);
}

int utime(const char *path, const struct utimbuf *ub)
{
	struct timespec ts[2];
	if (!ub) return utimensat(AT_FDCWD, path, 0, 0);
	ts[0].tv_sec = ub->actime; ts[0].tv_nsec = 0;
	ts[1].tv_sec = ub->modtime; ts[1].tv_nsec = 0;
	return utimensat(AT_FDCWD, path, ts, 0);
}

int futimesat(int dirfd, const char *path, const struct timeval tv[2])
{
	struct timespec ts[2];
	if (!tv) return utimensat(dirfd, path, 0, 0);
	if (tv[0].tv_usec < 0 || tv[0].tv_usec >= 1000000 ||
	    tv[1].tv_usec < 0 || tv[1].tv_usec >= 1000000) {
		errno = EINVAL;
		return -1;
	}
	/* The validation above bounds each product to [0, 999999000]. */
	ts[0].tv_sec = tv[0].tv_sec; ts[0].tv_nsec = (long)(tv[0].tv_usec * 1000);
	ts[1].tv_sec = tv[1].tv_sec; ts[1].tv_nsec = (long)(tv[1].tv_usec * 1000);
	return utimensat(dirfd, path, ts, 0);
}

// NOLINTEND(misc-include-cleaner)
