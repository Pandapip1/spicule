/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * lockf(): a thin wrapper over fcntl(F_SETLK/F_SETLKW/F_GETLK)
 * (src/fcntl/fcntl.c), itself backed by NT byte-range locks -- mandatory,
 * not advisory, unlike POSIX's flock() (see include/sys/file.h's banner).
 *
 * lockf.html's section-to-lock ("current offset forward for positive
 * len, backward for negative, whole rest of file for 0") is exactly
 * fcntl()'s l_whence == SEEK_CUR, l_start == 0, l_len == len semantics,
 * which record_lock_range() already implements -- so lockf() only builds
 * the struct flock and picks which fcntl() command each operation maps
 * to. */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "libc.h"

int lockf(int fd, int cmd, off_t len)
{
	struct flock fl;

	memset(&fl, 0, sizeof fl);
	fl.l_whence = SEEK_CUR;
	fl.l_start = 0;
	fl.l_len = len;

	switch (cmd) {
	case F_ULOCK:
		fl.l_type = F_UNLCK;
		return fcntl(fd, F_SETLK, &fl);
	case F_LOCK:
		fl.l_type = F_WRLCK;
		return fcntl(fd, F_SETLKW, &fl);
	case F_TLOCK:
		/* lockf(3) has one kind of lock, not fcntl()'s shared/exclusive
		 * distinction -- F_WRLCK is right for both F_TLOCK and F_LOCK.
		 * fcntl(F_SETLK) already fails EAGAIN/EWOULDBLOCK on conflict,
		 * which lockf.html documents for F_TLOCK. */
		fl.l_type = F_WRLCK;
		return fcntl(fd, F_SETLK, &fl);
	case F_TEST:
		/* fcntl(F_GETLK) ignores this process's own locks and reports
		 * a conflicting lock via l_type; report that back as lockf()'s
		 * own failure, not F_GETLK's success. */
		fl.l_type = F_WRLCK;
		if (fcntl(fd, F_GETLK, &fl) < 0) return -1;
		if (fl.l_type == F_UNLCK) return 0;
		errno = EAGAIN;
		return -1;
	default:
		errno = EINVAL;
		return -1;
	}
}

// NOLINTEND(misc-include-cleaner)
