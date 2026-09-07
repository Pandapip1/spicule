/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include <unistd.h>
#include <errno.h>
#include "libc.h"
#include "plat_fd.h"

off_t lseek(int fd, off_t off, int whence) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	long long base, target;

	if (!f) return -1;
	if (f->type != __FD_FILE) { errno = ESPIPE; return -1; }

	switch (whence) {
	case SEEK_SET: base = 0; break;
	case SEEK_CUR:
		base = __plat_seek_query(f->h, 0);
		if (base < 0) return -1;
		break;
	case SEEK_END:
		base = __plat_seek_query(f->h, 1);
		if (base < 0) return -1;
		break;
	default: errno = EINVAL; return -1;
	}
	if (!__file_offset_add(base, off, &target)) {
		errno = base >= 0 && off < 0 ? EINVAL : EOVERFLOW;
		return -1;
	}
	if (__plat_seek_set(f->h, target) < 0) return -1;
	return target;
}

// NOLINTEND(misc-include-cleaner)
