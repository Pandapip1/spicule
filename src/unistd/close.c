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

int close(int fd)
{
	struct __fd *f = __fd_get(fd);
	int r;
	if (!f) return -1;
	__mq_fd_closed(fd);
	__fd_release_dynamic(f);
	r = __plat_close(f->h);
	f->h = __PLAT_HANDLE_NULL;
	return r;
}

// NOLINTEND(misc-include-cleaner)
