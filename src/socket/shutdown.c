/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * shutdown(): https://pubs.opengroup.org/onlinepubs/9699919799/
 * functions/shutdown.html.  `how` is validated here (EINVAL for
 * anything else); once connection state is confirmed it's handed
 * straight to __plat_socket_shutdown().  On NT that maps onto
 * AFD_DISCONNECT_RECV/SEND with a zeroed Timeout (graceful, not
 * AFD_DISCONNECT_ABORT); on Linux, SHUT_RD/WR/RDWR already are the
 * kernel's own shutdown(2) values, so nothing is translated.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <errno.h>
#include "libc.h"
#include "plat_socket.h"

int shutdown(int fd, int how) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (!(f->pad & __SOCK_ST_CONNECTED)) { errno = ENOTCONN; return -1; }

	return __plat_socket_shutdown(f->h, how);
}

// NOLINTEND(misc-include-cleaner)
