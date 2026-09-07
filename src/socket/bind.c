/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * bind(): https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * bind.html.  EINVAL on rebind is checked here via the __SOCK_ST_BOUND
 * bit rather than trusted from either backend, since neither's rebind
 * behavior was verified against a real reference -- consistency between
 * backends matters more than which one already happens to get it right.
 *
 * Only SO_REUSEADDR is implemented (of the AFD_SHARE_EXCLUSIVE/REUSE/
 * WILDCARD/UNIQUE choices ReactOS's WSPBind picks from), so
 * __plat_socket_bind() just takes a plain reuse-if-requested boolean;
 * mapping that to a real AFD_SHARE_* value or setsockopt(2) call is each
 * backend's own affair.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include "libc.h"
#include "plat_socket.h"

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	struct __fd *f = __fd_get(fd);

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (f->pad & (__SOCK_ST_BOUND | __SOCK_ST_CONNECTED | __SOCK_ST_LISTENING)) { errno = EINVAL; return -1; }

	if (__plat_socket_bind(f->h, (f->pad & __SOCK_ST_REUSEADDR) ? 1 : 0, addr, len) < 0) return -1;

	f->pad |= __SOCK_ST_BOUND;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
