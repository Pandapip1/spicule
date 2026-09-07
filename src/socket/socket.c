/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * socket(): https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * socket.html.  Scope is AF_INET/SOCK_STREAM, AF_INET/SOCK_DGRAM, and an
 * anonymous AF_UNIX/SOCK_DGRAM; everything else is EAFNOSUPPORT/
 * EPROTOTYPE/EPROTONOSUPPORT.
 *
 * AF_UNIX/SOCK_DGRAM: this project has no <sys/un.h>, so
 * socket(AF_UNIX, SOCK_DGRAM, 0) hands back the same underlying
 * AF_INET/SOCK_DGRAM endpoint socket(AF_INET, SOCK_DGRAM, 0) would --
 * what socketpair.c's AF_UNIX/SOCK_DGRAM path builds its connected pair
 * out of, the same precedent its AF_UNIX/SOCK_STREAM path already set
 * for peers reporting AF_INET addresses.
 *
 * SOCK_CLOEXEC/SOCK_NONBLOCK bits live in `type`; both are masked off
 * before the SOCK_STREAM/SOCK_DGRAM comparison and folded into the new
 * fd's flags word instead, the same plumbing open() uses.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include "libc.h"
#include "plat_socket.h"
#include "plat_fd.h"
#include "ownership_stubs.h"

int socket(int domain, int type, int protocol) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__plat_handle_t h;
	int fd;
	int cloexec = type & SOCK_CLOEXEC;
	int nonblock = type & SOCK_NONBLOCK;
	int t = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);

	if (domain != AF_INET && domain != AF_UNIX) { errno = EAFNOSUPPORT; return -1; }
	if (t != SOCK_STREAM && t != SOCK_DGRAM) { errno = EPROTOTYPE; return -1; }
	/* AF_UNIX/SOCK_STREAM exists only internally (socketpair.c's
	 * loopback-TCP construction), never reached through this front
	 * door. EPROTONOSUPPORT not EAFNOSUPPORT: the family is real, just
	 * this family/type combination isn't supported. */
	if (domain == AF_UNIX && t != SOCK_DGRAM) { errno = EPROTONOSUPPORT; return -1; }
	if (t == SOCK_STREAM && protocol != 0 && protocol != IPPROTO_TCP) { errno = EPROTONOSUPPORT; return -1; }
	if (t == SOCK_DGRAM && domain == AF_INET && protocol != 0 && protocol != IPPROTO_UDP) { errno = EPROTONOSUPPORT; return -1; }
	if (t == SOCK_DGRAM && domain == AF_UNIX && protocol != 0) { errno = EPROTONOSUPPORT; return -1; }

	if (__plat_socket_open(&h, t) < 0) return -1;

	fd = __fd_install(h, (cloexec ? O_CLOEXEC : 0) | (nonblock ? O_NONBLOCK : 0), __FD_SOCKET);
	if (fd < 0) { __plat_close(h); return -1; }
	{
		/* Can't be NULL here: fd just came back from a successful
		 * __fd_install(). */
		struct __fd *nf = __fd_get(fd);
		__ownership_pointer_nonnull(nf);
		nf->pad = (t == SOCK_DGRAM) ? __SOCK_ST_DGRAM : 0;
	}
	return fd;
}

// NOLINTEND(misc-include-cleaner)
