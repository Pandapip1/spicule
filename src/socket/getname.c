/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getsockname()/getpeername():
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * getsockname.html and .../getpeername.html.
 *
 * One file because both calls share descriptor/argument/state
 * validation; only getsockname() needs a platform query. Both truncate
 * into the caller's buffer like accept(), with *address_len always
 * receiving the untruncated length.
 *
 * getpeername() never calls the platform: the peer address is immutable
 * for a connected stream socket, so the sockaddr cached by connect()/
 * accept() is returned directly, avoiding AFD_GET_PEER_NAME (an
 * undocumented, version-unstable ioctl).
 *
 * ERRORS: EINVAL (not EFAULT, unlike sockopt.c) for a NULL address or
 * address_len, since neither page lists EFAULT. ENOTCONN (getpeername
 * only) is checked from this library's own __SOCK_ST_CONNECTED state,
 * not the driver's error for the same case (AfdGetPeerName() reports
 * EINVAL there, not ENOTCONN) -- ReactOS's WSPGetPeerName does the same.
 *
 * getsockname() on a never-bound socket returns the wildcard AF_INET
 * address without querying the platform: unbound is "unspecified" per
 * POSIX, and asking AFD anyway turns a conforming success into
 * AfdGetSockName()'s STATUS_INVALID_PARAMETER failure.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "plat_socket.h"
#include "ownership_stubs.h"

/* Shared preamble: both calls' checks, argument validity before socket
 * state. Returns NULL with errno already set. */
static struct __fd *getname_fd(int fd, struct sockaddr *addr, socklen_t *len)
{
	struct __fd *f = __fd_get(fd);

	if (!f) return 0; /* __fd_get() set EBADF */
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return 0; }
	if (!addr || !len) { errno = EINVAL; return 0; }
	return f;
}

int getsockname(int fd, struct sockaddr *__restrict addr, socklen_t *__restrict len)
{
	struct __fd *f = getname_fd(fd, addr, len);

	if (!f) return -1;

	if (!(f->pad & __SOCK_ST_BOUND)) {
		/* Unbound is "unspecified", not an error; wildcard AF_INET
		 * (INADDR_ANY, port 0) truncate-copied same as a bound
		 * socket's address, so the truncation contract holds here
		 * too. */
		struct sockaddr_in wild;
		socklen_t n;

		memset(&wild, 0, sizeof(wild));
		wild.sin_family = AF_INET;
		n = *len < (socklen_t)sizeof(wild) ? *len : (socklen_t)sizeof(wild);
		memcpy(addr, &wild, n);
		*len = sizeof(wild);
		return 0;
	}

	return __plat_socket_getsockname(f->h, addr, len);
}

int getpeername(int fd, struct sockaddr *__restrict addr, socklen_t *__restrict len)
{
	struct __fd *f = getname_fd(fd, addr, len);
	socklen_t n;

	if (!f) return -1;
	/* __SOCK_ST_CONNECTED and afd.h's AFD_ST_CONNECTED are numerically
	 * identical bits of the same struct __fd byte -- see
	 * plat_socket.h's banner. */
	if (!(f->pad & __SOCK_ST_CONNECTED)) { errno = ENOTCONN; return -1; }
	if (!f->peer_len) { errno = ENOTCONN; return -1; }
	n = *len < f->peer_len ? *len : f->peer_len;
	__ownership_writable_span(addr, n);
	__ownership_readable_span(f->peer, n);
	memcpy(addr, f->peer, n);
	*len = f->peer_len;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
