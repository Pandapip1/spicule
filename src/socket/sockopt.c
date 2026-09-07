/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * setsockopt()/getsockopt():
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * setsockopt.html (both functions are on that one page). ENOPROTOOPT
 * for everything not genuinely supportable here.
 *
 * Supported, and why:
 *
 *   - SO_REUSEADDR: recorded in struct __fd's `pad` byte, consumed by
 *     bind() to pick AFD_SHARE_REUSE over AFD_SHARE_UNIQUE. Setting it
 *     after bind() has no effect -- AFD's share type is fixed at bind
 *     time, same as Linux.
 *   - SO_TYPE (getsockopt only): from the __SOCK_ST_DGRAM bit
 *     socket()/socketpair() set at creation.
 *   - SO_ERROR (getsockopt only): always 0 -- this project doesn't
 *     implement non-blocking connect, so there's never a deferred error
 *     to report or clear.
 *   - SO_SNDBUF/SO_RCVBUF (getsockopt only): answered per backend by
 *     __plat_socket_getsndbuf()/getrcvbuf() (Linux: a real kernel value;
 *     NT: a documented stand-in). Needed because third_party/ltp's
 *     aio_test.h setup_aio() calls getsockopt(SO_SNDBUF) right after
 *     socketpair() and treats failure as a fatal setup error.
 *
 * SO_LINGER, SO_RCVTIMEO/SO_SNDTIMEO, SO_KEEPALIVE, SO_BROADCAST,
 * SO_OOBINLINE and the rest need AFD_INFO queries this project doesn't
 * implement -- ENOPROTOOPT, not a silent no-op, so a caller relying on
 * one finds out. setsockopt() has no SO_SNDBUF/SO_RCVBUF case either:
 * neither backend actually negotiates a buffer size to claim to have
 * changed.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "afd.h"
#include "plat_socket.h"
#include "ownership_stubs.h"

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	int v;

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (level != SOL_SOCKET) { errno = ENOPROTOOPT; return -1; }

	switch (optname) {
	case SO_REUSEADDR:
		if (!optval || optlen < (socklen_t)sizeof(int)) { errno = EINVAL; return -1; }
		__ownership_readable_span(optval, sizeof(v));
		memcpy(&v, optval, sizeof(v));
		if (v) f->pad |= AFD_ST_REUSEADDR; else f->pad &= ~AFD_ST_REUSEADDR;
		return 0;
	default:
		errno = ENOPROTOOPT;
		return -1;
	}
}

int getsockopt(int fd, int level, int optname, void *__restrict optval, socklen_t *__restrict optlen) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	int v;

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (level != SOL_SOCKET) { errno = ENOPROTOOPT; return -1; }
	if (!optval || !optlen) { errno = EFAULT; return -1; }

	switch (optname) {
	case SO_REUSEADDR: v = (f->pad & AFD_ST_REUSEADDR) ? 1 : 0; break;
	case SO_TYPE:       v = (f->pad & AFD_ST_DGRAM) ? SOCK_DGRAM : SOCK_STREAM; break;
	case SO_ERROR:       v = 0; break;
	case SO_SNDBUF:
		v = __plat_socket_getsndbuf(f->h);
		if (v < 0) return -1; /* errno already set by the backend */
		break;
	case SO_RCVBUF:
		v = __plat_socket_getrcvbuf(f->h);
		if (v < 0) return -1;
		break;
	default:
		errno = ENOPROTOOPT;
		return -1;
	}

	{
		socklen_t n = *optlen < (socklen_t)sizeof(v) ? *optlen : (socklen_t)sizeof(v);
		__ownership_writable_span(optval, n);
		memcpy(optval, &v, n);
		*optlen = sizeof(v);
	}
	return 0;
}

// NOLINTEND(misc-include-cleaner)
