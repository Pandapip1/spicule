/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * accept(): https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * accept.html.  Truncates into the caller's buffer per DESCRIPTION;
 * address/address_len are left untouched unless both are non-NULL,
 * the same paired-argument contract getname.c's getsockname()/
 * getpeername() and sendrecv.c's recvfrom() already enforce for this
 * same truncate-copy shape.
 * __plat_socket_accept() fills a full-sized local `peer` buffer that can
 * never itself truncate (AF_INET always fits sockaddr_in), then this
 * front door truncate-copies into the caller's buffer.
 *
 * NT's real accept is two AFD steps (IOCTL_AFD_WAIT_FOR_LISTEN, then
 * IOCTL_AFD_ACCEPT on a freshly opened endpoint), collapsed into the one
 * portable call below -- see src/socket/nt/plat_socket.c. Conditional
 * accept (WSAAccept()'s lpfnCondition) is out of POSIX's accept() scope
 * and not implemented.
 *
 * A datagram socket's __SOCK_ST_LISTENING bit can never be set
 * (listen.c refuses SOCK_DGRAM with EOPNOTSUPP), so the check below
 * already reports EINVAL for one -- no separate SOCK_DGRAM gate needed.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "plat_socket.h"
#include "plat_fd.h"
#include "ownership_stubs.h"

int accept(int fd, struct sockaddr *__restrict addr, socklen_t *__restrict len)
{
	struct __fd *f = __fd_get(fd);
	__plat_handle_t newh;
	int newfd;
	struct sockaddr_in peer;
	socklen_t peerlen = sizeof peer;

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (!(f->pad & __SOCK_ST_LISTENING)) { errno = EINVAL; return -1; }

	if (__plat_socket_accept(f->h, (struct sockaddr *)&peer, &peerlen, &newh) < 0) return -1;

	newfd = __fd_install(newh, 0, __FD_SOCKET);
	if (newfd < 0) { __plat_close(newh); return -1; }
	/* Can't be NULL here: newfd just came back from a successful
	 * __fd_install() with nothing in between that could remove it. */
	struct __fd *nf = __fd_get(newfd);
	__ownership_pointer_nonnull(nf);
	nf->pad = __SOCK_ST_BOUND | __SOCK_ST_CONNECTED;
	memcpy(nf->peer, &peer, sizeof peer);
	nf->peer_len = sizeof peer;

	/* Done only on the success path, so a failure above leaves the
	 * caller's address buffer untouched. */
	if (addr && len) {
		socklen_t n = *len < (socklen_t)sizeof peer ? *len : (socklen_t)sizeof peer;
		memcpy(addr, &peer, n);
		*len = sizeof peer;
	}

	return newfd;
}

// NOLINTEND(misc-include-cleaner)
