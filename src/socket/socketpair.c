/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * socketpair(): a connected, bidirectional AF_UNIX pair.
 *
 * Two constructions, tried in order:
 *
 *   1. __plat_socketpair(): a real socketpair(2) where the platform has
 *      one (Linux) -- genuinely connects the two ends with the kernel's
 *      own flow control, which matters for SOCK_DGRAM (see
 *      socketpair_dgram()'s comment).
 *   2. Falls back to a private loopback AF_INET pair (TCP listener+accept
 *      for SOCK_STREAM, bind()+connect() UDP for SOCK_DGRAM) when
 *      __plat_socketpair() reports ENOSYS (NT: AFD has no native
 *      primitive). socketpair() has no pathname or externally visible
 *      address, so this has the same observable semantics while reusing
 *      the AF_INET transport this directory already implements.
 *
 * Both ends of the pair get whichever of SOCK_CLOEXEC/SOCK_NONBLOCK the
 * caller asked for, on every path.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "plat_socket.h"
#include "plat_fd.h"

/* Installs an already-connected __plat_socketpair() handle, mirroring
 * socket()'s __fd_install()/pad bookkeeping and connect()'s
 * __SOCK_ST_CONNECTED/peer caching without a separate connect() call.
 *
 * f->peer is cached as an all-zero AF_UNIX sockaddr rather than left
 * uninitialized: a real AF_UNIX socketpair(2) pair is anonymous on both
 * ends, and this project's getpeername() is pure field access with no
 * live kernel query, so this is honest about matching an unnamed peer
 * (unlike the loopback fallback's fabricated AF_INET peer). */
static int install_pair_handle(__plat_handle_t h, int dgram, int cloexec, int nonblock)
{
	struct __fd *f;
	struct sockaddr peer;
	int fd = __fd_install(h, (cloexec ? O_CLOEXEC : 0) | (nonblock ? O_NONBLOCK : 0), __FD_SOCKET);

	if (fd < 0) { __plat_close(h); return -1; }
	f = __fd_get(fd);
	f->pad = __SOCK_ST_BOUND | __SOCK_ST_CONNECTED | (dgram ? __SOCK_ST_DGRAM : 0);
	memset(&peer, 0, sizeof peer);
	peer.sa_family = AF_UNIX;
	memcpy(f->peer, &peer, sizeof peer);
	f->peer_len = sizeof peer;
	return fd;
}

/* pair[0] gets SOCK_CLOEXEC/SOCK_NONBLOCK from socket() directly.
 * pair[1] comes from accept() (no accept4() here), so both are applied
 * via separate fcntl() calls after the fd exists -- leaving the same
 * exec()/blocking-I/O race window accept4() exists to close, with no
 * narrower fix available without it. */
static int socketpair_stream(int cloexec, int nonblock, int pair[2])
{
	struct sockaddr_in address;
	socklen_t length;
	int listener = -1, client = -1, server = -1;
	int saved;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) goto fail;
	memset(&address, 0, sizeof address);
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, (struct sockaddr *)&address, sizeof address) < 0 ||
	    listen(listener, 1) < 0) goto fail;
	length = sizeof address;
	if (getsockname(listener, (struct sockaddr *)&address, &length) < 0) goto fail;

	client = socket(AF_INET, SOCK_STREAM | cloexec | nonblock, 0);
	if (client < 0 ||
	    connect(client, (struct sockaddr *)&address, sizeof address) < 0)
		goto fail;
	server = accept(listener, 0, 0);
	if (server < 0) goto fail;
	if (cloexec && fcntl(server, F_SETFD, FD_CLOEXEC) < 0) goto fail;
	if (nonblock && fcntl(server, F_SETFL, O_NONBLOCK) < 0) goto fail;
	(void)close(listener);
	pair[0] = client;
	pair[1] = server;
	return 0;

fail:
	saved = errno;
	if (server >= 0) (void)close(server);
	if (client >= 0) (void)close(client);
	if (listener >= 0) (void)close(listener);
	errno = saved;
	return -1;
}

/* No listener/accept dance: a datagram socket has no connection to
 * accept. Instead two UDP sockets are each bound to an ephemeral
 * loopback port and connect()'d to *each other's* address -- connect()
 * on SOCK_DGRAM just sets the default destination, so no handshake is
 * needed.
 *
 * Both ends come from socket() directly here, unlike the SOCK_STREAM
 * path's pair[1] (from accept()), so SOCK_CLOEXEC/SOCK_NONBLOCK apply
 * cleanly with no fcntl() race window. */
static int socketpair_dgram(int cloexec, int nonblock, int pair[2])
{
	struct sockaddr_in addr_a, addr_b;
	socklen_t length;
	int a = -1, b = -1;
	int saved;

	a = socket(AF_INET, SOCK_DGRAM | cloexec | nonblock, 0);
	b = socket(AF_INET, SOCK_DGRAM | cloexec | nonblock, 0);
	if (a < 0 || b < 0) goto fail;

	memset(&addr_a, 0, sizeof addr_a);
	addr_a.sin_family = AF_INET;
	addr_a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(a, (struct sockaddr *)&addr_a, sizeof addr_a) < 0) goto fail;
	length = sizeof addr_a;
	if (getsockname(a, (struct sockaddr *)&addr_a, &length) < 0) goto fail;

	memset(&addr_b, 0, sizeof addr_b);
	addr_b.sin_family = AF_INET;
	addr_b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(b, (struct sockaddr *)&addr_b, sizeof addr_b) < 0) goto fail;
	length = sizeof addr_b;
	if (getsockname(b, (struct sockaddr *)&addr_b, &length) < 0) goto fail;

	if (connect(a, (struct sockaddr *)&addr_b, sizeof addr_b) < 0) goto fail;
	if (connect(b, (struct sockaddr *)&addr_a, sizeof addr_a) < 0) goto fail;

	pair[0] = a;
	pair[1] = b;
	return 0;

fail:
	saved = errno;
	if (b >= 0) (void)close(b);
	if (a >= 0) (void)close(a);
	errno = saved;
	return -1;
}

int socketpair(int domain, int type, int protocol, int pair[2]) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int cloexec = type & SOCK_CLOEXEC;
	int nonblock = type & SOCK_NONBLOCK;
	int t = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
	__plat_handle_t native[2];

	if (domain != AF_UNIX) { errno = EAFNOSUPPORT; return -1; }
	if (t != SOCK_STREAM && t != SOCK_DGRAM) { errno = EPROTOTYPE; return -1; }
	if (protocol != 0) { errno = EPROTONOSUPPORT; return -1; }
	if (!pair) { errno = EINVAL; return -1; }

	if (__plat_socketpair(type, native) == 0) {
		int a = install_pair_handle(native[0], t == SOCK_DGRAM, cloexec, nonblock);
		int b;

		if (a < 0) { __plat_close(native[1]); return -1; }
		b = install_pair_handle(native[1], t == SOCK_DGRAM, cloexec, nonblock);
		if (b < 0) { int saved = errno; (void)close(a); errno = saved; return -1; }
		pair[0] = a;
		pair[1] = b;
		return 0;
	}
	if (errno != ENOSYS) return -1; /* a real failure, not "no native primitive" */

	return t == SOCK_DGRAM ? socketpair_dgram(cloexec, nonblock, pair) : socketpair_stream(cloexec, nonblock, pair);
}
