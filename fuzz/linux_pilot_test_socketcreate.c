/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux socket-CREATION pilot smoke test -- NOT part of spicule, same
 * standing as fuzz/linux_pilot_test.c and fuzz/linux_pilot_test_socket.c
 * (the earlier recv()/send()-only pilot).
 *
 * Exercises the REAL spicule public entry points socket()/bind()/listen()/
 * connect()/accept()/send()/recv() (src/socket/{socket,bind,connect,
 * listen,accept,sendrecv}.c, statically linked here, unmodified) against
 * the new src/socket/linux/plat_socket.c backend, running as a real,
 * native aarch64 Linux process on this host -- no Wine, no emulation,
 * and no raw socketpair(2) standing in for connection setup this time:
 * every step, including the connection itself, goes through the real
 * front doors.
 *
 * A real TCP listener is opened on 127.0.0.1:<ephemeral port> (port 0 --
 * bind() lets the kernel choose one -- then getsockname()'s absence from
 * this pilot's link set is worked around by using a fixed high port
 * instead, retried if already in use, since getsockname() is not one of
 * the five socket-creation front doors this pilot links).  A second
 * socket connect()s to
 * it. Because both sockets are real kernel TCP sockets on loopback with a
 * backlog already installed, connect() completes as soon as the kernel's
 * SYN queue accepts the handshake -- it does NOT need accept() to have
 * been called first -- so this whole test runs single-threaded and
 * sequential: listen, connect, accept, then exchange real bytes both
 * directions through the connected pair and verify content round-trips.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "libc.h"

extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

/* A fixed high port, retried on EADDRINUSE -- see this file's own banner
 * for why getsockname() is not available to discover the kernel's
 * choice instead. */
#define BASE_PORT 58231
#define PORT_TRIES 8

int main(void)
{
	int listen_fd = -1, client_fd, server_fd;
	int port = -1;
	int i;
	struct sockaddr_in addr;
	struct sockaddr_in peer;
	socklen_t peerlen;
	const char msg1[] = "hello from a real connect()ed spicule socket on linux";
	const char msg2[] = "and a real accept()ed reply travels back the other way";
	char buf[128];

	/* --- socket()/bind()/listen(): a real TCP listener --- */
	for (i = 0; i < PORT_TRIES; i++) {
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (listen_fd < 0) break;

		memset(&addr, 0, sizeof addr);
		addr.sin_family = AF_INET;
		addr.sin_port = htons((unsigned short)(BASE_PORT + i));
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
			port = BASE_PORT + i;
			break;
		}
		if (errno != EADDRINUSE) break;
		/* This backend has no close() front door linked; leak the fd
		 * and try the next port -- FD_MAX is nowhere close to
		 * PORT_TRIES, so this cannot exhaust the table. */
		listen_fd = -1;
	}
	CHECK(listen_fd >= 0 && port > 0, "socket()+bind() produced a real bound TCP listener");
	if (listen_fd < 0) { printf("\nSOME CHECKS FAILED (setup)\n"); return 1; }

	CHECK(listen(listen_fd, 8) == 0, "listen() on the real socket succeeded");

	/* --- connect(): a second real socket, dialing the listener --- */
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(client_fd >= 0, "socket() for the client succeeded");

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons((unsigned short)port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK(connect(client_fd, (struct sockaddr *)&addr, sizeof addr) == 0,
	     "connect() to the real listener succeeded");

	/* --- accept(): the real connection, off the real listen queue --- */
	memset(&peer, 0, sizeof peer);
	peerlen = sizeof peer;
	server_fd = accept(listen_fd, (struct sockaddr *)&peer, &peerlen);
	CHECK(server_fd >= 0, "accept() on the real listener returned a new connected socket");
	CHECK(peerlen == sizeof(struct sockaddr_in), "accept() reported the full sockaddr_in length");
	CHECK(peer.sin_family == AF_INET, "accept()'s peer address is AF_INET");
	CHECK(peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "accept()'s peer address is the real loopback address");

	/* --- send()/recv(): real bytes, both directions, through the
	 * connection socket()/bind()/listen()/connect()/accept() just
	 * established for real --- */
	{
		ssize_t n = send(client_fd, msg1, sizeof msg1 - 1, 0);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "send() on the connect()ed client wrote the full buffer");

		memset(buf, 0, sizeof buf);
		n = recv(server_fd, buf, sizeof buf, 0);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "recv() on the accept()ed server read the full buffer");
		CHECK(memcmp(buf, msg1, sizeof msg1 - 1) == 0, "recv() content matches what send() wrote");
	}
	{
		ssize_t n = send(server_fd, msg2, sizeof msg2 - 1, 0);
		CHECK(n == (ssize_t)(sizeof msg2 - 1), "send() on the accept()ed server wrote the full buffer");

		memset(buf, 0, sizeof buf);
		n = recv(client_fd, buf, sizeof buf, 0);
		CHECK(n == (ssize_t)(sizeof msg2 - 1), "recv() on the connect()ed client read the full buffer");
		CHECK(memcmp(buf, msg2, sizeof msg2 - 1) == 0, "recv() content matches what send() wrote (reverse direction)");
	}

	/* --- front-door state-machine checks (portable bookkeeping that
	 * stayed in the front door -- see src/internal/plat_socket.h) --- */
	CHECK(connect(client_fd, (struct sockaddr *)&addr, sizeof addr) == -1 && errno == EISCONN,
	     "a second connect() on an already-connected socket fails EISCONN before any syscall");
	CHECK(bind(client_fd, (struct sockaddr *)&addr, sizeof addr) == -1 && errno == EINVAL,
	     "bind() on an already-connected socket fails EINVAL before any syscall");
	CHECK(listen(client_fd, 8) == -1 && errno == EINVAL,
	     "listen() on a connected (non-listening) socket fails EINVAL before any syscall");
	CHECK(accept(client_fd, 0, 0) == -1 && errno == EINVAL,
	     "accept() on a non-listening socket fails EINVAL before any syscall");
	CHECK(listen(listen_fd, 8) == 0,
	     "a second listen() on an already-listening socket is accepted (POSIX doesn't forbid a repeat call)");

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
