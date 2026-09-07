/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * send()/recv():
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html
 *
 * Both go through IOCTL_AFD_SEND/IOCTL_AFD_RECV rather than plain
 * NtWriteFile/NtReadFile: test/networking-audit.md flags the bare-ioctl
 * form as unverified and recommends the ioctl path, which this follows.
 * src/unistd/read.c/write.c gain a thin __FD_SOCKET branch calling these
 * rather than duplicating the setup.
 *
 * NTSTATUS interpretation (recv's "0 = orderly shutdown", send's
 * EPIPE/SIGPIPE) lives in __plat_sock_recv()/__plat_sock_send(); this
 * file keeps only POSIX validation and fd-table bookkeeping, the same
 * split read()/write() already make.
 *
 * sendto()/recvfrom(): every SOCK_DGRAM socket this project can produce
 * is used connected (socketpair() hands back an already-connected
 * pair), and sendto.html says dest_addr is ignored on a connected
 * socket -- so both reduce to send()/recv() plus reporting the cached
 * peer address (struct __fd's peer/peer_len). An unconnected socket
 * gets the same ENOTCONN send()/recv() already give it; a real
 * per-datagram destination path is not implemented.
 */
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "afd.h"
#include "plat_socket.h"
#include "ownership_stubs.h"

ssize_t recv(int fd, void *buf withtok(writable_span(len)), size_t len,
	int flags)
{
	struct __fd *f = __fd_get(fd);

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (!(f->pad & AFD_ST_CONNECTED)) { errno = ENOTCONN; return -1; }
	if (len > 0x7fffffff) len = 0x7fffffff;

	return __plat_sock_recv(f->h, buf, len, flags);
}

ssize_t send(int fd, const void *buf withtok(readable_span(len)), size_t len,
	int flags)
{
	struct __fd *f = __fd_get(fd);

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (!(f->pad & AFD_ST_CONNECTED)) { errno = ENOTCONN; return -1; }
	if (len > 0x7fffffff) len = 0x7fffffff;

	return __plat_sock_send(f->h, buf, len, flags);
}

ssize_t sendto(int fd, const void *buf withtok(readable_span(len)), size_t len,
	int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct __fd *f = __fd_get(fd);

	(void)dest_addr;
	(void)addrlen;

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (!(f->pad & AFD_ST_CONNECTED)) { errno = ENOTCONN; return -1; }
	if (len > 0x7fffffff) len = 0x7fffffff;

	/* sendto.html: dest_addr is ignored on a connected socket -- every
	 * socket reaching here is connected, so it plays no further part. */
	return __plat_sock_send(f->h, buf, len, flags);
}

ssize_t recvfrom(int fd, void *buf withtok(writable_span(len)), size_t len,
	int flags, struct sockaddr *__restrict src_addr,
	socklen_t *__restrict addrlen)
{
	struct __fd *f = __fd_get(fd);
	ssize_t n;

	if (!f) return -1;
	if (f->type != __FD_SOCKET) { errno = ENOTSOCK; return -1; }
	if (!(f->pad & AFD_ST_CONNECTED)) { errno = ENOTCONN; return -1; }
	if (len > 0x7fffffff) len = 0x7fffffff;

	n = __plat_sock_recv(f->h, buf, len, flags);
	if (n < 0) return -1;

	/* recvfrom.html: source address is stored unless address is NULL.
	 * Every socket reaching here is connected, so the "source" is the
	 * peer connect()/accept() already recorded in peer/peer_len. */
	if (src_addr && addrlen) {
		socklen_t n2 = *addrlen < (socklen_t)f->peer_len ?
			*addrlen : (socklen_t)f->peer_len;
		unsafe_assume_writable_span(src_addr, n2);
		unsafe_assume_readable_span(f->peer, n2);
		memcpy(src_addr, f->peer, n2);
		*addrlen = f->peer_len;
	}
	return n;
}
