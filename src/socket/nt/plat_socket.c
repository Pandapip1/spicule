/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_socket.h -- see that header for
 * the contract each function makes and for why this file also carries
 * __afd_open()/__afd_ioctl() (declared in src/internal/afd.h), not just
 * the __plat_sock_* pair.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "libc.h"
#include "afd.h"
#include "plat_socket.h"
#include "plat_fd.h"

/* Open a fresh \Device\Afd\Endpoint handle carrying the AF_INET/
 * SOCK_STREAM transport ("\Device\Tcp") -- a FILE_FULL_EA_INFORMATION
 * named "AfdOpenPacketXX" whose value is an AFD_OPEN_PACKET naming the
 * transport device. See src/internal/afd.h's socket-creation banner for
 * the layout. Every socket() call and every accept()ed connection needs
 * one of these. */
int __afd_open(HANDLE *out, int socktype)
{
	/* The shape is read once and passed to both calls, so the buffer's
	 * declared size and its contents cannot come from two different
	 * answers -- a mismatch here would be a heap overflow, not a wrong
	 * packet. */
	int shape = __afd_open_shape();
	unsigned long ea_size = __afd_open_ea_size_for(shape);
	char *buf;
	UNICODE_STRING devname;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	HANDLE h = 0;
	NTSTATUS st;

	buf = malloc(ea_size);
	if (!buf) { errno = ENOMEM; return -1; }
	__afd_build_open_ea_for(shape, socktype, buf);

	/* \Device\Afd\Endpoint (dllmain.c's DevName; see afd.h banner). */
	{
		static const WCHAR endpoint[] = AFD_ENDPOINT_DEVICE;
		devname.Length = (unsigned short)((sizeof(endpoint) / sizeof(WCHAR) - 1) * sizeof(WCHAR));
		devname.MaximumLength = devname.Length + sizeof(WCHAR);
		devname.Buffer = (WCHAR *)endpoint;
	}
	InitializeObjectAttributes(&oa, &devname, OBJ_CASE_INSENSITIVE, 0, 0);

	/* FILE_SYNCHRONOUS_IO_NONALERT: this project's house style for every
	 * handle the AFD ioctls below wait on synchronously, reusing the
	 * NtWaitForSingleObject-on-STATUS_PENDING pattern every other __FD_*
	 * type relies on, rather than ReactOS's per-call-event scheme. */
	st = NtCreateFile(&h, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &io, 0, 0,
	                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
	                  FILE_SYNCHRONOUS_IO_NONALERT, buf, ea_size);
	free(buf);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*out = h;
	return 0;
}

/* Issue one AFD ioctl and wait for it to finish; STATUS_PENDING is waited
 * out on the handle itself. Returns the raw NTSTATUS: several other
 * src/socket/ files call this directly and interpret specific status
 * values themselves, so unlike every other function here this one cannot
 * collapse its result to errno. */
NTSTATUS __afd_ioctl(HANDLE h, ULONG code, void *in, ULONG inlen, void *out, ULONG outlen, IO_STATUS_BLOCK *io_out)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	io.Status = 0; io.Information = 0;
	st = NtDeviceIoControlFile(h, 0, 0, 0, &io, code, in, inlen, out, outlen);
	if (st == STATUS_PENDING) {
		NtWaitForSingleObject(h, 0, 0);
		st = io.Status;
	}
	if (io_out) *io_out = io;
	return st;
}

/* recv(): build the AFD_RECV_INFO request (MSG_OOB/MSG_PEEK -> the
 * matching TDI_RECEIVE_* flag) and issue IOCTL_AFD_RECV.
 *
 * A clean disconnect (STATUS_CONNECTION_DISCONNECTED/STATUS_LOCAL_
 * DISCONNECT/STATUS_REMOTE_DISCONNECT) is folded into a 0-byte return
 * HERE, while the real status is in hand: src/internal/errno.c's generic
 * mapping sends all three to ENOTCONN, indistinguishable there from a
 * socket that was never connected and must NOT read back as EOF. */
ssize_t __plat_sock_recv(__plat_handle_t h, void *buf, size_t len, int flags) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	AFD_WSABUF wb;
	AFD_RECV_INFO ri;
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	wb.len = (unsigned int)len;
	wb.buf = buf;
	ri.BufferArray = &wb;
	ri.BufferCount = 1;
	ri.AfdFlags = 0;
	ri.TdiFlags = 0;
	if (flags & MSG_OOB) ri.TdiFlags |= TDI_RECEIVE_EXPEDITED;
	if (flags & MSG_PEEK) ri.TdiFlags |= TDI_RECEIVE_PEEK;
	if (!ri.TdiFlags) ri.TdiFlags = TDI_RECEIVE_NORMAL;

	st = __afd_ioctl(h, IOCTL_AFD_RECV, &ri, sizeof(ri), 0, 0, &io);
	if (st == STATUS_CONNECTION_DISCONNECTED || st == STATUS_LOCAL_DISCONNECT || st == STATUS_REMOTE_DISCONNECT)
		return 0;
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

/* socket(): open a fresh AFD endpoint via __afd_open() above, a thin
 * __plat_handle_t-shaped wrapper. */
int __plat_socket_open(__plat_handle_t *out, int type)
{
	HANDLE h = 0;

	if (__afd_open(&h, type) < 0) return -1;
	*out = h;
	return 0;
}

/* bind(): build the AFD_BIND_DATA request and issue IOCTL_AFD_BIND. */
int __plat_socket_bind(__plat_handle_t h, int reuseaddr, const struct sockaddr *addr, socklen_t len)
{
	AFD_BIND_DATA bd;
	/* IOCTL_AFD_BIND replies with a TDI_ADDRESS_INFO, 26 bytes for one
	 * AF_INET address -- two bytes more than the request's 24-byte
	 * TRANSPORT_ADDRESS payload, so it does not fit back into `bd`.
	 * Spelled as uint32_t[] to get 4-byte alignment without an
	 * alignment attribute. */
	uint32_t reply[(AFD_TDI_ADDRESS_INFO_SIZE_IP + 3) / 4];
	NTSTATUS st;

	if (__afd_build_bind_request(&bd, reuseaddr ? AFD_SHARE_REUSE : AFD_SHARE_UNIQUE, addr, len) < 0)
		return -1;

	/* __afd_bind_request_size(), not sizeof(bd): the request is 26 bytes
	 * and sizeof(AFD_BIND_DATA) is 28. IOCTL_AFD_BIND is METHOD_NEITHER,
	 * so the declared length is what afd.sys bounds its read by. */
	st = __afd_ioctl(h, IOCTL_AFD_BIND, &bd, (ULONG)__afd_bind_request_size(),
	                 reply, (ULONG)sizeof(reply), 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* connect(): build the AFD_CONNECT_INFO request and issue
 * IOCTL_AFD_CONNECT. The wildcard-bind-first step and peer bookkeeping
 * stay in the front door -- this is only the wire-protocol step. */
int __plat_socket_connect(__plat_handle_t h, const struct sockaddr *addr, socklen_t len)
{
	AFD_CONNECT_INFO ci;
	NTSTATUS st;

	/* Built through src/internal/afd.h's AFD_CONNECT_REQ_OFF_*, not
	 * through AFD_CONNECT_INFO's members: see that header's connect
	 * banner for why the address's offset is pointer-sized, and why
	 * ReactOS's AFD_CONNECT_INFO puts it 12 bytes too early on x86_64. */
	memset(&ci, 0, sizeof(ci));
	if (__afd_build_connect_request(&ci, addr, len) < 0) return -1;

	/* __afd_connect_request_size(), not sizeof(ci): IOCTL_AFD_CONNECT is
	 * METHOD_NEITHER, so the declared length bounds afd.sys's read. */
	st = __afd_ioctl(h, IOCTL_AFD_CONNECT, &ci, (ULONG)__afd_connect_request_size(), 0, 0, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* listen(): issue IOCTL_AFD_START_LISTEN. The backlog clamp to SOMAXCONN
 * and the wildcard bind stay in the front door -- `backlog` arrives here
 * already clamped. */
int __plat_socket_listen(__plat_handle_t h, unsigned long backlog)
{
	AFD_LISTEN_DATA ld;
	NTSTATUS st;

	ld.UseSAN = 0;
	ld.UseDelayedAcceptance = 0;
	ld.Backlog = (uint32_t)backlog;

	st = __afd_ioctl(h, IOCTL_AFD_START_LISTEN, &ld, sizeof(ld), 0, 0, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* accept(): the two-step AFD sequence, per ReactOS's WSPAccept:
 * IOCTL_AFD_WAIT_FOR_LISTEN blocks until a connection is pending and
 * returns its SequenceNumber plus the peer's TDI address; a *new* AFD
 * endpoint is then opened exactly like socket() does, and
 * IOCTL_AFD_ACCEPT -- issued on the *listening* handle, naming the new
 * endpoint's handle in AFD_ACCEPT_DATA.ListenHandle -- binds the pending
 * connection onto it. */
int __plat_socket_accept(__plat_handle_t h, struct sockaddr *addr, socklen_t *len, __plat_handle_t *out)
{
	AFD_RECEIVED_ACCEPT_DATA recvd;
	AFD_ACCEPT_DATA ad;
	HANDLE newh = 0;
	NTSTATUS st;

	/* Zeroed before the call: IOCTL_AFD_WAIT_FOR_LISTEN is METHOD_BUFFERED
	 * with an out-only buffer, so the I/O manager copies back exactly
	 * IoStatus.Information bytes and leaves everything past that as the
	 * caller left it -- uninitialised stack unless put there first. */
	memset(&recvd, 0, sizeof recvd);
	st = __afd_ioctl(h, IOCTL_AFD_WAIT_FOR_LISTEN, 0, 0, &recvd, sizeof(recvd), 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);

	/* Interpreted here, before any endpoint is created: failing before
	 * __afd_open() keeps accept() all-or-nothing rather than leaking an
	 * endpoint. ECONNABORTED (not EPROTO): the connection is already off
	 * the listen queue and cannot be handed to the caller, which portable
	 * accept loops handle by going round again rather than giving up. */
	if (__afd_accept_reply_addr(&recvd, addr, len) < 0) {
		errno = ECONNABORTED;
		return -1;
	}

	/* SOCK_STREAM: accept() is refused entirely on a SOCK_DGRAM socket
	 * before this backend is ever reached, so this is always a stream
	 * endpoint. */
	if (__afd_open(&newh, SOCK_STREAM) < 0) return -1;

	ad.UseSAN = 0;
	ad.SequenceNumber = recvd.SequenceNumber;
	ad.ListenHandle = newh;

	st = __afd_ioctl(h, IOCTL_AFD_ACCEPT, &ad, sizeof(ad), 0, 0, 0);
	if (!NT_SUCCESS(st)) { __plat_close(newh); return __set_errno_status(st); }

	*out = newh;
	return 0;
}

/* send(): build the AFD_SEND_INFO request (MSG_OOB -> TDI_SEND_EXPEDITED)
 * and issue IOCTL_AFD_SEND.
 *
 * SIGPIPE (unless MSG_NOSIGNAL) is raised HERE, not by the front door
 * testing errno==EPIPE afterward: src/internal/errno.c's generic mapping
 * also sends STATUS_REQUEST_ABORTED to the same ECONNABORTED bucket, but
 * that status must NOT raise SIGPIPE -- only this call, with the real
 * status in hand, can tell them apart. */
ssize_t __plat_sock_send(__plat_handle_t h, const void *buf, size_t len, int flags) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	AFD_WSABUF wb;
	AFD_SEND_INFO si;
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	wb.len = (unsigned int)len;
	wb.buf = (char *)buf;
	si.BufferArray = &wb;
	si.BufferCount = 1;
	si.AfdFlags = 0;
	si.TdiFlags = (flags & MSG_OOB) ? TDI_SEND_EXPEDITED : 0;

	st = __afd_ioctl(h, IOCTL_AFD_SEND, &si, sizeof(si), 0, 0, &io);
	if (st == STATUS_CONNECTION_DISCONNECTED || st == STATUS_LOCAL_DISCONNECT ||
	    st == STATUS_REMOTE_DISCONNECT || st == STATUS_CONNECTION_RESET || st == STATUS_CONNECTION_ABORTED) {
		if (!(flags & MSG_NOSIGNAL)) {
			__sig_lock();
			__raise_internal(SIGPIPE);
			__sig_unlock();
		}
		errno = EPIPE;
		return -1;
	}
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

/* getsockname(): issue IOCTL_AFD_GET_SOCK_NAME and convert the reply. */
int __plat_socket_getsockname(__plat_handle_t h, struct sockaddr *addr, socklen_t *len)
{
	/* Spelled as uint32_t[] for 4-byte alignment without an alignment
	 * attribute, same as bind()'s reply buffer. */
	uint32_t reply[(AFD_SOCKNAME_RSP_SIZE + 3) / 4];
	NTSTATUS st;

	/* __afd_sockname_reply_size(), not sizeof(reply): the array is rounded
	 * up to a whole uint32_t, and declaring the spare bytes to a
	 * METHOD_NEITHER driver would describe two bytes the reply doesn't have. */
	memset(reply, 0, sizeof reply);
	st = __afd_ioctl(h, IOCTL_AFD_GET_SOCK_NAME, 0, 0, reply,
	                 (ULONG)__afd_sockname_reply_size(), 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);

	/* A success that carried no address: a guard, not a real path, since a
	 * well-formed reply always passes. */
	if (__afd_sockname_reply_addr(reply, addr, len) < 0) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* shutdown(): build the AFD_DISCONNECT_INFO request and issue
 * IOCTL_AFD_DISCONNECT. `how` arrives here already known to be one of the
 * three valid values. */
int __plat_socket_shutdown(__plat_handle_t h, int how)
{
	AFD_DISCONNECT_INFO di;
	NTSTATUS st;

	switch (how) {
	case SHUT_RD:   di.DisconnectType = AFD_DISCONNECT_RECV; break;
	case SHUT_WR:   di.DisconnectType = AFD_DISCONNECT_SEND; break;
	case SHUT_RDWR: di.DisconnectType = AFD_DISCONNECT_RECV | AFD_DISCONNECT_SEND; break;
	default: errno = EINVAL; return -1;
	}
	di.Timeout = 0; /* LARGE_INTEGER is a plain LONGLONG here (src/internal/nt.h) */

	st = __afd_ioctl(h, IOCTL_AFD_DISCONNECT, &di, sizeof(di), 0, 0, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* getsockopt(SO_SNDBUF)/getsockopt(SO_RCVBUF): a fixed constant instead of
 * a real AFD query. IOCTL_AFD_GET_INFO could answer this for real, but its
 * request/reply layout hasn't been independently cross-checked against a
 * second source the way this file's other ioctls have, so it's unused.
 * 8192 is not measured, just a plausible POSIX-legal stand-in so a caller
 * like LTP's setup_aio() gets an answer instead of ENOPROTOOPT. */
#define __NT_SOCKBUF_STANDIN 8192 // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- implementation-reserved namespace, same as every other libc-internal symbol

int __plat_socket_getsndbuf(__plat_handle_t h)
{
	(void)h;
	return __NT_SOCKBUF_STANDIN;
}

int __plat_socket_getrcvbuf(__plat_handle_t h)
{
	(void)h;
	return __NT_SOCKBUF_STANDIN;
}

/* socketpair(): AFD has no native socketpair primitive. ENOSYS tells
 * src/socket/socketpair.c to fall back to its own bind()/connect()
 * construction (loopback TCP for SOCK_STREAM, loopback UDP for
 * SOCK_DGRAM). */
int __plat_socketpair(int type, __plat_handle_t out[2])
{
	(void)type;
	(void)out;
	errno = ENOSYS;
	return -1;
}

// NOLINTEND(misc-include-cleaner)
