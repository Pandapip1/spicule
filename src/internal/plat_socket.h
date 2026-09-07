/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-socket-I/O interface src/socket/sendrecv.c's POSIX-facing
 * recv()/send() call into instead of building an AFD_RECV_INFO/
 * AFD_SEND_INFO request and issuing IOCTL_AFD_RECV/IOCTL_AFD_SEND
 * themselves.  See src/socket/nt/plat_socket.c for the implementation.
 *
 * Unlike plat_mem.h/plat_fd.h this is NOT the only place this
 * subsystem's raw NT syscalls end up: src/socket/afdsupport.c's
 * __afd_open()/__afd_ioctl() (declared in src/internal/afd.h, which is
 * out of scope to change) are a stable AFD-domain entry point that
 * getname.c's getpeername() half and sockopt.c never actually needed to
 * reach in the first place -- getpeername() is pure struct __fd field
 * access (f->peer/f->peer_len, populated generically by connect.c/
 * accept.c) and sockopt.c only manipulates the __SOCK_ST_REUSEADDR-style
 * bits below, so neither one has an NT syscall to relocate.  getname.c's
 * getsockname() half and shutdown.c did, and have been converted to
 * __plat_socket_getsockname()/__plat_socket_shutdown() below exactly
 * like bind()/connect()/listen()/accept() were: the front door's own
 * bookkeeping (the __SOCK_ST_* checks, the unbound-socket wildcard
 * short-circuit) stays in the front door, and only the actual wire-
 * protocol/syscall step moved into src/socket/nt/plat_socket.c and
 * src/socket/linux/plat_socket.c.
 *
 * __plat_sock_recv()/__plat_sock_send() are the genuine POSIX-shaped
 * half of this file that predates the rest of it -- ssize_t, errno
 * already set on failure, `flags` the plain <sys/socket.h> MSG_* bits --
 * because recv()/send() have no NT-shaped contract anyone outside this
 * library depends on.  Every NT-specific interpretation step lives
 * entirely inside their bodies: MSG_OOB/MSG_PEEK -> TDI_RECEIVE_*, a
 * clean peer shutdown folded into a 0-byte recv() return, and deciding
 * whether a broken connection raises SIGPIPE on send() -- see
 * __plat_sock_send()'s comment on why that decision cannot be made back
 * in the front door.
 *
 * __plat_socket_{open,bind,connect,listen,accept}() below are the
 * socket-CREATION half: what src/socket/{socket,bind,connect,listen,
 * accept}.c used to do by calling __afd_open()/__afd_ioctl() directly
 * (raw \Device\Afd wire protocol -- EA-buffer-encoded open packets,
 * AFD_BIND_DATA, AFD_CONNECT_INFO, the two-step AFD_WAIT_FOR_LISTEN +
 * fresh __afd_open() + AFD_ACCEPT accept() dance -- see
 * src/internal/afd.h).  Each front door's own POSIX-socket-state-
 * machine bookkeeping (the __SOCK_ST_* bits stashed in struct __fd's
 * `pad` byte, the ENOTSOCK/already-bound/already-connected checks, the
 * backlog clamp, the implicit wildcard bind before connect()/listen(),
 * accept()'s post-success addr/len truncate-and-copy) is NOT part of
 * this interface and stays in the front door, unchanged -- exactly like
 * __plat_fd.h's fd-table bookkeeping stays in src/unistd/{close,read,
 * write,...}.c.  Only the actual wire-protocol/syscall step moves.
 *
 * bind()'s `reuseaddr` is a plain boolean: which AFD_SHARE_* enum value
 * that becomes (AFD_SHARE_REUSE vs AFD_SHARE_UNIQUE) is a genuine NT
 * interpretation step and lives entirely inside __plat_socket_bind()'s
 * NT body -- the front door has no AFD-shaped concept to hand over.
 *
 * accept()'s NT backend is two real AFD steps (wait for a pending
 * connection, then open a fresh endpoint and bind the connection onto
 * it) collapsed into the one portable call below; the NT backend keeps
 * doing both steps internally, the Linux backend does the POSIX-native
 * one-step accept4(2).  addr/len follow accept(2)'s own convention
 * (silently truncate-if-too-small) so the front door can pass its own
 * full-sized local buffer through unchanged and do its usual
 * truncate-into-the-caller's-buffer copy afterward.
 *
 * SOCK_DGRAM (2026-09-01): __plat_socket_open() gained a `type`
 * parameter and __plat_socket_getsndbuf()/__plat_socket_getrcvbuf() were
 * added below; every other function above already generalised for free
 * (bind/connect/getsockname take a sockaddr and a length regardless of
 * the underlying transport's stream-vs-datagram nature; listen/accept
 * are refused a datagram socket entirely by the front door, before
 * either backend is reached -- see src/socket/listen.c). */
#ifndef _SPICULE_PLAT_SOCKET_H
#define _SPICULE_PLAT_SOCKET_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "plat_handle.h"

ssize_t __plat_sock_recv(__plat_handle_t h, void *buf, size_t len, int flags);
ssize_t __plat_sock_send(__plat_handle_t h, const void *buf, size_t len, int flags);

/* Per-socket connection-state bits stashed in struct __fd's `pad` byte
 * for __FD_SOCKET descriptors -- this library's own bookkeeping, not
 * anything either backend's wire protocol actually defines.  Numerically
 * identical to src/internal/afd.h's own AFD_ST_* (kept there, unchanged,
 * for src/socket/afdsupport.c and sendrecv.c's NT-only innards, which
 * still reach AFD directly and are out of this interface's scope): both
 * name bits of the very same struct __fd byte for the very same socket,
 * so the two definitions must never be allowed to drift apart. */
#define __SOCK_ST_BOUND     0x01
#define __SOCK_ST_LISTENING 0x02
#define __SOCK_ST_CONNECTED 0x04
#define __SOCK_ST_REUSEADDR 0x08
/* Set by socket()/socketpair() at creation time, never cleared: this
 * descriptor's underlying transport is SOCK_DGRAM, not SOCK_STREAM.
 * Consumed by listen.c (EOPNOTSUPP: a datagram socket cannot be marked
 * accepting connections) and sockopt.c's getsockopt(SO_TYPE).
 * Numerically identical to afd.h's own AFD_ST_DGRAM, for the same
 * reason the four bits above already are -- see this banner. */
#define __SOCK_ST_DGRAM     0x10

/* out required: both real implementations (linux/plat_socket.c,
 * nt/plat_socket.c) write `*out = box(...)`/`*out = ...` unconditionally
 * on their success path, with no NULL check of out itself anywhere.
 * socket.c's one real call site always passes `&h`, the address of its
 * own local, never NULL.
 *
 * `type` is the plain <sys/socket.h> SOCK_STREAM/SOCK_DGRAM value
 * (never OR'd with SOCK_CLOEXEC -- socket.c/socketpair.c strip that
 * before calling here, exactly like they already did before this
 * parameter existed).  Added for SOCK_DGRAM: this project's only two
 * creatable transports are AF_INET/SOCK_STREAM/IPPROTO_TCP and
 * AF_INET/SOCK_DGRAM/IPPROTO_UDP (an anonymous AF_UNIX socket is one of
 * these two wearing a different sa_family at the front door -- see
 * socket.c/socketpair.c), and the backend needs to know which one to
 * actually open; before SOCK_DGRAM existed there was only ever one
 * choice, so this took no parameter at all. */
int __plat_socket_open(__plat_handle_t *out, int type) __attribute__((nonnull(1)));
int __plat_socket_bind(__plat_handle_t h, int reuseaddr, const struct sockaddr *addr, socklen_t len);
int __plat_socket_connect(__plat_handle_t h, const struct sockaddr *addr, socklen_t len);
int __plat_socket_listen(__plat_handle_t h, unsigned long backlog);
/* out required, same shape as __plat_socket_open()'s own: both real
 * implementations write `*out = ...` unconditionally on the success
 * path. accept.c's one real call site always passes `&newh`, never
 * NULL. addr/len are NOT required here: neither backend dereferences
 * them directly in C (both only forward the raw pointer/length into a
 * syscall -- SYS_accept4's own arguments on Linux, the AFD wait/accept
 * request on NT), so there is nothing at this level for the attribute
 * to describe, matching this tree's own "forwarding-only, not marked"
 * precedent (e.g. posix_spawn_file_actions.c's add*() functions and
 * fa). */
int __plat_socket_accept(__plat_handle_t h, struct sockaddr *addr, socklen_t *len, __plat_handle_t *out)
    __attribute__((nonnull(4)));

/* getsockname(): addr/len follow the same truncate-if-too-small
 * convention as __plat_socket_accept()'s -- the front door's own
 * full-sized local buffer is passed straight through.  Only called once
 * the front door has already established the socket is bound (an
 * unbound socket's wildcard-address short-circuit stays in the front
 * door, exactly like bind()'s auto-bind-before-connect/listen stays in
 * listen.c/connect.c rather than moving here). */
int __plat_socket_getsockname(__plat_handle_t h, struct sockaddr *addr, socklen_t *len);
/* shutdown(): `how` is the plain SHUT_RD/SHUT_WR/SHUT_RDWR value from
 * <sys/socket.h> -- validating it against those three values and
 * checking __SOCK_ST_CONNECTED both stay in the front door; only the
 * actual disconnect step is here. */
int __plat_socket_shutdown(__plat_handle_t h, int how);

/* getsockopt(SOL_SOCKET, SO_SNDBUF/SO_RCVBUF): added for SOCK_DGRAM --
 * third_party/ltp's aio_test.h setup_aio() (the shared fixture behind
 * aio_cancel/2-1..7-1 and lio_listio/2-1) calls getsockopt(SO_SNDBUF)
 * on a socketpair()'d datagram socket immediately after creating it and
 * needs a real, finite answer to size the messages it then queues
 * (deliberately more of them than the buffer holds, so at least one
 * aio_write() blocks and is left cancelable -- the whole point of the
 * fixture).  Returns the buffer size in bytes on success, or -1 with
 * errno set.
 *
 * The two backends answer this honestly in different senses, and each
 * one says so in its own body: the Linux backend queries the real
 * kernel value off the real socket a SOCK_DGRAM fd is genuinely backed
 * by (src/socket/linux/plat_socket.c), so its answer governs actual
 * blocking behaviour.  The NT backend has no AFD_INFO wire-protocol
 * research behind it (src/internal/afd.h's socket-creation banner shows
 * the depth that kind of research takes, and IOCTL_AFD_GET_INFO's
 * AFD_INFO/AFD_INFO_SEND_BUFFER_SIZE layout was not attempted this
 * pass), so it returns a fixed constant instead of ENOPROTOOPT --
 * honestly labelled as this library's own stand-in, not afd.sys's real
 * negotiated buffer, in src/socket/nt/plat_socket.c. */
int __plat_socket_getsndbuf(__plat_handle_t h);
int __plat_socket_getrcvbuf(__plat_handle_t h);

/* socketpair(): a real, native socketpair(2) if this platform's kernel
 * has one (Linux does), or -1/ENOSYS if it does not (NT: AFD has no
 * such primitive -- an endpoint is always opened, then separately
 * bound/connected).  `type` is SOCK_STREAM or SOCK_DGRAM, optionally
 * OR'd with SOCK_CLOEXEC exactly as socketpair()'s own caller wrote it
 * (Linux's real socketpair(2) honors that bit directly, unlike
 * socket(2)/accept4(2)'s split story elsewhere in this codebase -- see
 * src/socket/linux/plat_socket.c).  On success, out[0]/out[1] are both
 * filled; added for SOCK_DGRAM (2026-09-01) because a genuine kernel
 * AF_UNIX datagram pair has real, mutual send/receive flow control
 * between the two ends (a full peer receive queue blocks the sender)
 * that this project's own loopback-UDP fallback
 * (src/socket/socketpair.c's socketpair_dgram()) does not reproduce --
 * UDP delivers to the peer's receive queue immediately over loopback
 * and has no such coupling, which third_party/ltp's aio_test.h fixture
 * (setup_aio(), the shared basis for aio_cancel/2-1..7-1 and
 * lio_listio/2-1) depends on to make at least one aio_write() actually
 * block.  socketpair.c calls this first and falls back to its own
 * construction only on ENOSYS, so a platform with no native
 * socketpair(2) still gets a socket, just not this flow-control
 * fidelity. */
int __plat_socketpair(int type, __plat_handle_t out[2]);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
