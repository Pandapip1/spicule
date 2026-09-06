/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/socket.h>.
 *
 * Scope: AF_INET with SOCK_STREAM (TCP), AF_INET with SOCK_DGRAM (UDP),
 * and an anonymous (never pathname-bound) AF_UNIX with SOCK_DGRAM reached
 * only through socket()/socketpair(). General AF_UNIX pathname sockets
 * remain out of scope: no <sys/un.h> exists in this tree, so there is no
 * address type to bind() one to. sendmsg()/recvmsg()'s ancillary data,
 * AF_INET6 sockets, and sockatmark() are deliberately not declared here,
 * per this project's standing rule that a declared-but-undefined symbol
 * is a latent link-error bug, not a lesser form of "not implemented yet".
 * The SOCK_/AF_/SO_/MSG_ constants are defined regardless, so e.g.
 * `socket(AF_INET6, ...)` compiles and fails at runtime with
 * EAFNOSUPPORT rather than at compile time.
 *
 * sendto()/recvfrom() reduce entirely to send()/recv() on a connected
 * socket; every SOCK_DGRAM socket this project can produce is used
 * connected, so an unconnected socket supplying its destination per-call
 * remains out of scope.
 */
#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <memory_tokens.h>

#define __NEED_size_t
#define __NEED_ssize_t
#define __NEED_socklen_t
#define __NEED_sa_family_t

#include <bits/alltypes.h>

/* sa_data is sized 14 so that sizeof(struct sockaddr) matches
 * sockaddr_in's own size (this project's only address family); POSIX
 * leaves the exact size unspecified beyond "large enough". */
struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

/* Large enough to hold a sockaddr_in (this project's only address
 * family); POSIX only requires it be as large as the largest sockaddr
 * variant the implementation supports and suitably aligned. */
struct sockaddr_storage {
	sa_family_t ss_family;
	char __ss_pad[26];
};

struct linger {
	int l_onoff;
	int l_linger;
};

/* These must numerically match src/internal/afd.h's TDI_ADDRESS_TYPE_IP,
 * since AF_INET is written directly into AFD's wire-format
 * TA_ADDRESS.AddressType by src/socket/afdsupport.c. */
#define AF_UNSPEC 0
#define AF_UNIX   1
#define AF_INET   2
#define AF_INET6  23  /* not implemented; declared only so it compiles */
#define PF_UNSPEC AF_UNSPEC
#define PF_UNIX   AF_UNIX
#define PF_INET   AF_INET
#define PF_INET6  AF_INET6

#define SOCK_STREAM    1
#define SOCK_DGRAM     2  /* AF_INET (UDP) and anonymous AF_UNIX only -- see this header's banner */
#define SOCK_RAW       3  /* not implemented */
#define SOCK_SEQPACKET 5  /* not implemented */

/* Shares <fcntl.h>'s O_CLOEXEC bit value rather than inventing a new one:
 * socket()/socketpair() strip it from the type argument and fold it
 * straight into struct __fd's flags word, no translation needed. Real,
 * not "declared only so it compiles": both functions honor it. */
#define SOCK_CLOEXEC   02000000

/* Shares <fcntl.h>'s O_NONBLOCK bit value, for the same reason
 * SOCK_CLOEXEC shares O_CLOEXEC's. What is NOT true yet: no socket I/O
 * call (connect/send/recv/accept) actually consults the bit -- it is
 * stored and reported, not acted on, so a socket created with this flag
 * still blocks to completion exactly as one without it does. */
#define SOCK_NONBLOCK  04000

#define SOL_SOCKET 0xffff

#define SO_REUSEADDR  0x0004
#define SO_KEEPALIVE  0x0008
#define SO_DONTROUTE  0x0010
#define SO_BROADCAST  0x0020
#define SO_LINGER     0x0080
#define SO_OOBINLINE  0x0100
/* SO_SNDBUF/SO_RCVBUF: getsockopt() only (src/socket/sockopt.c). */
#define SO_SNDBUF     0x1001
#define SO_RCVBUF     0x1002
#define SO_SNDLOWAT   0x1003
#define SO_RCVLOWAT   0x1004
#define SO_SNDTIMEO   0x1005
#define SO_RCVTIMEO   0x1006
#define SO_ERROR      0x1007
#define SO_TYPE       0x1008
#define SO_ACCEPTCONN 0x1009
#define SO_DEBUG      0x0001

#define MSG_OOB       0x01
#define MSG_PEEK      0x02
#define MSG_DONTROUTE 0x04
#define MSG_EOR       0x08
#define MSG_TRUNC     0x10
#define MSG_CTRUNC    0x20
#define MSG_WAITALL   0x40
#define MSG_NOSIGNAL  0x4000

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2

/* SOMAXCONN is this project's chosen backlog ceiling; AFD's own
 * AFD_LISTEN_DATA.Backlog has no documented cap of its own, so
 * src/socket/listen.c clamps to it. */
#define SOMAXCONN 128

async_signal_safe
io_operation
int socket(int, int, int);
async_signal_safe
int socketpair(int, int, int, int [2]);
async_signal_safe
io_operation
int bind(int, const struct sockaddr *, socklen_t);
async_signal_safe
io_operation
int listen(int, int);
async_signal_safe
io_operation
int accept(int, struct sockaddr *__restrict, socklen_t *__restrict);
async_signal_safe
io_operation
int connect(int, const struct sockaddr *, socklen_t);
async_signal_safe
int getsockname(int, struct sockaddr *__restrict, socklen_t *__restrict);
async_signal_safe
int getpeername(int, struct sockaddr *__restrict, socklen_t *__restrict);
async_signal_safe
io_operation
ssize_t send(int, const void *buf withtok(readable_span(len)), size_t len,
             int flags);
async_signal_safe
io_operation
ssize_t recv(int, void *buf withtok(writable_span(len)), size_t len, int flags);
async_signal_safe
io_operation
ssize_t sendto(int, const void *buf withtok(readable_span(len)), size_t len,
               int flags, const struct sockaddr *, socklen_t);
async_signal_safe
io_operation
ssize_t recvfrom(int, void *buf withtok(writable_span(len)), size_t len,
                 int flags, struct sockaddr *__restrict,
                 socklen_t *__restrict);
async_signal_safe
io_operation
int shutdown(int, int);
async_signal_safe
int setsockopt(int, int, int, const void *, socklen_t);
async_signal_safe
int getsockopt(int, int, int, void *__restrict, socklen_t *__restrict);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
