/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_socket.h -- see
 * src/mman/linux/plat_mem.c's own banner for the raw-syscall discipline
 * this file follows too.
 *
 * Much simpler than the NT backend's \Device\Afd wire protocol, since
 * spicule's own AF_INET/SOCK_STREAM/IPPROTO_TCP values and struct
 * sockaddr_in layout already match the real kernel socket ABI exactly.
 * SOL_SOCKET/SO_REUSEADDR are the one exception -- spicule's own
 * <sys/socket.h> gives them a private encoding that does NOT match the
 * real kernel ABI, so __plat_socket_bind()'s reuseaddr flag is translated
 * explicitly via setsockopt(2) before bind(2), the same pattern
 * to_linux_flags() below uses for send()/recv().
 *
 * __plat_handle_t encoding matches src/unistd/linux/plat_fd.c's boxed-fd
 * scheme (fd+1) exactly, since a Linux socket fd lives in the same
 * descriptor space as a Linux file fd.
 *
 * recv()/send() need no NTSTATUS-style disconnect/SIGPIPE interpretation
 * here (contrast src/socket/nt/plat_socket.c): a Linux recvfrom(2) already
 * returns 0 on a clean peer shutdown, and sendto(2) against a broken
 * connection already returns -EPIPE with the kernel raising real SIGPIPE
 * as an ordinary side effect (unless MSG_NOSIGNAL).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include "plat_socket.h"
#include "unsafe_pointer.h"

/* aarch64/x86_64 Linux syscall numbers, confirmed against each host's own
 * <sys/syscall.h>. Neither arch has a separate SYS_recv/SYS_send: glibc's
 * own recv()/send() are thin wrappers over recvfrom/sendto with a NULL
 * address argument, which is exactly what this file does too. */
#if defined(__aarch64__)
#define SYS_recvfrom     207
#define SYS_sendto       206
#define SYS_socket       198
#define SYS_bind         200
#define SYS_listen       201
#define SYS_connect      203
#define SYS_getsockname  204
#define SYS_setsockopt   208
#define SYS_getsockopt   209
#define SYS_shutdown     210
#define SYS_accept4      242
#define SYS_socketpair   199
#elif defined(__x86_64__)
#define SYS_recvfrom     45
#define SYS_sendto       44
#define SYS_socket       41
#define SYS_shutdown     48
#define SYS_bind         49
#define SYS_listen       50
#define SYS_connect      42
#define SYS_getsockname  51
#define SYS_setsockopt   54
#define SYS_getsockopt   55
#define SYS_accept4      288
#define SYS_socketpair   53
#elif defined(__i386__)
/* i386 Linux syscall numbers, confirmed against this host's own
 * /nix/store linux-headers asm/unistd_32.h -- the "direct syscalls"
 * table (each socket op has its own number), not the legacy
 * socketcall(2) multiplexer (102) glibc itself no longer uses on a
 * modern kernel either. */
#define SYS_recvfrom     371
#define SYS_sendto       369
#define SYS_socket       359
#define SYS_bind         361
#define SYS_listen       363
#define SYS_connect      362
#define SYS_getsockname  367
#define SYS_setsockopt   366
#define SYS_getsockopt   365
#define SYS_shutdown     373
#define SYS_accept4      364
#define SYS_socketpair   360
#else
#error "plat_socket.c: unsupported architecture"
#endif

/* A minimal 6-argument raw syscall: `svc #0`/`syscall` directly, no host
 * libc in the call path. NOT `extern long syscall(long, ...)`: that
 * symbol resolves to the HOST's real glibc at link time, which sets
 * glibc's OWN errno on failure rather than handing back the raw kernel
 * -errno this file's `errno = (int)-ret` translation requires. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
/* Same "point %eax at an explicit args array" technique as
 * src/unistd/linux/plat_fd.c's own i386 raw_syscall() -- see that
 * file's banner (%ebp is both cdecl's frame-pointer register and the
 * only place left for a 6th arg). */
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

/* Matches src/unistd/linux/plat_fd.c's unbox() exactly. */
static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* The other direction, for the two calls that hand back a brand new fd
 * (socket(2), accept4(2)) rather than operating on an already-boxed one. */
static __plat_handle_t box(int fd)
{
	/* __plat_handle_t is an opaque one-word carrier shared with the NT
	 * backend; the real payload here is the plain fd number, boxed +1
	 * so 0 stays free for __PLAT_HANDLE_NULL, never dereferenced. */
	return unsafe_assume_valid_pointer((__plat_handle_t)(long)(fd + 1));
}

/* spicule's own <sys/socket.h> SOL_SOCKET/SO_REUSEADDR are a private
 * encoding that does not match the real Linux kernel ABI, so bind()'s
 * reuseaddr flag is translated explicitly, never passed through. */
#define LX_SOL_SOCKET   1
#define LX_SO_REUSEADDR 2
/* Real Linux kernel SOL_SOCKET option numbers, not spicule's own encoding. */
#define LX_SO_SNDBUF    7
#define LX_SO_RCVBUF    8

/* spicule's own <sys/socket.h> MSG_* bits are a private encoding, not a
 * copy of any host ABI. MSG_OOB/MSG_PEEK/MSG_DONTROUTE/MSG_NOSIGNAL
 * happen to already match the Linux kernel's flag bits, but
 * MSG_TRUNC/MSG_CTRUNC/MSG_EOR/MSG_WAITALL do NOT -- so every flag is
 * translated explicitly rather than passed through. */
#define LX_MSG_OOB       0x0001
#define LX_MSG_PEEK      0x0002
#define LX_MSG_DONTROUTE 0x0004
#define LX_MSG_CTRUNC    0x0008
#define LX_MSG_TRUNC     0x0020
#define LX_MSG_EOR       0x0080
#define LX_MSG_WAITALL   0x0100
#define LX_MSG_NOSIGNAL  0x4000

static int to_linux_flags(int flags)
{
	int out = 0;
	if (flags & MSG_OOB)       out |= LX_MSG_OOB;
	if (flags & MSG_PEEK)      out |= LX_MSG_PEEK;
	if (flags & MSG_DONTROUTE) out |= LX_MSG_DONTROUTE;
	if (flags & MSG_CTRUNC)    out |= LX_MSG_CTRUNC;
	if (flags & MSG_TRUNC)     out |= LX_MSG_TRUNC;
	if (flags & MSG_EOR)       out |= LX_MSG_EOR;
	if (flags & MSG_WAITALL)   out |= LX_MSG_WAITALL;
	if (flags & MSG_NOSIGNAL)  out |= LX_MSG_NOSIGNAL;
	return out;
}

/* recv(): recvfrom(2) with a NULL address -- always a connected socket
 * here, so there is no peer address to capture. */
ssize_t __plat_sock_recv(__plat_handle_t h, void *buf, size_t len, int flags)
{
	long ret = raw_syscall(SYS_recvfrom, (long)unbox(h), (long)buf, (long)len,
	                       (long)to_linux_flags(flags), 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

/* send(): sendto(2) with a NULL address, same reason __plat_sock_recv()
 * has none. The kernel raises EPIPE/SIGPIPE on its own; nothing left for
 * this backend to raise itself (contrast the NT backend). */
ssize_t __plat_sock_send(__plat_handle_t h, const void *buf, size_t len, int flags)
{
	long ret = raw_syscall(SYS_sendto, (long)unbox(h), (long)buf, (long)len,
	                       (long)to_linux_flags(flags), 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret;
}

/* socket(): a real socket(2), always AF_INET -- this project's only
 * supported wire address family. `type` picks SOCK_STREAM/IPPROTO_TCP or
 * SOCK_DGRAM/IPPROTO_UDP. */
int __plat_socket_open(__plat_handle_t *out, int type)
{
	int dgram = type == SOCK_DGRAM;
	long fd = raw_syscall(SYS_socket, (long)AF_INET,
	                      dgram ? (long)SOCK_DGRAM : (long)SOCK_STREAM,
	                      dgram ? (long)IPPROTO_UDP : (long)IPPROTO_TCP, 0L, 0L, 0L);
	if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	*out = box((int)fd);
	return 0;
}

/* bind(): SO_REUSEADDR (if requested) via a real setsockopt(2), then a
 * real bind(2) -- Linux's socket ABI has no share-mode field on bind(2)
 * itself; the option must already be set on the fd first. addr/len are
 * passed straight through, no marshaling needed. */
int __plat_socket_bind(__plat_handle_t h, int reuseaddr, const struct sockaddr *addr, socklen_t len)
{
	int fd = unbox(h);
	long ret;

	if (reuseaddr) {
		int one = 1;
		ret = raw_syscall(SYS_setsockopt, (long)fd, (long)LX_SOL_SOCKET, (long)LX_SO_REUSEADDR,
		                  (long)&one, (long)sizeof(one), 0L);
		if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	}

	ret = raw_syscall(SYS_bind, (long)fd, (long)addr, (long)len, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* connect(): a real connect(2). The front door's implicit wildcard-
 * bind-before-connect step stays in src/socket/connect.c; the socket is
 * always already bound by the time this function runs. */
int __plat_socket_connect(__plat_handle_t h, const struct sockaddr *addr, socklen_t len)
{
	long ret = raw_syscall(SYS_connect, (long)unbox(h), (long)addr, (long)len, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* listen(): a real listen(2).  `backlog` arrives here already clamped to
 * SOMAXCONN by the front door. */
int __plat_socket_listen(__plat_handle_t h, unsigned long backlog)
{
	long ret = raw_syscall(SYS_listen, (long)unbox(h), (long)backlog, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* accept(): a real accept4(2) (flags 0 -- no SOCK_NONBLOCK/SOCK_CLOEXEC
 * wiring for sockets yet). One syscall does the whole job natively,
 * unlike AFD's two-step WAIT_FOR_LISTEN + fresh endpoint + ACCEPT dance.
 * addr/len pass straight through: accept4(2) already truncates natively. */
int __plat_socket_accept(__plat_handle_t h, struct sockaddr *addr, socklen_t *len, __plat_handle_t *out)
{
	long fd = raw_syscall(SYS_accept4, (long)unbox(h), (long)addr, (long)len, 0L, 0L, 0L);
	if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	*out = box((int)fd);
	return 0;
}

/* getsockname(): a real getsockname(2). addr/len pass straight through,
 * no marshaling needed. The front door's own unbound-socket short-circuit
 * means this is only ever reached for an already-bound socket. */
int __plat_socket_getsockname(__plat_handle_t h, struct sockaddr *addr, socklen_t *len)
{
	long ret = raw_syscall(SYS_getsockname, (long)unbox(h), (long)addr, (long)len, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* shutdown(): a real shutdown(2). `how` passes straight through: Linux's
 * SHUT_RD/SHUT_WR/SHUT_RDWR are the same POSIX-standard values spicule's
 * own <sys/socket.h> already uses. */
int __plat_socket_shutdown(__plat_handle_t h, int how)
{
	long ret = raw_syscall(SYS_shutdown, (long)unbox(h), (long)how, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* getsockopt(SO_SNDBUF)/getsockopt(SO_RCVBUF): a real getsockopt(2)
 * against a real socket -- unlike the NT backend's fixed stand-in, this
 * is the kernel's actual buffer size. */
static int getbuf(__plat_handle_t h, int optname)
{
	int fd = unbox(h);
	int v = 0;
	/* unsigned, not long: getsockopt(2)'s optlen out-parameter is a kernel
	 * socklen_t (4 bytes) -- a pointer to an 8-byte long here would have
	 * the kernel write 4 bytes into what this code reads back as 8. */
	unsigned argsize = (unsigned)sizeof(v);
	long ret = raw_syscall(SYS_getsockopt, (long)fd, (long)LX_SOL_SOCKET, (long)optname,
	                       (long)&v, (long)&argsize, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return v;
}

int __plat_socket_getsndbuf(__plat_handle_t h)
{
	return getbuf(h, LX_SO_SNDBUF);
}

int __plat_socket_getrcvbuf(__plat_handle_t h)
{
	return getbuf(h, LX_SO_RCVBUF);
}

/* socketpair(): a real socketpair(2), AF_UNIX always. `type` is handed
 * straight through, SOCK_CLOEXEC bit and all: Linux's real socketpair(2)
 * has always accepted SOCK_CLOEXEC/SOCK_NONBLOCK OR'd into `type`. */
int __plat_socketpair(int type, __plat_handle_t out[2])
{
	int sv[2];
	long ret = raw_syscall(SYS_socketpair, (long)AF_UNIX, (long)type, 0L, (long)sv, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	out[0] = box(sv[0]);
	out[1] = box(sv[1]);
	return 0;
}

// NOLINTEND(misc-include-cleaner)
