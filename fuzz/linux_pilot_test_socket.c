/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux socket-backend pilot smoke test -- NOT part of spicule, same
 * standing as fuzz/linux_pilot_test.c (the mman/unistd pilot).
 *
 * Exercises the REAL spicule public entry points recv()/send()
 * (src/socket/sendrecv.c, statically linked here, unmodified) against
 * the new src/socket/linux/plat_socket.c backend, running as a real,
 * native aarch64 Linux process on this host -- no Wine, no emulation.
 *
 * spicule's own socket()/accept()/bind()/connect() front doors are out of
 * scope entirely (they call raw NT AFD `\Device\Afd` machinery directly
 * -- see src/socket/linux/plat_socket.c's own banner for why porting
 * them is a separate, larger effort). A raw socketpair(2) stands in for
 * "get me a connected pair of sockets" here, the same shape of
 * scaffolding fuzz/linux_pilot_test.c already uses (a raw openat(2)
 * standing in for open()) for the exact same reason: the thing being
 * tested is recv()/send(), not connection setup.
 *
 * Both ends of the pair are registered directly into spicule's own fd
 * table (__fds[], via __fd_alloc() from fuzz/linux_pilot_harness_socket.c)
 * with .type = __FD_SOCKET and .pad's AFD_ST_CONNECTED bit set by hand --
 * src/socket/sendrecv.c's recv()/send() front doors both refuse to even
 * attempt the call otherwise ("if (!(f->pad & AFD_ST_CONNECTED)) {
 * errno = ENOTCONN; return -1; }"), and nothing this pilot links (no
 * connect()/accept() front door) would ever set that bit on its own.
 */
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include "libc.h"
#include "afd.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

#define SYS_socketpair 199 /* aarch64; confirmed against this host's own <sys/syscall.h> */
#define SYS_close      57

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

/* Box a raw Linux fd the same way src/unistd/linux/plat_fd.c and
 * src/socket/linux/plat_socket.c both do (fd+1), and install it into
 * spicule's own fd table as an already-connected socket -- standing in
 * for what a ported connect()/accept() would normally do. */
static int install_connected_socket(long rawfd)
{
	int fd = __fd_alloc(0);
	struct __fd *f;
	if (fd < 0) return -1;
	f = &__fds[fd];
	memset(f, 0, sizeof *f);
	f->h = (HANDLE)(rawfd + 1);
	f->flags = O_RDWR;
	f->type = __FD_SOCKET;
	f->pad = AFD_ST_CONNECTED;
	return fd;
}

int main(void)
{
	/* The kernel's socketpair(2) writes its result as two adjacent
	 * `int`s (4 bytes each), not two `long`s -- getting this wrong (a
	 * `long[2]` target) packs both 4-byte fds into the first 8-byte slot
	 * and leaves the second slot untouched, silently handing back a
	 * garbled first descriptor and a bogus all-zero second one. Confirmed
	 * the hard way: an earlier `long rawpair[2]` version of this file
	 * built and linked cleanly but hung forever inside a genuine kernel
	 * recvfrom() block (real fd 4's data was sent to the wrong/garbled
	 * descriptor), caught only by actually running the binary. */
	int rawpair[2];
	long sp_ret;
	int a, b;
	const char msg1[] = "hello from spicule socket() on linux";
	const char msg2[] = "and the reply travels back the other way";
	char buf[128];

	/* AF_UNIX(1)/SOCK_STREAM(1)/protocol 0 -- a connected pair, the same
	 * shape src/socket/socketpair.c's own front door would eventually
	 * produce once socket-creation is ported; getting there via socket()/
	 * connect() is exactly the out-of-scope AFD machinery this pilot does
	 * not attempt (see file banner), so a raw syscall stands in. */
	sp_ret = syscall(SYS_socketpair, 1L /* AF_UNIX */, 1L /* SOCK_STREAM */,
	                 0L, (long)rawpair);
	if (sp_ret < 0) { printf("FAIL - raw socketpair() setup (errno=%ld)\n", -sp_ret); return 1; }
	printf("ok   - raw socketpair() setup succeeded (raw fds=%d,%d)\n", rawpair[0], rawpair[1]);

	a = install_connected_socket((long)rawpair[0]);
	CHECK(a >= 0, "__fd_alloc()/install registered raw fd A as a connected __FD_SOCKET");
	b = install_connected_socket((long)rawpair[1]);
	CHECK(b >= 0, "__fd_alloc()/install registered raw fd B as a connected __FD_SOCKET");
	if (a < 0 || b < 0) return 1;

	/* --- socket/linux/plat_socket.c: send() on A, recv() on B --- */
	{
		ssize_t n = send(a, msg1, sizeof msg1 - 1, 0);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "send() on A wrote the full buffer");

		memset(buf, 0, sizeof buf);
		n = recv(b, buf, sizeof buf, 0);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "recv() on B read the full buffer");
		CHECK(memcmp(buf, msg1, sizeof msg1 - 1) == 0, "recv() content matches what send() wrote");
	}

	/* --- the other direction: send() on B, recv() on A --- */
	{
		ssize_t n = send(b, msg2, sizeof msg2 - 1, 0);
		CHECK(n == (ssize_t)(sizeof msg2 - 1), "send() on B wrote the full buffer");

		memset(buf, 0, sizeof buf);
		n = recv(a, buf, sizeof buf, 0);
		CHECK(n == (ssize_t)(sizeof msg2 - 1), "recv() on A read the full buffer");
		CHECK(memcmp(buf, msg2, sizeof msg2 - 1) == 0, "recv() content matches what send() wrote (reverse direction)");
	}

	/* --- MSG_PEEK: leaves the data in the socket's receive queue --- */
	{
		ssize_t n;
		n = send(a, msg1, sizeof msg1 - 1, 0);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "send() on A (for MSG_PEEK check) wrote the full buffer");

		memset(buf, 0, sizeof buf);
		n = recv(b, buf, sizeof buf, MSG_PEEK);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "recv(MSG_PEEK) on B read the full buffer");
		CHECK(memcmp(buf, msg1, sizeof msg1 - 1) == 0, "recv(MSG_PEEK) content matches");

		memset(buf, 0, sizeof buf);
		n = recv(b, buf, sizeof buf, 0);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "recv() after MSG_PEEK still sees the same bytes (peek did not consume)");
		CHECK(memcmp(buf, msg1, sizeof msg1 - 1) == 0, "recv() after MSG_PEEK content matches");
	}

	/* --- descriptors this pilot never registered/connected: rejected before any syscall --- */
	{
		ssize_t n = recv(999, buf, sizeof buf, 0);
		CHECK(n == -1 && errno == EBADF, "recv() on an unregistered descriptor fails EBADF");
	}
	{
		int c = __fd_alloc(0);
		CHECK(c >= 0, "__fd_alloc() for an unconnected-socket check succeeded");
		if (c >= 0) {
			struct __fd *f = &__fds[c];
			memset(f, 0, sizeof *f);
			f->h = (HANDLE)1; /* a bogus but non-NULL handle: never actually dereferenced */
			f->flags = O_RDWR;
			f->type = __FD_SOCKET;
			f->pad = 0; /* NOT connected */
			{
				ssize_t n = send(c, msg1, sizeof msg1 - 1, 0);
				CHECK(n == -1 && errno == ENOTCONN, "send() on a not-yet-connected socket fails ENOTCONN, never reaching the backend");
			}
		}
	}

	syscall(SYS_close, rawpair[0]);
	syscall(SYS_close, rawpair[1]);

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
