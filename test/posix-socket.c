/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/socket.h>/<netinet/in.h>/<arpa/inet.h>, AF_INET/SOCK_STREAM only
 * (test/networking-audit.md, this project's own design audit for
 * sockets). Each assertion
 * cites the clause of https://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/<name>.html or .../basedefs/<header>.html it
 * checks, same convention as test/posix-sysmisc.c.
 *
 * Byte-order and address-text conversion (src/socket/inet.c) need no OS
 * support at all and are always exercised. socket()'s own domain/type/
 * protocol validation (src/socket/socket.c) happens before any AFD
 * handle is ever opened, so it too is always exercised.  SO_REUSEADDR/
 * SO_TYPE/SO_ERROR (src/socket/sockopt.c) are pure struct __fd state
 * with no AFD ioctl involved, so they are too -- as are the parts of
 * getsockname()/getpeername() (src/socket/getname.c) that are decided
 * before an ioctl is issued: the descriptor errors, getpeername()'s
 * [ENOTCONN], and getsockname()'s unbound case, which POSIX makes a
 * success and which this implementation therefore answers without
 * asking AFD at all.  Their reply parsing has its own device-free test,
 * test/posix-socket-getname.c; what needs a live AFD here is only the
 * addresses themselves.
 *
 * Everything past socket() succeeding needs a real \Device\Afd
 * endpoint that actually answers AFD ioctls, and that is exactly the
 * part this project's own design audit (networking-audit.md sec 1)
 * flagged as unverifiable against Wine ahead of time: "the only place
 * spicule can test against is Wine, and Wine's AFD is provably not a
 * faithful clone of real Windows' AFD for at least socket creation and
 * connect."  Empirically, in this environment: opening a handle via
 * NtCreateFile+the AfdOpenPacketXX EA against \Device\Afd\Endpoint
 * (src/socket/afdsupport.c's __afd_open(); the EA recipe follows
 * ReactOS's WSPSocket, but the EA *value* is the real-Windows 24-byte
 * AFD_OPEN_PACKET, not ReactOS's 12-byte AFD_CREATE_PACKET -- see
 * src/internal/afd.h's socket-creation banner, and
 * test/posix-socket-ea.c, which asserts that buffer's layout with no
 * device involved) *succeeds* under this environment's Wine -- Wine's server
 * accepts the open -- but the very first real ioctl against that
 * handle, IOCTL_AFD_BIND, fails with STATUS_BAD_DEVICE_TYPE
 * (0xC00000CB): Wine's own AFD implementation only wires up a handle
 * opened via its own invented IOCTL_AFD_WINE_CREATE (networking-audit.md
 * sec 1); a handle opened the portable, real-Windows way is never
 * routed to that implementation, so every ioctl on it after the open
 * itself hits Wine's dispatcher with nothing behind the handle.  This
 * was confirmed by hand against both stock upstream Wine (what CI's
 * build-toolchain job produces) and this project's own locally patched
 * Wine build (~/Projects/wine, the RtlCloneUserProcess/exited-PID
 * patches noted in CONTRIBUTING.md) -- neither carries an AFD patch, so
 * both fail identically here.  This is precisely the situation
 * CONTRIBUTING.md's task anticipated ("If Wine turns out not to accept
 * the portable form, report that precisely -- it is a Wine limitation
 * worth a separate fix, not a reason to depend on Wine's private
 * control code") and precisely why the code follows ReactOS, not Wine:
 * this project's CI has a real-Windows leg that a Wine-shaped
 * implementation would silently not work on there.
 *
 * So, following configure's own precedent for an environment gap
 * (delayall.c/DELAY_ALL, documented in configure and Makefile): a
 * runtime capability probe, socket()+bind()+listen() against a fixed
 * loopback port, gates every assertion downstream of "AFD ioctls
 * actually work."  If the probe fails, this prints one SKIP line
 * naming the mechanism and observed errno and returns exit code 77
 * (a distinct "ran, but verified nothing new" outcome, not a plain
 * pass and not a FAIL either) rather than either silently skipping or
 * failing the whole suite.  tools/run-tests.py recognizes 77 and reports
 * it as its own bucket in the run summary, separate from both PASS and
 * FAIL -- the same shape asan-build.sh already uses for its "N not
 * applicable natively" bucket, just decided at run time here instead of
 * build time (this environment's Wine, unlike a native asan build,
 * *looks* capable right up until the first real ioctl).  A silent
 * `return 0` here would report PASS for a feature nothing was actually
 * checked to work, on every platform, indefinitely -- the failure mode
 * this file exists to avoid.  On real Windows (untestable here, reasoned
 * about only) the probe is expected to succeed, since the whole point of
 * following ReactOS instead of Wine was to match what real Windows' AFD
 * actually expects; there, this test exits 0 with every assertion having
 * actually run.
 */
#include "test-policy.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>

static int fails;
/* Counts each SKIP line below: an assertion group this run did not
 * actually exercise (network stack unavailable here), as opposed to
 * `fails`, which counts assertions that ran and got the wrong answer.
 * See main()'s tail for why these are reported, and exit, differently. */
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* htonl.html: "convert values between host and network byte order";
 * spicule only targets little-endian arches (arch/i386, arch/x86_64,
 * per src/socket/inet.c's banner), so network byte order (big-endian)
 * and host byte order always differ here. */
static void test_byteorder(void)
{
	CHECK(htons(0x1234) == 0x3412);
	CHECK(ntohs(0x3412) == 0x1234);
	CHECK(htonl(0x12345678UL) == 0x78563412UL);
	CHECK(ntohl(0x78563412UL) == 0x12345678UL);
	CHECK(htons(0) == 0);
	CHECK(htonl(0) == 0);
	/* htons()/ntohs() and htonl()/ntohl() are each other's inverse. */
	CHECK(ntohs(htons(0xbeef)) == 0xbeef);
	CHECK(ntohl(htonl(0xdeadbeefUL)) == 0xdeadbeefUL);
}

/* inet_addr.html: dotted forms "a.b.c.d"/"a.b.c"/"a.b"/"a", decimal
 * parts; "(in_addr_t)(-1)" on failure. */
static void test_inet_addr(void)
{
	struct in_addr expect;
	expect.s_addr = htonl(0x01020304UL);
	CHECK(inet_addr("1.2.3.4") == expect.s_addr);
	CHECK(inet_addr("127.0.0.1") == htonl(INADDR_LOOPBACK));
	CHECK(inet_addr("0.0.0.0") == INADDR_ANY);
	CHECK(inet_addr("not-an-address") == INADDR_NONE);
	CHECK(inet_addr("") == INADDR_NONE);
	CHECK(inet_addr("1.2.3.4.5") == INADDR_NONE); /* too many parts */
	CHECK(inet_addr(0) == INADDR_NONE);
	/* inet_addr.html's 1-part and 2-part short forms. */
	CHECK(inet_addr("16909060") == htonl(16909060UL)); /* "a" form: whole 32 bits */
	CHECK(inet_addr("1.258") == htonl(0x01000102UL));   /* "a.b": b is 24 bits -- 258 = 0x000102 */
}

/* inet_ntop.html/inet_pton.html: AF_INET and the pure-C AF_INET6 text
 * conversions; round trip, ENOSPC and malformed-input 0 return. */
static void test_inet_pton_ntop(void)
{
	struct in_addr a;
	struct in6_addr a6;
	char buf[INET6_ADDRSTRLEN];
	char tiny[4];

	CHECK(inet_pton(AF_INET, "127.0.0.1", &a) == 1);
	CHECK(a.s_addr == htonl(INADDR_LOOPBACK));
	CHECK(inet_pton(AF_INET, "255.255.255.255", &a) == 1);
	CHECK(a.s_addr == htonl(INADDR_BROADCAST));
	CHECK(inet_pton(AF_INET, "1.2.3", &a) == 0);       /* inet_pton, unlike inet_addr, wants all four parts */
	CHECK(inet_pton(AF_INET, "1.2.3.4.5", &a) == 0);
	CHECK(inet_pton(AF_INET, "256.0.0.1", &a) == 0);   /* out of range octet */
	CHECK(inet_pton(AF_INET, "", &a) == 0);
	/* inet_ntop.html's DESCRIPTION gives inet_pton() the strict form
	 * "ddd.ddd.ddd.ddd where 'ddd' is a one to three digit decimal
	 * number between 0 and 255", and then says in the same paragraph
	 * that inet_pton() "does not accept other formats (such as the
	 * octal numbers, hexadecimal numbers, and fewer than four numbers
	 * that inet_addr() accepts)".  "077" is precisely a string
	 * inet_addr() reads as octal, so reading it here as decimal 77
	 * would make one spelling mean two different addresses through
	 * two functions of the same library -- the confusion that
	 * sentence exists to forbid. */
	CHECK(inet_pton(AF_INET, "0.0.0.00", &a) == 0);
	CHECK(inet_pton(AF_INET, "7.077.0.7", &a) == 0);
	CHECK(inet_pton(AF_INET, "01.2.3.4", &a) == 0);
	/* ...but a lone "0" is a one-digit decimal number, not a leading
	 * zero, and stays legal in every position. */
	CHECK(inet_pton(AF_INET, "0.0.0.0", &a) == 1);
	CHECK(a.s_addr == INADDR_ANY);
	CHECK(inet_pton(AF_INET, "10.0.0.1", &a) == 1);
	CHECK(a.s_addr == htonl(0x0a000001UL));
	CHECK(inet_pton(AF_INET6, "::1", &a6) == 1);
	CHECK(inet_ntop(AF_INET6, &a6, buf, sizeof buf) == buf);
	CHECK(!strcmp(buf, "::1"));

	/* fuzz: issue #5 (fuzz_inet, CI runs 33122015293 and 33126258867,
	 * 2026-08-27), input byte 0x88.  At the commit those runs fuzzed
	 * (8b2af2c), AF_INET6 was not yet implemented and fuzz_inet.c's own
	 * harness still asserted inet_pton(AF_INET6, ...) must fail with
	 * -1/EAFNOSUPPORT for every input; spicule's pre-IPv6 inet_pton()
	 * did not, so the harness's own oracle called abort() (see
	 * test/posix-inet.c's test_inet6_text_forms fence, "THE FORMER
	 * FAILURE").  00d1af9/888a4d1/56f7fae/06e51e1 (later the same day)
	 * implemented real AF_INET6 support, which is what test_inet6_text_
	 * forms above documents and this file's own two lines just above
	 * already exercise -- the assertion the crash tripped no longer
	 * applies to a family this library actually supports.  0x88 is
	 * simply not a hex digit, ':' or '.', so kept here unconditionally
	 * as the regression this issue asked for: a single non-hex,
	 * non-separator byte is refused like any other malformed text (0,
	 * not a crash), and errno.html's "no function ... shall set errno
	 * to 0" holds on the way past. */
	errno = EDOM;
	CHECK(inet_pton(AF_INET6, "\x88", &a6) == 0);
	CHECK(errno == EDOM);

	a.s_addr = htonl(0x01020304UL);
	CHECK(inet_ntop(AF_INET, &a, buf, sizeof buf) == buf);
	CHECK(!strcmp(buf, "1.2.3.4"));

	errno = 0;
	CHECK(inet_ntop(AF_INET, &a, tiny, sizeof tiny) == 0); /* "1.2.3.4" is 7 chars + NUL, tiny holds 4 */
	CHECK(errno == ENOSPC);

	CHECK(!strcmp(inet_ntoa(a), "1.2.3.4")); /* inet_addr.html: inet_ntoa()'s static buffer */
}

/* socket.html mandatory ERRORS: EAFNOSUPPORT/EPROTOTYPE/EPROTONOSUPPORT
 * are all decided before any AFD handle is opened
 * (src/socket/socket.c), so these need no working network stack. */
static void test_socket_domain_errors(void)
{
	errno = 0;
	CHECK(socket(AF_INET6, SOCK_STREAM, 0) == -1);
	CHECK(errno == EAFNOSUPPORT);

	/* SOCK_RAW/SOCK_SEQPACKET remain wholly unimplemented (<sys/socket.h>'s
	 * banner) -- SOCK_DGRAM itself moved off this list (2026-09-01),
	 * see test_socket_dgram()/test_socketpair_dgram() below for its
	 * positive-path coverage. */
	errno = 0;
	CHECK(socket(AF_INET, SOCK_RAW, 0) == -1);
	CHECK(errno == EPROTOTYPE);

	errno = 0;
	CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == -1);
	CHECK(errno == EPROTONOSUPPORT);

	/* AF_UNIX/SOCK_STREAM: the family is real (SOCK_DGRAM on it is,
	 * see below) and the type is real (AF_INET has it too), but this
	 * exact pair is not one this project's socket() front door creates
	 * -- only socketpair()'s own internal loopback-TCP construction
	 * uses it, never reached through socket() itself (src/socket/
	 * socket.c's banner). */
	errno = 0;
	CHECK(socket(AF_UNIX, SOCK_STREAM, 0) == -1);
	CHECK(errno == EPROTONOSUPPORT);

	errno = 0;
	CHECK(socket(AF_UNIX, SOCK_DGRAM, 47) == -1);
	CHECK(errno == EPROTONOSUPPORT);
}

/* SOCK_DGRAM positive path (2026-09-01): AF_INET/SOCK_DGRAM (UDP) and
 * anonymous AF_UNIX/SOCK_DGRAM both create a real, usable descriptor --
 * see <sys/socket.h>'s banner and src/socket/socket.c for why the
 * AF_UNIX one is, underneath, the exact same kind of endpoint. */
static void test_socket_dgram(void)
{
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(fd >= 0);
	if (fd >= 0) {
		int v = -1;
		socklen_t vlen = sizeof v;
		CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &vlen) == 0);
		CHECK(v == SOCK_DGRAM);
		(void)close(fd);
	}

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(fd >= 0);
	if (fd >= 0) (void)close(fd);
}

/* setsockopt.html/<sys/socket.h>: SO_REUSEADDR/SO_TYPE/SO_ERROR are the
 * options src/socket/sockopt.c genuinely supports, and none of them
 * touch AFD (SO_REUSEADDR is only consumed by a later bind()), so this
 * needs no working AFD ioctl -- but socket() itself still opens a real
 * \Device\Afd\Endpoint handle (src/socket/afdsupport.c's __afd_open()),
 * which this project's `make asan` native-build stub environment
 * (fuzz/ntstubs.c's in-memory simulated volume, which has no such
 * device node at all) fails outright rather than merely refusing an
 * ioctl on -- so this, unlike the rest of this function, tolerates
 * socket() itself failing, the same environment-gap shape as
 * network_probe() below rather than a hard requirement. */
static void test_sockopt_no_network(void)
{
	int s, v;
	socklen_t vl;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		printf("SKIP posix-socket sockopt tests (socket() failed, errno=%d)\n", errno);
		unverified++;
		return;
	}

	v = 0; vl = sizeof(v);
	CHECK(getsockopt(s, SOL_SOCKET, SO_TYPE, &v, &vl) == 0);
	CHECK(v == SOCK_STREAM);

	v = 0; vl = sizeof(v);
	CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &vl) == 0);
	CHECK(v == 0);

	v = 0; vl = sizeof(v);
	CHECK(getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, &vl) == 0);
	CHECK(v == 0); /* setsockopt.html: not set yet */

	v = 1;
	CHECK(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v) == 0);
	v = 0; vl = sizeof(v);
	CHECK(getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, &vl) == 0);
	CHECK(v == 1);

	errno = 0;
	CHECK(setsockopt(s, SOL_SOCKET, SO_LINGER, &v, sizeof v) == -1); /* not among the genuinely-supported options */
	CHECK(errno == ENOPROTOOPT);

	errno = 0;
	CHECK(getsockopt(0, SOL_SOCKET, SO_TYPE, &v, &vl) == -1); /* fd 0 is not a socket */
	CHECK(errno == ENOTSOCK);

	close(s);
}

/* getsockname.html/getpeername.html, everything on those two pages that
 * can be decided without an AFD ioctl -- which, in this environment, is
 * the only part of either function that can be observed working at all.
 * Grouped with the no-network tests above and gated the same way, for
 * the same reason: socket() itself needs a device node that `make asan`'s
 * stub environment does not have.
 *
 * All four cases here are answered by src/socket/getname.c before it
 * reaches an ioctl, and each is answered there on purpose:
 *
 *   - [EBADF]/[ENOTSOCK] are the descriptor checks every other call in
 *     <sys/socket.h> makes.
 *   - getsockname() on a socket that was never bound is a SUCCESS, not
 *     an error: "If the socket has not been bound to a local name, the
 *     value stored in the object pointed to by address is unspecified"
 *     (getsockname.html DESCRIPTION).  afd.sys would fail that endpoint
 *     (STATUS_INVALID_PARAMETER, no address file and no connection), so
 *     the ioctl is not issued -- the wildcard is returned instead.  The
 *     assertion is on what POSIX guarantees (a success, and the family)
 *     plus the wildcard this implementation documents itself as
 *     returning, not on the "unspecified" value as if it were required.
 *   - getpeername() [ENOTCONN] is the behavioural half of the same
 *     coin: an unconnected socket must SAY it is unconnected, not
 *     succeed with a zeroed address.  That distinction is the one thing
 *     in this pair a caller can actually be broken by, and it is the
 *     one thing Wine can still check here. */
static void test_getname_no_network(void)
{
	struct sockaddr_in a;
	socklen_t l;
	int s;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		printf("SKIP posix-socket getsockname/getpeername tests (socket() failed, errno=%d)\n", errno);
		unverified++;
		return;
	}

	/* getsockname.html/getpeername.html: "[EBADF] The socket argument
	 * is not a valid file descriptor." */
	l = sizeof a;
	errno = 0;
	CHECK(getsockname(-1, (struct sockaddr *)&a, &l) == -1);
	CHECK(errno == EBADF);
	l = sizeof a;
	errno = 0;
	CHECK(getpeername(-1, (struct sockaddr *)&a, &l) == -1);
	CHECK(errno == EBADF);

	/* "[ENOTSOCK] The socket argument does not refer to a socket." */
	l = sizeof a;
	errno = 0;
	CHECK(getsockname(0, (struct sockaddr *)&a, &l) == -1); /* fd 0 is not a socket */
	CHECK(errno == ENOTSOCK);
	l = sizeof a;
	errno = 0;
	CHECK(getpeername(0, (struct sockaddr *)&a, &l) == -1);
	CHECK(errno == ENOTSOCK);

	/* A null out-parameter: neither page specifies it (unlike
	 * accept.html, which explicitly permits a null address), and
	 * [EINVAL] is the only invalid-argument code either page's ERRORS
	 * list carries -- see src/socket/getname.c's banner. */
	l = sizeof a;
	errno = 0;
	CHECK(getsockname(s, 0, &l) == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(getsockname(s, (struct sockaddr *)&a, 0) == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(getpeername(s, 0, &l) == -1);
	CHECK(errno == EINVAL);

	/* getsockname.html: an unbound socket is a success with an
	 * unspecified value.  This implementation's unspecified value is
	 * the wildcard, and the truncation contract holds on that path
	 * too: *address_len is the address's full length. */
	memset(&a, 0xCC, sizeof a);
	l = sizeof a;
	errno = 0;
	CHECK(getsockname(s, (struct sockaddr *)&a, &l) == 0);
	CHECK(a.sin_family == AF_INET);
	CHECK(l == sizeof a);
	CHECK(a.sin_port == 0);
	CHECK(a.sin_addr.s_addr == htonl(INADDR_ANY));

	/* getpeername.html: "[ENOTCONN] The socket is not connected or
	 * otherwise has not had the peer pre-specified."  Not a zeroed
	 * address returned successfully. */
	memset(&a, 0xCC, sizeof a);
	l = sizeof a;
	errno = 0;
	CHECK(getpeername(s, (struct sockaddr *)&a, &l) == -1);
	CHECK(errno == ENOTCONN);
	CHECK(a.sin_family == 0xCCCC); /* and the caller's buffer is untouched */

	close(s);
}

/* Fixed loopback port used both by the capability probe and the main
 * end-to-end test below, in the dynamic/private range (RFC 6335).
 *
 * This used to be a workaround: getsockname() was out of scope, so
 * there was no way to ask AFD which ephemeral port an INADDR_ANY/port-0
 * bind() had landed on.  getsockname() now exists (src/socket/
 * getname.c) and the workaround could be retired -- deliberately not
 * done here.  Binding port 0 and querying it back would make the
 * listener's port depend on a call that, in this environment, cannot be
 * observed working at all (every AFD ioctl fails under Wine, so the
 * whole group SKIPs), which means the change could only be validated on
 * the real-Windows leg, and its only benefit -- not colliding with
 * another process on 55123 -- is a benefit on the leg where nothing
 * else is running.  The fixed port stays until getsockname() has been
 * seen to work somewhere. */
#define TEST_PORT 55123

static int make_loopback_addr(struct sockaddr_in *a)
{
	memset(a, 0, sizeof *a);
	a->sin_family = AF_INET;
	a->sin_port = htons(TEST_PORT);
	a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return sizeof *a;
}

/* The runtime capability probe -- see the file banner.  Returns a bound
 * and listening socket fd, or -1 if AFD ioctls do not work here (after
 * printing the one SKIP line). */
static int network_probe(void)
{
	struct sockaddr_in addr;
	int s;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		printf("SKIP posix-socket network tests (socket() failed, errno=%d)\n", errno);
		unverified++;
		return -1;
	}
	if (bind(s, (struct sockaddr *)&addr, make_loopback_addr(&addr)) < 0) {
		/* Report the call and its errno and stop there.  This message
		 * used to blame Wine's AFD, which was true of the environment
		 * it was written in.  It is also wrong to say the same line
		 * prints on the real-Windows CI legs: measured 2026-08-24 on
		 * the windows-test (x86_64) job, this file prints
		 * "posix-socket: all ok" and exits 0 there -- exit 0 means the
		 * unverified counter is zero, so bind() and everything after
		 * it DID run.  The SKIP path below is reached under Wine only.
		 * That matters for reading a green run: the network group is
		 * verified, but on exactly one leg, so a red or absent
		 * windows-test leg takes all of it with it.  A
		 * failing bind() cannot tell the two apart from here: the
		 * ioctl either was not understood or was understood and the
		 * address rejected, and only the errno distinguishes them.
		 * test/posix-socket-bind.c checks the request's byte layout
		 * with no device at all, which is the part this cannot. */
		printf("SKIP posix-socket network tests (bind() failed, errno=%d; "
		       "IOCTL_AFD_BIND on a \\Device\\Afd\\Endpoint handle -- "
		       "see test/posix-socket-bind.c and test/networking-audit.md sec 1)\n",
		       errno);
		close(s);
		unverified++;
		return -1;
	}
	if (listen(s, 1) < 0) {
		printf("SKIP posix-socket network tests (listen() failed, errno=%d)\n", errno);
		close(s);
		unverified++;
		return -1;
	}
	return s;
}

/* The core case: a loopback connection between a listening socket and
 * a client in the same process (single-threaded and sequential is
 * enough -- connect.html's stream-socket handshake completes and
 * returns once the peer's listen() backlog can hold it, without
 * needing accept() to have run yet, so connect() before accept() here
 * is not a race). */
static void test_loopback_roundtrip(int listener)
{
	struct sockaddr_in addr, peer;
	socklen_t peerlen;
	int client, accepted;
	char buf[32];
	ssize_t n;

	client = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(client >= 0);
	if (client < 0) return;

	/* connect.html: "the initiating socket is not bound, it will be
	 * bound" -- exercised implicitly here since `client` never called
	 * bind() itself. */
	CHECK(connect(client, (struct sockaddr *)&addr, make_loopback_addr(&addr)) == 0);

	errno = 0;
	CHECK(connect(client, (struct sockaddr *)&addr, sizeof addr) == -1); /* connect.html: EISCONN */
	CHECK(errno == EISCONN);

	peerlen = sizeof peer;
	accepted = accept(listener, (struct sockaddr *)&peer, &peerlen);
	CHECK(accepted >= 0);
	if (accepted < 0) { close(client); return; }
	/* accept.html: the returned address is the peer's -- loopback,
	 * same port range this test bound the client to (an ephemeral
	 * port AFD chose, since `client` was never bind()'d itself). */
	CHECK(peer.sin_family == AF_INET);
	CHECK(peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

	/* getsockname.html/getpeername.html, the halves that need a live
	 * AFD and so run on the real-Windows leg only.  Three sockets are
	 * in hand here and each pins something different:
	 *
	 *   - `listener` is bound to TEST_PORT and never connected, so its
	 *     local name is the address bind() was given.  That is the one
	 *     assertion that ties getsockname()'s answer to a value this
	 *     test chose rather than to one the stack chose.
	 *   - `client` was never bind()'d: connect() bound it to an
	 *     ephemeral port (connect.html, and src/socket/connect.c's
	 *     wildcard bind).  Its local port is therefore whatever AFD
	 *     picked -- unknowable, but necessarily non-zero once bound,
	 *     and necessarily the port the listener saw the connection
	 *     come from, which accept() already reported in `peer`.  That
	 *     cross-check is the strongest available statement that
	 *     getsockname() returned this socket's address and not some
	 *     other endpoint's.
	 *   - `client`'s peer is the listener's address, and `accepted`'s
	 *     peer is the client's -- the two are each other's mirror, so
	 *     a getpeername() reading the wrong reply offset (see
	 *     test/posix-socket-getname.c) cannot satisfy both.
	 */
	{
		struct sockaddr_in ln, cn, cp, ap;
		socklen_t l;

		l = sizeof ln;
		CHECK(getsockname(listener, (struct sockaddr *)&ln, &l) == 0);
		CHECK(l == sizeof ln); /* the full length, not the stored count */
		CHECK(ln.sin_family == AF_INET);
		CHECK(ln.sin_port == htons(TEST_PORT));
		CHECK(ln.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

		l = sizeof cn;
		CHECK(getsockname(client, (struct sockaddr *)&cn, &l) == 0);
		CHECK(cn.sin_family == AF_INET);
		CHECK(cn.sin_port != 0); /* connect() bound it to something */
		CHECK(cn.sin_port == peer.sin_port); /* the port accept() saw */
		CHECK(cn.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

		l = sizeof cp;
		CHECK(getpeername(client, (struct sockaddr *)&cp, &l) == 0);
		CHECK(l == sizeof cp);
		CHECK(cp.sin_family == AF_INET);
		CHECK(cp.sin_port == htons(TEST_PORT));
		CHECK(cp.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

		l = sizeof ap;
		CHECK(getpeername(accepted, (struct sockaddr *)&ap, &l) == 0);
		CHECK(ap.sin_family == AF_INET);
		CHECK(ap.sin_port == cn.sin_port); /* the mirror of getsockname(client) */
		CHECK(ap.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

		/* The truncation clause, on a live address rather than on a
		 * fixture: "the stored address shall be truncated", and
		 * address_len still reports the untruncated length. */
		{
			unsigned char small[sizeof(struct sockaddr_in) + 8];
			memset(small, 0xCC, sizeof small);
			l = 4;
			CHECK(getpeername(client, (struct sockaddr *)small, &l) == 0);
			CHECK(l == sizeof(struct sockaddr_in));
			CHECK(small[4] == 0xCC); /* nothing past the supplied length */
			CHECK(!memcmp(small, &cp, 4)); /* and what fit is the real address */
		}
	}

	/* send.html/recv.html: a normal round trip each direction, plus
	 * read()/write() (src/unistd/read.c, write.c) going through the
	 * exact same __FD_SOCKET path. */
	CHECK(send(client, "ping", 4, 0) == 4);
	memset(buf, 0, sizeof buf);
	n = recv(accepted, buf, sizeof buf, 0);
	CHECK(n == 4);
	CHECK(!memcmp(buf, "ping", 4));

	CHECK(write(accepted, "pong!", 5) == 5);
	memset(buf, 0, sizeof buf);
	n = read(client, buf, sizeof buf);
	CHECK(n == 5);
	CHECK(!memcmp(buf, "pong!", 5));

	/* shutdown.html SHUT_WR: further sends on `client` fail, and the
	 * peer sees end-of-stream (recv.html: "0...the peer has performed
	 * an orderly shutdown"). */
	CHECK(shutdown(client, SHUT_WR) == 0);
	{
		signal(SIGPIPE, SIG_IGN); /* send.html: SIGPIPE unless MSG_NOSIGNAL; either way, no crash */
		errno = 0;
		CHECK(send(client, "x", 1, MSG_NOSIGNAL) == -1);
		CHECK(errno == EPIPE);
	}
	n = recv(accepted, buf, sizeof buf, 0);
	CHECK(n == 0);

	close(client);
	close(accepted);
}

static void test_socketpair_stream(void)
{
	int pair[2];
	int result;
	char buffer[8];

	result = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
	CHECK(result == 0);
	if (result < 0) return;
	CHECK(write(pair[0], "local", 5) == 5);
	memset(buffer, 0, sizeof buffer);
	CHECK(read(pair[1], buffer, sizeof buffer) == 5);
	CHECK(!memcmp(buffer, "local", 5));
	CHECK(write(pair[1], "pair", 4) == 4);
	memset(buffer, 0, sizeof buffer);
	CHECK(read(pair[0], buffer, sizeof buffer) == 4);
	CHECK(!memcmp(buffer, "pair", 4));
	CHECK(close(pair[0]) == 0);
	CHECK(close(pair[1]) == 0);
}

/* SOCK_DGRAM (2026-09-01): a connected datagram pair round-trips
 * send()/recv() and read()/write() (the latter via src/unistd/read.c's
 * and write.c's own __FD_SOCKET dispatch to recv()/send(), the same
 * path test_socketpair_stream() above already exercises) exactly like
 * a stream pair does, plus listen()/accept() correctly refusing to
 * apply to one -- src/socket/listen.c's EOPNOTSUPP and
 * src/socket/accept.c's EINVAL (never having been marked listening),
 * both against a real, connected datagram socket rather than only the
 * domain/type checks test_socket_domain_errors() covers. */
static void test_socketpair_dgram(void)
{
	int pair[2];
	int result;
	char buffer[8];

	result = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);
	CHECK(result == 0);
	if (result < 0) return;

	errno = 0;
	CHECK(listen(pair[0], 1) == -1);
	CHECK(errno == EOPNOTSUPP);
	errno = 0;
	CHECK(accept(pair[0], 0, 0) == -1);
	CHECK(errno == EINVAL);

	CHECK(send(pair[0], "dgram", 5, 0) == 5);
	memset(buffer, 0, sizeof buffer);
	CHECK(recv(pair[1], buffer, sizeof buffer, 0) == 5);
	CHECK(!memcmp(buffer, "dgram", 5));

	CHECK(write(pair[1], "back", 4) == 4);
	memset(buffer, 0, sizeof buffer);
	CHECK(read(pair[0], buffer, sizeof buffer) == 4);
	CHECK(!memcmp(buffer, "back", 4));

	CHECK(close(pair[0]) == 0);
	CHECK(close(pair[1]) == 0);
}

/* accept.html: EINVAL for a socket that was never listen()'d;
 * bind.html: EINVAL for a second bind() on an already-bound socket;
 * ENOTSOCK for every socket call given a non-socket fd -- all pure
 * struct __fd state, but grouped with the network-gated tests since
 * the first two need a real listener/bound socket to check against. */
static void test_socket_state_errors(int listener)
{
	struct sockaddr_in addr;
	int s;

	s = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(s >= 0);
	errno = 0;
	CHECK(accept(s, 0, 0) == -1); /* never listen()'d */
	CHECK(errno == EINVAL);

	errno = 0;
	CHECK(bind(listener, (struct sockaddr *)&addr, make_loopback_addr(&addr)) == -1); /* already bound */
	CHECK(errno == EINVAL);

	errno = 0;
	CHECK(bind(0, (struct sockaddr *)&addr, sizeof addr) == -1); /* fd 0 is not a socket */
	CHECK(errno == ENOTSOCK);

	close(s);
}

int main(void)
{
	int listener;

	test_byteorder();
	test_inet_addr();
	test_inet_pton_ntop();
	test_socket_domain_errors();
	test_sockopt_no_network();
	test_getname_no_network();

	listener = network_probe();
	if (listener >= 0) {
		test_socket_state_errors(listener);
		test_loopback_roundtrip(listener);
		test_socketpair_stream();
		close(listener);
	}

	/* SOCK_DGRAM (2026-09-01): AF_INET/SOCK_DGRAM (UDP) and anonymous
	 * AF_UNIX/SOCK_DGRAM are both implemented now -- see <sys/socket.h>'s
	 * banner, src/socket/socket.c and src/socket/socketpair.c.
	 * test_socket_dgram() above needs no network probe (socket()
	 * creation alone, like test_socket_domain_errors()); the
	 * socketpair()/send()/recv() round trip below does the same real
	 * work test_socketpair_stream() does for SOCK_STREAM, so it is
	 * gated behind the same network_probe() this file already uses for
	 * every other test that opens a real endpoint.  sendmsg()/
	 * recvmsg()'s ancillary data, general pathname AF_UNIX (struct
	 * sockaddr_un) and sockatmark() remain staged for later work, per
	 * test/networking-audit.md sec 6 -- not merely untested, genuinely
	 * not implemented, and (per this project's own standing rule,
	 * test/posix-sysmisc.c's file banner) not even declared in
	 * <sys/socket.h> (see that header's own banner), so none of that can
	 * even be written outside an #if 0 fence. */
	test_socket_dgram();
	if (listener >= 0) test_socketpair_dgram();

#if SPICULE_TEST(PASS, posix_socket_send_recv_and_socketpair_interfaces) /* sys_socket.h.html's sendto()/recvfrom(): on a connected
	socket -- stream or, since 2026-09-01, datagram -- both reduce to
	send()/recv() plus the fixed peer address the connection already
	carries (sendto.html: "If the socket is connected, the dest_addr
	argument shall be ignored"; recvfrom.html's address is that same
	peer coming back the other way) -- src/socket/sendrecv.c
	implements exactly that reduction.  sendmsg()/recvmsg() (ancillary
	data) and a real per-datagram destination on an unconnected socket
	remain out of scope -- see the comment above this case. */
	{
		int sv[2];
		char b[4];
		socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
		sendto(sv[0], "ping", 4, 0, 0, 0);
		recvfrom(sv[1], b, sizeof b, 0, 0, 0);
	}
#endif
#if SPICULE_TEST(PASS, posix_socket_ipv6_address_types) /* netinet_in.h.html's struct sockaddr_in6, the IN6_IS_ADDR_
	address-predicate macros, IN6ADDR_..._INIT, in6addr_any and
	in6addr_loopback are now declared and
	src/socket/inet.c.  This is a type and some byte-test macros/
	constants, not an AF_INET6 transport -- socket(AF_INET6, ...)
	still and correctly fails EAFNOSUPPORT (src/socket/socket.c),
	exactly like the AF_INET6 macro itself already did before this
	struct existed.  Nothing here needed networking-audit.md sec 6's
	staged AFD work: a struct definition and pure byte-comparison
	macros carry no undefined symbol for this project's "declared-
	but-undefined is a link-error bug" rule to apply to. */
	{
		struct sockaddr_in6 a6;
		a6.sin6_family = AF_INET6;
	}
#endif

	if (fails) { printf("posix-socket: failures: %d\n", fails); return 1; }
	if (unverified) {
		/* Everything that ran passed, but that is not the same claim as
		 * "all ok" -- see the file banner and the SKIP line(s) above for
		 * which assertion groups never ran at all. Exit 77 rather than 0
		 * so tools/run-tests.py reports this run in its own bucket instead
		 * of silently counting it as a pass.
		 *
		 * `unverified` only ever comes from test_sockopt_no_network(),
		 * test_getname_no_network() and network_probe() above -- all
		 * unconditional and unrelated to the two SPICULE_TEST-fenced cases
		 * in this file.  A tools/test-policy.py probe recompiles this
		 * whole file to validate ONE fenced case in isolation, and those
		 * unconditional checks still run alongside it; without this
		 * guard, a missing network stack here (see the file banner) would
		 * report the OTHER fenced case's probe UNRESOLVED too, regardless
		 * of that case's own result. */
		printf("posix-socket: %d assertion group(s) unverified in this "
		       "environment (see SKIP lines above); no failures in what "
		       "did run\n", unverified);
		if (!SPICULE_TEST_POLICY_PROBE) return 77;
	}
	printf("posix-socket: all ok\n");
	return 0;
}
