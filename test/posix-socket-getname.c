/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Structural invariants of the two AFD name-query replies recorded in
 * src/internal/afd.h:
 * IOCTL_AFD_GET_SOCK_NAME's and IOCTL_AFD_GET_PEER_NAME's, as read back
 * by src/socket/afdsupport.c's __afd_sockname_reply_addr() and
 * __afd_peername_reply_addr().  Production getpeername() deliberately
 * uses connect()/accept()'s cached peer instead; keeping this wire parser
 * tested prevents the reverse-engineered layout from silently rotting.
 *
 * The exact sibling of test/posix-socket-bind.c and
 * test/posix-socket-accept.c, for the same reason and by the same
 * method: it opens no socket and touches no device, so it runs
 * identically on a host with no \Device\Afd, under Wine (whose AFD
 * rejects this project's endpoint handles outright with
 * STATUS_BAD_DEVICE_TYPE and can therefore never exercise either
 * ioctl), under `make asan` natively, and on CI's real-Windows legs.
 * test/posix-socket.c can only SKIP the live calls.
 *
 * THE DEFECT THIS IS THE REGRESSION ASSERTION FOR: the two replies are
 * not the same shape, and reading one with the other's offset does not
 * fail loudly -- it produces a plausible address four bytes out of
 * place.
 *
 *   - IOCTL_AFD_GET_SOCK_NAME answers with a TDI_ADDRESS_INFO: a ULONG
 *     ActivityCount and *then* the TRANSPORT_ADDRESS, 26 bytes for one
 *     AF_INET address.  afd.sys does not answer it itself; it forwards
 *     the caller's buffer to the transport as a TDI
 *     TDI_QUERY_INFORMATION/TDI_QUERY_ADDRESS_INFO (ReactOS
 *     drivers/network/afd/afd/info.c, AfdGetSockName()), and
 *     TDI_ADDRESS_INFO is what that query returns.  ReactOS's client
 *     agrees: WSPGetSockName (dll/win32/msafd/misc/dllmain.c) declares
 *     its buffer PTDI_ADDRESS_INFO and reads the address out of
 *     `&TdiAddress->Address`.  It is the same reply IOCTL_AFD_BIND
 *     already returns, which is where this project's 26 came from.
 *   - IOCTL_AFD_GET_PEER_NAME answers with a bare TRANSPORT_ADDRESS, 22
 *     bytes.  AfdGetPeerName() consults no transport: it
 *     RtlCopyMemory's the FCB->RemoteAddress recorded at connect/accept
 *     time straight out, bounded by
 *     TaLengthOfTransportAddress() == 4 + 4 + 14 == 22.  WSPGetPeerName
 *     declares its buffer PTRANSPORT_ADDRESS, not PTDI_ADDRESS_INFO.
 *
 * Section 4 below is the assertion that spicule distinguishes them: the
 * same 26-byte sock-name image, handed to the peer-name reader, must
 * NOT yield the address it carries.
 *
 * The test/ sources are built with -Iarch/$(ARCH) -Iarch/generic -Iobj/include
 * -Iinclude only (see Makefile) -- src/internal/ is NOT on the include
 * path -- so the prototypes and every expected constant are declared
 * locally, the same way test/posix-socket-bind.c does.  That is
 * deliberate rather than merely accepted: a layout test that included
 * the header it is checking would agree with it by construction.  The
 * numbers below come from the references named above, not from spicule.
 *
 * What this file CANNOT check, stated rather than left implied: the two
 * ioctl *codes* (0x1202F and 0x12033).  Neither is reachable from a
 * test without a device to send it to.  0x1202F has an independent
 * cross-check in the sources -- Wine's separately reverse-engineered
 * IOCTL_AFD_GETSOCKNAME is numerically equal (test/networking-audit.md
 * sec 1) -- and 0x12033 has none at all, because Wine's ws2_32 answers
 * getpeername from its own cached state and never issues an ioctl for
 * it.  A wrong code there is a real-Windows-only finding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int fails;
#define CHECK(cond, what) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (what)); } } while (0)
#define CHECK_EQ(got, want, what) do { \
	unsigned long g_ = (unsigned long)(got), w_ = (unsigned long)(want); \
	if (g_ != w_) { fails++; \
		printf("FAIL %s:%d: %s = %lu (0x%lx), want %lu (0x%lx)\n", \
		       __FILE__, __LINE__, (what), g_, g_, w_, w_); } \
} while (0)

/* src/internal/afd.h; see the banner for why they are re-declared. */
unsigned long __afd_sockname_reply_size(void);
int __afd_sockname_reply_addr(const void *reply, struct sockaddr *addr, unsigned *len);
unsigned long __afd_peername_reply_size(void);
int __afd_peername_reply_addr(const void *reply, struct sockaddr *addr, unsigned *len);

/* --- constants, from the references named in the banner --- */

/* TRANSPORT_ADDRESS then TA_ADDRESS, both at tdi.h's default alignment,
 * relative to wherever the TRANSPORT_ADDRESS starts. */
#define TA_ADDR_COUNT   0u
#define TA_ADDR_LENGTH  4u
#define TA_ADDR_TYPE    6u
#define TA_ADDR         8u

/* TDI_ADDRESS_IP, packed to 1, relative to TA_ADDR. */
#define IP_PORT 0u
#define IP_ADDR 2u
#define TDI_ADDRESS_LENGTH_IP 14u
#define TDI_ADDRESS_TYPE_IP 2u

/* Where each reply puts that TRANSPORT_ADDRESS, and how big each reply
 * is.  These two lines are the whole point of the file. */
#define SOCKNAME_OFF 4u  /* past TDI_ADDRESS_INFO's ULONG ActivityCount */
#define PEERNAME_OFF 0u  /* a bare TRANSPORT_ADDRESS */
#define SOCKNAME_SIZE (SOCKNAME_OFF + TA_ADDR + TDI_ADDRESS_LENGTH_IP) /* 26 */
#define PEERNAME_SIZE (PEERNAME_OFF + TA_ADDR + TDI_ADDRESS_LENGTH_IP) /* 22 */

#define POISON 0x5Au

/* Write a TRANSPORT_ADDRESS at `off` into `buf`, byte by byte, so the
 * fixture assumes no struct layout of its own. */
static void build_ta(unsigned char *buf, unsigned off, long count,
                     unsigned alen, unsigned atype, unsigned port, unsigned long ip)
{
	unsigned char *p = buf + off;
	uint32_t c = (uint32_t)count;
	unsigned short l = (unsigned short)alen, t = (unsigned short)atype;
	unsigned short netport = htons((unsigned short)port);
	uint32_t netip = htonl((uint32_t)ip);

	memcpy(p + TA_ADDR_COUNT, &c, sizeof c);
	memcpy(p + TA_ADDR_LENGTH, &l, sizeof l);
	memcpy(p + TA_ADDR_TYPE, &t, sizeof t);
	memset(p + TA_ADDR, 0, TDI_ADDRESS_LENGTH_IP);
	memcpy(p + TA_ADDR + IP_PORT, &netport, sizeof netport);
	memcpy(p + TA_ADDR + IP_ADDR, &netip, sizeof netip);
}

/* --- 1. the two declared reply sizes -------------------------------- *
 * 26 and 22.  Equal sizes here would mean the ActivityCount had been
 * lost or invented, which is exactly the confusion section 4 checks the
 * consequences of. */
static void check_sizes(void)
{
	CHECK_EQ(__afd_sockname_reply_size(), SOCKNAME_SIZE, "__afd_sockname_reply_size()");
	CHECK_EQ(__afd_peername_reply_size(), PEERNAME_SIZE, "__afd_peername_reply_size()");
	CHECK_EQ(__afd_sockname_reply_size() - __afd_peername_reply_size(), 4u,
	         "the ULONG ActivityCount that separates the two replies");
}

/* --- 2. a well-formed reply of each shape reads back as the address it
 * carries, from the offset that shape puts it at. */
static void check_wellformed(void)
{
	unsigned char buf[64];
	struct sockaddr_in sin;
	unsigned len;

	memset(buf, 0, sizeof buf);
	build_ta(buf, SOCKNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 55123, 0x7F000001UL);
	memset(&sin, POISON, sizeof sin);
	len = sizeof sin;
	CHECK_EQ(__afd_sockname_reply_addr(buf, (struct sockaddr *)&sin, &len), 0,
	         "sock-name: a well-formed reply is accepted");
	CHECK_EQ(sin.sin_family, AF_INET, "sock-name: sin_family");
	CHECK_EQ(ntohs(sin.sin_port), 55123u, "sock-name: sin_port");
	CHECK_EQ(ntohl(sin.sin_addr.s_addr), 0x7F000001UL, "sock-name: sin_addr");
	CHECK_EQ(len, sizeof sin, "sock-name: *address_len");

	memset(buf, 0, sizeof buf);
	build_ta(buf, PEERNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 80, 0x01020304UL);
	memset(&sin, POISON, sizeof sin);
	len = sizeof sin;
	CHECK_EQ(__afd_peername_reply_addr(buf, (struct sockaddr *)&sin, &len), 0,
	         "peer-name: a well-formed reply is accepted");
	CHECK_EQ(sin.sin_family, AF_INET, "peer-name: sin_family");
	CHECK_EQ(ntohs(sin.sin_port), 80u, "peer-name: sin_port");
	CHECK_EQ(ntohl(sin.sin_addr.s_addr), 0x01020304UL, "peer-name: sin_addr");
	CHECK_EQ(len, sizeof sin, "peer-name: *address_len");
}

/* --- 3. a reply that describes no address is rejected, and rejected
 * without touching the caller's buffer.
 *
 * The zeroed case is the one that matters most: both ioctls are
 * METHOD_NEITHER, so afd.sys writes through the caller's buffer with no
 * Information-bounded copy-back to bound it and AfdGetPeerName()
 * completes with Information 0 outright.  A reply the driver declined
 * to write is therefore indistinguishable from one it wrote, EXCEPT
 * that src/socket/getname.c zeroes the buffer first -- at which point
 * TAAddressCount 0 and AddressLength 0 are the tell. */
static void check_rejects(void)
{
	unsigned char buf[64];
	struct sockaddr_in sin, before;
	unsigned len;

	memset(&before, POISON, sizeof before);

	memset(buf, 0, sizeof buf);
	sin = before; len = sizeof sin;
	CHECK_EQ(__afd_sockname_reply_addr(buf, (struct sockaddr *)&sin, &len), -1,
	         "sock-name: an all-zero (unwritten) reply is rejected");
	CHECK(!memcmp(&sin, &before, sizeof sin), "sock-name: rejected reply leaves the buffer untouched");
	CHECK_EQ(len, sizeof sin, "sock-name: rejected reply leaves *address_len untouched");

	memset(buf, 0, sizeof buf);
	sin = before; len = sizeof sin;
	CHECK_EQ(__afd_peername_reply_addr(buf, (struct sockaddr *)&sin, &len), -1,
	         "peer-name: an all-zero (unwritten) reply is rejected");
	CHECK(!memcmp(&sin, &before, sizeof sin), "peer-name: rejected reply leaves the buffer untouched");

	/* TAAddressCount 0 with a perfectly good address behind it: the
	 * count is the only field that says the address is there. */
	memset(buf, 0, sizeof buf);
	build_ta(buf, SOCKNAME_OFF, 0, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 80, 0x01020304UL);
	sin = before; len = sizeof sin;
	CHECK_EQ(__afd_sockname_reply_addr(buf, (struct sockaddr *)&sin, &len), -1,
	         "sock-name: TAAddressCount 0 is rejected");

	/* AddressLength short of the 14 an AF_INET address occupies: the
	 * stand-in for a length check on IoStatus.Information. */
	memset(buf, 0, sizeof buf);
	build_ta(buf, PEERNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP - 1, TDI_ADDRESS_TYPE_IP, 80, 0x01020304UL);
	sin = before; len = sizeof sin;
	CHECK_EQ(__afd_peername_reply_addr(buf, (struct sockaddr *)&sin, &len), -1,
	         "peer-name: AddressLength 13 is rejected");
}

/* --- 4. the two readers are actually reading different offsets.
 *
 * One direction is caught outright.  A sock-name reply read as a
 * peer-name reply takes ActivityCount for TAAddressCount and the low
 * half of the real TAAddressCount for AddressLength; TAAddressCount is
 * 1 for a single address, so AddressLength reads as 1 and the
 * "< TDI_ADDRESS_LENGTH_IP" guard rejects it.
 *
 * *** The other direction is NOT caught, and that is the finding this
 * section exists to record. ***  A peer-name reply read as a sock-name
 * reply takes (AddressLength | AddressType << 16) == 0x0002000E for
 * TAAddressCount -- non-zero, so it passes -- and the address's own
 * first two bytes, the port, for AddressLength -- 20480 for port 80, so
 * that passes too.  Neither guard can see the mistake: they exist to
 * reject a reply the driver did not write, not to identify which reply
 * it is, and nothing in a TRANSPORT_ADDRESS is a discriminator.  What
 * comes back is a wrong address, successfully.
 *
 * So the assertion is the one that holds either way and is the property
 * actually wanted: handed the SAME buffer, the two readers must not
 * agree.  Agreement means one of them is using the other's offset,
 * which is exactly the swap this file is the regression assertion for.
 */
static void check_not_interchangeable(void)
{
	unsigned char buf[64];
	struct sockaddr_in as_sock, as_peer, before;
	unsigned len_sock, len_peer;
	int rc_sock, rc_peer;
	uint32_t activity = 3; /* AFD reports a live reference count here */

	memset(&before, POISON, sizeof before);

	/* The direction the guards do catch. */
	memset(buf, 0, sizeof buf);
	build_ta(buf, SOCKNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 55123, 0x7F000001UL);
	memcpy(buf, &activity, sizeof activity);
	as_peer = before; len_peer = sizeof as_peer;
	CHECK_EQ(__afd_peername_reply_addr(buf, (struct sockaddr *)&as_peer, &len_peer), -1,
	         "a sock-name reply is rejected by the peer-name reader");
	CHECK(!memcmp(&as_peer, &before, sizeof as_peer),
	      "and nothing was written from the wrong offset");

	/* The direction they do not, asserted as disagreement. */
	memset(buf, 0, sizeof buf);
	build_ta(buf, PEERNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 80, 0x01020304UL);
	as_peer = before; len_peer = sizeof as_peer;
	as_sock = before; len_sock = sizeof as_sock;
	rc_peer = __afd_peername_reply_addr(buf, (struct sockaddr *)&as_peer, &len_peer);
	rc_sock = __afd_sockname_reply_addr(buf, (struct sockaddr *)&as_sock, &len_sock);
	CHECK_EQ(rc_peer, 0, "the peer-name reader accepts a peer-name reply");
	CHECK(rc_sock != 0 || memcmp(&as_sock, &as_peer, sizeof as_sock) != 0,
	      "the two readers do not agree on one buffer (they read different offsets)");
}

/* --- 5. getsockname.html/getpeername.html: "If the actual length of the
 * address is greater than the length of the supplied sockaddr
 * structure, the stored address shall be truncated" -- and
 * *address_len still receives the FULL length, not the number of bytes
 * stored.  The half that is easy to get backwards is the second one. */
static void check_truncation(void)
{
	unsigned char buf[64];
	unsigned char small[sizeof(struct sockaddr_in) + 8];
	unsigned len;

	memset(buf, 0, sizeof buf);
	build_ta(buf, SOCKNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 55123, 0x7F000001UL);

	memset(small, POISON, sizeof small);
	len = 4;
	CHECK_EQ(__afd_sockname_reply_addr(buf, (struct sockaddr *)small, &len), 0,
	         "truncating conversion still succeeds");
	CHECK_EQ(len, sizeof(struct sockaddr_in), "truncated: *address_len is the untruncated length");
	CHECK_EQ(small[4], POISON, "truncated: nothing written past the caller's length");

	/* Zero is a legal supplied length: nothing is stored, and the full
	 * length is still reported. */
	memset(small, POISON, sizeof small);
	len = 0;
	CHECK_EQ(__afd_sockname_reply_addr(buf, (struct sockaddr *)small, &len), 0,
	         "a zero-length buffer still succeeds");
	CHECK_EQ(len, sizeof(struct sockaddr_in), "zero-length: *address_len is the full length");
	CHECK_EQ(small[0], POISON, "zero-length: nothing written at all");

	/* A supplied length LARGER than the address must not make the
	 * reported length larger: it is the address's length, not the
	 * buffer's. */
	memset(small, POISON, sizeof small);
	len = sizeof small;
	CHECK_EQ(__afd_sockname_reply_addr(buf, (struct sockaddr *)small, &len), 0,
	         "an oversized buffer still succeeds");
	CHECK_EQ(len, sizeof(struct sockaddr_in), "oversized: *address_len is the address's length");
	CHECK_EQ(small[sizeof(struct sockaddr_in)], POISON, "oversized: nothing written past the address");
}

/* --- 6. neither reader reads past the bytes its ioctl declares.  Under
 * `make asan` these are the real checks -- a read at +26/+22 in an
 * exactly-sized heap block is a heap-buffer-overflow, not a quietly
 * passing guard byte.  Under the cross build they are two more passes. */
static void check_exact_allocation(void)
{
	unsigned char *b;
	struct sockaddr_in sin;
	unsigned len;

	b = malloc(SOCKNAME_SIZE);
	if (!b) { CHECK(0, "malloc"); return; }
	memset(b, 0, SOCKNAME_SIZE);
	build_ta(b, SOCKNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 7, 0x08080808UL);
	len = sizeof sin;
	CHECK_EQ(__afd_sockname_reply_addr(b, (struct sockaddr *)&sin, &len), 0,
	         "exact-size sock-name reply: accepted");
	CHECK_EQ(ntohl(sin.sin_addr.s_addr), 0x08080808UL, "exact-size sock-name reply: address");
	free(b);

	b = malloc(PEERNAME_SIZE);
	if (!b) { CHECK(0, "malloc"); return; }
	memset(b, 0, PEERNAME_SIZE);
	build_ta(b, PEERNAME_OFF, 1, TDI_ADDRESS_LENGTH_IP, TDI_ADDRESS_TYPE_IP, 7, 0x08080808UL);
	len = sizeof sin;
	CHECK_EQ(__afd_peername_reply_addr(b, (struct sockaddr *)&sin, &len), 0,
	         "exact-size peer-name reply: accepted");
	CHECK_EQ(ntohl(sin.sin_addr.s_addr), 0x08080808UL, "exact-size peer-name reply: address");
	free(b);
}

int main(void)
{
	check_sizes();
	check_wellformed();
	check_rejects();
	check_not_interchangeable();
	check_truncation();
	check_exact_allocation();

	if (!fails) printf("posix-socket-getname: all tests passed\n");
	return fails != 0;
}
