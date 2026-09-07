/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Structural invariants of the IOCTL_AFD_CONNECT *request* body
 * src/socket/afdsupport.c's __afd_build_connect_request() hands
 * NtDeviceIoControlFile() on behalf of connect().
 *
 * The third of the sibling set -- test/posix-socket-ea.c (the
 * AfdOpenPacketXX EA buffer) and test/posix-socket-bind.c (the
 * IOCTL_AFD_BIND body) -- built the same way and for the same reason:
 * it opens no socket and touches no device, so it runs identically on
 * a host with no \Device\Afd, under Wine (whose AFD is its own
 * implementation and returns STATUS_NOT_IMPLEMENTED for a TDI-mode
 * connect, so it can never exercise this layout), under `make asan`
 * natively, and on CI's real-Windows legs.  Both of its siblings pass
 * on real Windows; that is why this technique is the one used here.
 *
 * It exists because a malformed connect request is not observable any
 * other way.  Once the open packet and the bind address were fixed,
 * socket()/bind()/listen() all began succeeding on real Windows and
 * test/posix-socket.c started failing at its connect() -- on the
 * x86_64 leg.  A wrong offset there is invisible to every device-free
 * check that merely compiles the structure, and invisible to i386
 * entirely (see below).
 *
 * *** The specific defect this is the regression assertion for, and
 * the one place a *pointer-sized* offset matters. ***
 *
 * This project's two reference sources disagree about this structure,
 * and they disagree only on 64-bit:
 *
 *   - ReactOS sdk/include/reactos/drivers/afd/shared.h, AFD_CONNECT_INFO:
 *       BOOLEAN UseSAN; ULONG Root; ULONG Unknown;
 *       TRANSPORT_ADDRESS RemoteAddress;
 *   - System Informer phnt, ntafd.h, AFD_CONNECT_JOIN_INFO (which its
 *     own AFD_CONNECT opcode comment names: "in: AFD_CONNECT_JOIN_INFO_TL
 *     or AFD_CONNECT_JOIN_INFO (depending on transport mode)"):
 *       BOOLEAN SanActive; HANDLE RootEndpoint; HANDLE ConnectEndpoint;
 *       TRANSPORT_ADDRESS RemoteAddress;
 *
 * Two ULONGs versus two HANDLEs.  On i386 a HANDLE is 4 bytes and the
 * two layouts are byte-for-byte identical -- RemoteAddress at +12
 * either way -- so no amount of i386 testing can tell them apart, and
 * an i386-only regression suite would have caught nothing.  On x86_64
 * a HANDLE is 8 and 8-aligned, so phnt puts RemoteAddress at +24 where
 * ReactOS puts it at +12: the whole TRANSPORT_ADDRESS 12 bytes early,
 * with afd.sys reading TAAddressCount out of the tail of
 * ConnectEndpoint.  That is what main()'s negative control reproduces
 * byte for byte and then proves these assertions reject.
 *
 * spicule follows phnt, for the reasons src/internal/afd.h's connect
 * banner sets out (chiefly: `RootEndpoint`/`ConnectEndpoint` are the
 * multipoint endpoint *handles* WSAJoinLeaf passes -- phnt shares this
 * structure between AFD_CONNECT and AFD_JOIN_LEAF -- and a handle
 * cannot be a ULONG on Win64; while ReactOS's own `Root` and literal
 * `Unknown` record that its authors did not know what the fields were).
 *
 * The test/ sources are built with -Iarch/$(ARCH) -Iarch/generic -Iobj/include
 * -Iinclude only (see Makefile) -- src/internal/ is NOT on the include
 * path -- so the prototypes and every expected constant are declared
 * locally, exactly as its two siblings do.  That is deliberate rather
 * than merely accepted: a layout test that included the header it is
 * checking would agree with it by construction.  The numbers below
 * come from the references, not from spicule:
 *
 *   - The request shape: phnt ntafd.h, AFD_CONNECT_JOIN_INFO, above.
 *   - TRANSPORT_ADDRESS / TA_ADDRESS at default alignment (LONG
 *     TAAddressCount; USHORT AddressLength; USHORT AddressType; UCHAR
 *     Address[]): mingw-w64's vendored tdi.h,
 *     /usr/share/mingw-w64/include/tdi.h, which declares them *before*
 *     its pshpack1.h.  Hence +0/+4/+6/+8 within the address.
 *   - AddressLength == sockaddr length - sizeof(sa_family) == 14, and
 *     AddressType == sa_family, the address bytes being sockaddr.sa_data
 *     verbatim: ReactOS dll/win32/msafd/misc/dllmain.c, WSPConnect()
 *     (which fills ConnectInfo->RemoteAddress the same way WSPBind()
 *     fills BindData->Address), and independently phnt ntafd.h's
 *     AFD_ADDRESS union, whose TdiAddressUnpacked arm is UCHAR
 *     Padding[10] followed by a SOCKADDR_STORAGE with an ASCII diagram
 *     putting SOCKADDR's sa_family exactly on TA_ADDRESS's AddressType.
 *   - TDI_ADDRESS_IP packed to 1, so sin_port +0, in_addr +2,
 *     sin_zero +6, TDI_ADDRESS_LENGTH_IP == 14: mingw-w64 tdi.h again,
 *     between `#include "pshpack1.h"` and `#include "poppack.h"`.
 *   - IOCTL_AFD_CONNECT == 0x12007, METHOD_NEITHER: phnt ntafd.h; and
 *     numerically equal to Wine's independently-derived code (see
 *     test/networking-audit.md sec 1).
 *   - The two requests that have to have succeeded before this one is
 *     reachable: test/posix-socket-ea.c and test/posix-socket-bind.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(got, want, what) do { \
	unsigned long g_ = (unsigned long)(got), w_ = (unsigned long)(want); \
	if (g_ != w_) { fails++; \
		printf("FAIL %s:%d: %s = %lu (0x%lx), want %lu (0x%lx)\n", \
		       __FILE__, __LINE__, (what), g_, g_, w_, w_); } \
} while (0)

/* src/internal/afd.h; see the banner for why they are re-declared. */
unsigned long __afd_connect_request_size(void);
int __afd_build_connect_request(void *buf, const struct sockaddr *addr, unsigned len);

/* --- constants, from the references named in the banner --- */

/* sizeof(HANDLE).  Not read from spicule: a HANDLE is a PVOID (winnt.h),
 * so it is exactly a pointer, which is 4 bytes on i386 and 8 on x86_64
 * and carries the same alignment.  Everything else about this layout
 * follows from that one number, which is the entire reason the two
 * reference sources can disagree on x86_64 and agree on i386. */
#define HSZ ((unsigned long)sizeof(void *))

/* phnt AFD_CONNECT_JOIN_INFO: a BOOLEAN, then two HANDLEs (each
 * aligned to HSZ, so the BOOLEAN's 1 byte is followed by HSZ-1 bytes of
 * padding), then a TRANSPORT_ADDRESS -- whose LONG TAAddressCount needs
 * only 4-byte alignment but starts right after the second HANDLE. */
#define REQ_SAN_ACTIVE   0UL
#define REQ_ROOT_EP      HSZ
#define REQ_CONNECT_EP   (2UL * HSZ)
#define REQ_ADDR_COUNT   (3UL * HSZ)
#define REQ_ADDR_LENGTH  (REQ_ADDR_COUNT + 4UL)
#define REQ_ADDR_TYPE    (REQ_ADDR_COUNT + 6UL)
#define REQ_ADDR         (REQ_ADDR_COUNT + 8UL)

/* TDI_ADDRESS_IP, packed to 1, relative to REQ_ADDR. */
#define IP_PORT  0u
#define IP_ADDR  2u
#define IP_ZERO  6u
#define IP_ZERO_LEN 8u
#define TDI_ADDRESS_LENGTH_IP 14UL

#define REQ_SIZE (REQ_ADDR + TDI_ADDRESS_LENGTH_IP) /* 46 on x86_64, 34 on i386 */

/* ReactOS shared.h's AFD_CONNECT_INFO, for the negative control: a
 * BOOLEAN then two ULONGs (4-aligned, so the BOOLEAN is followed by 3
 * bytes of padding regardless of ABI), then the TRANSPORT_ADDRESS. */
#define ROS_ADDR_COUNT   12UL
#define ROS_ADDR_LENGTH  (ROS_ADDR_COUNT + 4UL)
#define ROS_ADDR_TYPE    (ROS_ADDR_COUNT + 6UL)
#define ROS_ADDR         (ROS_ADDR_COUNT + 8UL)
#define ROS_SIZE         (ROS_ADDR + TDI_ADDRESS_LENGTH_IP) /* 34, both ABIs */

/* Windows'/TDI's own numbers, spelled out so that changing spicule's
 * headers cannot silently change what this test asserts. */
#define WIN_AF_INET 2u
#define TDI_ADDRESS_TYPE_IP 2u

/* Little-endian readers: the buffer is a byte image of an NT structure,
 * so it is decoded as one rather than cast to a struct (which would
 * assume the very layout under test). */
static unsigned long rd32(const unsigned char *p)
{
	return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
	     | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned rd16(const unsigned char *p)
{
	return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

#define GUARD 16u
#define GUARD_BYTE 0xABu
/* Room for the AFD_CONNECT_INFO the caller declares storage as, which
 * rounds the request's tail up for alignment; nothing past that may be
 * touched.  8 covers the largest such rounding on either ABI. */
#define SLOP 8u

static void fill_addr(struct sockaddr_in *a, unsigned long ip_host_order, unsigned port)
{
	memset(a, 0, sizeof(*a));
	a->sin_family = AF_INET;
	a->sin_port = htons((unsigned short)port);
	a->sin_addr.s_addr = htonl((uint32_t)ip_host_order);
}

/* Every offset assertion, factored out so that main() can run the exact
 * same battery against a deliberately-wrong image and count how many of
 * them fire.  `report` selects whether a failure is printed and charged
 * to the global count (the real image) or merely counted and returned
 * (the negative control).  The two callers must stay indistinguishable
 * to this function -- that is what makes the negative control mean
 * something. */
static int verify_image(const unsigned char *buf, unsigned long size,
                        const struct sockaddr_in *sa, int report)
{
	int local = 0;
	int saved = fails;
	unsigned long i;
	unsigned char want_port[2], want_addr[4];

#define V(cond, what) do { \
	if (!(cond)) { local++; \
		if (report) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (what)); } } \
} while (0)
#define V_EQ(got, want, what) do { \
	unsigned long g_ = (unsigned long)(got), w_ = (unsigned long)(want); \
	if (g_ != w_) { local++; \
		if (report) { fails++; \
			printf("FAIL %s:%d: %s = %lu (0x%lx), want %lu (0x%lx)\n", \
			       __FILE__, __LINE__, (what), g_, g_, w_, w_); } } \
} while (0)

	/* --- 1. size ------------------------------------------------- *
	 * 3 * sizeof(HANDLE) + 8 + 14.  It must NOT be
	 * sizeof(AFD_CONNECT_INFO), which rounds the tail up for
	 * TAAddressCount's alignment and would declare bytes the request
	 * does not describe.  IOCTL_AFD_CONNECT is METHOD_NEITHER, so
	 * this declared length is the only bound afd.sys has on how far
	 * into the buffer it reads. */
	V_EQ(size, REQ_SIZE, "request size");

	/* --- 2. the AFD_CONNECT_JOIN_INFO header --------------------- *
	 * SanActive: no Winsock SAN provider.  RootEndpoint and
	 * ConnectEndpoint: the multipoint root/leaf handles, both NULL
	 * for an ordinary connect().  All three are zero, which means
	 * they cannot themselves distinguish the two layouts -- the
	 * address offsets below are what does. */
	V_EQ(buf[REQ_SAN_ACTIVE], 0u, "SanActive");
	for (i = 0; i < HSZ; i++) V_EQ(buf[REQ_ROOT_EP + i], 0u, "RootEndpoint byte");
	for (i = 0; i < HSZ; i++) V_EQ(buf[REQ_CONNECT_EP + i], 0u, "ConnectEndpoint byte");

	/* --- 3. the TRANSPORT_ADDRESS header ------------------------- *
	 * This is the assertion the whole file exists for: on x86_64
	 * TAAddressCount is at +24, not ReactOS's +12. */
	V_EQ(rd32(buf + REQ_ADDR_COUNT), 1u, "TAAddressCount");
	V_EQ(REQ_ADDR_COUNT % 4u, 0u, "TAAddressCount offset % 4");
	V_EQ(REQ_ADDR_COUNT, 3UL * HSZ, "TAAddressCount offset vs 3 * sizeof(HANDLE)");

	/* --- 4. the TA_ADDRESS header -------------------------------- *
	 * AddressLength counts only the address bytes -- the sockaddr
	 * minus its 2-byte family -- so 14 for an AF_INET address. */
	V_EQ(rd16(buf + REQ_ADDR_LENGTH), TDI_ADDRESS_LENGTH_IP, "TA_ADDRESS.AddressLength");
	V_EQ(rd16(buf + REQ_ADDR_LENGTH),
	     (unsigned)(sizeof(struct sockaddr_in) - sizeof(sa->sin_family)),
	     "AddressLength vs sizeof(sockaddr_in) - sizeof(sa_family)");
	V_EQ(rd16(buf + REQ_ADDR_TYPE), TDI_ADDRESS_TYPE_IP, "TA_ADDRESS.AddressType");
	V_EQ(rd16(buf + REQ_ADDR_TYPE), WIN_AF_INET, "AddressType vs AF_INET");

	/* --- 5. the sockaddr overlay --------------------------------- *
	 * phnt's AFD_ADDRESS diagram: an entire SOCKADDR sits on the
	 * request from AddressType onwards.  So AddressType +
	 * sizeof(sockaddr_in) must land exactly on the end. */
	V_EQ(REQ_ADDR_TYPE + sizeof(struct sockaddr_in), size,
	     "AddressType + sizeof(sockaddr_in) vs request size");
	V_EQ(REQ_ADDR - REQ_ADDR_TYPE, sizeof(sa->sin_family),
	     "Address - AddressType vs sizeof(sa_family)");
	/* ...and the 14 bytes at REQ_ADDR are sa_data verbatim, which is
	 * what ReactOS's WSPConnect RtlCopyMemory()s.  Comparing against
	 * the caller's own sockaddr is the strongest form of this check:
	 * it needs no knowledge of the field order inside sa_data. */
	V(memcmp(buf + REQ_ADDR, ((const unsigned char *)sa) + sizeof(sa->sin_family),
	         TDI_ADDRESS_LENGTH_IP) == 0, "address bytes vs sockaddr.sa_data");

	/* --- 6. the packed TDI_ADDRESS_IP fields --------------------- *
	 * Spelled out separately from the memcmp above so a failure says
	 * which field moved.  in_addr at +2, NOT +4 (the pack(1) the
	 * bind request's own test asserts). */
	memcpy(want_port, &sa->sin_port, 2);
	memcpy(want_addr, &sa->sin_addr.s_addr, 4);
	V(memcmp(buf + REQ_ADDR + IP_PORT, want_port, 2) == 0, "sin_port bytes");
	V(memcmp(buf + REQ_ADDR + IP_ADDR, want_addr, 4) == 0, "in_addr bytes");
	V_EQ(IP_ZERO + IP_ZERO_LEN, TDI_ADDRESS_LENGTH_IP, "sin_zero end vs address length");
	for (i = 0; i < IP_ZERO_LEN; i++)
		V_EQ(buf[REQ_ADDR + IP_ZERO + i], 0u, "sin_zero byte");

	/* --- 7. the absolute numbers, per ABI ------------------------ *
	 * Everything above is expressed in terms of sizeof(HANDLE); this
	 * pins what that works out to, so that a future change to HSZ's
	 * derivation cannot make the whole file vacuously self-consistent. */
	if (HSZ == 8UL) {
		V_EQ(REQ_ADDR_COUNT, 24u, "x86_64: TAAddressCount offset");
		V_EQ(REQ_ADDR, 32u, "x86_64: address offset");
		V_EQ(size, 46u, "x86_64: request size");
	} else {
		V_EQ(HSZ, 4u, "sizeof(HANDLE) is 4 or 8");
		V_EQ(REQ_ADDR_COUNT, 12u, "i386: TAAddressCount offset");
		V_EQ(REQ_ADDR, 20u, "i386: address offset");
		V_EQ(size, 34u, "i386: request size");
	}
#undef V
#undef V_EQ
	if (!report) fails = saved; /* belt and braces: V/V_EQ already gate this */
	return local;
}

/* The image ReactOS's AFD_CONNECT_INFO would have produced, built here
 * by hand so the negative control does not depend on spicule ever having
 * contained it.  BOOLEAN at +0, two ULONGs at +4 and +8, then the
 * TRANSPORT_ADDRESS at +12 -- on both ABIs. */
static void build_reactos_image(unsigned char *buf, const struct sockaddr_in *sa)
{
	uint32_t one = 1;
	unsigned short l = (unsigned short)TDI_ADDRESS_LENGTH_IP;
	unsigned short t = (unsigned short)TDI_ADDRESS_TYPE_IP;

	memset(buf, 0, (size_t)ROS_SIZE);
	memcpy(buf + ROS_ADDR_COUNT, &one, sizeof(one));
	memcpy(buf + ROS_ADDR_LENGTH, &l, sizeof(l));
	memcpy(buf + ROS_ADDR_TYPE, &t, sizeof(t));
	memcpy(buf + ROS_ADDR, ((const unsigned char *)sa) + sizeof(sa->sin_family),
	       (size_t)TDI_ADDRESS_LENGTH_IP);
}

/* Build one request and check every offset in it. */
static void check_one(unsigned long ip_host_order, unsigned port)
{
	struct sockaddr_in sa;
	unsigned char *alloc, *buf;
	unsigned long size;
	unsigned i;

	size = __afd_connect_request_size();
	alloc = malloc((size_t)(size + SLOP + GUARD));
	if (!alloc) { printf("FAIL %s: out of memory\n", __FILE__); fails++; return; }
	memset(alloc, GUARD_BYTE, (size_t)(size + SLOP + GUARD));
	buf = alloc;

	fill_addr(&sa, ip_host_order, port);
	CHECK(__afd_build_connect_request(buf, (struct sockaddr *)&sa, sizeof sa) == 0);

	/* The buffer a caller declares as an AFD_CONNECT_INFO is
	 * pointer-aligned; the two HANDLE fields require it. */
	CHECK_EQ((unsigned long)((size_t)buf % sizeof(void *)), 0u, "request address % sizeof(HANDLE)");

	(void)verify_image(buf, size, &sa, 1);

	/* --- nothing written past the declared length ---------------- *
	 * The builder writes exactly `size` bytes; the SLOP bytes cover
	 * the tail sizeof(AFD_CONNECT_INFO) rounds up to and are allowed
	 * to be touched, but nothing beyond them may be. */
	for (i = 0; i < GUARD; i++)
		CHECK_EQ(alloc[size + SLOP + i], GUARD_BYTE, "guard byte past the request");

	/* --- deterministic ------------------------------------------- */
	{
		unsigned char *again = malloc((size_t)(size + SLOP));
		if (!again) { printf("FAIL %s: out of memory\n", __FILE__); fails++; free(alloc); return; }
		memset(again, 0x5A, (size_t)(size + SLOP));
		CHECK(__afd_build_connect_request(again, (struct sockaddr *)&sa, sizeof sa) == 0);
		CHECK(memcmp(again, buf, (size_t)size) == 0);
		free(again);
	}

	free(alloc);
}

int main(void)
{
	struct sockaddr_in sa;
	struct sockaddr sa6;
	unsigned char buf[128];

	/* The addresses connect() is actually reachable with here:
	 * loopback on the port test/posix-socket.c listens on, and a
	 * couple of neighbours to make sure nothing is hard-coded. */
	check_one(INADDR_LOOPBACK, 45123u);
	check_one(INADDR_LOOPBACK, 1u);
	check_one(0x7F000002UL, 65535u);

	/* --- the negative control ------------------------------------ *
	 * Build the image ReactOS's AFD_CONNECT_INFO describes, run the
	 * identical assertion battery over it, and require that the
	 * battery *rejects* it on x86_64.  Without this, every check
	 * above could be satisfied by a test that simply agreed with
	 * whatever the library produced.
	 *
	 * On i386 the two layouts are byte-for-byte identical -- a HANDLE
	 * is 4 bytes there -- so the battery must *accept* it, and the
	 * two images must compare equal.  Asserting that explicitly is
	 * the point: it is exactly why the x86_64 leg was the only one
	 * that could ever have caught this, and it stops a future reader
	 * from "fixing" an i386 non-failure. */
	{
		struct sockaddr_in c;
		unsigned char ros[128];
		unsigned long size = __afd_connect_request_size();
		int rejected;

		fill_addr(&c, INADDR_LOOPBACK, 45123u);
		memset(buf, 0, sizeof buf);
		CHECK(__afd_build_connect_request(buf, (struct sockaddr *)&c, sizeof c) == 0);
		build_reactos_image(ros, &c);

		rejected = verify_image(ros, ROS_SIZE, &c, 0);
		if (HSZ == 8UL) {
			CHECK(rejected > 0);
			CHECK_EQ(size != ROS_SIZE, 1u, "x86_64: request size differs from ReactOS's");
			CHECK(memcmp(buf, ros, (size_t)ROS_SIZE) != 0);
			/* Concretely: at ReactOS's +12 the real request holds the
			 * tail of ConnectEndpoint (zero), not TAAddressCount (1). */
			CHECK_EQ(rd32(buf + ROS_ADDR_COUNT), 0u,
			         "x86_64: what sits where ReactOS put TAAddressCount");
			CHECK_EQ(rd32(buf + REQ_ADDR_COUNT), 1u, "x86_64: TAAddressCount at +24");
		} else {
			CHECK_EQ(rejected, 0, "i386: ReactOS's layout is the same layout");
			CHECK_EQ(size, ROS_SIZE, "i386: request size matches ReactOS's");
			CHECK(memcmp(buf, ros, (size_t)ROS_SIZE) == 0);
		}
		/* And the sanity check that the control is a control: the
		 * battery accepts the real image in both cases. */
		CHECK_EQ(verify_image(buf, size, &c, 0), 0, "battery accepts the real image");
	}

	/* --- rejections, which must never reach the device ------------ *
	 * connect.html: EAFNOSUPPORT if "the specified address is not a
	 * valid address for the address family of the specified socket",
	 * EINVAL for a bad address_len.  A rejected address must also
	 * leave the caller's buffer untouched -- afd.sys would otherwise
	 * see a half-built request if a caller ignored the return value. */
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	memset(buf, GUARD_BYTE, sizeof buf);
	errno = 0;
	CHECK(__afd_build_connect_request(buf, (struct sockaddr *)&sa, sizeof sa - 1) == -1);
	CHECK_EQ(errno, EINVAL, "errno for a short address_len");
	CHECK_EQ(buf[REQ_ADDR_COUNT], GUARD_BYTE, "buffer untouched after a rejected length");
	errno = 0;
	CHECK(__afd_build_connect_request(buf, (struct sockaddr *)0, sizeof sa) == -1);
	CHECK_EQ(errno, EINVAL, "errno for a NULL address");
	/* <netinet/in.h> here declares no sockaddr_in6 (AF_INET6 is out of
	 * scope; <sys/socket.h> defines the constant only so such a call
	 * compiles and fails).  A bare sockaddr carrying that family is
	 * the same thing as far as this check is concerned. */
	memset(&sa6, 0, sizeof sa6);
	sa6.sa_family = AF_INET6;
	errno = 0;
	CHECK(__afd_build_connect_request(buf, &sa6, sizeof sa6) == -1);
	CHECK_EQ(errno, EAFNOSUPPORT, "errno for AF_INET6");
	CHECK_EQ(buf[REQ_ADDR_COUNT], GUARD_BYTE, "buffer untouched after a rejected family");

	if (!fails) printf("posix-socket-connect: all tests passed\n");
	return fails != 0;
}
