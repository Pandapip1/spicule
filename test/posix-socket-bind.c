/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Structural invariants of the IOCTL_AFD_BIND *request* body
 * src/socket/afdsupport.c's __afd_build_bind_request() hands
 * NtDeviceIoControlFile() on behalf of bind().
 *
 * The exact sibling of test/posix-socket-ea.c, for the exact same
 * reason and by the exact same method: it opens no socket and touches
 * no device, so it runs identically on a host with no \Device\Afd,
 * under Wine (whose AFD rejects this handle outright with
 * STATUS_BAD_DEVICE_TYPE and can therefore never exercise the layout),
 * under `make asan` natively, and on CI's real-Windows legs.
 *
 * It exists because a malformed bind request is not observable any
 * other way here.  After the open packet was fixed, socket() started
 * succeeding on real Windows and bind() began failing with errno=99
 * (EADDRNOTAVAIL), which src/internal/errno.c maps from
 * STATUS_INVALID_ADDRESS / STATUS_INVALID_ADDRESS_COMPONENT -- i.e.
 * afd.sys/tcpip read an address out of the buffer and did not like it.
 * test/posix-socket.c can only SKIP in that case.
 *
 * The specific defect this is the regression assertion for:
 * src/internal/afd.h declared TDI_ADDRESS_IP as an ordinary C struct
 *
 *      USHORT sin_port; ULONG in_addr; UCHAR sin_zero[8];
 *
 * but tdi.h declares it inside pshpack1.h/poppack.h, packed to 1.  The
 * unpacked version puts two padding bytes after sin_port, so in_addr
 * landed at +16 of the request instead of +14 and AddressLength was
 * declared as 16 instead of 14.  Binding 127.0.0.1 therefore handed
 * afd.sys the four bytes at +14 -- 00 00 7F 00, i.e. 0.0.127.0 -- which
 * is not a local address, hence EADDRNOTAVAIL.  ADDR_LENGTH and the
 * in_addr placement below are the direct assertions for that.
 *
 * The test/ sources are built with -Iarch/$(ARCH) -Iarch/generic -Iobj/include
 * -Iinclude only (see Makefile) -- src/internal/ is NOT on the include
 * path -- so the two prototypes and every expected constant are
 * declared locally, the same way test/posix-socket-ea.c does.  That is
 * deliberate rather than merely accepted: a layout test that included
 * the header it is checking would agree with it by construction.  The
 * numbers below come from the references, not from spicule:
 *
 *   - The request shape (ULONG ShareAccess, then a TRANSPORT_ADDRESS):
 *     System Informer phnt, ntafd.h, `AFD_BIND_INFO`; ReactOS
 *     sdk/include/reactos/drivers/afd/shared.h, `AFD_BIND_DATA`.  The
 *     two agree, field for field.
 *   - TRANSPORT_ADDRESS / TA_ADDRESS at default alignment (LONG
 *     TAAddressCount; USHORT AddressLength; USHORT AddressType; UCHAR
 *     Address[]): mingw-w64's vendored tdi.h,
 *     /usr/share/mingw-w64/include/tdi.h, which declares them *before*
 *     its pshpack1.h.  Hence +4/+8/+10/+12.
 *   - AddressLength == sockaddr length - sizeof(sa_family) == 14, and
 *     AddressType == sa_family, with the address bytes being
 *     sockaddr.sa_data verbatim: ReactOS
 *     dll/win32/msafd/misc/dllmain.c, WSPBind() --
 *       Address[0].AddressLength =
 *           SocketAddressLength - sizeof(SocketAddress->sa_family);
 *       Address[0].AddressType = SocketAddress->sa_family;
 *       RtlCopyMemory(Address[0].Address, SocketAddress->sa_data, ...)
 *     -- and, independently, phnt ntafd.h's `AFD_ADDRESS` union, whose
 *     `TdiAddressUnpacked` arm is `UCHAR Padding[10]` (commented
 *     "RTL_SIZEOF_THROUGH_FIELD(TDI_ADDRESS_INFO,
 *     Address.Address[0].AddressLength)") followed by a
 *     SOCKADDR_STORAGE, with an ASCII diagram putting SOCKADDR's
 *     sa_family exactly on TA_ADDRESS's AddressType.
 *   - TDI_ADDRESS_IP packed to 1, so sin_port +0, in_addr +2,
 *     sin_zero +6, TDI_ADDRESS_LENGTH_IP == 14: mingw-w64 tdi.h again,
 *     between `#include "pshpack1.h"` and `#include "poppack.h"`.
 *   - IOCTL_AFD_BIND == 0x12003, METHOD_NEITHER: phnt ntafd.h; and
 *     numerically equal to Wine's independently-derived code (see
 *     test/networking-audit.md sec 1).
 *   - The socket-creation packet that has to have succeeded before any
 *     of this is reachable: test/posix-socket-ea.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
unsigned long __afd_bind_request_size(void);
int __afd_build_bind_request(void *buf, unsigned long share_type,
                             const struct sockaddr *addr, unsigned len);

/* --- constants, from the references named in the banner --- */

/* AFD_BIND_INFO / AFD_BIND_DATA, then TRANSPORT_ADDRESS at default
 * alignment, then TA_ADDRESS at default alignment. */
#define REQ_SHARE_TYPE   0u
#define REQ_ADDR_COUNT   4u
#define REQ_ADDR_LENGTH  8u
#define REQ_ADDR_TYPE   10u
#define REQ_ADDR        12u

/* TDI_ADDRESS_IP, packed to 1, relative to REQ_ADDR. */
#define IP_PORT  0u
#define IP_ADDR  2u
#define IP_ZERO  6u
#define IP_ZERO_LEN 8u
#define TDI_ADDRESS_LENGTH_IP 14u

#define REQ_SIZE (REQ_ADDR + TDI_ADDRESS_LENGTH_IP) /* 26 */

/* Windows'/TDI's own numbers, spelled out so that changing spicule's
 * headers cannot silently change what this test asserts.  AF_INET and
 * TDI_ADDRESS_TYPE_IP are both 2, which is exactly why AddressType can
 * overlay sa_family. */
#define WIN_AF_INET 2u
#define TDI_ADDRESS_TYPE_IP 2u

/* AFD_SHARE_* / AFD share-access values: phnt ntafd.h
 * (AFD_NORMALADDRUSE/AFD_REUSEADDRESS/AFD_WILDCARDADDRESS/
 * AFD_EXCLUSIVEADDRUSE) == ReactOS shared.h (AFD_SHARE_UNIQUE/REUSE/
 * WILDCARD/EXCLUSIVE): 0/1/2/3. */
#define SHARE_UNIQUE 0u
#define SHARE_REUSE  1u

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
/* Room for the struct the builder writes through, which is two bytes
 * larger than the request it declares (see REQ_SIZE vs the tail-slack
 * check below), plus the guard run. */
#define SLOP 8u

static void fill_addr(struct sockaddr_in *a, unsigned long ip_host_order, unsigned port)
{
	memset(a, 0, sizeof(*a));
	a->sin_family = AF_INET;
	a->sin_port = htons((unsigned short)port);
	a->sin_addr.s_addr = htonl((uint32_t)ip_host_order);
}

/* Build one request and check every offset in it. */
static void check_one(unsigned long share, unsigned long ip_host_order, unsigned port)
{
	struct sockaddr_in sa;
	unsigned char *alloc, *buf;
	unsigned long size;
	unsigned char want_port[2], want_addr[4];
	unsigned i;

	size = __afd_bind_request_size();
	alloc = malloc(size + SLOP + GUARD);
	if (!alloc) { printf("FAIL %s: out of memory\n", __FILE__); fails++; return; }
	memset(alloc, GUARD_BYTE, size + SLOP + GUARD);
	buf = alloc;

	fill_addr(&sa, ip_host_order, port);
	CHECK(__afd_build_bind_request(buf, share, (struct sockaddr *)&sa, sizeof sa) == 0);

	/* --- 1. size and alignment ----------------------------------- *
	 * The request is 26 bytes: 4 + 4 + 2 + 2 + 14.  It must NOT be
	 * sizeof(AFD_BIND_DATA) (28) -- that rounds the tail up for
	 * TAAddressCount's alignment and declares two bytes the request
	 * does not describe.  IOCTL_AFD_BIND is METHOD_NEITHER, so this
	 * declared length is the only bound afd.sys has on how far into
	 * the buffer it reads. */
	CHECK_EQ(size, REQ_SIZE, "__afd_bind_request_size()");
	CHECK_EQ((unsigned long)((size_t)buf % 4u), 0u, "request address % 4");
	/* TAAddressCount is a LONG and must be 4-aligned within it. */
	CHECK_EQ(REQ_ADDR_COUNT % 4u, 0u, "TAAddressCount offset % 4");

	/* --- 2. the AFD_BIND_INFO header ----------------------------- */
	CHECK_EQ(rd32(buf + REQ_SHARE_TYPE), share, "ShareType");
	CHECK_EQ(rd32(buf + REQ_ADDR_COUNT), 1u, "TAAddressCount");

	/* --- 3. the TA_ADDRESS header -------------------------------- *
	 * AddressLength counts *only* the address bytes -- the sockaddr
	 * minus its 2-byte family -- so 14 for an AF_INET address.  16
	 * here is the unpacked-TDI_ADDRESS_IP regression. */
	CHECK_EQ(rd16(buf + REQ_ADDR_LENGTH), TDI_ADDRESS_LENGTH_IP, "TA_ADDRESS.AddressLength");
	CHECK_EQ(rd16(buf + REQ_ADDR_LENGTH),
	         (unsigned)(sizeof(struct sockaddr_in) - sizeof(sa.sin_family)),
	         "AddressLength vs sizeof(sockaddr_in) - sizeof(sa_family)");
	CHECK_EQ(rd16(buf + REQ_ADDR_TYPE), TDI_ADDRESS_TYPE_IP, "TA_ADDRESS.AddressType");
	CHECK_EQ(rd16(buf + REQ_ADDR_TYPE), WIN_AF_INET, "AddressType vs AF_INET");

	/* --- 4. the sockaddr overlay --------------------------------- *
	 * phnt's AFD_ADDRESS diagram: an entire SOCKADDR sits on the
	 * request from AddressType onwards (sa_family on AddressType,
	 * sa_data on Address).  So AddressType + sizeof(sockaddr_in)
	 * must land exactly on the end of the request. */
	CHECK_EQ(REQ_ADDR_TYPE + sizeof(struct sockaddr_in), size,
	         "AddressType + sizeof(sockaddr_in) vs request size");
	CHECK_EQ(REQ_ADDR - REQ_ADDR_TYPE, sizeof(sa.sin_family),
	         "Address - AddressType vs sizeof(sa_family)");
	/* ...and the 14 bytes at REQ_ADDR are sa_data verbatim, which is
	 * what ReactOS's WSPBind RtlCopyMemory()s.  Comparing against the
	 * caller's own sockaddr is the strongest form of this check: it
	 * needs no knowledge of the field order inside sa_data. */
	CHECK(memcmp(buf + REQ_ADDR, ((const unsigned char *)&sa) + sizeof(sa.sin_family),
	             TDI_ADDRESS_LENGTH_IP) == 0);

	/* --- 5. the packed TDI_ADDRESS_IP fields --------------------- *
	 * Spelled out separately from the memcmp above so a failure says
	 * which field moved.  in_addr at +2, NOT +4: that two-byte shift
	 * is the reported defect. */
	memcpy(want_port, &sa.sin_port, 2);
	memcpy(want_addr, &sa.sin_addr.s_addr, 4);
	CHECK(memcmp(buf + REQ_ADDR + IP_PORT, want_port, 2) == 0);
	CHECK(memcmp(buf + REQ_ADDR + IP_ADDR, want_addr, 4) == 0);
	CHECK_EQ(REQ_ADDR + IP_ADDR, 14u, "absolute offset of in_addr");
	CHECK_EQ(REQ_ADDR + IP_PORT, 12u, "absolute offset of sin_port");
	/* sin_zero: 8 bytes of zero, and they are the last of the 14. */
	CHECK_EQ(IP_ZERO + IP_ZERO_LEN, TDI_ADDRESS_LENGTH_IP, "sin_zero end vs address length");
	for (i = 0; i < IP_ZERO_LEN; i++)
		CHECK_EQ(buf[REQ_ADDR + IP_ZERO + i], 0u, "sin_zero byte");

	/* --- 6. nothing written past the declared length -------------- *
	 * The builder writes through an AFD_BIND_DATA, whose sizeof() is
	 * two bytes larger; those two bytes are allowed to be touched,
	 * but nothing beyond them may be.  (SLOP covers the difference.) */
	for (i = 0; i < GUARD; i++)
		CHECK_EQ(alloc[size + SLOP + i], GUARD_BYTE, "guard byte past the request");

	/* --- 7. deterministic ---------------------------------------- */
	{
		unsigned char *again = malloc(size + SLOP);
		if (!again) { printf("FAIL %s: out of memory\n", __FILE__); fails++; free(alloc); return; }
		memset(again, 0x5A, size + SLOP);
		CHECK(__afd_build_bind_request(again, share, (struct sockaddr *)&sa, sizeof sa) == 0);
		CHECK(memcmp(again, buf, size) == 0);
		free(again);
	}

	free(alloc);
}

int main(void)
{
	struct sockaddr_in sa;
	struct sockaddr sa6;
	unsigned char buf[64];

	/* The three addresses bind() is actually reachable with here:
	 * loopback on a fixed port (what test/posix-socket.c uses), the
	 * wildcard with an ephemeral port, and a non-zero port on the
	 * wildcard. */
	check_one(SHARE_UNIQUE, INADDR_LOOPBACK, 45123u);
	check_one(SHARE_REUSE, INADDR_LOOPBACK, 45123u);
	check_one(SHARE_UNIQUE, INADDR_ANY, 0u);
	check_one(SHARE_UNIQUE, INADDR_ANY, 80u);
	/* 0.0.127.0 is what the unpacked-struct defect made afd.sys read
	 * when 127.0.0.1 was requested; assert it is *not* what a
	 * 127.0.0.1 request produces at in_addr's real offset. */
	{
		unsigned char *p = buf;
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_port = htons(45123);
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		memset(buf, 0, sizeof buf);
		CHECK(__afd_build_bind_request(p, SHARE_UNIQUE, (struct sockaddr *)&sa, sizeof sa) == 0);
		CHECK_EQ(rd32(p + REQ_ADDR + IP_ADDR), (unsigned long)htonl((uint32_t)INADDR_LOOPBACK),
		         "in_addr as afd.sys reads it");
		CHECK(rd32(p + REQ_ADDR + IP_ADDR) != (unsigned long)htonl((uint32_t)0x00007F00UL));
	}

	/* --- rejections, which must never reach the device ------------ *
	 * bind.html: EAFNOSUPPORT if "the specified address is not a
	 * valid address for the address family of the specified socket",
	 * EINVAL for a bad address_len. */
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	errno = 0;
	CHECK(__afd_build_bind_request(buf, SHARE_UNIQUE, (struct sockaddr *)&sa, sizeof sa - 1) == -1);
	CHECK_EQ(errno, EINVAL, "errno for a short address_len");
	errno = 0;
	CHECK(__afd_build_bind_request(buf, SHARE_UNIQUE, (struct sockaddr *)0, sizeof sa) == -1);
	CHECK_EQ(errno, EINVAL, "errno for a NULL address");
	/* <netinet/in.h> here declares no sockaddr_in6 (AF_INET6 is out of
	 * scope; <sys/socket.h> defines the constant only so such a call
	 * compiles and fails).  A bare sockaddr carrying that family is
	 * the same thing as far as this check is concerned, and it is
	 * long enough to get past the length check first. */
	memset(&sa6, 0, sizeof sa6);
	sa6.sa_family = AF_INET6;
	errno = 0;
	CHECK(__afd_build_bind_request(buf, SHARE_UNIQUE, &sa6, sizeof sa6) == -1);
	CHECK_EQ(errno, EAFNOSUPPORT, "errno for AF_INET6");

	if (!fails) printf("posix-socket-bind: all tests passed\n");
	return fails != 0;
}
