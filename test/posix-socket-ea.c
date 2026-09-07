/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Structural invariants of the FILE_FULL_EA_INFORMATION buffer
 * src/socket/afdsupport.c's __afd_open() hands NtCreateFile when it
 * creates an AFD endpoint for socket().
 *
 * This test opens nothing.  It asks __afd_open_ea_size() for the byte
 * count and __afd_build_open_ea() for the bytes, then re-parses those
 * bytes *by offset*, with no reference to the structs in
 * src/internal/afd.h, and checks every rule NT's own EA validator
 * applies plus the field layout real Windows' afd.sys reads back.  So
 * it runs identically on a host with no \Device\Afd, under Wine, under
 * `make asan` natively, and on CI's real-Windows legs.
 *
 * It exists because a malformed EA buffer is not observable any other
 * way here: socket() reported only errno=EFAULT (STATUS_ACCESS_VIOLATION
 * out of NtCreateFile) on real Windows, and *succeeded* under Wine,
 * whose AFD is a separate implementation that never parses this packet.
 * test/posix-socket.c honestly reports "unverified" (77) in that case,
 * so nothing else in the suite could have caught it.  The specific
 * defect: the EA value carried ReactOS's 12-byte AFD_CREATE_PACKET
 * header rather than real Windows' 24-byte AFD_OPEN_PACKET header, so
 * afd.sys read the UTF-16 device name text where it expects
 * SocketType/Protocol/TransportDeviceNameLength and walked megabytes
 * past the buffer.  The TRANSPORT_NAME_LENGTH check below is the direct
 * regression assertion for that.
 *
 * The test/ sources are built with -Iarch/$(ARCH) -Iarch/generic -Iobj/include
 * -Iinclude only (see Makefile) -- src/internal/ is NOT on the include
 * path -- so the two prototypes and every expected constant are
 * declared locally, the same way test/posix-errno.c and test/misc.c do.
 * That is deliberate here rather than merely accepted: a layout test
 * that included the header it is checking would agree with it by
 * construction.  The numbers below come from the references, not from
 * spicule:
 *
 *   - FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) == 8, and the
 *     ComputedLength / NUL-termination / NextEntryOffset rules:
 *     ReactOS ntoskrnl/io/iomgr/util.c, IoCheckEaBufferValidity().
 *   - The EA name "AfdOpenPacketXX" (15 chars) and its NUL: ReactOS
 *     sdk/include/reactos/drivers/afd/shared.h (AfdCommand,
 *     AFD_PACKET_COMMAND_LENGTH); System Informer phnt ntafd.h
 *     (AfdOpenPacket, and AFD_OPEN_PACKET_FULL_EA's
 *     `CHAR EaName[sizeof(AfdOpenPacket)]`).
 *   - The 24-byte AFD_OPEN_PACKET header and its field order
 *     (EndpointFlags, GroupID, AddressFamily, SocketType, Protocol,
 *     TransportDeviceNameLength-in-bytes, TransportDeviceName in
 *     UTF-16): phnt ntafd.h `AFD_OPEN_PACKET`, and, independently,
 *     Mateusz Lewczak, "Under the Hood of AFD.sys" part 1,
 *     https://leftarcode.com/posts/afd-reverse-engineering-part1/
 *     ("AFD_OPEN_PACKET_EA").
 *   - "\Device\Tcp" as the AF_INET/SOCK_STREAM transport: phnt ntafd.h
 *     DD_TCP_DEVICE_NAME; ReactOS dll/win32/msafd/misc/dllmain.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(got, want, what) do { \
	unsigned long g_ = (unsigned long)(got), w_ = (unsigned long)(want); \
	if (g_ != w_) { fails++; \
		printf("FAIL %s:%d: %s = %lu (0x%lx), want %lu (0x%lx)\n", \
		       __FILE__, __LINE__, (what), g_, g_, w_, w_); } \
} while (0)

/* src/internal/afd.h; see the banner for why they are re-declared.
 *
 * The *_for() variants are used rather than the plain ones so that this
 * file keeps asserting the NT 6 layout on every host, including a host
 * whose own afd.sys wants the NT 4/5 layout.  __afd_build_open_ea()
 * picks a shape from the OS version (src/internal/ntversion.c); this
 * test is about the bytes of one specific shape, not about which one
 * the platform gets, so it names the shape.  Which shape a platform is
 * given, and that the other shape's bytes are right too, is
 * test/posix-socket-shape.c's job. */
#define SHAPE_NT6 1 /* AFD_SHAPE_NT6, src/internal/afd.h */
/* <sys/socket.h>'s own SOCK_STREAM value (1), re-spelled locally for
 * the same reason every other constant in this file is: this test does
 * not include spicule's headers.  __afd_build_open_ea_for() gained this
 * parameter for SOCK_DGRAM (2026-09-01, src/internal/afd.h); this file
 * still asserts only the SOCK_STREAM/"\Device\Tcp" shape it always has
 * -- the transport-name and AddressFamily/SocketType/Protocol checks
 * below are unchanged. */
#define SOCKTYPE_STREAM 1
unsigned long __afd_open_ea_size_for(int shape);
void __afd_build_open_ea_for(int shape, int socktype, void *buf);

/* --- constants, from the references named in the banner --- */

/* FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName).  Note this is NOT
 * sizeof(FILE_FULL_EA_INFORMATION), which is 12: sizeof() counts the
 * EaName[1] placeholder and rounds up to NextEntryOffset's 4-byte
 * alignment.  IoCheckEaBufferValidity() uses FIELD_OFFSET. */
#define EA_HEADER 8u
#define EA_NAME "AfdOpenPacketXX"
#define EA_NAME_LEN 15u

/* AFD_OPEN_PACKET field offsets, relative to the start of the value. */
#define PKT_ENDPOINT_FLAGS 0u
#define PKT_GROUP_ID 4u
#define PKT_ADDRESS_FAMILY 8u
#define PKT_SOCKET_TYPE 12u
#define PKT_PROTOCOL 16u
#define PKT_TRANSPORT_NAME_LENGTH 20u
#define PKT_TRANSPORT_NAME 24u
#define PKT_HEADER 24u

/* Windows' AF_/SOCK_/IPPROTO_ numbers, which are what afd.sys reads
 * here.  They happen to equal spicule's <sys/socket.h>/<netinet/in.h>
 * values, but this test spells the wire numbers out so that changing
 * spicule's headers cannot silently change what it asserts. */
#define WIN_AF_INET 2u
#define WIN_SOCK_STREAM 1u
#define WIN_IPPROTO_TCP 6u

/* "\Device\Tcp", 11 characters, in UTF-16LE. */
static const unsigned char transport_utf16le[] = {
	'\\', 0, 'D', 0, 'e', 0, 'v', 0, 'i', 0, 'c', 0, 'e', 0,
	'\\', 0, 'T', 0, 'c', 0, 'p', 0
};
#define TRANSPORT_CHARS 11u
#define TRANSPORT_BYTES (TRANSPORT_CHARS * 2u) /* 22 */

/* Little-endian readers: the buffer is a byte image of an NT structure,
 * so it is decoded as one rather than cast to a struct (which would
 * assume the very layout under test, and would also be an unaligned
 * access on a buffer this test deliberately re-offsets into). */
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

int main(void)
{
	unsigned long size, computed, value_off;
	unsigned long next_entry_offset, ea_value_length, ea_name_length;
	unsigned long name_len_bytes;
	unsigned char *alloc, *buf;
	const unsigned char *pkt;
	unsigned i;

	size = __afd_open_ea_size_for(SHAPE_NT6);

	/* Allocate size + a guard run, so "the builder writes exactly the
	 * bytes it declares" is checkable.  malloc() is at least 8-byte
	 * aligned everywhere spicule runs, which covers the 4-byte
	 * alignment NT requires of an EA entry (below). */
	alloc = malloc(size + GUARD);
	if (!alloc) { printf("FAIL %s: out of memory\n", __FILE__); return 1; }
	memset(alloc, GUARD_BYTE, size + GUARD);
	buf = alloc;
	__afd_build_open_ea_for(SHAPE_NT6, SOCKTYPE_STREAM, buf);

	/* --- 1. entry alignment -------------------------------------- *
	 * NtCreateFile probes the EA buffer at ULONG alignment and every
	 * entry begins on a 4-byte boundary (IoCheckEaBufferValidity()
	 * advances by ALIGN_UP_BY(ComputedLength, sizeof(ULONG))).  The
	 * single entry starts at the buffer itself. */
	CHECK_EQ((unsigned long)((size_t)buf % 4u), 0u, "EA buffer address % 4");

	/* --- 2. the header fields ------------------------------------ */
	next_entry_offset = rd32(buf + 0);
	ea_name_length = buf[5];
	ea_value_length = rd16(buf + 6);

	/* Single entry, so it is also the final entry: NextEntryOffset
	 * must be 0.  Any other value is read as "another entry follows
	 * at +NextEntryOffset" and must equal ALIGN_UP(ComputedLength, 4);
	 * with nothing after it that walks off the buffer. */
	CHECK_EQ(next_entry_offset, 0u, "NextEntryOffset");
	CHECK_EQ(buf[4], 0u, "Flags");
	CHECK_EQ(ea_name_length, EA_NAME_LEN, "EaNameLength");

	/* --- 3. the name: length excludes the NUL, buffer includes it - */
	CHECK(memcmp(buf + EA_HEADER, EA_NAME, EA_NAME_LEN) == 0);
	CHECK_EQ(ea_name_length, (unsigned long)strlen(EA_NAME), "EaNameLength vs strlen");
	/* IoCheckEaBufferValidity(): "Make sure the name is null terminated"
	 * -- Current->EaName[EaNameLength] != ANSI_NULL is a hard failure. */
	CHECK_EQ(buf[EA_HEADER + ea_name_length], 0u, "EaName[EaNameLength] (the terminator)");

	/* --- 4. where the value begins ------------------------------- *
	 * Immediately past the name's terminator: EA_HEADER + name + 1.
	 * That must also be 4-aligned, or every ULONG in the value below
	 * is a misaligned access on the kernel side. */
	value_off = EA_HEADER + ea_name_length + 1u;
	CHECK_EQ(value_off, 24u, "value offset");
	CHECK_EQ(value_off % 4u, 0u, "value offset % 4");

	/* --- 5. total length vs the sum of the entries ---------------- *
	 * IoCheckEaBufferValidity()'s ComputedLength, exactly:
	 *   EaValueLength + EaNameLength + FIELD_OFFSET(.., EaName) + 1.
	 * The declared total must be at least this (or the buffer is
	 * rejected as STATUS_EA_LIST_INCONSISTENT), and here it must be
	 * exactly this: __afd_open_ea_size() declares no byte the single
	 * entry does not describe. */
	computed = ea_value_length + ea_name_length + EA_HEADER + 1u;
	CHECK_EQ(size, computed, "declared EA length vs ComputedLength");
	CHECK(size >= computed);
	CHECK_EQ(size % 4u, 0u, "declared EA length % 4");

	/* --- 6. the value payload's own layout ------------------------ *
	 * Real Windows' AFD_OPEN_PACKET: a 24-byte header, then the
	 * transport device name in UTF-16.  ReactOS's AFD_CREATE_PACKET
	 * has a 12-byte header instead; if this ever regresses to that
	 * shape, PKT_ADDRESS_FAMILY onwards are name text and every check
	 * in this block fails. */
	pkt = buf + value_off;
	CHECK_EQ(ea_value_length, PKT_HEADER + TRANSPORT_BYTES + 2u, "EaValueLength");
	CHECK_EQ(rd32(pkt + PKT_ENDPOINT_FLAGS), 0u, "EndpointFlags");
	CHECK_EQ(rd32(pkt + PKT_GROUP_ID), 0u, "GroupID");
	CHECK_EQ(rd32(pkt + PKT_ADDRESS_FAMILY), WIN_AF_INET, "AddressFamily");
	CHECK_EQ(rd32(pkt + PKT_SOCKET_TYPE), WIN_SOCK_STREAM, "SocketType");
	CHECK_EQ(rd32(pkt + PKT_PROTOCOL), WIN_IPPROTO_TCP, "Protocol");

	/* --- 7. the device name: UTF-16, length in BYTES -------------- *
	 * The regression assertion for the reported defect.  Under the
	 * ReactOS layout this ULONG landed on characters 4-5 of
	 * "\Device\Tcp" ('i','c') and read back as 0x00630069 == 6488169,
	 * which afd.sys then used as a length -- hence
	 * STATUS_ACCESS_VIOLATION / EFAULT.  It must be a byte count of
	 * the name, i.e. exactly twice the character count, and it must
	 * fit inside the value the EA declares. */
	name_len_bytes = rd32(pkt + PKT_TRANSPORT_NAME_LENGTH);
	CHECK_EQ(name_len_bytes, TRANSPORT_BYTES, "TransportDeviceNameLength (bytes)");
	CHECK_EQ(name_len_bytes, 2u * TRANSPORT_CHARS, "TransportDeviceNameLength vs 2*chars");
	CHECK_EQ(name_len_bytes % 2u, 0u, "TransportDeviceNameLength % 2 (UTF-16)");
	CHECK(PKT_TRANSPORT_NAME + name_len_bytes <= ea_value_length);
	/* The name itself, UTF-16LE, followed by a UTF-16 NUL that the
	 * length does not count (ReactOS's WSPSocket copies
	 * TransportName.Length + sizeof(WCHAR); phnt's
	 * _Field_size_bytes_opt_ counts only the text). */
	CHECK(memcmp(pkt + PKT_TRANSPORT_NAME, transport_utf16le, sizeof(transport_utf16le)) == 0);
	CHECK_EQ(pkt[PKT_TRANSPORT_NAME + name_len_bytes], 0u, "device name terminator, low byte");
	CHECK_EQ(pkt[PKT_TRANSPORT_NAME + name_len_bytes + 1u], 0u, "device name terminator, high byte");
	/* ...and that NUL is the last thing in the declared value. */
	CHECK_EQ(PKT_TRANSPORT_NAME + name_len_bytes + 2u, ea_value_length,
	         "value end vs name + terminator");

	/* --- 8. the builder wrote nothing past what it declared ------- */
	for (i = 0; i < GUARD; i++)
		CHECK_EQ(alloc[size + i], GUARD_BYTE, "guard byte past the declared EA length");

	/* --- 9. and it is deterministic ------------------------------- *
	 * Two builds into differently-poisoned buffers must be identical:
	 * every declared byte is written, none left over from before. */
	{
		unsigned char *again = malloc(size);
		if (!again) { printf("FAIL %s: out of memory\n", __FILE__); free(alloc); return 1; }
		memset(again, 0x5A, size);
		__afd_build_open_ea_for(SHAPE_NT6, SOCKTYPE_STREAM, again);
		CHECK(memcmp(again, buf, size) == 0);
		free(again);
	}

	free(alloc);

	if (!fails) printf("posix-socket-ea: all tests passed\n");
	return fails != 0;
}
