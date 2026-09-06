/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The AFD-endpoint-creation and sockaddr<->TDI-address helpers every
 * src/socket/ (every .c there) file shares.  See src/internal/afd.h's banner for the
 * two sources this is checked against.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include "libc.h"
#include "afd.h"
#include "ownership_stubs.h"

/* TransportDeviceNameLength is a byte count, not a character count
 * (UTF-16); both transport names are 11 chars so one length serves
 * either. */
static const WCHAR afd_transport_tcp[] = AFD_TRANSPORT_TCP;
static const WCHAR afd_transport_udp[] = AFD_TRANSPORT_UDP;
#define AFD_TRANSPORT_WCHARS ((sizeof(afd_transport_tcp) / sizeof(WCHAR)) - 1) /* excludes the NUL */
#define AFD_TRANSPORT_BYTES (AFD_TRANSPORT_WCHARS * sizeof(WCHAR))

/* Build-time assertion: AFD_TRANSPORT_BYTES is computed from the TCP
 * name alone, so a differently-sized UDP name would silently mis-size
 * requests without this. */
typedef char __afd_transport_lengths_match[ // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- implementation-reserved namespace, same as every other libc-internal symbol
	(sizeof(afd_transport_udp) == sizeof(afd_transport_tcp)) ? 1 : -1];

static const WCHAR *afd_transport_for(int socktype)
{
	return socktype == SOCK_DGRAM ? afd_transport_udp : afd_transport_tcp;
}

/* Header size + name + NUL, not sizeof(AFD_OPEN_PACKET)/AFD_CREATE_PACKET
 * (those pad and count a placeholder TransportName[1]). The NUL is kept
 * in the buffer though not counted by the name-length field, matching
 * ReactOS's WSPSocket. */
#define AFD_OPEN_PACKET_BYTES(hdr) ((hdr) + AFD_TRANSPORT_BYTES + sizeof(WCHAR))

/* See afd.h.  The header byte count for a shape, and the only place
 * that mapping is written down. */
static unsigned long afd_shape_header(int shape)
{
	return shape == AFD_SHAPE_NT4
	     ? (unsigned long)AFD_CREATE_PACKET_HEADER_SIZE
	     : (unsigned long)AFD_OPEN_PACKET_HEADER_SIZE;
}

/* Version-gated rather than probed: handing either driver the other's
 * layout succeeds, so there's no failure to probe for. Threshold is NT
 * 6.0, matching ReactOS's apitest; an unversioned platform is treated
 * as modern. */
int __afd_open_shape(void)
{
	return __nt_version_at_least(6, 0) ? AFD_SHAPE_NT6 : AFD_SHAPE_NT4;
}

/* Exact fit matching NT's IoCheckEaBufferValidity() ComputedLength
 * (FIELD_OFFSET(EaName) + EaNameLength + 1 + EaValueLength) -- not
 * ReactOS's WSPSocket formula, which pads 3 bytes larger and leaves the
 * total 4-misaligned. */
unsigned long __afd_open_ea_size_for(int shape)
{
	return (unsigned long)(AFD_EA_HEADER_SIZE + AFD_EA_NAME_LEN + 1
	                       + AFD_OPEN_PACKET_BYTES(afd_shape_header(shape)));
}

unsigned long __afd_open_ea_size(void)
{
	return __afd_open_ea_size_for(__afd_open_shape());
}

/* The two shapes are written out separately in full, not shared via
 * offset arithmetic, since they differ by three fields in the middle. */
void __afd_build_open_ea_for(int shape, int socktype, void *buf)
{
	FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION *)buf;
	unsigned long hdr = afd_shape_header(shape);
	const WCHAR *transport = afd_transport_for(socktype);
	void *value;

	__ownership_writable_span(buf, __afd_open_ea_size_for(shape));
	memset(buf, 0, __afd_open_ea_size_for(shape));

	/* Single, final entry: NextEntryOffset is 0 (a non-zero value
	 * would require another entry to follow). */
	ea->NextEntryOffset = 0;
	ea->Flags = 0;
	/* Excludes the NUL, but the validator checks
	 * EaName[EaNameLength] == '\0', so the copy below is +1. */
	ea->EaNameLength = AFD_EA_NAME_LEN;
	__ownership_writable_span(ea->EaName, AFD_EA_NAME_LEN + 1);
	memcpy(ea->EaName, AFD_EA_NAME, AFD_EA_NAME_LEN + 1);
	ea->EaValueLength = (unsigned short)AFD_OPEN_PACKET_BYTES(hdr);

	/* Starts right after the name's NUL; with a 15-byte name that's
	 * offset 24, keeping the packet's uint32_t fields aligned. */
	value = (void *)(ea->EaName + AFD_EA_NAME_LEN + 1);

	if (shape == AFD_SHAPE_NT4) {
		/* ReactOS sdk/include/reactos/drivers/afd/shared.h's
		 * AFD_CREATE_PACKET, read back by AfdCreateSocket() in
		 * drivers/network/afd/afd/main.c. */
		AFD_CREATE_PACKET *pkt = (AFD_CREATE_PACKET *)value;
		pkt->EndpointFlags = 0; /* connection-oriented */
		pkt->GroupID = 0;
		pkt->SizeOfTransportName = (uint32_t)AFD_TRANSPORT_BYTES;
		__ownership_writable_span(pkt->TransportName,
		                          AFD_TRANSPORT_BYTES + sizeof(WCHAR));
		memcpy(pkt->TransportName, transport, AFD_TRANSPORT_BYTES + sizeof(WCHAR));
	} else {
		/* phnt ntafd.h's AFD_OPEN_PACKET. */
		AFD_OPEN_PACKET *pkt = (AFD_OPEN_PACKET *)value;
		pkt->EndpointFlags = 0; /* not CONNECTIONLESS/RAW/MESSAGE_ORIENTED */
		pkt->GroupID = 0;
		/* Fields ReactOS's AFD_CREATE_PACKET lacks. socktype must
		 * agree with the transport device name (via
		 * afd_transport_for()) or afd.sys opens a mismatched
		 * endpoint. */
		pkt->AddressFamily = AF_INET;
		pkt->SocketType = socktype;
		pkt->Protocol = socktype == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP;
		pkt->TransportDeviceNameLength = (uint32_t)AFD_TRANSPORT_BYTES;
		__ownership_writable_span(pkt->TransportDeviceName,
		                          AFD_TRANSPORT_BYTES + sizeof(WCHAR));
		memcpy(pkt->TransportDeviceName, transport, AFD_TRANSPORT_BYTES + sizeof(WCHAR));
	}
}

void __afd_build_open_ea(void *buf)
{
	__afd_build_open_ea_for(__afd_open_shape(), SOCK_STREAM, buf);
}

/* __afd_open()/__afd_ioctl() (declared in afd.h) live in
 * src/socket/nt/plat_socket.c; this file is the pure byte-marshaling
 * half -- EA/request/reply builders that issue no syscalls of their
 * own. */

/* sockaddr_in -> TRANSPORT_ADDRESS. AF_INET is this project's only
 * supported family (else EAFNOSUPPORT); TCP and UDP share this same
 * marshaling since the TDI wire address is identical either way.
 *
 * Written through afd.h's TDI_IP_OFF_* offsets rather than a
 * TDI_ADDRESS_IP struct: tdi.h packs that struct to 1, so in_addr sits
 * at +2, not the +4 a plain C struct would give it. */
int __afd_addr_from_sockaddr(const struct sockaddr *restrict addr, socklen_t len, TRANSPORT_ADDRESS *restrict out)
{
	const struct sockaddr_in *sin;
	if (!addr || len < (socklen_t)sizeof(struct sockaddr_in)) { errno = EINVAL; return -1; }
	if (addr->sa_family != AF_INET) { errno = EAFNOSUPPORT; return -1; }

	sin = (const struct sockaddr_in *)addr;
	out->TAAddressCount = 1;
	/* Length of the *address*, i.e. the sockaddr minus its family --
	 * 14 for sockaddr_in, never sizeof() of a padded struct. */
	out->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	/* AddressType overlays sa_family, and AF_INET == TDI_ADDRESS_TYPE_IP == 2. */
	out->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	memset(out->Address[0].Address, 0, TDI_ADDRESS_LENGTH_IP);
	__ownership_writable_span(out->Address[0].Address + TDI_IP_OFF_PORT, sizeof(sin->sin_port));
	memcpy(out->Address[0].Address + TDI_IP_OFF_PORT, &sin->sin_port, sizeof(sin->sin_port));
	__ownership_writable_span(out->Address[0].Address + TDI_IP_OFF_ADDR, sizeof(sin->sin_addr.s_addr));
	memcpy(out->Address[0].Address + TDI_IP_OFF_ADDR, &sin->sin_addr.s_addr, sizeof(sin->sin_addr.s_addr));
	/* sin_zero is already zeroed by the memset above. */
	return 0;
}

/* See afd.h.  26, not sizeof(AFD_BIND_DATA) (28). */
unsigned long __afd_bind_request_size(void)
{
	return (unsigned long)AFD_BIND_REQ_SIZE;
}

/* See afd.h. */
int __afd_build_bind_request(void *buf, unsigned long share_type,
                             const struct sockaddr *addr, socklen_t len)
{
	AFD_BIND_DATA *bd = (AFD_BIND_DATA *)buf;

	if (__afd_addr_from_sockaddr(addr, len, &bd->Address) < 0) return -1;
	bd->ShareType = (uint32_t)share_type;
	return 0;
}

/* 46 on x86_64, 34 on i386 -- not sizeof(AFD_CONNECT_INFO), which pads
 * the tail. IOCTL_AFD_CONNECT is METHOD_NEITHER, so this size is the
 * only bound afd.sys has on the address it reads. */
unsigned long __afd_connect_request_size(void)
{
	return (unsigned long)AFD_CONNECT_REQ_SIZE;
}

/* Written through byte offsets, not AFD_CONNECT_INFO members: the two
 * reference sources disagree on RemoteAddress's position (x86_64 only),
 * and offset arithmetic keeps that visible instead of hiding it in
 * padding.
 *
 * SanActive/RootEndpoint/ConnectEndpoint are zero for an ordinary
 * connect() -- no SAN provider, no WSAJoinLeaf multipoint endpoints. */
int __afd_build_connect_request(void *buf, const struct sockaddr *addr, socklen_t len)
{
	unsigned char *p = (unsigned char *)buf;
	TRANSPORT_ADDRESS ta;

	/* Validate before writing anything, so a rejected address leaves
	 * the caller's buffer untouched. */
	if (__afd_addr_from_sockaddr(addr, len, &ta) < 0) return -1;

	__ownership_writable_span(p, (size_t)AFD_CONNECT_REQ_SIZE);
	memset(p, 0, (size_t)AFD_CONNECT_REQ_SIZE);
	/* SanActive / RootEndpoint / ConnectEndpoint: already zero. */
	{
		uint32_t count = (uint32_t)ta.TAAddressCount;
		unsigned short l = ta.Address[0].AddressLength;
		unsigned short t = ta.Address[0].AddressType;
		__ownership_writable_span(p + AFD_CONNECT_REQ_OFF_ADDR_COUNT, sizeof(count));
		memcpy(p + AFD_CONNECT_REQ_OFF_ADDR_COUNT, &count, sizeof(count));
		__ownership_writable_span(p + AFD_CONNECT_REQ_OFF_ADDR_LENGTH, sizeof(l));
		memcpy(p + AFD_CONNECT_REQ_OFF_ADDR_LENGTH, &l, sizeof(l));
		__ownership_writable_span(p + AFD_CONNECT_REQ_OFF_ADDR_TYPE, sizeof(t));
		memcpy(p + AFD_CONNECT_REQ_OFF_ADDR_TYPE, &t, sizeof(t));
		__ownership_writable_span(p + AFD_CONNECT_REQ_OFF_ADDR,
		                          TDI_ADDRESS_LENGTH_IP);
		memcpy(p + AFD_CONNECT_REQ_OFF_ADDR, ta.Address[0].Address, TDI_ADDRESS_LENGTH_IP);
	}
	return 0;
}

/* ---- IOCTL_AFD_SELECT request/reply, by offset -----------------------
 *
 * ReactOS's ULONG_PTR Exclusive puts Handles at +24 on x86_64, where
 * phnt/wepoll/libuv all put it at +16; everything here uses named
 * offsets so no compiler's ULONG_PTR layout can move the array again. */

/* See afd.h. */
unsigned long __afd_poll_request_size(unsigned long nhandles)
{
	return (unsigned long)AFD_POLL_REQ_SIZE(nhandles);
}

/* Timeout is a plain LONGLONG (no .QuadPart union here), memcpy'd
 * rather than cast-stored so the buffer needs only pointer alignment. */
void __afd_build_poll_request(void *buf, long long timeout, unsigned long nhandles) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char *p = (unsigned char *)buf;
	uint32_t count = (uint32_t)nhandles;
	uint32_t exclusive = 0;

	__ownership_writable_span(p, AFD_POLL_REQ_SIZE(nhandles));
	memset(p, 0, AFD_POLL_REQ_SIZE(nhandles));
	__ownership_writable_span(p + AFD_POLL_REQ_OFF_TIMEOUT, sizeof(timeout));
	memcpy(p + AFD_POLL_REQ_OFF_TIMEOUT, &timeout, sizeof(timeout));
	__ownership_writable_span(p + AFD_POLL_REQ_OFF_HANDLE_COUNT, sizeof(count));
	memcpy(p + AFD_POLL_REQ_OFF_HANDLE_COUNT, &count, sizeof(count));
	/* Four bytes, always zero. Must stay zero: AfdPoll() reads it as
	 * Unique, and non-zero cancels any other unique poll IRP on the
	 * same file object (STATUS_CANCELLED) -- silently breaking a
	 * concurrent select()/poll() on the same socket. */
	__ownership_writable_span(p + AFD_POLL_REQ_OFF_EXCLUSIVE, sizeof(exclusive));
	memcpy(p + AFD_POLL_REQ_OFF_EXCLUSIVE, &exclusive, sizeof(exclusive));
}

/* See afd.h. */
void __afd_poll_set_handle(void *buf, unsigned long i, HANDLE h, uint32_t events)
{
	unsigned char *e = (unsigned char *)buf + AFD_POLL_REQ_OFF_HANDLES + (size_t)i * AFD_POLL_H_SIZE;
	uint32_t zero = 0;

	__ownership_writable_span(e + AFD_POLL_H_OFF_HANDLE, sizeof(h));
	memcpy(e + AFD_POLL_H_OFF_HANDLE, (const void *)&h, sizeof(h));
	__ownership_writable_span(e + AFD_POLL_H_OFF_EVENTS, sizeof(events));
	memcpy(e + AFD_POLL_H_OFF_EVENTS, &events, sizeof(events));
	__ownership_writable_span(e + AFD_POLL_H_OFF_STATUS, sizeof(zero));
	memcpy(e + AFD_POLL_H_OFF_STATUS, &zero, sizeof(zero));
}

/* IOCTL_AFD_SELECT is METHOD_BUFFERED: afd.sys writes observed events
 * back into these same slots. */
uint32_t __afd_poll_get_events(const void *buf, unsigned long i)
{
	const unsigned char *e = (const unsigned char *)buf + AFD_POLL_REQ_OFF_HANDLES + (size_t)i * AFD_POLL_H_SIZE;
	uint32_t events;

	__ownership_readable_span(e + AFD_POLL_H_OFF_EVENTS, sizeof(events));
	memcpy(&events, e + AFD_POLL_H_OFF_EVENTS, sizeof(events));
	return events;
}

/* See afd.h.  The reply's own count -- the *only* thing that says how
 * many of the Handles[] slots afd.sys actually wrote. */
uint32_t __afd_poll_get_handle_count(const void *buf)
{
	uint32_t count;

	__ownership_readable_span((const unsigned char *)buf + AFD_POLL_REQ_OFF_HANDLE_COUNT,
	                          sizeof(count));
	memcpy(&count, (const unsigned char *)buf + AFD_POLL_REQ_OFF_HANDLE_COUNT, sizeof(count));
	return count;
}

/* Matches by handle, not request-slot index: AfdPoll() compacts its
 * output, advancing the output pointer only for endpoints that fired,
 * so output slot i is unrelated to request slot i once more than one
 * handle is polled. */
uint32_t __afd_poll_events_for(const void *buf, unsigned long nrequested, HANDLE h)
{
	uint32_t count = __afd_poll_get_handle_count(buf);
	unsigned long i;

	/* Reply can't name more handles than requested; clamp rather than
	 * trust it and read past the buffer. */
	if ((unsigned long long)count > (unsigned long long)nrequested)
		count = (uint32_t)nrequested;

	for (i = 0; i < (unsigned long)count; i++) {
		const unsigned char *e = (const unsigned char *)buf + AFD_POLL_REQ_OFF_HANDLES
		                       + (size_t)i * AFD_POLL_H_SIZE;
		HANDLE eh;

		__ownership_readable_span(e + AFD_POLL_H_OFF_HANDLE, sizeof(eh));
		memcpy((void *)&eh, e + AFD_POLL_H_OFF_HANDLE, sizeof(eh));
		if (eh == h) {
			uint32_t events;
			__ownership_readable_span(e + AFD_POLL_H_OFF_EVENTS, sizeof(events));
			memcpy(&events, e + AFD_POLL_H_OFF_EVENTS, sizeof(events));
			return events;
		}
	}
	/* Not named in the reply means no event fired -- a real answer,
	 * not a failure to obtain one. */
	return 0;
}

/* See afd.h. */
NTSTATUS __afd_poll_get_status(const void *buf, unsigned long i)
{
	const unsigned char *e = (const unsigned char *)buf + AFD_POLL_REQ_OFF_HANDLES + (size_t)i * AFD_POLL_H_SIZE;
	NTSTATUS st;

	__ownership_readable_span(e + AFD_POLL_H_OFF_STATUS, sizeof(st));
	memcpy(&st, e + AFD_POLL_H_OFF_STATUS, sizeof(st));
	return st;
}

/* TA_ADDRESS -> sockaddr_in, truncating into *addr and *len the way
 * accept.html specifies ("If...address_len is not large enough...
 * stored address shall be truncated").  Reads the same packed offsets
 * __afd_addr_from_sockaddr() writes. */
void __afd_addr_to_sockaddr(const TA_ADDRESS *ta, struct sockaddr *addr, socklen_t *len)
{
	struct sockaddr_in sin;
	const unsigned char *a = ta->Address;
	socklen_t n;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	memcpy(&sin.sin_port, a + TDI_IP_OFF_PORT, sizeof(sin.sin_port));
	memcpy(&sin.sin_addr.s_addr, a + TDI_IP_OFF_ADDR, sizeof(sin.sin_addr.s_addr));

	if (!addr || !len) return;
	n = *len < (socklen_t)sizeof(sin) ? *len : (socklen_t)sizeof(sin);
	__ownership_writable_span(addr, n);
	memcpy(addr, &sin, n);
	*len = sizeof(sin);
}

/* Two fields checked, both load-bearing. TAAddressCount says whether an
 * address is present at all -- this buffer is out-only, so an unwritten
 * Address[0] is uninitialised stack, not a request readback. AddressLength
 * stands in for a length check on IoStatus.Information: the driver
 * zeroes it on a short copy-back, so rejecting zero rejects a truncated
 * reply with no second source of truth needed. AddressType is skipped --
 * AF_INET is the only family this library ever produces.
 *
 * Offsets are +0/+4 literally, not via AFD_*_RSP_OFF_* names, since
 * those differ per reply while a TRANSPORT_ADDRESS's own layout does
 * not. */
int __afd_transport_addr_out(const void *tap, struct sockaddr *addr, socklen_t *len)
{
	const unsigned char *p = (const unsigned char *)tap;
	TA_ADDRESS ta;
	int32_t count;
	unsigned short alen;

	__ownership_readable_span(p, sizeof(count));
	memcpy(&count, p, sizeof(count));
	if (count < 1) return -1;

	__ownership_readable_span(p + 4, sizeof(alen));
	memcpy(&alen, p + 4, sizeof(alen));
	if (alen < TDI_ADDRESS_LENGTH_IP) return -1;

	if (!addr || !len) return 0;

	/* Copied by byte count rather than through a TA_ADDRESS * aimed
	 * at the buffer: the caller's buffer need not be aligned, and
	 * tests hand it a plain unsigned char image. */
	memset(&ta, 0, sizeof(ta));
	__ownership_readable_span(p + 4, (size_t)(2 + 2 + TDI_ADDRESS_LENGTH_IP));
	memcpy(&ta, p + 4, (size_t)(2 + 2 + TDI_ADDRESS_LENGTH_IP));
	__afd_addr_to_sockaddr(&ta, addr, len);
	return 0;
}

/* See afd.h.  The wait-for-listen reply is a TRANSPORT_ADDRESS behind a
 * ULONG SequenceNumber, so the whole of this function is that offset. */
int __afd_accept_reply_addr(const void *reply, struct sockaddr *addr, socklen_t *len)
{
	return __afd_transport_addr_out((const unsigned char *)reply + AFD_ACCEPT_RSP_OFF_ADDR_COUNT,
	                                addr, len);
}

/* Separate functions, not one taking an offset argument: each ioctl has
 * exactly one right answer, and a caller able to pass the other one is
 * the bug this shape exists to prevent. These make the two name
 * replies' differing sizes (26 bytes w/ ActivityCount vs 22 without)
 * reachable from tests with no \Device\Afd. */
unsigned long __afd_sockname_reply_size(void)
{
	return (unsigned long)AFD_SOCKNAME_RSP_SIZE;
}

int __afd_sockname_reply_addr(const void *reply, struct sockaddr *addr, socklen_t *len)
{
	return __afd_transport_addr_out((const unsigned char *)reply + AFD_SOCKNAME_RSP_OFF_ADDR,
	                                addr, len);
}

unsigned long __afd_peername_reply_size(void)
{
	return (unsigned long)AFD_PEERNAME_RSP_SIZE;
}

int __afd_peername_reply_addr(const void *reply, struct sockaddr *addr, socklen_t *len)
{
	return __afd_transport_addr_out((const unsigned char *)reply + AFD_PEERNAME_RSP_OFF_ADDR,
	                                addr, len);
}

// NOLINTEND(misc-include-cleaner)
