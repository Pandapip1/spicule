/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Structural invariants of the IOCTL_AFD_SELECT request/reply buffer
 * src/socket/afdsupport.c's __afd_build_poll_request() family builds
 * and reads back on behalf of src/select/select.c's __fd_probe().
 *
 * That __FD_SOCKET case was not reachable when this file was written
 * -- both callers of __fd_probe() routed only pipes to it -- so this
 * file was what held the wire format correct in the meantime, with no
 * socket and no device needed to do it.  Both callers now route
 * sockets there too (see src/select/select.c's banner), and
 * test/posix-select-socket.c exercises the live path where a real AFD
 * endpoint exists; this file keeps its value regardless, since it is
 * the only check of this layout that runs where no device does.
 *
 * The fourth of the sibling set (test/posix-socket-ea.c, -bind.c,
 * -connect.c), built the same way and for the same reason: it opens no
 * socket and touches no device, so it runs identically on a host with
 * no \Device\Afd, under Wine, under `make asan` natively, and on CI's
 * real-Windows legs.  Its siblings pass on real Windows.
 *
 * *** The defect this is the regression assertion for. ***
 *
 * ReactOS sdk/include/reactos/drivers/afd/shared.h declares
 *
 *      LARGE_INTEGER Timeout;      +0
 *      ULONG         HandleCount;  +8
 *      ULONG_PTR     Exclusive;    +12 on i386, +16 on x86_64
 *      AFD_HANDLE    Handles[1];   +16 on i386, +24 on x86_64
 *
 * and spicule followed it.  The AFD driver's own source says that
 * middle field is not pointer-sized -- afd.h, "Structures for
 * IOCTL_AFD_POLL" (Copyright (c) 1992 Microsoft Corporation;
 * sources.inc MAJORCOMP=ntos MINORCOMP=afd):
 *
 *      typedef struct _AFD_POLL_INFO {
 *          LARGE_INTEGER Timeout;
 *          ULONG NumberOfHandles;
 *          BOOLEAN Unique;
 *          AFD_POLL_HANDLE_INFO Handles[1];
 *      } AFD_POLL_INFO, *PAFD_POLL_INFO;
 *
 * -- and its poll.c AfdPoll() reads ->Unique, ->NumberOfHandles and
 * ->Handles straight out of Irp->AssociatedIrp.SystemBuffer.  Three
 * later, independent, x64-era sources put Handles at that same +16 on
 * *both* ABIs:
 *
 *   - System Informer phnt, ntafd.h, AFD_POLL_INFO: character for
 *     character the Microsoft declaration above.
 *   - wepoll (github.com/piscisaureus/wepoll, wepoll.c):
 *       LARGE_INTEGER Timeout; ULONG NumberOfHandles; ULONG Exclusive;
 *       AFD_POLL_HANDLE_INFO Handles[1];
 *     with IOCTL_AFD_POLL spelled as the literal 0x00012024, which is
 *     _AFD_CONTROL_CODE(AFD_POLL = 9, METHOD_BUFFERED).
 *   - libuv, include/uv/win.h, _AFD_POLL_INFO: identical to wepoll's.
 *
 * The last two are not transcriptions of a header -- they are working
 * code driving the shipping afd.sys on x86 and x64 at very large
 * volume (libuv is Node.js's event loop).  A Handles array 8 bytes out
 * of place on x64 would not survive that.  ReactOS dissents alone.
 *
 * Those sources do disagree about that field's *type* (BOOLEAN Unique
 * for Microsoft and phnt, ULONG Exclusive for wepoll and libuv).  This
 * test does not resolve that and does not need to: all of them put
 * four bytes at +12 before an 8-aligned Handles, and spicule always
 * sends zero there, which is the same four zero bytes either way.
 * What is asserted is the four bytes and the zero.
 *
 * With ReactOS's layout on x86_64 the Handles array starts 8 bytes
 * late, so the driver reads the socket HANDLE out of the caller's
 * Exclusive/padding and the requested event mask out of the handle's
 * low half.  Observed rather than reasoned: issuing the ioctl that way
 * on a real AFD endpoint returns STATUS_INVALID_HANDLE (0xC0000008)
 * where the +16 form returns STATUS_SUCCESS, and __fd_probe() maps a
 * failed ioctl to "ready, and hung up" -- deliberately, so that a
 * socket whose state cannot be sampled cannot hang an infinite-timeout
 * select()/poll(); see that function's comment.  main()'s negative
 * control reproduces that byte image and proves these assertions
 * reject it.
 *
 * The test/ sources are built with -Iarch/$(ARCH) -Iarch/generic -Iobj/include
 * -Iinclude only (see Makefile) -- src/internal/ is NOT on the include
 * path -- so the prototypes and every expected constant are declared
 * locally, exactly as the siblings do.  A layout test that included
 * the header it is checking would agree with it by construction.
 *
 * Further references: the AFD_POLL_* event bits asserted below are
 * phnt ntafd.h's AFD_POLL_RECEIVE/SEND/DISCONNECT/ABORT/LOCAL_CLOSE/
 * CONNECT/ACCEPT/CONNECT_FAIL, which equal ReactOS shared.h's
 * AFD_EVENT_* and wepoll's/libuv's AFD_POLL_* -- all four sources
 * agree on those, unlike the structure around them.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(got, want, what) do { \
	unsigned long long g_ = (unsigned long long)(got), w_ = (unsigned long long)(want); \
	if (g_ != w_) { fails++; \
		printf("FAIL %s:%d: %s = %llu (0x%llx), want %llu (0x%llx)\n", \
		       __FILE__, __LINE__, (what), g_, g_, w_, w_); } \
} while (0)

/* src/internal/afd.h; see the banner for why they are re-declared.
 * HANDLE is a PVOID (winnt.h), spelled void * here so this file needs
 * nothing from src/internal/. */
unsigned long __afd_poll_request_size(unsigned long nhandles);
void __afd_build_poll_request(void *buf, long long timeout, unsigned long nhandles);
void __afd_poll_set_handle(void *buf, unsigned long i, void *h, uint32_t events);
uint32_t __afd_poll_get_events(const void *buf, unsigned long i);
int32_t __afd_poll_get_status(const void *buf, unsigned long i);
uint32_t __afd_poll_get_handle_count(const void *buf);
uint32_t __afd_poll_events_for(const void *buf, unsigned long nrequested, void *h);

/* --- constants, from the references named in the banner --- */

/* sizeof(HANDLE) == sizeof(PVOID): 4 on i386, 8 on x86_64.  Only the
 * Handles *element* size depends on it here; the header offsets below
 * are the same on both ABIs, which is what makes ReactOS's
 * pointer-sized Exclusive the anomaly. */
/* size_t throughout, never `unsigned long`: this target is LLP64, so
 * `unsigned long` is 32 bits while a pointer is 64, and `i * H_SIZE`
 * spelled in unsigned long would multiply in 32 bits and only then
 * widen for the pointer arithmetic below. */
#define HSZ (sizeof(void *))

#define REQ_TIMEOUT      ((size_t)0)
#define REQ_HANDLE_COUNT ((size_t)8)
#define REQ_EXCLUSIVE    ((size_t)12)
#define REQ_HANDLES      ((size_t)16)

#define H_HANDLE  ((size_t)0)
#define H_EVENTS  HSZ
#define H_STATUS  (HSZ + 4)
#define H_SIZE    (HSZ + 8)   /* 16 on x86_64, 12 on i386 */

#define REQ_SIZE(n) (REQ_HANDLES + (size_t)(n) * H_SIZE)

/* ReactOS's layout, for the negative control: Exclusive is ULONG_PTR,
 * so it is pointer-aligned and pointer-sized. */
#define ROS_HANDLES    (HSZ == 8 ? (size_t)24 : (size_t)16)
#define ROS_SIZE(n)    (ROS_HANDLES + (size_t)(n) * H_SIZE)

/* The event bits all four sources agree on (phnt AFD_POLL_*, ReactOS
 * AFD_EVENT_*, wepoll/libuv AFD_POLL_*). */
#define EV_RECEIVE      0x0001u
#define EV_OOB_RECEIVE  0x0002u
#define EV_SEND         0x0004u
#define EV_DISCONNECT   0x0008u
#define EV_ABORT        0x0010u
#define EV_LOCAL_CLOSE  0x0020u
#define EV_CONNECT      0x0040u
#define EV_ACCEPT       0x0080u
#define EV_CONNECT_FAIL 0x0100u

/* Little-endian readers: the buffer is a byte image of an NT structure,
 * so it is decoded as one rather than cast to a struct (which would
 * assume the very layout under test). */
static unsigned long rd32(const unsigned char *p)
{
	return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
	     | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned long long rd64(const unsigned char *p)
{
	return (unsigned long long)rd32(p) | ((unsigned long long)rd32(p + 4) << 32);
}
/* A pointer read back byte-wise, so no assumption is made about where
 * within the element the compiler would have put it. */
static unsigned long long rdptr(const unsigned char *p)
{
	return HSZ == 8 ? rd64(p) : (unsigned long long)rd32(p);
}

#define GUARD 16u
#define GUARD_BYTE 0xABu

/* Distinct, recognisable fake handles.  Never dereferenced -- this
 * file touches no device -- but chosen so a byte landing at the wrong
 * offset is obvious in a failure message. */
static void *fake_handle(unsigned i)
{
	return (void *)(uintptr_t)(0x11110000UL + (i + 1) * 0x101UL);
}

/* Every offset assertion, factored out so main() can run the identical
 * battery against a deliberately-wrong image and count how many fire.
 * `report` selects whether a failure is printed and charged to the
 * global count (the real image) or merely counted (the control).  The
 * two callers must be indistinguishable to this function -- that is
 * what makes the negative control mean anything. */
static int verify_image(const unsigned char *buf, size_t size,
                        size_t n, long long timeout, int report)
{
	int local = 0;
	size_t i, j;

#define V(cond, what) do { \
	if (!(cond)) { local++; \
		if (report) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (what)); } } \
} while (0)
#define V_EQ(got, want, what) do { \
	unsigned long long g_ = (unsigned long long)(got), w_ = (unsigned long long)(want); \
	if (g_ != w_) { local++; \
		if (report) { fails++; \
			printf("FAIL %s:%d: %s = %llu (0x%llx), want %llu (0x%llx)\n", \
			       __FILE__, __LINE__, (what), g_, g_, w_, w_); } } \
} while (0)

	/* --- 1. size ------------------------------------------------- *
	 * 16 + n * (sizeof(HANDLE) + 8).  Not sizeof(AFD_POLL_INFO),
	 * which rounds the tail up for Timeout's 8-byte alignment. */
	V_EQ(size, REQ_SIZE(n), "request size");

	/* --- 2. the AFD_POLL_INFO header ----------------------------- *
	 * The whole disagreement lives between +8 and +16. */
	V_EQ(rd64(buf + REQ_TIMEOUT), (unsigned long long)timeout, "Timeout");
	V_EQ(rd32(buf + REQ_HANDLE_COUNT), n, "HandleCount");
	/* Exclusive/Unique: four bytes at +12, always zero.  Asserting
	 * the four bytes is the assertion; the type is what phnt and
	 * wepoll/libuv still disagree about (see the banner). */
	V_EQ(rd32(buf + REQ_EXCLUSIVE), 0u, "Exclusive/Unique");
	/* ...and this is the assertion the file exists for: the array
	 * begins at +16 on both ABIs, NOT at ReactOS's +24 on x86_64. */
	V_EQ(REQ_HANDLES, 16u, "Handles offset");
	V_EQ(REQ_HANDLES, REQ_EXCLUSIVE + 4u, "Handles vs Exclusive + 4");

	/* --- 3. the AFD_HANDLE array --------------------------------- *
	 * HANDLE, then two 32-bit fields; 16 bytes per element on
	 * x86_64 and 12 on i386.  Every element is checked, so a stride
	 * error shows up as well as a base error. */
	V_EQ(H_SIZE, HSZ + 8u, "AFD_HANDLE size");
	V_EQ(H_EVENTS, HSZ, "AFD_HANDLE.Events offset");
	V_EQ(H_STATUS, HSZ + 4u, "AFD_HANDLE.Status offset");
	for (i = 0; i < n; i++) {
		const unsigned char *e = buf + REQ_HANDLES + i * H_SIZE;
		V_EQ(rdptr(e + H_HANDLE), (unsigned long long)(uintptr_t)fake_handle((unsigned)i),
		     "AFD_HANDLE.Handle");
		V_EQ(rd32(e + H_EVENTS), EV_RECEIVE | EV_SEND | (unsigned)(i + 1),
		     "AFD_HANDLE.Events");
		V_EQ(rd32(e + H_STATUS), 0u, "AFD_HANDLE.Status");
		/* The accessors must agree with the raw bytes -- if they
		 * did not, the ioctl's reply would be read from somewhere
		 * other than where the request was written. */
		V_EQ(__afd_poll_get_events(buf, (unsigned long)i), rd32(e + H_EVENTS), "get_events vs raw");
		V_EQ((uint32_t)__afd_poll_get_status(buf, (unsigned long)i), rd32(e + H_STATUS),
		     "get_status vs raw");
		/* Elements must not overlap and must be contiguous. */
		if (i + 1 < n)
			V_EQ((size_t)((buf + REQ_HANDLES + (i + 1) * H_SIZE) - e), H_SIZE,
			     "stride between elements");
	}
	/* The last element must end exactly on the declared size. */
	if (n > 0)
		V_EQ(REQ_HANDLES + (n - 1) * H_SIZE + H_SIZE, size, "last element ends at size");

	/* --- 4. alignment -------------------------------------------- *
	 * The HANDLE at +16 must be naturally aligned for a
	 * pointer-aligned buffer, which is what the driver's kernel copy
	 * of a METHOD_BUFFERED request gets. */
	V_EQ(REQ_HANDLES % HSZ, 0u, "Handles offset % sizeof(HANDLE)");
	V_EQ(REQ_TIMEOUT % 8u, 0u, "Timeout offset % 8");
	V_EQ(REQ_HANDLE_COUNT % 4u, 0u, "HandleCount offset % 4");
	for (j = 0; j < n; j++)
		V_EQ((REQ_HANDLES + j * H_SIZE) % HSZ, 0u, "element offset % sizeof(HANDLE)");

	/* --- 5. the absolute numbers, per ABI ------------------------ */
	if (HSZ == 8) {
		V_EQ(H_SIZE, 16u, "x86_64: AFD_HANDLE size");
		V_EQ(size, 16u + n * 16u, "x86_64: request size");
	} else {
		V_EQ(HSZ, 4u, "sizeof(HANDLE) is 4 or 8");
		V_EQ(H_SIZE, 12u, "i386: AFD_HANDLE size");
		V_EQ(size, 16u + n * 12u, "i386: request size");
	}
#undef V
#undef V_EQ
	return local;
}

/* The image ReactOS's AFD_POLL_INFO would have produced, built here by
 * hand so the control does not depend on spicule ever having contained
 * it: ULONG_PTR Exclusive, hence Handles at +24 on x86_64. */
static void build_reactos_image(unsigned char *buf, long long timeout, size_t n)
{
	uint32_t count = (uint32_t)n;
	size_t i;

	memset(buf, 0, (size_t)ROS_SIZE(n));
	memcpy(buf + REQ_TIMEOUT, &timeout, sizeof(timeout));
	memcpy(buf + REQ_HANDLE_COUNT, &count, sizeof(count));
	/* Exclusive: pointer-sized, zero. */
	for (i = 0; i < n; i++) {
		unsigned char *e = buf + ROS_HANDLES + i * H_SIZE;
		void *h = fake_handle((unsigned)i);
		uint32_t ev = (uint32_t)(EV_RECEIVE | EV_SEND | (unsigned)(i + 1));
		uint32_t zero = 0;
		memcpy(e + H_HANDLE, &h, sizeof(h));
		memcpy(e + H_EVENTS, &ev, sizeof(ev));
		memcpy(e + H_STATUS, &zero, sizeof(zero));
	}
}

/* Build one request for n handles and check every offset in it. */
static void check_n(size_t n, long long timeout)
{
	unsigned char *alloc, *buf;
	size_t size, slop;
	unsigned i;

	size = __afd_poll_request_size((unsigned long)n);
	/* The tail sizeof(AFD_POLL_INFO) rounds up to is allowed to be
	 * touched; 8 covers it on either ABI. */
	slop = 8;
	alloc = malloc((size_t)(size + slop + GUARD));
	if (!alloc) { printf("FAIL %s: out of memory\n", __FILE__); fails++; return; }
	memset(alloc, GUARD_BYTE, (size_t)(size + slop + GUARD));
	buf = alloc;

	__afd_build_poll_request(buf, timeout, n);
	for (i = 0; i < n; i++)
		__afd_poll_set_handle(buf, i, fake_handle(i), (uint32_t)(EV_RECEIVE | EV_SEND | (i + 1)));

	CHECK_EQ((size_t)buf % sizeof(void *), 0u, "request address % sizeof(HANDLE)");
	(void)verify_image(buf, size, n, timeout, 1);

	/* Nothing written past the declared length. */
	for (i = 0; i < GUARD; i++)
		CHECK_EQ(alloc[size + slop + i], GUARD_BYTE, "guard byte past the request");

	/* Deterministic, and the builder zeroes what it does not set --
	 * it must not leak whatever was in the caller's buffer into a
	 * field afd.sys reads. */
	{
		unsigned char *again = malloc((size_t)(size + slop));
		if (!again) { printf("FAIL %s: out of memory\n", __FILE__); fails++; free(alloc); return; }
		memset(again, 0x5A, (size_t)(size + slop));
		__afd_build_poll_request(again, timeout, n);
		for (i = 0; i < n; i++)
			__afd_poll_set_handle(again, i, fake_handle(i), (uint32_t)(EV_RECEIVE | EV_SEND | (i + 1)));
		CHECK(memcmp(again, buf, (size_t)size) == 0);
		free(again);
	}

	free(alloc);
}

/* --- the reply side ---------------------------------------------------
 *
 * Everything above is about the request.  These are about reading the
 * answer back, and they are the device-free negative control for a
 * distinct defect that shipped in src/select/select.c's __FD_SOCKET
 * case: it passed one buffer as both the ioctl's input and its output
 * and then read Handles[0].PollEvents unconditionally.
 *
 * Why that is wrong, from the AFD driver's own source (poll.c,
 * Copyright (c) 1992 Microsoft Corporation):
 *
 *   - AfdPoll() sets `Irp->IoStatus.Information = 0;` on entry and
 *     `pollInfo->NumberOfHandles = 0;` immediately before its readiness
 *     scan, then completes with
 *     `Irp->IoStatus.Information = (ULONG)pollHandleInfo -
 *     (ULONG)pollInfo;` -- with no events that is the 16-byte header
 *     alone.
 *   - IOCTL_AFD_SELECT is METHOD_BUFFERED, so the driver works on a
 *     kernel copy and the I/O manager copies back exactly those
 *     Information bytes (ReactOS ntoskrnl/io/iomgr/irp.c does the
 *     RtlCopyMemory of Information bytes into Irp->UserBuffer;
 *     Microsoft documents the hazard class as "Failure to
 *     Initialize Output Buffers").  The caller's Handles[] is
 *     left untouched.
 *     Aliased with the request, it still holds the *requested* mask,
 *     so an idle socket reads back as every requested bit fired --
 *     readable and writable, on the success path, forever.
 *
 *     The trap in that: AfdPoll() *does* clear the field, at
 *     `pollHandleInfo->PollEvents = 0;` on every iteration of its
 *     scan, and for a one-handle poll that slot is Handles[0].
 *     So checking "does the driver clear it?" answers yes and
 *     clears the buggy code.  The clear happens in the kernel's
 *     SystemBuffer and dies at the Information-bounded copy-back.
 *   - AfdPoll() also *compacts*: `if ( found ) {
 *     pollInfo->NumberOfHandles++; pollHandleInfo++; }`, so the output
 *     pointer advances only for endpoints that fired and output slot i
 *     is not request slot i.
 *
 * The composition of those three facts is inference rather than
 * something asserted anywhere in a first-party document, and it is
 * only checkable against a live driver.  What *is* checkable with no
 * device is that the interpreter refuses to be fooled by such an
 * image, which is what these cases assert.
 *
 * The fix is __afd_poll_events_for(): read the reply's own
 * NumberOfHandles, clamp it to what was asked about, and match on the
 * handle.  wepoll and libuv both reject NumberOfHandles < 1 and Wine's
 * ws2_32 loops to params->count -- three independent implementations
 * with the same shape.
 */
static void build_reply_header(unsigned char *buf, uint32_t count)
{
	/* Exactly what METHOD_BUFFERED copies back when nothing fired:
	 * the first 16 bytes, and nothing else. */
	long long timeout = 0;
	uint32_t unique = 0;
	memcpy(buf + REQ_TIMEOUT, &timeout, sizeof(timeout));
	memcpy(buf + REQ_HANDLE_COUNT, &count, sizeof(count));
	memcpy(buf + REQ_EXCLUSIVE, &unique, sizeof(unique));
}

static void put_reply_entry(unsigned char *buf, size_t slot, void *h, uint32_t events, uint32_t status)
{
	unsigned char *e = buf + REQ_HANDLES + slot * H_SIZE;
	memcpy(e + H_HANDLE, &h, sizeof(h));
	memcpy(e + H_EVENTS, &events, sizeof(events));
	memcpy(e + H_STATUS, &status, sizeof(status));
}

static void check_reply(void)
{
	unsigned char buf[256];
	size_t size1 = __afd_poll_request_size(1);
	size_t size3 = __afd_poll_request_size(3);
	unsigned i;

	/* --- 1. THE defect: a zero-event reply over an aliased request.
	 * Build the request src/select/select.c sends, then overwrite
	 * only the 16 header bytes with NumberOfHandles = 0, which is
	 * bit-for-bit what the I/O manager leaves behind when the driver
	 * reports Information == 16 into the same buffer.  Handles[0]
	 * still holds the requested mask -- every readable and writable
	 * bit set.  The interpreter must report nothing ready. */
	memset(buf, 0, sizeof buf);
	__afd_build_poll_request(buf, 0, 1);
	__afd_poll_set_handle(buf, 0, fake_handle(0), 0x1FFu); /* every bit AFD defines */
	build_reply_header(buf, 0);
	CHECK_EQ(rd32(buf + REQ_HANDLE_COUNT), 0u, "stale image: NumberOfHandles");
	CHECK_EQ(rd32(buf + REQ_HANDLES + H_EVENTS), 0x1FFu, "stale image: Handles[0] still holds the request");
	CHECK_EQ(__afd_poll_get_handle_count(buf), 0u, "get_handle_count on a zero-event reply");
	/* The raw accessor still sees the stale bytes -- that is what it
	 * is for, and why it must not be what a caller uses. */
	CHECK_EQ(__afd_poll_get_events(buf, 0), 0x1FFu, "raw get_events reads the stale slot");
	/* ...and this is the assertion the whole thing exists for. */
	CHECK_EQ(__afd_poll_events_for(buf, 1, fake_handle(0)), 0u,
	         "zero-event reply must report nothing ready, not the requested mask");

	/* --- 2. A reply the driver actually wrote is still read. */
	memset(buf, 0, sizeof buf);
	build_reply_header(buf, 1);
	put_reply_entry(buf, 0, fake_handle(0), EV_RECEIVE | EV_SEND, 0);
	CHECK_EQ(__afd_poll_get_handle_count(buf), 1u, "get_handle_count on a one-event reply");
	CHECK_EQ(__afd_poll_events_for(buf, 1, fake_handle(0)), EV_RECEIVE | EV_SEND,
	         "a reply that names the handle is read");

	/* --- 3. Fail closed: an all-zero output buffer (what a caller
	 * that does not alias the request hands the ioctl, and what it
	 * still holds if the driver writes nothing at all) reports
	 * nothing ready rather than anything ready. */
	memset(buf, 0, sizeof buf);
	CHECK_EQ(__afd_poll_get_handle_count(buf), 0u, "zeroed buffer: count");
	CHECK_EQ(__afd_poll_events_for(buf, 1, fake_handle(0)), 0u, "zeroed buffer: nothing ready");

	/* --- 4. Compaction: the driver advances its write pointer only
	 * for handles that fired, so output slot 0 can belong to request
	 * slot 2.  An indexed read would hand handle 0 handle 2's
	 * events; matching on the handle must not. */
	memset(buf, 0, sizeof buf);
	build_reply_header(buf, 1);
	put_reply_entry(buf, 0, fake_handle(2), EV_RECEIVE, 0);
	CHECK_EQ(__afd_poll_events_for(buf, 3, fake_handle(2)), EV_RECEIVE,
	         "compacted reply: the handle that fired");
	CHECK_EQ(__afd_poll_events_for(buf, 3, fake_handle(0)), 0u,
	         "compacted reply: request slot 0 did not fire");
	CHECK_EQ(__afd_poll_events_for(buf, 3, fake_handle(1)), 0u,
	         "compacted reply: request slot 1 did not fire");
	/* The indexed accessor is what would have got this wrong. */
	CHECK_EQ(__afd_poll_get_events(buf, 0), EV_RECEIVE, "indexed read sees slot 0 regardless of whose it is");

	/* --- 5. A handle named in a slot the count does not cover is
	 * not read: only the first `count` slots were written. */
	memset(buf, 0, sizeof buf);
	build_reply_header(buf, 1);
	put_reply_entry(buf, 0, fake_handle(0), EV_SEND, 0);
	put_reply_entry(buf, 1, fake_handle(1), 0x1FFu, 0); /* stale, beyond the count */
	CHECK_EQ(__afd_poll_events_for(buf, 3, fake_handle(0)), EV_SEND, "in-count slot is read");
	CHECK_EQ(__afd_poll_events_for(buf, 3, fake_handle(1)), 0u, "slot past the count is not read");

	/* --- 6. A nonsense count from the device is clamped to what was
	 * asked about, so it cannot walk off the buffer.  Guard bytes
	 * past the one-handle request must be untouched, and the answer
	 * must still be the honest one. */
	memset(buf, 0, sizeof buf);
	memset(buf + size1, GUARD_BYTE, sizeof buf - size1);
	build_reply_header(buf, 0xFFFFFFFFu);
	put_reply_entry(buf, 0, fake_handle(0), EV_RECEIVE, 0);
	CHECK_EQ(__afd_poll_events_for(buf, 1, fake_handle(0)), EV_RECEIVE,
	         "absurd count is clamped, not believed");
	CHECK_EQ(__afd_poll_events_for(buf, 1, fake_handle(7)), 0u,
	         "absurd count does not manufacture a match");
	for (i = 0; (size_t)i < sizeof buf - size1; i++)
		CHECK_EQ(buf[size1 + i], GUARD_BYTE, "absurd count read past the request");

	/* --- 7. get_handle_count reads the same four bytes at +8 the
	 * builder writes as HandleCount -- request and reply share the
	 * field, which is exactly why the reply's value has to be read
	 * rather than assumed. */
	memset(buf, 0, sizeof buf);
	__afd_build_poll_request(buf, 0, 3);
	CHECK_EQ(__afd_poll_get_handle_count(buf), 3u, "get_handle_count vs builder");
	CHECK_EQ(__afd_poll_get_handle_count(buf), rd32(buf + REQ_HANDLE_COUNT), "get_handle_count vs raw");
	CHECK(size3 > size1);
}

int main(void)
{
	/* One handle is what src/select/select.c's __fd_probe() actually
	 * sends; the larger counts pin the array stride, which a base
	 * offset alone would not. */
	check_n(1, 0);
	check_n(1, -10000000LL); /* a relative NT timeout, i.e. negative */
	check_n(2, 0);
	check_n(5, 0x7FFFFFFFFFFFFFFFLL);

	/* --- the negative control ------------------------------------ *
	 * Build the image ReactOS's AFD_POLL_INFO describes and run the
	 * identical battery over it, requiring rejection on x86_64.
	 * On i386 the two layouts coincide (ULONG_PTR is 4 bytes there),
	 * so the battery must accept it and the images must compare
	 * equal -- which is precisely why only the x86_64 leg could ever
	 * have caught this, and why a later reader must not "fix" an
	 * i386 non-failure. */
	{
		unsigned char real[128], ros[128];
		size_t n = 3, size = __afd_poll_request_size((unsigned long)n);
		int rejected;
		unsigned i;

		__afd_build_poll_request(real, 0, n);
		for (i = 0; i < n; i++)
			__afd_poll_set_handle(real, i, fake_handle(i), (uint32_t)(EV_RECEIVE | EV_SEND | (i + 1)));
		memset(ros, 0, sizeof ros);
		build_reactos_image(ros, 0, n);

		rejected = verify_image(ros, ROS_SIZE(n), n, 0, 0);
		if (HSZ == 8) {
			CHECK(rejected > 0);
			CHECK(size != ROS_SIZE(n));
			CHECK(memcmp(real, ros, (size_t)size) != 0);
			/* Concretely: ReactOS's +24 lands in the *middle* of
			 * the real Handles[0] -- 8 bytes in, on its Events and
			 * Status pair.  afd.sys following ReactOS's layout on
			 * x86_64 would therefore take the socket handle to be
			 * (Status << 32) | Events, i.e. the literal event mask
			 * 0x5 here, and then read the requested event mask out
			 * of Handles[1]'s handle.  Nothing about that fails
			 * loudly: the ioctl fails with STATUS_INVALID_HANDLE
			 * and __fd_probe() falls back to "ready, and hung
			 * up", so select()/poll() on a socket just says
			 * "ready", always -- which is exactly what
			 * test/posix-select-socket.c's idle-socket
			 * assertions reject on a machine with a working
			 * AFD. */
			CHECK_EQ(ROS_HANDLES, REQ_HANDLES + 8u,
			         "x86_64: ReactOS's Handles lands mid-element");
			CHECK_EQ(rdptr(real + ROS_HANDLES),
			         (unsigned long long)(EV_RECEIVE | EV_SEND | 1u),
			         "x86_64: what sits where ReactOS put Handles[0]");
			CHECK_EQ(rdptr(real + REQ_HANDLES),
			         (unsigned long long)(uintptr_t)fake_handle(0),
			         "x86_64: Handles[0] at +16");
		} else {
			CHECK_EQ(rejected, 0, "i386: ReactOS's layout is the same layout");
			CHECK_EQ(size, ROS_SIZE(n), "i386: request size matches ReactOS's");
			CHECK(memcmp(real, ros, (size_t)size) == 0);
		}
		/* The control is a control: the battery accepts the real image. */
		CHECK_EQ(verify_image(real, size, n, 0, 0), 0, "battery accepts the real image");
	}

	/* --- the event bits all four sources agree on ----------------- *
	 * Asserted here because select.c's readable/writable masks are
	 * built from them, and a shifted bit would be as silent as a
	 * shifted field. */
	CHECK_EQ(EV_RECEIVE, 1u << 0, "AFD_POLL_RECEIVE");
	CHECK_EQ(EV_OOB_RECEIVE, 1u << 1, "AFD_POLL_RECEIVE_EXPEDITED");
	CHECK_EQ(EV_SEND, 1u << 2, "AFD_POLL_SEND");
	CHECK_EQ(EV_DISCONNECT, 1u << 3, "AFD_POLL_DISCONNECT");
	CHECK_EQ(EV_ABORT, 1u << 4, "AFD_POLL_ABORT");
	CHECK_EQ(EV_LOCAL_CLOSE, 1u << 5, "AFD_POLL_LOCAL_CLOSE");
	CHECK_EQ(EV_CONNECT, 1u << 6, "AFD_POLL_CONNECT");
	CHECK_EQ(EV_ACCEPT, 1u << 7, "AFD_POLL_ACCEPT");
	CHECK_EQ(EV_CONNECT_FAIL, 1u << 8, "AFD_POLL_CONNECT_FAIL");

	check_reply();

	if (!fails) printf("posix-socket-poll: all tests passed\n");
	return fails != 0;
}
