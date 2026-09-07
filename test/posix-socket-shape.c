/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Which AFD socket-creation packet shape this platform gets, and
 * whether both shapes' bytes are right.
 *
 * *** This test exists to be run on ReactOS. ***  Everything CI can
 * reach reports NT 6 or later, chooses the 24-byte AFD_OPEN_PACKET, and
 * therefore exercises the same path test/posix-socket-ea.c already
 * covers byte for byte.  The 12-byte AFD_CREATE_PACKET path has no
 * oracle here at all: real Windows wants the 24-byte form, and Wine's
 * AFD was patched by this project to accept the 24-byte form, so it
 * agrees with us by construction.  The file is written so that someone
 * with a ReactOS VM can run one binary and read three distinguishable
 * outcomes off its output:
 *
 *   - the 12-byte path was chosen and the endpoint works
 *       -> NT_VERSION says 5.x, AFD_SHAPE says nt4, checks 40-43 PASS;
 *   - the 12-byte path was chosen and the endpoint does not work
 *       -> the same two lines, and a FAIL among checks 40-43 naming
 *          the call and its errno;
 *   - the wrong path was chosen for this platform
 *       -> NT_VERSION and AFD_SHAPE disagree with the machine, visible
 *          without interpreting any check at all, because both are
 *          printed unconditionally.
 *
 * The detected version is *printed*, never merely acted on.  A gate
 * whose input is invisible cannot be debugged from a log.
 *
 * ---- the defect this guards -----------------------------------------
 *
 * NT 4/2000-era afd.sys (and ReactOS's, which reimplements it) reads
 * the socket() extended attribute as a 12-byte AFD_CREATE_PACKET:
 * EndpointFlags, GroupID, SizeOfTransportName, then the name.  Vista
 * and later read a 24-byte AFD_OPEN_PACKET, with AddressFamily,
 * SocketType and Protocol inserted before the name length.
 *
 * Nothing in the bytes says which is meant.  Sending the 24-byte shape
 * to the 12-byte driver has it read our AddressFamily (AF_INET == 2) as
 * the name's byte length and copy two bytes out of our SocketType, so
 * the endpoint's transport device name becomes a one-character string
 * -- and NtCreateFile *returns success*.
 *
 * ---- three different evidence grades, kept apart ---------------------
 *
 * MEASURED.  On a ReactOS boot with afd.sys instrumented
 * (DebugTraceLevel MIN_TRACE -> MID_TRACE, drivers/network/afd/afd/
 * main.c:21), an spicule socket() program made AfdCreateSocket()'s
 * success path print
 *
 *     (/drivers/network/afd/afd/main.c:438)(AfdCreateSocket)
 *         Success: AfdOpenPacketXX \x01
 *
 * with the name text exactly one character, U+0001 (raw: 53 75 63 63
 * 65 73 73 3a 20 41 66 64 4f 70 65 6e 50 61 63 6b 65 74 58 58 20 01 0d
 * 0a).  Both halves are predicted independently by the mechanism: the
 * length is 2 because our AddressFamily is AF_INET == 2, and the
 * character is 0x0001 because it is the low half of our SocketType ==
 * SOCK_STREAM.  The control, on the same boot through the same
 * instrumented driver: native ws2_32 callers printed `Success:
 * AfdOpenPacketXX \Device\Udp`, so the tracer is proven able to print a
 * real device name and a broken DPRINT is ruled out.
 *
 * INFERRED.  The chain from that corrupt endpoint to bind()'s ENOENT --
 * WarmSocketForBind()'s length guard not firing on a length of 2,
 * TdiOpenAddressFile() handing L"\1" to ZwCreateFile -- is read from
 * ReactOS's source, not observed.  bind()'s actual status was not
 * captured on that boot: the test program reported over COM2, which had
 * no driver.
 *
 * VERIFIED.  A corrected spicule build was then run against that same
 * instrumented driver.  This test reported NT 5.2 from the PEB, selected
 * the nt4 shape, passed all 31 checks (including socket(), bind(),
 * listen() and close()), and afd.sys printed `Success: AfdOpenPacketXX
 * \Device\Tcp`.  This file keeps that result from becoming anecdotal:
 * its byte-level checks run everywhere, while the endpoint checks repeat
 * the positive result whenever a native AFD is available.
 *
 * (The opposite error -- the 12-byte shape sent to a 24-byte driver --
 * was observed as STATUS_ACCESS_VIOLATION / EFAULT on this project's
 * real-Windows CI legs, and test/posix-socket-ea.c is its regression
 * assertion.)
 *
 * Because the wrong guess *succeeds* in one direction, there is nothing
 * for a probe to fail on, and the shape has to be selected from the OS
 * version -- which is what ReactOS's own AFD apitest does
 * (modules/rostests/apitests/afd/AfdHelpers.c: `LOBYTE(LOWORD(
 * GetVersion())) >= 6`).  See src/internal/ntversion.c for the three
 * conditions that justify version-gating and why almost nothing else
 * meets them.
 *
 * ---- sources for the numbers asserted below --------------------------
 *
 * Read from a ReactOS checkout at commit
 * 268f687a799ab3d46a8ba3d5d0bbf71f79a1be2e:
 *
 *   - sdk/include/reactos/drivers/afd/shared.h, AFD_CREATE_PACKET
 *     (DWORD EndpointFlags, DWORD GroupID, DWORD SizeOfTransportName,
 *     WCHAR TransportName[1]) and AfdCommand "AfdOpenPacketXX" /
 *     AFD_PACKET_COMMAND_LENGTH 15.
 *   - drivers/network/afd/afd/main.c, AfdCreateSocket(): copies
 *     SizeOfTransportName bytes from `ConnectInfo->TransportName`, i.e.
 *     from +12 -- the member, not sizeof(AFD_CREATE_PACKET), which is
 *     16.  (The `EaInfoValue` it computes at +sizeof() feeds a debug
 *     print and nothing else.)
 *   - drivers/network/afd/afd/bind.c, WarmSocketForBind(): rejects only
 *     a zero-length or NULL TdiDeviceName, which is why a two-byte
 *     corrupt name passes it.
 *   - modules/rostests/apitests/afd/AfdHelpers.c: the GetVersion()
 *     branch, and both packets sized with FIELD_OFFSET(.., TransportName).
 *
 * And, for the 24-byte shape: System Informer's phnt ntafd.h
 * (AFD_OPEN_PACKET) and Mateusz Lewczak, "Under the Hood of AFD.sys"
 * part 1, https://leftarcode.com/posts/afd-reverse-engineering-part1/.
 *
 * As with test/posix-socket-ea.c, src/internal/ is NOT on the test
 * include path, so every prototype and constant below is declared
 * locally rather than included -- a layout test that included the
 * header under test would agree with it by construction.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- the numbered-check harness -------------------------------------
 *
 * Every check prints one line carrying its own fixed number, whether it
 * passes or fails, and the run prints how many executed.  The numbers
 * are literals at the call sites rather than a running counter on
 * purpose: a block that does not run then leaves a *gap in the
 * numbering* as well as a lower total, so "this case was skipped" and
 * "this case quietly printed nothing" are not the same log.  Silence is
 * the one outcome this pattern refuses to produce. */
static int fails;
static int executed;

static void check(int n, const char *name, unsigned long long act, unsigned long long exp)
{
	int ok = (act == exp);
	executed++;
	if (!ok) fails++;
	printf("CHECK %02d [%s] %s exp=%llu act=%llu\n", n, ok ? "PASS" : "FAIL", name, exp, act);
}

/* The same, for values worth reading in hex (none are, today) or for a
 * comparison the caller has already reduced to a boolean it can explain
 * -- `exp` and `act` are then printed as 1 and the outcome. */
static void check_true(int n, const char *name, int cond, const char *detail)
{
	executed++;
	if (!cond) fails++;
	printf("CHECK %02d [%s] %s exp=1 act=%d%s%s\n", n, cond ? "PASS" : "FAIL",
	       name, cond ? 1 : 0, (detail && *detail) ? " " : "", (detail && *detail) ? detail : "");
}

/* Lines the harness must surface even on a clean run: tools/run-tests.py
 * echoes any line starting with its MEASURE_PREFIX ("measure: ", the M
 * macro below) regardless of outcome.  Running the binary directly
 * always prints them too. */
/* The one exit path, so that the executed-check total is printed on
 * every outcome including the truncated ones.  A run that stops early
 * still has to say how much of itself ran; that is the whole point of
 * the total.  `code` is what to return when nothing has failed --
 * a genuine check failure always outranks an unverified block. */
static int finish(int code)
{
	printf("CHECKS EXECUTED=%d\n", executed);
	if (fails) {
		printf("posix-socket-shape: %d check(s) failed\n", fails);
		return 1;
	}
	if (code == 0) printf("posix-socket-shape: all checks passed\n");
	return code;
}

#define M "measure: socket-shape "

/* ---- what the library exposes (src/internal/afd.h, src/internal/libc.h) */
#define SHAPE_NT4 0
#define SHAPE_NT6 1
/* <sys/socket.h>'s own SOCK_STREAM value (1) -- __afd_build_open_ea_for()
 * gained this parameter for SOCK_DGRAM (2026-09-01, src/internal/afd.h);
 * this file only checks the packet *shape* (NT4 vs NT6), so it keeps
 * asserting SOCK_STREAM/"\Device\Tcp" for both, unchanged. */
#define SOCKTYPE_STREAM 1
unsigned long __afd_open_ea_size_for(int shape);
void __afd_build_open_ea_for(int shape, int socktype, void *buf);
unsigned long __afd_open_ea_size(void);
void __afd_build_open_ea(void *buf);
int __afd_open_shape(void);
int __nt_os_version(unsigned *major, unsigned *minor);
int __nt_version_at_least(unsigned major, unsigned minor);

/* ---- constants, from the references named in the banner -------------- */
#define EA_HEADER 8u   /* FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) */
#define EA_NAME "AfdOpenPacketXX"
#define EA_NAME_LEN 15u
#define VALUE_OFF (EA_HEADER + EA_NAME_LEN + 1u) /* 24 */

#define NT4_HEADER 12u /* FIELD_OFFSET(AFD_CREATE_PACKET, TransportName) */
#define NT6_HEADER 24u /* FIELD_OFFSET(AFD_OPEN_PACKET, TransportDeviceName) */

/* AFD_CREATE_PACKET field offsets, relative to the start of the value. */
#define NT4_ENDPOINT_FLAGS 0u
#define NT4_GROUP_ID 4u
#define NT4_NAME_LENGTH 8u
#define NT4_NAME 12u

/* AFD_OPEN_PACKET's, for the one field this file compares across the
 * two -- the whole ambiguity in one number. */
#define NT6_ADDRESS_FAMILY 8u

#define WIN_AF_INET 2u

/* "\Device\Tcp", 11 characters, UTF-16LE. */
static const unsigned char transport_utf16le[] = {
	'\\', 0, 'D', 0, 'e', 0, 'v', 0, 'i', 0, 'c', 0, 'e', 0,
	'\\', 0, 'T', 0, 'c', 0, 'p', 0
};
#define TRANSPORT_CHARS 11u
#define TRANSPORT_BYTES (TRANSPORT_CHARS * 2u) /* 22 */

/* value = header + name + the UTF-16 NUL the length does not count. */
#define NT4_VALUE_BYTES (NT4_HEADER + TRANSPORT_BYTES + 2u) /* 36 */
#define NT6_VALUE_BYTES (NT6_HEADER + TRANSPORT_BYTES + 2u) /* 48 */
#define NT4_EA_BYTES (VALUE_OFF + NT4_VALUE_BYTES)          /* 60 */
#define NT6_EA_BYTES (VALUE_OFF + NT6_VALUE_BYTES)          /* 72 */

/* The buffer is a byte image of an NT structure, so it is decoded as
 * one rather than cast to a struct -- which would assume the layout
 * under test. */
static unsigned long rd32(const unsigned char *p)
{
	return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
	     | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned rd16(const unsigned char *p)
{
	return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

/* A fixed port in the dynamic/private range (RFC 6335), for the same
 * reason test/posix-socket.c uses one: getsockname() is out of scope in
 * src/socket/, so a port-0 bind cannot be read back.  A *different*
 * number from that file's, so the two cannot collide when a suite runs
 * them concurrently. */
#define TEST_PORT 55127

int main(void)
{
	unsigned maj = 0, min = 0;
	int measured, shape, want_shape;
	unsigned char *nt4, *nt6, *chosen;
	unsigned long nt4_size, nt6_size, chosen_size;
	const unsigned char *pkt;

	/* --- what was detected, printed before anything depends on it --- */
	measured = __nt_os_version(&maj, &min);
	shape = __afd_open_shape();

	printf(M "nt_version=%u.%u source=%s\n", maj, min, measured ? "peb" : "assumed");
	printf(M "afd_open_shape=%s header=%u ea_bytes=%lu\n",
	       shape == SHAPE_NT4 ? "nt4" : "nt6",
	       shape == SHAPE_NT4 ? NT4_HEADER : NT6_HEADER,
	       __afd_open_ea_size());

	nt4_size = __afd_open_ea_size_for(SHAPE_NT4);
	nt6_size = __afd_open_ea_size_for(SHAPE_NT6);
	nt4 = malloc(nt4_size);
	nt6 = malloc(nt6_size);
	if (!nt4 || !nt6) { printf("FAIL %s: out of memory\n", __FILE__); return 1; }
	memset(nt4, 0x5A, nt4_size);
	memset(nt6, 0x5A, nt6_size);
	__afd_build_open_ea_for(SHAPE_NT4, SOCKTYPE_STREAM, nt4);
	__afd_build_open_ea_for(SHAPE_NT6, SOCKTYPE_STREAM, nt6);

	/* --- 01-05: the selection itself ------------------------------ *
	 * The gate has to be checked against the version it claims to
	 * read, not merely reported: "printed 5.2 and then built the
	 * 24-byte packet anyway" is precisely the failure the ReactOS
	 * session needs to be able to see. */
	check_true(1, "os_major_is_plausible", maj >= 4u && maj <= 20u, "");
	want_shape = (maj > 6u || (maj == 6u && min >= 0u)) ? SHAPE_NT6 : SHAPE_NT4;
	check(2, "shape_matches_version", (unsigned)shape, (unsigned)want_shape);
	check(3, "version_at_least_6_0_agrees",
	      (unsigned)(__nt_version_at_least(6, 0) ? SHAPE_NT6 : SHAPE_NT4), (unsigned)shape);
	/* The comparison is on the pair, not a flattened number: 10.0
	 * must outrank 6.3, and 6.1 must not read as "61". */
	check(4, "version_at_least_pairwise",
	      (unsigned)(__nt_version_at_least(maj, min) ? 1 : 0), 1u);
	check(5, "version_at_least_rejects_higher_minor",
	      (unsigned)(__nt_version_at_least(maj, min + 1u) ? 1 : 0), 0u);

	/* --- 06-08: the detected shape is what socket() will actually
	 * send.  Two entry points compute the buffer (size, then bytes);
	 * if they ever disagreed the result would be a heap overflow, not
	 * a wrong packet. */
	chosen_size = __afd_open_ea_size();
	chosen = malloc(chosen_size);
	if (!chosen) { printf("FAIL %s: out of memory\n", __FILE__); return 1; }
	memset(chosen, 0xA5, chosen_size);
	__afd_build_open_ea(chosen);
	check(6, "default_size_matches_shape", chosen_size,
	      shape == SHAPE_NT4 ? nt4_size : nt6_size);
	check(7, "default_bytes_match_shape",
	      (unsigned long long)(memcmp(chosen, shape == SHAPE_NT4 ? nt4 : nt6,
	                                  (size_t)chosen_size) == 0), 1ull);
	check(8, "shape_is_stable_across_calls",
	      (unsigned)__afd_open_shape(), (unsigned)shape);

	/* --- 10-24: the 12-byte AFD_CREATE_PACKET image ---------------- *
	 * Asserted on every platform, including all the ones that would
	 * never choose it.  Otherwise the legacy layout is unasserted
	 * everywhere CI can reach, and the first machine to exercise it
	 * would also be the first to test it. */
	check(10, "nt4_ea_size", nt4_size, NT4_EA_BYTES);
	check(11, "nt4_next_entry_offset", rd32(nt4 + 0), 0u);
	check(12, "nt4_flags", nt4[4], 0u);
	check(13, "nt4_ea_name_length", nt4[5], EA_NAME_LEN);
	check_true(14, "nt4_ea_name", memcmp(nt4 + EA_HEADER, EA_NAME, EA_NAME_LEN) == 0, EA_NAME);
	check(15, "nt4_ea_name_terminator", nt4[EA_HEADER + EA_NAME_LEN], 0u);
	check(16, "nt4_ea_value_length", rd16(nt4 + 6), NT4_VALUE_BYTES);
	/* IoCheckEaBufferValidity()'s ComputedLength, exactly: the entry
	 * must describe every byte the buffer declares, and the total
	 * must be 4-aligned so the value's ULONGs are aligned too. */
	check(17, "nt4_computed_length", (unsigned long long)rd16(nt4 + 6) + nt4[5] + EA_HEADER + 1u,
	      (unsigned long long)nt4_size);
	check(18, "nt4_ea_size_mod_4", nt4_size % 4u, 0u);

	pkt = nt4 + VALUE_OFF;
	check(19, "nt4_endpoint_flags", rd32(pkt + NT4_ENDPOINT_FLAGS), 0u);
	check(20, "nt4_group_id", rd32(pkt + NT4_GROUP_ID), 0u);
	/* The field real Windows would read as SocketType. */
	check(21, "nt4_size_of_transport_name", rd32(pkt + NT4_NAME_LENGTH), TRANSPORT_BYTES);
	check(22, "nt4_name_length_is_bytes_not_chars",
	      rd32(pkt + NT4_NAME_LENGTH), 2u * TRANSPORT_CHARS);
	check_true(23, "nt4_transport_name",
	           memcmp(pkt + NT4_NAME, transport_utf16le, sizeof transport_utf16le) == 0,
	           "\\Device\\Tcp UTF-16LE at +12");
	/* The NUL the length does not count but the buffer carries, and
	 * it is the last thing in the declared value. */
	check(24, "nt4_value_end", NT4_NAME + rd32(pkt + NT4_NAME_LENGTH) + 2u,
	      (unsigned long long)rd16(nt4 + 6));

	/* --- 30-33: the two shapes side by side ------------------------ *
	 * Not a restatement of test/posix-socket-ea.c (which checks the
	 * 24-byte image field by field); these are the *differences*, and
	 * they are what makes the pair undecidable on the wire. */
	check(30, "nt6_ea_size", nt6_size, NT6_EA_BYTES);
	check(31, "shape_size_difference", nt6_size - nt4_size, NT6_HEADER - NT4_HEADER);
	/* One offset, +8 of the value, holding two entirely different
	 * fields with no marker to say which: 22 (a byte count) in the
	 * NT4 image, 2 (AF_INET) in the NT6 image.  This is the whole
	 * defect, expressed as an assertion -- and it is why a driver
	 * handed the wrong one reads AF_INET as a two-byte name length
	 * and still returns success. */
	check(32, "nt4_plus_8_is_name_length", rd32(nt4 + VALUE_OFF + NT4_NAME_LENGTH), TRANSPORT_BYTES);
	check(33, "nt6_plus_8_is_address_family", rd32(nt6 + VALUE_OFF + NT6_ADDRESS_FAMILY), WIN_AF_INET);

	free(chosen);
	free(nt6);
	free(nt4);

	/* --- 40-43: the endpoint the chosen shape actually produces ----
	 * The half no byte-level check can reach.  socket() succeeding
	 * proves nothing on its own -- that is the entire point of this
	 * bug -- so bind() is here: it is the first call that
	 * dereferences the transport name the driver stored from our
	 * packet, and therefore the first that can tell a correctly-built
	 * endpoint from a corrupt one.  listen() follows because it is
	 * the first to use the address file bind() opened.
	 *
	 * *** A failure here is reported as UNVERIFIED (exit 77), not as
	 * a FAIL, and that is a limitation of the observer, not
	 * politeness. ***  From inside this process a failing bind()
	 * cannot distinguish "the endpoint is corrupt because the packet
	 * shape was wrong" from "this runtime does not implement
	 * IOCTL_AFD_BIND at all" -- the same ambiguity
	 * test/posix-socket.c's network_probe() banner describes.  Both
	 * produce a failing bind() and an errno.  Measured 2026-08-25 on
	 * this workstation, Wine fails it with errno=5 (EIO) while the
	 * real-Windows CI legs pass it, so treating any failure as a red
	 * would mean asserting something about Wine's AFD that is not
	 * this test's subject.
	 *
	 * The errno is printed either way, and it is the thing to read:
	 * on a platform whose measure: line says shape=nt4, an ENOENT
	 * here is the documented signature of the corruption this gate
	 * exists to prevent (a transport name that is not a device),
	 * whereas EIO or ENOSYS is a runtime that does not implement the
	 * ioctl.  Checks 40-43 passing on such a platform is the positive
	 * result observed on ReactOS for the corrected 12-byte path -- see
	 * the banner.
	 *
	 * On a host with no \Device\Afd at all -- `make asan`'s native
	 * stub environment -- socket() fails first and checks 40-43 do
	 * not appear at all: a gap in the numbering and a total of 27
	 * rather than 31, which is the honest report. */
	{
		struct sockaddr_in a;
		int s, e;

		errno = 0;
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) {
			printf("UNVERIFIED %s: no AFD endpoint here (socket() errno=%d); "
			       "checks 40-43 not executed\n", __FILE__, errno);
			return finish(77);
		}
		check_true(40, "socket_open", s >= 0, NULL);

		memset(&a, 0, sizeof a);
		a.sin_family = AF_INET;
		a.sin_port = htons(TEST_PORT);
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		errno = 0;
		if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) {
			e = errno;
			close(s);
			printf("UNVERIFIED %s: bind() failed, errno=%d, with afd_open_shape=%s; "
			       "checks 41-43 not executed. A corrupt endpoint and an "
			       "unimplemented IOCTL_AFD_BIND are indistinguishable from here "
			       "-- see this file's banner\n",
			       __FILE__, e, shape == SHAPE_NT4 ? "nt4" : "nt6");
			return finish(77);
		}
		check_true(41, "bind_loopback", 1, NULL);

		errno = 0;
		if (listen(s, 1) != 0) {
			e = errno;
			close(s);
			printf("UNVERIFIED %s: listen() failed, errno=%d; "
			       "checks 42-43 not executed\n", __FILE__, e);
			return finish(77);
		}
		check_true(42, "listen", 1, NULL);

		errno = 0;
		check(43, "close", (unsigned long long)(close(s) == 0), 1ull);
	}

	return finish(0);
}
