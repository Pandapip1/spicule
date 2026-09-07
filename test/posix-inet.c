/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <arpa/inet.h>: htonl(),
 * htons(), ntohl(), ntohs() (functions/htonl.html), inet_addr() and
 * inet_ntoa() (functions/inet_addr.html), inet_ntop() and inet_pton()
 * (functions/inet_ntop.html), plus the header's own required contents
 * (basedefs/arpa_inet.h.html, over basedefs/netinet_in.h.html).  Every
 * page is at https://pubs.opengroup.org/onlinepubs/9699919799/.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM test/posix-socket.c.
 * POSIX-GAP-ACCOUNTING.md lists `arpa/inet.h` (8 functions) under
 * "Implemented, not clause-audited", noting that these "need no OS
 * support" and that test/posix-socket.c "does exercise them
 * unconditionally"; its successor-queue entry says the header "was
 * deliberately left alone in that pass because the socket subsystem was
 * under concurrent modification" and "should wait for the socket
 * subsystem to settle".  It has, for the part this file audits:
 * `git log --oneline -- src/socket/` lists two commits in the whole
 * directory's life, the one that created it and c7c0171, a one-line
 * conformance fix to inet_pton() described below -- so the AFD churn
 * that note was avoiding is not in this file's way, and nothing in the
 * file touches AFD, a descriptor or a device anyway.  So
 * this file is the clause audit that row is waiting for, and it is
 * deliberately NOT a second copy of posix-socket.c's assertions.  That
 * file exercises the happy path of all eight names as part of proving
 * the socket subsystem works at all; this one goes down the three
 * pages sentence by sentence, and what it adds is the corners: the
 * four dotted forms and the radix rule of inet_addr(), inet_ntoa()'s
 * static storage, inet_ntop()'s exact [ENOSPC] boundary, and the
 * grammar inet_pton() must *refuse*.
 *
 * The one deliberate overlap is the AF_INET6 success pair, which
 * posix-socket.c also exercises; see test_inet6_text_forms below for
 * the clause-level coverage.
 *
 * WHY EVERY ASSERTION HERE IS UNCONDITIONAL.  src/socket/inet.c's own
 * banner says it: all eight are pure C over a caller's buffer with no
 * NT dependency at all.  They behave identically under Wine, on the
 * real-Windows CI leg and in `make asan`'s native ELF build, so unlike
 * the rest of test/posix-socket.c nothing here needs a capability probe
 * and nothing here can print SKIP.
 *
 * That property is also how every assertion below was checked before it
 * was written down rather than reasoned about: this file and
 * src/socket/inet.c compile and link against a host libc unchanged (the
 * eight definitions preempt the host's), so the expected values here
 * are observed outputs of THIS implementation, not derived ones -- and
 * each fenced test was run the same way to confirm it fails today, and
 * fails for the reason its fence gives.  What that run cannot see is
 * the two PE targets' 32-bit `unsigned long`, which matters in exactly
 * one place; that place is called out where it arises, in
 * test_inet_addr_rejects_sign_and_space's fence.
 *
 * ==================== the findings, up front ==========================
 *
 * 1. FIXED -- inet_ntop()/inet_pton() now support AF_INET6.  This
 *    is not an ancillary half of the page: inet_ntop.html requires the
 *    two families in one sentence -- "The AF_INET and AF_INET6 address
 *    families shall be supported." -- and spells out the three IPv6
 *    text forms in the same DESCRIPTION that gives the IPv4 one.
 *    Covered by test_inet6_text_forms, and the header macro it needs,
 *    test_inet6_addrstrlen_defined.
 * 2. BUG -- inet_addr() accepts a leading '+' and leading white space
 *    in a part, and (on the two targets where `unsigned long` is 32
 *    bits, i.e. both PE targets) a leading '-', which turns a string
 *    that denotes no address into a specific wrong one.  Fenced:
 *    test_inet_addr_rejects_sign_and_space.
 * 3. BUG -- inet_addr() writes errno on every call, success or failure,
 *    and the value it writes is 0, which errno.html forbids outright:
 *    "No function in this volume of POSIX.1-2017 shall set errno to 0."
 *    Fenced: test_inet_addr_preserves_errno.
 *
 * Not a finding of this file, and no longer a defect at all: until
 * c7c0171 (2026-08-25, landed while this audit was being written)
 * inet_pton() accepted a part with a leading zero ("0.0.0.00",
 * "01.2.3.4") and read it as decimal.  That was the same disagreement
 * as finding 2 seen from the other end -- inet_pton() too lax about a
 * leading '0', inet_addr() too lax about everything strtoul() happens
 * to swallow -- and it is now fixed, asserted live in
 * test/posix-socket.c's test_inet_pton_ntop, and no longer guarded
 * around in fuzz/fuzz_inet.c.  The remaining half is finding 2, which
 * that commit did not touch.
 *
 * The header include list is load-bearing and minimal on purpose.
 * arpa_inet.h.html requires <arpa/inet.h> itself to define in_port_t,
 * in_addr_t, the in_addr structure and the INET_ADDRSTRLEN and
 * INET6_ADDRSTRLEN macros ("as described in <netinet/in.h>"), and only
 * *permits* the rest: "Inclusion of the <arpa/inet.h> header may also
 * make visible all symbols from <netinet/in.h> and <inttypes.h>."
 * <netinet/in.h> is therefore NOT included below, and <sys/socket.h> --
 * included for AF_INET/AF_UNIX/AF_UNSPEC and socklen_t, which are its
 * own -- does not include it either, so those names reach this
 * translation unit through <arpa/inet.h> or not at all.  If that stops
 * being true this file stops compiling, which is how a consumer meets
 * the same clause.
 */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* --------------------------------------------------------------------
 * basedefs/arpa_inet.h.html DESCRIPTION, first three sentences: the
 * header "shall define the in_port_t and in_addr_t types as described
 * in <netinet/in.h>", "shall define the in_addr structure as described
 * in <netinet/in.h>", and "shall define the INET_ADDRSTRLEN and
 * INET6_ADDRSTRLEN macros as described in <netinet/in.h>".
 *
 * netinet_in.h.html supplies the descriptions being referred to:
 * "in_port_t Equivalent to the type uint16_t as described in
 * <inttypes.h>."; "in_addr_t Equivalent to the type uint32_t as
 * described in <inttypes.h>."; the in_addr structure "shall include at
 * least the following member: in_addr_t s_addr"; and, with the values
 * spelled out, "INET_ADDRSTRLEN 16. Length of the string form for IP."
 * and "INET6_ADDRSTRLEN 46. Length of the string form for IPv6."
 *
 * All five now hold.  INET6_ADDRSTRLEN is checked separately below.
 *
 * Deliberately unused here, and worth saying why: INADDR_LOOPBACK,
 * which spicule defines and test/posix-socket.c uses throughout, is
 * nowhere in netinet_in.h.html -- the page requires INADDR_ANY ("IPv4
 * wildcard address") and INADDR_BROADCAST ("IPv4 broadcast address")
 * and stops there.  It is a BSD extension this tree happens to
 * provide, not a clause, so no assertion in this file rests on it and
 * none is counted as coverage of it.
 * ------------------------------------------------------------------ */
static void test_arpa_inet_header_contents(void)
{
	in_port_t port = 0;
	in_addr_t addr = 0;
	struct in_addr ia;

	ia.s_addr = 0;
	CHECK(sizeof port == sizeof(uint16_t));
	CHECK(sizeof port == 2);
	CHECK(sizeof addr == sizeof(uint32_t));
	CHECK(sizeof addr == 4);
	CHECK(sizeof ia.s_addr == sizeof addr);
	CHECK(INET_ADDRSTRLEN == 16);

	/* inet_addr.html RETURN VALUE names the failure value as
	 * "(in_addr_t)(-1)"; netinet_in.h.html does not name INADDR_NONE
	 * at all, so every failure assertion in this file is written the
	 * standard's way and the tree's own constant is checked against it
	 * once, here. */
	CHECK(INADDR_NONE == (in_addr_t)(-1));
	CHECK(INADDR_ANY == 0);
	CHECK(INADDR_BROADCAST == (in_addr_t)0xffffffffUL);
}

/* --------------------------------------------------------------------
 * arpa_inet.h.html, the two declaration clauses -- which are NOT the
 * same clause, and the difference is the point of this test.
 *
 * For htonl(), htons(), ntohl() and ntohs(): "The following shall be
 * declared as functions, or defined as macros, or both. If functions
 * are declared, function prototypes shall be provided."  htonl.html
 * says the same from the other side: "On some implementations, these
 * functions are defined as macros."  A macro-only header conforms.
 *
 * For inet_addr(), inet_ntoa(), inet_ntop() and inet_pton(): "The
 * following shall be declared as functions and may also be defined as
 * macros. Function prototypes shall be provided."  Here a real function
 * is required, so a caller may take the address of one and call
 * through it.  That is what the pointers below check, and they are
 * checked only for these four: doing the same for the byte-order four
 * would assert something the page does not require, and would break
 * against a conforming macro-only implementation.
 *
 * spicule declares all eight as functions and defines no macro
 * (include/arpa/inet.h, src/socket/inet.c), so it meets the stricter
 * clause where the stricter clause applies.
 * ------------------------------------------------------------------ */
static void test_declared_as_functions(void)
{
	in_addr_t (*p_addr)(const char *) = inet_addr;
	char *(*p_ntoa)(struct in_addr) = inet_ntoa;
	const char *(*p_ntop)(int, const void *, char *, socklen_t) = inet_ntop;
	int (*p_pton)(int, const char *, void *) = inet_pton;
	struct in_addr a;
	char buf[INET_ADDRSTRLEN];

	CHECK(p_addr("1.2.3.4") == inet_addr("1.2.3.4"));
	CHECK(p_pton(AF_INET, "1.2.3.4", &a) == 1);
	CHECK(p_ntop(AF_INET, &a, buf, sizeof buf) == buf);
	CHECK(!strcmp(buf, "1.2.3.4"));
	CHECK(!strcmp(p_ntoa(a), "1.2.3.4"));
}

/* --------------------------------------------------------------------
 * htonl.html DESCRIPTION: "These functions shall convert 16-bit and
 * 32-bit quantities between network byte order and host byte order",
 * and RETURN VALUE: htonl()/htons() "shall return the argument value
 * converted from host to network byte order", ntohl()/ntohs() "shall
 * return the argument value converted from network to host byte order".
 *
 * test/posix-socket.c's test_byteorder already asserts the swap itself
 * on this little-endian-only tree, and that each function is its own
 * inverse.  What it does not pin down is what "network byte order"
 * *is* as a sequence of bytes -- and that is the property everything
 * else in this file leans on, because inet_addr.html states it as a
 * requirement on the values these functions produce and consume: "All
 * Internet addresses shall be returned in network order (bytes ordered
 * from left to right)."
 *
 * The two assertions below are the same requirement read twice: the
 * octets of htonl(0x01020304) in memory are 1, 2, 3, 4 in that order
 * (true on a big-endian host too, so this is a byte-order-independent
 * test of a byte-order function), and inet_pton() -- which
 * inet_ntop.html requires to store its result "in network byte order"
 * -- puts the same four octets in the same order for "1.2.3.4".  If
 * either half were wrong, every sockaddr_in this library fills in
 * would be wrong with it.
 * ------------------------------------------------------------------ */
static void test_byteorder_wire_layout(void)
{
	unsigned char wire[4];
	uint32_t n32;
	uint16_t n16;
	struct in_addr a;

	n32 = htonl(0x01020304UL);
	memcpy(wire, &n32, sizeof n32);
	CHECK(wire[0] == 1 && wire[1] == 2 && wire[2] == 3 && wire[3] == 4);

	n16 = htons(0x0102);
	memcpy(wire, &n16, sizeof n16);
	CHECK(wire[0] == 1 && wire[1] == 2);

	a.s_addr = 0;
	CHECK(inet_pton(AF_INET, "1.2.3.4", &a) == 1);
	CHECK(a.s_addr == htonl(0x01020304UL));
	memcpy(wire, &a.s_addr, 4);
	CHECK(wire[0] == 1 && wire[1] == 2 && wire[2] == 3 && wire[3] == 4);

	/* inet_addr() is under the same "network order" sentence. */
	CHECK(inet_addr("1.2.3.4") == a.s_addr);
}

/* --------------------------------------------------------------------
 * inet_addr.html DESCRIPTION, the four forms.  The page's own words:
 *
 *   a.b.c.d  "When four parts are specified, each shall be interpreted
 *            as a byte of data and assigned, from left to right, to the
 *            four bytes of an Internet address."
 *   a.b.c    "When a three-part address is specified, the last part
 *            shall be interpreted as a 16-bit quantity and placed in
 *            the rightmost two bytes of the network address."
 *   a.b      "When a two-part address is supplied, the last part shall
 *            be interpreted as a 24-bit quantity and placed in the
 *            rightmost three bytes of the network address."
 *   a        "When only one part is given, the value shall be stored
 *            directly in the network address without any byte
 *            rearrangement."
 *
 * and the radix rule: "All numbers supplied as parts in IPv4 dotted
 * decimal notation may be decimal, octal, or hexadecimal, as specified
 * in the ISO C standard (that is, a leading 0x or 0X implies
 * hexadecimal; otherwise, a leading '0' implies octal; otherwise, the
 * number is interpreted as decimal)."  RETURN VALUE: "Upon successful
 * completion, inet_addr() shall return the Internet address. Otherwise,
 * it shall return (in_addr_t)(-1)."
 *
 * test/posix-socket.c covers the "a" and "a.b" forms with decimal
 * parts.  What is checked here is the "a.b.c" form and the radix rule
 * -- the half of the DESCRIPTION most implementations of this function
 * get wrong, and the half that makes inet_pton()'s refusals below mean
 * anything -- together with the range limit implied by each form's
 * "byte of data"/"16-bit quantity"/"24-bit quantity" wording.
 *
 * Not asserted, because the page does not decide it: which of the two
 * readings of "255.255.255.255" is right.  That string converts to the
 * same 32 bits as the failure return, and since ERRORS says "No errors
 * are defined" there is nothing else for a caller to consult.  It is
 * the defect inet_pton()'s three-way return exists to avoid, and the
 * reason every failure assertion in this file uses a string that is not
 * the broadcast address.
 * ------------------------------------------------------------------ */
static void test_inet_addr_forms_and_radix(void)
{
	/* "a.b.c": the last part is the rightmost two bytes. */
	CHECK(inet_addr("1.2.3") == htonl(0x01020003UL));
	CHECK(inet_addr("192.168.258") == htonl(0xc0a80102UL));

	/* Hexadecimal and octal parts, in each of the four forms. */
	CHECK(inet_addr("0x7f.0.0.1") == htonl(0x7f000001UL));
	CHECK(inet_addr("0177.0.0.1") == htonl(0x7f000001UL));
	CHECK(inet_addr("1.0x2.0x3.4") == htonl(0x01020304UL));
	CHECK(inet_addr("0x7f.0x1") == htonl(0x7f000001UL));
	CHECK(inet_addr("0x7f000001") == htonl(0x7f000001UL));
	CHECK(inet_addr("017700000001") == htonl(0x7f000001UL));

	/* "a leading '0' implies octal", so the parts of "010.1.1.1" are
	 * 8, 1, 1, 1 -- not 10, 1, 1, 1.  This is the assertion that pins
	 * the radix rule to one reading. */
	CHECK(inet_addr("010.1.1.1") == htonl(0x08010101UL));

	/* "(in_addr_t)(-1)".  Seven strings, six ways of being malformed:
	 * a trailing separator, a trailing space, a part wider than its
	 * form allows (twice -- a byte and a 16-bit quantity), a one-part
	 * value wider than the address, a digit the declared radix does
	 * not have, and an empty leading part. */
	CHECK(inet_addr("1.2.3.4.") == (in_addr_t)(-1));
	CHECK(inet_addr("1.2.3.4 ") == (in_addr_t)(-1));
	CHECK(inet_addr("1.2.3.256") == (in_addr_t)(-1));
	CHECK(inet_addr("1.2.0x30000") == (in_addr_t)(-1));
	CHECK(inet_addr("0x100000000") == (in_addr_t)(-1));
	CHECK(inet_addr("0.0.0.09") == (in_addr_t)(-1));
	CHECK(inet_addr(".1.2.3") == (in_addr_t)(-1));
}

/* --------------------------------------------------------------------
 * inet_addr.html, inet_ntoa(): "The inet_ntoa() function shall convert
 * the Internet host address specified by in to a string in the Internet
 * standard dot notation", and RETURN VALUE: it "shall return a pointer
 * to the network address in Internet standard dot notation".  There is
 * no failure return and no error: ERRORS says "No errors are defined."
 *
 * So the clause worth testing is the storage, which the page addresses
 * twice -- DESCRIPTION: "The inet_ntoa() function need not be
 * thread-safe.", and APPLICATION USAGE: "The return value of
 * inet_ntoa() may point to static data that may be overwritten by
 * subsequent calls to inet_ntoa()."
 *
 * src/socket/inet.c uses one process-wide `static char
 * buf[INET_ADDRSTRLEN]`, which is exactly what that permits.
 * Asserting the overwrite is what makes the permission a recorded
 * property instead of an accident, and it is the behaviour a caller
 * that stashes the pointer will meet.  spicule has no threads, so the
 * thread-safety half of the clause has no object here.
 * ------------------------------------------------------------------ */
static void test_inet_ntoa_static_storage(void)
{
	struct in_addr a, b;
	char *first;
	char buf[INET_ADDRSTRLEN];

	a.s_addr = htonl(0x01020304UL);
	b.s_addr = htonl(0xfffffffeUL);

	first = inet_ntoa(a);
	CHECK(first != 0);
	CHECK(!strcmp(first, "1.2.3.4"));
	CHECK(strlen(first) < INET_ADDRSTRLEN);

	CHECK(!strcmp(inet_ntoa(b), "255.255.255.254"));
	/* "may be overwritten by subsequent calls": `first` was never a
	 * private copy, and a caller holding it now holds the second
	 * answer. */
	CHECK(!strcmp(first, "255.255.255.254"));

	/* The longest output there is, against the buffer size
	 * netinet_in.h.html fixes for exactly it. */
	b.s_addr = INADDR_BROADCAST;
	CHECK(!strcmp(inet_ntoa(b), "255.255.255.255"));
	CHECK(strlen(inet_ntoa(b)) == INET_ADDRSTRLEN - 1);

	/* "the network address in Internet standard dot notation" is the
	 * same text inet_ntop() produces from the same four bytes. */
	a.s_addr = htonl(0xc0a80001UL);
	CHECK(inet_ntop(AF_INET, &a, buf, sizeof buf) == buf);
	CHECK(!strcmp(inet_ntoa(a), buf));
}

/* --------------------------------------------------------------------
 * inet_ntop.html, the AF_INET half.  DESCRIPTION: the function "shall
 * convert a numeric address into a text string suitable for
 * presentation"; the src buffer's "address must be in network byte
 * order"; "The size argument specifies the size of this buffer, which
 * shall be large enough to hold the text string (INET_ADDRSTRLEN
 * characters for IPv4, INET6_ADDRSTRLEN characters for IPv6)."
 * RETURN VALUE: it "shall return a pointer to the buffer containing the
 * text string if the conversion succeeds, and NULL otherwise, and set
 * errno to indicate the error."  ERRORS: "[EAFNOSUPPORT] The af
 * argument is invalid." and "[ENOSPC] The size of the inet_ntop()
 * result buffer is inadequate."
 *
 * The boundary is the interesting part, and posix-socket.c only
 * brackets it (4 bytes for a 7-character address).  "Inadequate" means
 * strictly fewer bytes than the text and its terminator, so for
 * "1.2.3.4" size 8 must succeed and size 7 must fail; an off-by-one in
 * either direction is invisible to a test that passes 4.
 *
 * The guard-byte assertion is deliberately more than the page requires
 * -- POSIX says nothing about the caller's buffer on failure -- and is
 * here because fuzz/fuzz_inet.c depends on it, for the reason its own
 * banner gives: the function's scratch buffer is large enough that a
 * partial write would land inside the caller's object, where ASan sees
 * nothing.  Marked, so a later reader does not mistake it for a clause.
 * ------------------------------------------------------------------ */
static void test_inet_ntop_size_and_family(void)
{
	struct in_addr a;
	char buf[INET_ADDRSTRLEN];
	char guard[INET_ADDRSTRLEN + 1];

	/* INET_ADDRSTRLEN is exactly enough for the longest address, which
	 * is what "16. Length of the string form for IP." promises. */
	a.s_addr = INADDR_BROADCAST;
	CHECK(inet_ntop(AF_INET, &a, buf, sizeof buf) == buf);
	CHECK(!strcmp(buf, "255.255.255.255"));

	a.s_addr = htonl(0x01020304UL);
	memset(guard, 'Z', sizeof guard);
	CHECK(inet_ntop(AF_INET, &a, guard, 8) == guard);
	CHECK(!strcmp(guard, "1.2.3.4"));

	memset(guard, 'Z', sizeof guard);
	errno = 0;
	CHECK(inet_ntop(AF_INET, &a, guard, 7) == 0);
	CHECK(errno == ENOSPC);
	CHECK(guard[0] == 'Z');   /* beyond the clause: see the comment above */

	errno = 0;
	CHECK(inet_ntop(AF_INET, &a, guard, 0) == 0);
	CHECK(errno == ENOSPC);

	/* "[EAFNOSUPPORT] The af argument is invalid."  AF_INET6 is now a
	 * supported text family; these two remain genuinely unknown. */
	errno = 0;
	CHECK(inet_ntop(AF_UNIX, &a, buf, sizeof buf) == 0);
	CHECK(errno == EAFNOSUPPORT);
	errno = 0;
	CHECK(inet_ntop(AF_UNSPEC, &a, buf, sizeof buf) == 0);
	CHECK(errno == EAFNOSUPPORT);
}

/* --------------------------------------------------------------------
 * inet_ntop.html, inet_pton()'s AF_INET grammar and its three-way
 * return.  DESCRIPTION: "If the af argument of inet_pton() is AF_INET,
 * the src string shall be in the standard IPv4 dotted-decimal form:
 * ddd.ddd.ddd.ddd where "ddd" is a one to three digit decimal number
 * between 0 and 255 (see inet_addr()).  The inet_pton() function does
 * not accept other formats (such as the octal numbers, hexadecimal
 * numbers, and fewer than four numbers that inet_addr() accepts)."
 *
 * That last sentence is the classic conformance trap, and it is why
 * this file audits both functions together: everything
 * test_inet_addr_forms_and_radix asserts inet_addr() must ACCEPT,
 * inet_pton() must REFUSE, so a shared parser is necessarily wrong for
 * one of them.  spicule keeps them apart -- src/socket/inet.c writes
 * inet_pton()'s loop by hand instead of reusing the strtoul() path --
 * and every refusal below holds.  The last string it was too lax about,
 * a part with a leading zero, was fixed in c7c0171 and is asserted live
 * in test/posix-socket.c's test_inet_pton_ntop, so it is not repeated
 * here; what this file adds on that clause is the length rule beside
 * it, "a one to three digit decimal number", which is a different
 * sub-clause and which no other test covers.
 *
 * RETURN VALUE gives three outcomes: the function "shall return 1 if
 * the conversion succeeds, with the address pointed to by dst in
 * network byte order. It shall return 0 if the input is not a valid
 * IPv4 dotted-decimal string or a valid IPv6 address string, or -1 with
 * errno set to [EAFNOSUPPORT] if the af argument is unknown."  The 0 is
 * not an error: [EAFNOSUPPORT] belongs to the -1, and errno.html's "No
 * function in this volume of POSIX.1-2017 shall set errno to 0" forbids
 * clearing errno on the way past.  Both halves are asserted; what is
 * NOT asserted is that errno is left exactly as the caller set it,
 * because errno.html permits any function call to change it.
 * ------------------------------------------------------------------ */
static void test_inet_pton_strict_grammar(void)
{
	struct in_addr a;

	a.s_addr = 0;
	CHECK(inet_pton(AF_INET, "0.0.0.0", &a) == 1);
	CHECK(a.s_addr == INADDR_ANY);
	CHECK(inet_pton(AF_INET, "192.168.0.1", &a) == 1);
	CHECK(a.s_addr == htonl(0xc0a80001UL));
	CHECK(inet_pton(AF_INET, "255.255.255.255", &a) == 1);
	CHECK(a.s_addr == INADDR_BROADCAST);

	/* "fewer than four numbers that inet_addr() accepts" */
	CHECK(inet_pton(AF_INET, "16909060", &a) == 0);
	CHECK(inet_pton(AF_INET, "1.258", &a) == 0);
	CHECK(inet_pton(AF_INET, "192.168.258", &a) == 0);

	/* "the octal numbers, hexadecimal numbers" */
	CHECK(inet_pton(AF_INET, "0x7f.0.0.1", &a) == 0);
	CHECK(inet_pton(AF_INET, "0x7f000001", &a) == 0);
	CHECK(inet_pton(AF_INET, "0177.0.0.1", &a) == 0);

	/* "a one to three digit decimal number between 0 and 255": four
	 * digits is outside the grammar even where the value is in range,
	 * and 256 is outside it even with three. */
	CHECK(inet_pton(AF_INET, "0001.2.3.4", &a) == 0);
	CHECK(inet_pton(AF_INET, "1.2.3.1024", &a) == 0);
	CHECK(inet_pton(AF_INET, "256.0.0.1", &a) == 0);

	/* Nothing may surround or follow the four numbers. */
	CHECK(inet_pton(AF_INET, " 1.2.3.4", &a) == 0);
	CHECK(inet_pton(AF_INET, "1.2.3.4 ", &a) == 0);
	CHECK(inet_pton(AF_INET, "1.2.3.4\n", &a) == 0);
	CHECK(inet_pton(AF_INET, "+1.2.3.4", &a) == 0);
	CHECK(inet_pton(AF_INET, "1..2.3", &a) == 0);
	CHECK(inet_pton(AF_INET, ".1.2.3.4", &a) == 0);

	/* The 0 return is not the -1 return: no [EAFNOSUPPORT], and errno
	 * is not cleared either.  EDOM is used only as a value no path in
	 * inet_pton() would plausibly produce. */
	errno = EDOM;
	CHECK(inet_pton(AF_INET, "not an address", &a) == 0);
	CHECK(errno != 0);
	CHECK(errno != EAFNOSUPPORT);
	errno = EDOM;
	CHECK(inet_pton(AF_INET, "", &a) == 0);
	CHECK(errno != 0);
	CHECK(errno != EAFNOSUPPORT);

	/* "-1 with errno set to [EAFNOSUPPORT] if the af argument is
	 * unknown" -- and it is a different outcome from the 0 above. */
	errno = 0;
	CHECK(inet_pton(AF_UNIX, "1.2.3.4", &a) == -1);
	CHECK(errno == EAFNOSUPPORT);
	errno = 0;
	CHECK(inet_pton(AF_UNSPEC, "1.2.3.4", &a) == -1);
	CHECK(errno == EAFNOSUPPORT);
}

/* --------------------------------------------------------------------
 * The AF_INET6 half of inet_ntop.html.
 * ------------------------------------------------------------------ */
#if SPICULE_TEST(PASS, posix_inet_inet6_text_forms) /* Implemented: inet_ntop.html DESCRIPTION -- "The AF_INET and AF_INET6
	address families shall be supported."  The same paragraph says
	of inet_ntop()'s af argument "This can be AF_INET or
	AF_INET6", and of inet_pton()'s dst buffer that it "shall be
	large enough to hold the numeric address (32 bits for AF_INET,
	128 bits for AF_INET6)".  The three text forms inet_pton() must
	accept are spelled out in the page's own numbered list: 1. "The
	preferred form is "x:x:x:x:x:x:x:x", where the 'x's are the
	hexadecimal values of the eight 16-bit pieces of the address";
	2. "A string of contiguous zero fields in the preferred form
	can be shown as "::".  The "::" can only appear once in an
	address. Unspecified addresses ("0:0:0:0:0:0:0:0") may be
	represented simply as "::"."; 3. "x:x:x:x:x:x:d.d.d.d", the
	mixed form whose low 32 bits are written as an IPv4 address.

	src/socket/inet.c now implements all three forms and canonical
	zero-run compression, while <netinet/in.h> supplies in6_addr.

	THE FORMER FAILURE, observed rather than derived: linking a
	caller against src/socket/inet.c and a host libc,
	inet_pton(AF_INET6, "::1", b) and inet_pton(AF_INET6,
	"2001:db8::1", b) both return -1 with errno EAFNOSUPPORT, and
	inet_ntop(AF_INET6, b, out, 64) returns NULL with the same
	errno.  Absence of the type: `grep -rn "INET6_ADDRSTRLEN\|
	in6_addr" include/ src/ test/ fuzz/` finds four hits and all
	four are prose -- <netinet/in.h>'s banner, two comments in
	test/posix-socket.c, one line of test/verification-coverage-
	accounting.md -- with no definition anywhere.  (The same grep
	finding those four is the control: the pattern matches text
	that is there, so the missing definition is a real absence and
	not a mistyped query.)

	The former classification was UNIMPL, not N/A, and the distinction
	mattered more here than
	anywhere else in the socket subsystem.  The rest of spicule's
	IPv6 absence has a mechanism behind it: an AF_INET6 socket
	needs an AFD path this tree does not have, and
	test/networking-audit.md sec 6 stages that work behind a bind()
	that does not yet function under Wine.  These two clauses have
	none of that.  They are string parsing and string formatting
	over a 16-byte array -- no descriptor, no device, no ioctl,
	nothing NT supplies or withholds -- and src/socket/inet.c's own
	banner says so of the whole file ("pure C with no NT dependency
	at all").  They were missing because nobody had written them, which is
	what UNIMPL means in this ledger.

	NOT N/A on the "no IPv6 stack here" argument, which is the
	tempting one: inet_pton(AF_INET6) no more requires a stack that
	can carry an IPv6 packet than inet_pton(AF_INET) requires one
	that can carry an IPv4 packet.  A caller that reads an address
	out of a configuration file to validate, compare, store or
	print it needs the parser and nothing else.

	It was not classified as a BUG either, and this counter-argument was
	writing down, because test/posix-socket.c's test_inet_pton_ntop
	asserts today's behaviour as CORRECT: [EAFNOSUPPORT] is a
	documented ERRORS value of both functions, so returning it
	looks conforming.  It is not.  ERRORS defines it for an af that
	"is invalid", and RETURN VALUE for one that "is unknown", while
	the DESCRIPTION sentence quoted at the top of this fence makes
	AF_INET6 neither: it is a family the implementation shall
	support.  Answering "I do not know this family" for a family
	the page names in the same paragraph is the
	declared-but-unimplemented trap, not conformance.
	posix-socket.c's assertions remain the right ones for that file
	-- they pin the behaviour a caller gets today so it cannot
	change silently -- and this fence records that the behaviour
	they pin is a gap.

	WHAT A CALLER OBSERVED BEFORE THE FIX.  A program that includes
	<arpa/inet.h> and writes `struct in6_addr a; inet_pton(AF_INET6,
	s, &a);` does not compile (no such type, and no
	INET6_ADDRSTRLEN to size the other direction's buffer); one
	that reaches the call through a void * gets -1/EAFNOSUPPORT for
	every input, well-formed ones included.

	WHAT WAS WRITTEN.  The two conversions in
	src/socket/inet.c -- the parser is the larger half: eight
	16-bit fields, at most one "::" run, an optional trailing
	dotted quad, and for the reverse a rule for choosing which zero
	run to elide -- plus the in6_addr structure ("uint8_t
	s6_addr[16]", netinet_in.h.html) and INET6_ADDRSTRLEN in
	<netinet/in.h>.  No new NT call, and no dependency on the
	staged AFD work, which is the point: this half can land before
	any of it.  It does NOT require the rest of that header's IPv6
	set (sockaddr_in6, ipv6_mreq, the IPV6_* options,
	IN6_IS_ADDR_*), which stay out of scope with the sockets that
	would use them. */
static void test_inet6_text_forms(void)
{
	struct in6_addr a6;
	char buf[INET6_ADDRSTRLEN];
	static const unsigned char loopback[16] =
		{ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
	static const unsigned char mapped[16] =
		{ 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 1,2,3,4 };

	/* form 1 and form 2, for one address */
	CHECK(inet_pton(AF_INET6, "0:0:0:0:0:0:0:1", &a6) == 1);
	CHECK(!memcmp(a6.s6_addr, loopback, 16));
	CHECK(inet_pton(AF_INET6, "::1", &a6) == 1);
	CHECK(!memcmp(a6.s6_addr, loopback, 16));

	/* form 3, the IPv4-mapped case that makes it useful */
	CHECK(inet_pton(AF_INET6, "::ffff:1.2.3.4", &a6) == 1);
	CHECK(!memcmp(a6.s6_addr, mapped, 16));

	/* ""::" can only appear once in an address", and an IPv4 string is
	 * not an IPv6 one: 0, not -1 */
	CHECK(inet_pton(AF_INET6, "1::2::3", &a6) == 0);
	CHECK(inet_pton(AF_INET6, "::0:", &a6) == 0);
	CHECK(inet_pton(AF_INET6, "1.2.3.4", &a6) == 0);

	/* fuzz: issue #5 (fuzz_inet, CI runs 33122015293 and 33126258867,
	 * both 2026-08-27) reported a finding for the single input byte
	 * 0x88.  At the commit those runs actually fuzzed (8b2af2c, which
	 * predates AF_INET6 support -- see "THE FORMER FAILURE" in the
	 * fence above), fuzz_inet.c's own harness still asserted that
	 * inet_pton(AF_INET6, ...) must fail with -1/EAFNOSUPPORT for every
	 * input, the same assertion test_inet_pton_strict_grammar now makes
	 * about AF_UNIX/AF_UNSPEC below; spicule's pre-IPv6 inet_pton()
	 * returned something other than -1 without setting errno to it, so
	 * the harness's own oracle_mismatch_i() called abort()
	 * (host_oracle.c).  That was not a memory-safety bug and left no
	 * artefact to replay byte-for-byte: 00d1af9, 888a4d1, 56f7fae and
	 * 06e51e1 (later the same day) implemented real AF_INET6 support,
	 * which made the harness's blanket "AF_INET6 is unsupported"
	 * assertion wrong rather than fixing what it checked, and the
	 * harness was rewritten to assert EAFNOSUPPORT of AF_UNIX instead
	 * (fuzz/fuzz_inet.c, current). 0x88 is simply not a hex digit, ':'
	 * or '.', so it is unconditionally invalid IPv6 text with or
	 * without EAFNOSUPPORT anywhere in the picture; kept here,
	 * unconditional, as the regression this issue asked for: a single
	 * non-hex, non-separator byte must be refused like any other
	 * malformed text, not crash, and not touch errno on its way past
	 * (errno.html: "No function in this volume of POSIX.1-2017 shall
	 * set errno to 0", so EDOM here must survive unchanged). */
	errno = EDOM;
	CHECK(inet_pton(AF_INET6, "\x88", &a6) == 0);
	CHECK(errno == EDOM);

	/* and back, in the compressed form */
	memcpy(a6.s6_addr, loopback, 16);
	CHECK(inet_ntop(AF_INET6, &a6, buf, sizeof buf) == buf);
	CHECK(!strcmp(buf, "::1"));
	errno = 0;
	CHECK(inet_ntop(AF_INET6, &a6, buf, 3) == 0);
	CHECK(errno == ENOSPC);
}
#endif

#if SPICULE_TEST(PASS, posix_inet_inet6_addrstrlen_defined) /* Implemented: basedefs/arpa_inet.h.html DESCRIPTION -- "The
	<arpa/inet.h> header shall define the INET_ADDRSTRLEN and
	INET6_ADDRSTRLEN macros as described in <netinet/in.h>", and
	basedefs/netinet_in.h.html, which describes them with their
	values: "INET_ADDRSTRLEN 16. Length of the string form for IP."
	and "INET6_ADDRSTRLEN 46. Length of the string form for IPv6."
	spicule's <netinet/in.h> now defines both.

	Fenced separately from test_inet6_text_forms because it is a distinct
	header contract.

	It fails a consumer differently.  A program that sizes a buffer
	with INET6_ADDRSTRLEN and calls only inet_ntop(AF_INET, ...) --
	which is what portable code that may one day be handed an IPv6
	address looks like -- fails to compile here over a macro whose
	value the standard fixes.

	And it is the one name in this gap that no banner in the tree
	records.  POSIX-COVERAGE.md's group U deliberately did not
	fence "<netinet/in.h>'s IPv6 set" because that header's own
	banner scopes it out -- but the banner scopes out
	"AF_INET6/struct sockaddr_in6/struct in6_addr and the IPV6_*
	socket options", and INET6_ADDRSTRLEN is in none of those four
	groups.  Nor is it in <arpa/inet.h>'s banner, which lists what
	that header omits and does not mention it.  The clause quoted
	above is on the <arpa/inet.h> page, not the <netinet/in.h> one,
	so a reader following either banner's scope note would conclude
	the header is complete.  That is the silence this fence breaks.

	It deliberately did not land as a standalone fix.  Defining
	a constant that sizes a buffer for a conversion the library
	cannot perform is the "declared elsewhere, not here" trap
	<arpa/inet.h>'s own banner says this project avoids, and
	<netinet/in.h>'s banner gives the same rule for the IPv6 set it
	omits ("never declare what has no body").  The constant should
	land with the conversions, in one commit. */
static void test_inet6_addrstrlen_defined(void)
{
	CHECK(INET6_ADDRSTRLEN == 46);
	CHECK(INET6_ADDRSTRLEN > INET_ADDRSTRLEN);
}
#endif

/* --------------------------------------------------------------------
 * inet_addr()'s two defects.
 * ------------------------------------------------------------------ */
#if SPICULE_TEST(PASS, posix_inet_inet_addr_rejects_sign_and_space) /* inet_addr.html DESCRIPTION and RETURN VALUE -- the
	function converts "the string pointed to by cp, in the standard
	IPv4 dotted decimal notation", and "Otherwise, it shall return
	(in_addr_t)(-1)".  spicule accepts three spellings that are not
	in that notation under any reading of the page.

	MECHANISM.  src/socket/inet.c parses each part with
	strtoul(p, &end, 0) and checks only that it consumed something.
	strtoul() is specified to skip leading white space and to
	accept an optional '+' or '-' before the digits, so each of
	these reaches the range checks as an ordinary value:

	  " 1.2.3.4"  -> 1.2.3.4        (leading white space skipped)
	  "+1.2.3.4"  -> 1.2.3.4        (sign consumed)
	  "1. 2.3.4"  -> 1.2.3.4        (both, mid-string)
	  "-2"        -> 255.255.255.254 on both PE targets

	The last is target-dependent and is the one that produces a
	wrong ADDRESS rather than a wrongly-accepted spelling, so it is
	worth spelling out.  strtoul() negates within unsigned long, so
	"-2" yields ULONG_MAX-1; the one-part form's only range check
	is `parts[0] > 0xffffffffUL`, which on the targets where
	unsigned long is 32 bits -- i386 and, LLP64, x86_64, i.e. every
	target this project ships -- is a comparison against ULONG_MAX
	and can never be true.  The value survives and htonl() turns it
	into 255.255.255.254.  Where unsigned long is 64 bits, which is
	only `make asan`'s native ELF build, the same check does reject
	it: one string, two answers, by target.

	OBSERVED, not derived.  The four assertions below were run
	against src/socket/inet.c itself, by linking this file with it
	against a host libc.  The first three fail there (the values
	above are what came back); the fourth PASSES there, because
	that build's unsigned long is 64 bits -- which is the
	divergence, seen from the only side directly runnable this way.
	The 32-bit side was measured the same way, on the same parse loop
	with a 32-bit part type standing in for LLP64, and returned
	255.255.255.254.  All four stay fenced together because the
	clause they test is one clause, and because a live assertion
	that holds on one target and not another is worse than none.

	WHY THIS IS A BUG AND NOT LATITUDE.  fuzz/fuzz_inet.c declines
	to oracle inet_addr() against the host's precisely here, and
	its banner argues the corner is under-specified: the page says
	the parts may be "decimal, octal, or hexadecimal, as specified
	in the ISO C standard", which is strtoul()'s own vocabulary, so
	reaching for strtoul() is defensible.  That argument is
	accepted as far as the RADIX goes -- test_inet_addr_forms_and_
	radix asserts the radix behaviour as CORRECT for exactly that
	reason -- but it does not reach the sign or the space.  The
	sentence it rests on is about how a NUMBER is written, and it
	offers a closed trichotomy for that: "a leading 0x or 0X
	implies hexadecimal; otherwise, a leading '0' implies octal;
	otherwise, the number is interpreted as decimal".  A part
	beginning with '+' or ' ' falls into the third arm, and " 1" is
	not a decimal number.  A '-' does not make the part a number in
	a different base; it makes the string denote no address at all.

	The decisive evidence is inside this implementation rather than
	outside it.  inet_addr("1.2.3.4 ") is rejected today -- the
	trailing-garbage check at the end of the parse loop -- while
	inet_addr(" 1.2.3.4") is accepted.  A reading under which white
	space belongs to the notation would have to accept both; a
	reading under which it does not would reject both.  The library
	holds neither reading: it holds "whatever strtoul() ate", which
	is not an interpretation of the page but the absence of one.
	test_inet_addr_forms_and_radix's `inet_addr("1.2.3.4 ")`
	assertion is the live half of that argument and stays green
	either way.

	WHAT A CALLER OBSERVES TODAY.  A configuration reader that
	trims its own lines is unaffected; one that does not silently
	accepts " 10.0.0.1", so a file this library accepts is rejected
	by glibc, musl and Winsock, and a validation pass built on
	inet_addr() passes strings its consumer will later reject.  The
	"-2" case is worse in kind: not a lenient acceptance of a valid
	address, but the conversion of a plainly invalid string into a
	specific, plausible, wrong one.

	THE FIX, if taken up: guard the strtoul() call the way musl's
	inet_aton() does, by requiring the first character of each part
	to be a digit before accepting what strtoul() returned.  One
	condition, no cost, and it leaves the radix behaviour these
	tests assert untouched.  Note that fixing it also releases
	fuzz/fuzz_inet.c to oracle inet_addr() against the host's: as
	of c7c0171, which removed that harness's leading-zero guard,
	the divergence described here is the only reason its banner
	still gives for not making that comparison. */
static void test_inet_addr_rejects_sign_and_space(void)
{
	CHECK(inet_addr(" 1.2.3.4") == (in_addr_t)(-1));
	CHECK(inet_addr("+1.2.3.4") == (in_addr_t)(-1));
	CHECK(inet_addr("1. 2.3.4") == (in_addr_t)(-1));
	CHECK(inet_addr("-2") == (in_addr_t)(-1));
}
#endif

#if SPICULE_TEST(PASS, posix_inet_inet_addr_preserves_errno) /* errno.html DESCRIPTION -- "No function in this volume of
	POSIX.1-2017 shall set errno to 0."  inet_addr()'s parse loop
	(src/socket/inet.c) executes `errno = 0;` before every
	strtoul() call, on the success path and the failure path alike,
	and inet_addr.html's ERRORS section is "No errors are defined."
	-- so the function has nothing to report through errno and
	clears it anyway.

	This is the one clause on these three pages that is violated
	unconditionally, on every call, on every target.

	OBSERVED, not derived: the two assertions below were run
	against src/socket/inet.c itself (this file links with it
	against a host libc) and both fail -- errno is 0 after
	inet_addr("1.2.3.4") and after inet_addr("not an address"),
	having been EDOM immediately before each call.  Unlike the
	fence above this one, nothing here is target-dependent: the
	assignment is unconditional.

	WHY IT IS THERE, AND WHY THAT MAKES IT A BUG RATHER THAN A
	STYLE POINT.  `errno = 0` before strtoul() is the first half of
	the standard [ERANGE] idiom; the second half -- a test of errno
	after the call -- was never written, so the assignment protects
	nothing.  (The overflow it was presumably meant to catch is in
	fact caught, by the explicit range checks that follow: a
	saturated ULONG_MAX fails every one of them, and in the
	one-part form converts to the failure value anyway.  This is a
	dead assignment, not a missing check.)  Its one live effect is
	destructive: it destroys errno for the caller.

	WHAT A CALLER OBSERVES TODAY.  errno.html's own sentence -- the
	value "shall be defined only after a call to a function for
	which it is explicitly stated to be set and until it is changed
	by the next function call" -- is what makes the "set errno to
	0, call, examine errno" idiom work at all, and this breaks it
	across an intervening inet_addr().  The concrete shape:
	strtol() sets [ERANGE], the caller has not read errno yet, an
	inet_addr() call on the next field of the same line clears it,
	and the overflow is never noticed.  This project already reads
	the same page this way -- POSIX-COVERAGE.md's group T section
	defends its own `CHECK(errno == 0)` assertions with it -- so
	the reading is the tree's, not this file's.

	Asserted as `errno != 0` rather than `errno == <what I set>`
	because that is exactly the clause: the page permits any
	function call to change errno, and forbids only setting it to
	zero.

	THE FIX: delete the `errno = 0;` line.  Nothing reads it.  A
	later change that does want to consult errno after strtoul()
	must save and restore the caller's value around the parse. */
static void test_inet_addr_preserves_errno(void)
{
	errno = EDOM;
	CHECK(inet_addr("1.2.3.4") == htonl(0x01020304UL));
	CHECK(errno != 0);

	errno = EDOM;
	CHECK(inet_addr("not an address") == (in_addr_t)(-1));
	CHECK(errno != 0);
}
#endif

int main(void)
{
	test_arpa_inet_header_contents();
	test_declared_as_functions();
	test_byteorder_wire_layout();
	test_inet_addr_forms_and_radix();
	test_inet_ntoa_static_storage();
	test_inet_ntop_size_and_family();
	test_inet_pton_strict_grammar();

#if SPICULE_TEST(PASS, posix_inet_inet6_text_forms) /* See the fence above test_inet6_text_forms.  Fenced here
	too because the function it calls is inside that #if 0. */
	test_inet6_text_forms();
#endif
#if SPICULE_TEST(PASS, posix_inet_inet6_addrstrlen_defined) /* See the fence above test_inet6_addrstrlen_defined. */
	test_inet6_addrstrlen_defined();
#endif
#if SPICULE_TEST(PASS, posix_inet_inet_addr_rejects_sign_and_space)
	test_inet_addr_rejects_sign_and_space();
#endif
#if SPICULE_TEST(PASS, posix_inet_inet_addr_preserves_errno)
	test_inet_addr_preserves_errno();
#endif

	if (fails) { printf("posix-inet: failures: %d\n", fails); return 1; }
	printf("posix-inet: all ok\n");
	return 0;
}
