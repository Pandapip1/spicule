/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <netdb.h> coverage. spicule now HAS a <netdb.h>, on Linux
 * (include/netdb.h; src/netdb/linux/); see that header's own banner
 * for exact scope (getaddrinfo()/freeaddrinfo()/
 * gai_strerror(), getnameinfo(), all four enumerable databases --
 * service/protocol/host/network -- plus gethostbyname() as a disclosed
 * legacy addition, backed by a real /etc/hosts parser, a real minimal
 * UDP DNS stub resolver, and a real /etc/nsswitch.conf parser). Every
 * test below that used to be an UNIMPL fence is UNWRAPPED accordingly
 * and runs for real, each call site's original clause citations kept
 * verbatim (nothing about what they assert changed, only whether the
 * code compiles). New, non-POSIX-clause-audit coverage for the real
 * backends -- the /etc/hosts and /etc/nsswitch.conf fixture behavior,
 * and a real UDP round trip against a hermetic fake DNS server this
 * file spins up itself -- is appended after the original POSIX audit
 * content, not mixed into it.
 *
 * Two of the unwrapped tests, posix_netdb_hostent_sequential_access and
 * posix_netdb_netent_lookup, needed a real, disclosed change beyond
 * just deleting the #if: they originally walked whatever this host's
 * own real /etc/hosts / /etc/networks happened to contain, which is
 * unsound the moment that file is large (this environment's own real
 * /etc/hosts is an ad-block list with tens of thousands of entries) --
 * see each test's own comment for the fix, the same
 * SPICULE_TEST_HOSTS_PATH-shaped fixture override src/internal/
 * nss_paths.h already provides and this file's own
 * test_netdb_hosts_fixture() already uses for the identical reason.
 *

 * POSIX.1-2017 (IEEE Std 1003.1-2017, The Open Group Base
 * Specifications Issue 7, 2018 Edition), served at
 * https://pubs.opengroup.org/onlinepubs/9699919799/ ; clause text read
 * from Ubuntu's manpages-posix-dev 2017a-2, which reprints that
 * edition verbatim (pubs.opengroup.org is unreachable from here).
 *
 * ==================== the gap ========================================
 *
 * The name-level cross-index behind test/posix-pthread.c finds 22
 * <netdb.h> interfaces with no mention anywhere in the test/ tree.  (Its
 * per-header bucketing puts 20 of them under <netdb.h> and two --
 * freeaddrinfo, getnameinfo -- under <sys/socket.h>, because it buckets
 * by the FIRST #include in a page's SYNOPSIS and freeaddrinfo.html
 * lists <sys/socket.h> first.  The 2017a page's own NAME section also
 * carries a typo, `getprotent`, which the index faithfully counts and
 * which is not a real interface; it is dropped here.  Both are index
 * artefacts, recorded rather than quietly fixed.)  The 22:
 *
 *   name resolution   freeaddrinfo gai_strerror getnameinfo
 *   host database     sethostent gethostent endhostent
 *   network database  setnetent getnetent getnetbyaddr getnetbyname
 *                     endnetent
 *   protocol database setprotoent getprotoent getprotobyname
 *                     getprotobynumber endprotoent
 *   service database  setservent getservent getservbyname
 *                     getservbyport endservent
 *
 * getaddrinfo() itself is absent too but reads as covered by the index,
 * because the identifier appears once in prose at
 * test/posix-socket.c:431 -- in a list of things a v6 path would need,
 * not in an assertion.  That is the index's known over-report; it is
 * noted here rather than silently corrected, and getaddrinfo() is
 * fenced below alongside freeaddrinfo(), which shares its page.
 *
 * This is a live gap rather than a decline: spicule HAS a socket layer
 * (src/socket/, include/netinet/in.h, include/arpa/inet.h, and
 * test/posix-socket*.c's six files), so a program that can already
 * open and connect a socket here still cannot turn a name into an
 * address, or a port number into a service name, by any POSIX route.
 * The <netdb.h> databases are also the part of this header that needs
 * no resolver at all: XSH endservent.html says only that the data "is
 * considered to be stored in a database that can be accessed
 * sequentially or randomly.  The implementation of this database is
 * unspecified" -- so the well-known-services table can be a static
 * array, and NT ships %SystemRoot%\system32\drivers\etc\services in
 * exactly the /etc/services format.
 *
 * ==================== interfaces intentionally left unfenced ===========
 *
 * Not fenced here, with reasons: h_errno and the gethostbyname()/
 * gethostbyaddr() pair.  Checked, not assumed: the 2017a <netdb.h>
 * page's "The following shall be declared as functions" block lists 21
 * names and none of the three is among them, and manpages-posix-dev
 * ships no gethostbyname page at all.  POSIX removed them in this
 * edition, so their absence here is conformant and a fence would assert
 * the wrong thing.  Also not fenced: <net/if.h>'s if_nametoindex family
 * (a separate header, and a separate unit).
 */

/* setenv()/unsetenv() (used by this file's own new hermetic-fixture
 * tests, further down) are gated behind a feature-test macro in this
 * project's own headers -- see test/posix-time.c/test/posix-unistd.c
 * for the same pattern already established across this test suite. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* fixture_write(): defined further down (this file's own "not a
 * POSIX-clause fence" section), forward-declared here so the hosts/
 * networks sequential-access tests below -- which need a small,
 * controlled database rather than whatever this host's own real
 * /etc/hosts or /etc/networks happens to contain -- can use it too. See
 * that section's own banner and src/internal/nss_paths.h for why an
 * env-var fixture override is this codebase's standing answer to
 * exactly this problem. */
static void fixture_write(const char *path, const char *content);

/* ==================================================================
 * Name resolution -- .../functions/freeaddrinfo.html (which specifies
 * getaddrinfo too), getnameinfo.html, gai_strerror.html
 * ================================================================== */

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_getaddrinfo_loopback)):
 * include/netdb.h now exists; see this file's own top banner.
 * <arpa/inet.h> (for htons()/htonl(), used below) was missing from
 * this fence's own original include list -- never caught while the
 * whole block was `#if 0`'d out; caught now, unwrapping it. */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static void test_posix_netdb_getaddrinfo_loopback(void)
{
	struct addrinfo hints, *res = NULL, *p;
	int seen = 0;

	/* freeaddrinfo.html: "The getaddrinfo() function shall translate
	 * the name of a service location (for example, a host name) and/or
	 * a service name and shall return a set of socket addresses and
	 * associated information to be used in creating a socket with
	 * which to address the specified service."  A numeric address with
	 * AI_NUMERICHOST needs no resolver, so this clause is decidable
	 * with no network at all: "if the AI_NUMERICHOST flag is
	 * specified, then a non-null nodename string shall be a numeric
	 * host address string." */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	CHECK(getaddrinfo("127.0.0.1", "80", &hints, &res) == 0);
	CHECK(res != NULL);

	/* "shall return a set of socket addresses" -- a list linked by
	 * ai_next, each entry self-describing through ai_family,
	 * ai_socktype, ai_addr and ai_addrlen. */
	for (p = res; p != NULL; p = p->ai_next) {
		CHECK(p->ai_family == AF_INET);
		CHECK(p->ai_socktype == SOCK_STREAM);
		CHECK(p->ai_addr != NULL);
		CHECK(p->ai_addrlen == (socklen_t)sizeof(struct sockaddr_in));
		if (p->ai_addr != NULL) {
			struct sockaddr_in sin;

			memcpy(&sin, p->ai_addr, sizeof sin);
			CHECK(sin.sin_family == AF_INET);
			/* servname "80" is a port number, in network byte
			 * order in the returned sockaddr. */
			CHECK(sin.sin_port == htons(80));
			CHECK(sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
			seen++;
		}
	}
	CHECK(seen >= 1);

	/* "The freeaddrinfo() function shall free one or more addrinfo
	 * structures returned by getaddrinfo(), along with any additional
	 * storage associated with those structures.  If the ai_next field
	 * of the structure is not null, the entire list of structures
	 * shall be freed." */
	freeaddrinfo(res);

	/* ERRORS: "[EAI_NONAME] The name does not resolve for the supplied
	 * parameters" -- which is what AI_NUMERICHOST on a non-numeric
	 * name must produce, again without any resolver. */
	res = NULL;
	CHECK(getaddrinfo("not.a.numeric.address", "80", &hints, &res)
	      == EAI_NONAME);
}

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_getnameinfo_numeric)):
 * getnameinfo() now exists on both platforms (src/netdb/linux/
 * getnameinfo.c, src/netdb/nt/plat_netdb.c) and the NI_NUMERICHOST |
 * NI_NUMERICSERV case this test exercises needs no database on either
 * one -- see include/netdb.h's own banner. */
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void test_posix_netdb_getnameinfo_numeric(void)
{
	struct sockaddr_in sin;
	char node[NI_MAXHOST];
	char serv[NI_MAXSERV];

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* getnameinfo.html: "shall translate a socket address to a node
	 * name and service location ... If the node argument is non-NULL
	 * and the nodelen argument is non-zero, then the node argument
	 * shall point to a buffer able to contain up to nodelen bytes that
	 * receives the node name as a null-terminated string."  With
	 * NI_NUMERICHOST -- "the numeric form of the node's address is
	 * returned instead of its name" -- and NI_NUMERICSERV -- "the
	 * numeric form of the service address is returned ... instead of
	 * its name" -- no resolver is consulted, so the answer is fixed. */
	memset(node, 0, sizeof node);
	memset(serv, 0, sizeof serv);
	CHECK(getnameinfo((const struct sockaddr *)&sin, sizeof sin,
			  node, sizeof node, serv, sizeof serv,
			  NI_NUMERICHOST | NI_NUMERICSERV) == 0);
	CHECK(strcmp(node, "127.0.0.1") == 0);
	CHECK(strcmp(serv, "80") == 0);

	/* "The NI_MAXHOST and NI_MAXSERV [constants] ... shall be defined
	 * in <netdb.h>" and are the buffer sizes this interface is
	 * specified against, so they must be large enough for what it
	 * returns. */
	CHECK(NI_MAXHOST > 0 && NI_MAXSERV > 0);
	CHECK(strlen(node) < (size_t)NI_MAXHOST);

	/* "If the node argument is NULL and the nodelen argument is zero,
	 * ... the node name shall not be returned" -- and likewise for
	 * serv; at least one of the two must be requested. */
	memset(serv, 0, sizeof serv);
	CHECK(getnameinfo((const struct sockaddr *)&sin, sizeof sin,
			  NULL, 0, serv, sizeof serv, NI_NUMERICSERV) == 0);
	CHECK(strcmp(serv, "80") == 0);
}

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_gai_strerror_text)):
 * <netdb.h> already included above. */
static void test_posix_netdb_gai_strerror_text(void)
{
	static const int codes[] = {
		EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY,
		EAI_NONAME, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM, EAI_OVERFLOW
	};
	size_t i, j;

	/* gai_strerror.html: "shall return a text string describing an
	 * error value for the getaddrinfo() and getnameinfo() functions
	 * listed in the <netdb.h> header."  RETURN VALUE: "Upon successful
	 * completion, gai_strerror() returns a pointer to a string
	 * describing the error value.  If the error value is not one of
	 * those listed above, the function returns a pointer to a string
	 * indicating an unknown error." -- so it never returns NULL, and
	 * never an empty string. */
	for (i = 0; i < sizeof codes / sizeof codes[0]; i++) {
		const char *s = gai_strerror(codes[i]);

		CHECK(s != NULL);
		if (s != NULL)
			CHECK(s[0] != '\0');
	}

	/* The codes themselves are distinct: getaddrinfo() returns them as
	 * its own return value, so two that collide would be
	 * indistinguishable to a caller. */
	for (i = 0; i < sizeof codes / sizeof codes[0]; i++)
		for (j = i + 1; j < sizeof codes / sizeof codes[0]; j++)
			CHECK(codes[i] != codes[j]);

	/* "a string indicating an unknown error" for a value that is not
	 * one of them -- still a string. */
	CHECK(gai_strerror(0x5eed) != NULL);
	CHECK(gai_strerror(0x5eed)[0] != '\0');
}

/* ==================================================================
 * The service database -- .../functions/endservent.html, which
 * specifies setservent/getservent/getservbyname/getservbyport too
 * ================================================================== */

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_getservbyname_wellknown)):
 * a real /etc/services(5) parser now backs this whole family
 * (src/netdb/linux/services.c); see that file's own banner.
 *
 * Linux-only: src/netdb/nt/plat_netdb.c's own banner says a real NT
 * services database (the file's own comment names
 * %SystemRoot%\system32\drivers\etc\services as the eventual real
 * backend) is future work -- every entry point in this family is an
 * unconditional NULL stub there today, so this test would only be
 * proving that stub NULL rather than the interface's real behavior. */
#include <netdb.h>
#include <netinet/in.h>

#if defined(__linux__)
static void test_posix_netdb_getservbyname_wellknown(void)
{
	struct servent *se;

	/* endservent.html: "The getservbyname() function shall search the
	 * database from the beginning and find the first entry for which
	 * the service name specified by name matches the s_name member and
	 * the protocol name specified by proto matches the s_proto member
	 * ... If proto is a null pointer, any value of the s_proto member
	 * shall be matched."
	 *
	 * "http/80/tcp" is an IANA well-known assignment, present in every
	 * /etc/services and in NT's own
	 * %SystemRoot%\system32\drivers\etc\services, so this is a fact
	 * about the database rather than about one host. */
	se = getservbyname("http", "tcp");
	CHECK(se != NULL);
	if (se != NULL) {
		/* <netdb.h> defines servent's members: "s_port: A value
		 * which, when converted to uint16_t, yields the port
		 * number in network byte order at which the service
		 * resides." */
		CHECK(strcmp(se->s_name, "http") == 0);
		CHECK((uint16_t)se->s_port == htons(80));
		CHECK(se->s_proto != NULL && strcmp(se->s_proto, "tcp") == 0);
		/* "s_aliases: A pointer to an array of pointers to
		 * alternative service names, terminated by a null
		 * pointer." -- possibly empty, but never a null array. */
		CHECK(se->s_aliases != NULL);
	}

	/* getservbyport(): "shall search the database from the beginning
	 * and find the first entry for which the port specified by port
	 * matches the s_port member" -- the inverse of the above, and the
	 * port argument is in network byte order. */
	se = getservbyport((int)htons(80), "tcp");
	CHECK(se != NULL);
	if (se != NULL)
		CHECK(strcmp(se->s_name, "http") == 0);

	/* RETURN VALUE: "a null pointer if the end of the database was
	 * reached or the requested entry was not found." */
	CHECK(getservbyname("no-such-service-name", "tcp") == NULL);

	/* "The setservent() function shall open a connection to the
	 * database, and set the next entry to the first entry", "The
	 * getservent() function shall read the next entry of the
	 * database", "The endservent() function shall close the connection
	 * to the database".  Walking from the start must reach at least
	 * one entry, and must terminate. */
	setservent(1);
	se = getservent();
	CHECK(se != NULL);
	if (se != NULL)
		CHECK(se->s_name != NULL);
	endservent();
}
#else
/* See this test's own banner above: NT has no real services database
 * backend yet, only an unconditional NULL stub. */
static void test_posix_netdb_getservbyname_wellknown(void)
{
	printf("SKIP posix-netdb services database (no real services "
	       "database backend on this platform -- see "
	       "src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* ==================================================================
 * The protocol database -- .../functions/endprotoent.html
 * ================================================================== */

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_getprotobyname_tcp)):
 * a real /etc/protocols(5) parser now backs this whole family
 * (src/netdb/linux/protocols.c); see that file's own banner.
 *
 * Linux-only: same reasoning as test_posix_netdb_getservbyname_wellknown
 * just above -- src/netdb/nt/plat_netdb.c's protocol-database entry
 * points are all unconditional NULL stubs, so there is no real protocols
 * database backend on NT for this to prove anything against yet. */
#include <netdb.h>
#include <netinet/in.h>

#if defined(__linux__)
static void test_posix_netdb_getprotobyname_tcp(void)
{
	struct protoent *pe;

	/* endprotoent.html: "The getprotobyname() function shall search
	 * the database from the beginning and find the first entry for
	 * which the protocol name specified by name matches the p_name
	 * member".  TCP is protocol number 6 by IANA assignment, which
	 * <netinet/in.h> already spells IPPROTO_TCP in this tree. */
	pe = getprotobyname("tcp");
	CHECK(pe != NULL);
	if (pe != NULL) {
		CHECK(strcmp(pe->p_name, "tcp") == 0);
		CHECK(pe->p_proto == IPPROTO_TCP);
		CHECK(pe->p_aliases != NULL);
	}

	/* "The getprotobynumber() function shall search the database from
	 * the beginning and find the first entry for which the protocol
	 * number specified by proto matches the p_proto member." */
	pe = getprotobynumber(IPPROTO_UDP);
	CHECK(pe != NULL);
	if (pe != NULL) {
		CHECK(strcmp(pe->p_name, "udp") == 0);
		CHECK(pe->p_proto == IPPROTO_UDP);
	}

	CHECK(getprotobyname("no-such-protocol-name") == NULL);

	/* setprotoent()/getprotoent()/endprotoent(), the sequential
	 * access the same page specifies. */
	setprotoent(1);
	pe = getprotoent();
	CHECK(pe != NULL);
	if (pe != NULL)
		CHECK(pe->p_name != NULL);
	endprotoent();
}
#else
/* See this test's own banner above: NT has no real protocols database
 * backend yet, only an unconditional NULL stub. */
static void test_posix_netdb_getprotobyname_tcp(void)
{
	printf("SKIP posix-netdb protocols database (no real protocols "
	       "database backend on this platform -- see "
	       "src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* ==================================================================
 * The host and network databases --
 * .../functions/endhostent.html, endnetent.html
 * ================================================================== */

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_hostent_sequential_access)):
 * a real sequential /etc/hosts(5) walk now backs sethostent()/
 * gethostent()/endhostent() (src/netdb/linux/hostent.c). Unlike
 * getservbyname_wellknown/getprotobyname_tcp just above, this one CANNOT
 * safely run against this host's own real /etc/hosts: an ad-block-style
 * hosts file (routinely thousands of lines, blocking known ad/tracker
 * domains) is a completely ordinary real-world /etc/hosts, and would
 * fire this test's own 64-entry guard before gethostent() ever
 * legitimately reaches end-of-database -- a fact about this particular
 * machine's own configuration, not about the interface (measured
 * directly against this environment's real /etc/hosts: tens of
 * thousands of entries, not the handful the original fence's own
 * reasoning assumed). The fix is the same env-var fixture
 * override src/internal/nss_paths.h already provides and this file's own
 * test_netdb_hosts_fixture() (further down) already uses for the
 * identical reason: a small, controlled /etc/hosts this test fully
 * controls, not whatever this host happens to have.
 *
 * Linux-only: sethostent()/gethostent()/endhostent() are all
 * unconditional stand-ins on NT (sethostent()/endhostent() no-op,
 * gethostent() always returns NULL -- src/netdb/nt/plat_netdb.c), so
 * SPICULE_TEST_HOSTS_PATH has nothing on that platform to actually walk. */
#include <netdb.h>
#include <sys/socket.h>

#if defined(__linux__)
static void test_posix_netdb_hostent_sequential_access(void)
{
	struct hostent *he;
	int entries = 0;

	fixture_write("nd-hosts",
		"127.0.0.1 localhost\n"
		"::1 localhost6\n" /* real IPv6 literal: must be skipped, not counted */
		"# a comment line, must not be parsed as a record\n"
		"10.0.0.5 seqhost.example seqalias\n");
	CHECK(setenv("SPICULE_TEST_HOSTS_PATH", "nd-hosts", 1) == 0);

	/* endhostent.html: "The sethostent() function shall open a
	 * connection to the database and set the next entry for retrieval
	 * to the first entry in the database ... The gethostent()
	 * function shall read the next entry in the database ... Entries
	 * shall be returned in hostent structures ... The endhostent()
	 * function shall close the connection to the database, releasing
	 * any open file descriptor."
	 *
	 * RETURN VALUE: "a pointer to a hostent structure if the requested
	 * entry was found, and a null pointer if the end of the database
	 * was reached".  The database may legitimately be empty, so the
	 * assertion is about the SHAPE of what comes back and about
	 * termination -- not about any host existing. */
	sethostent(1);
	while ((he = gethostent()) != NULL && entries < 64) {
		/* <netdb.h>'s hostent: "h_name: Official name of the
		 * host", "h_aliases: ... terminated by a null pointer",
		 * "h_length: The length, in bytes, of the address",
		 * "h_addr_list: ... network addresses (in network byte
		 * order) for the host, terminated by a null pointer." */
		CHECK(he->h_name != NULL);
		CHECK(he->h_aliases != NULL);
		CHECK(he->h_addr_list != NULL);
		CHECK(he->h_addrtype == AF_INET || he->h_addrtype == AF_INET6);
		if (he->h_addrtype == AF_INET)
			CHECK(he->h_length == 4);
		if (he->h_addrtype == AF_INET6)
			CHECK(he->h_length == 16);
		entries++;
	}
	/* Terminated rather than ran to the guard: the null-pointer
	 * end-of-database clause is what stops this loop. With the fixture
	 * above (2 real IPv4 lines, 1 skipped IPv6 line, 1 comment) this is
	 * exactly 2, not merely "some number less than 64". */
	CHECK(entries < 64);
	CHECK(entries == 2);
	endhostent();

	unsetenv("SPICULE_TEST_HOSTS_PATH");
}
#else
/* See this test's own banner above: NT's sethostent()/gethostent()/
 * endhostent() are unconditional stand-ins with no real /etc/hosts
 * backend for a fixture to be walked against. */
static void test_posix_netdb_hostent_sequential_access(void)
{
	printf("SKIP posix-netdb hostent sequential access (no real hosts "
	       "database backend on this platform -- see "
	       "src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* UNWRAPPED (was SPICULE_TEST(UNIMPL, posix_netdb_netent_lookup)):
 * a real /etc/networks(5) parser now backs this whole family
 * (src/netdb/linux/networks.c); see that file's own banner for why
 * /etc/networks being absent (the common case on a real machine) is
 * this database's own normal empty state. The same fixture-override
 * reasoning as the hostent test just above applies here too: a
 * controlled fixture makes this deterministic instead of depending on
 * whether this particular host happens to have a networks database
 * (and, if so, how big it is) at all.
 *
 * Linux-only: setnetent()/getnetent()/endnetent()/getnetbyname()/
 * getnetbyaddr() are all unconditional stand-ins on NT (no-op or NULL --
 * src/netdb/nt/plat_netdb.c), so SPICULE_TEST_NETWORKS_PATH has nothing on
 * that platform to actually walk. */
#include <netdb.h>
#include <sys/socket.h>

#if defined(__linux__)
static void test_posix_netdb_netent_lookup(void)
{
	struct netent *ne;
	int entries = 0;

	fixture_write("nd-networks",
		"loopnet 127.0.0.0\n"
		"# a comment line, must not be parsed as a record\n"
		"seqnet 10.0\n");
	CHECK(setenv("SPICULE_TEST_NETWORKS_PATH", "nd-networks", 1) == 0);

	/* endnetent.html: "The setnetent() function shall open and rewind
	 * the database ... The getnetent() function shall read the next
	 * entry of the database ... The endnetent() function shall close
	 * the database."  Same shape-and-termination discipline as the
	 * host database: the network database is routinely empty, so
	 * asserting an entry exists would be asserting a fact about the
	 * host, not about the interface. */
	setnetent(1);
	while ((ne = getnetent()) != NULL && entries < 64) {
		/* <netdb.h>'s netent: "n_name: Official, fully-qualified
		 * ... name", "n_aliases: ... terminated by a null
		 * pointer", "n_addrtype: The address type of the
		 * network", "n_net: The network number, in host byte
		 * order." */
		CHECK(ne->n_name != NULL);
		CHECK(ne->n_aliases != NULL);
		CHECK(ne->n_addrtype == AF_INET);
		entries++;
	}
	CHECK(entries < 64);
	CHECK(entries == 2);
	endnetent();

	/* "The getnetbyaddr() function shall search the database from the
	 * beginning, and find the first entry for which the network number
	 * specified by net matches the n_net member and the address type
	 * specified by type matches the n_addrtype member ... The
	 * getnetbyname() function shall search the database from the
	 * beginning and find the first entry for which the network name
	 * specified by name matches the n_name member".  RETURN VALUE
	 * gives the miss case, which is the one guaranteed to be
	 * reachable regardless of what this fixture contains: "a null
	 * pointer if the end of the database was reached or the requested
	 * entry was not found." */
	CHECK(getnetbyname("no-such-network-name") == NULL);
	CHECK(getnetbyaddr(0xfffffffeUL, AF_INET) == NULL);

	/* The positive case, now decidable against a fixture this test
	 * fully controls: "loopnet 127.0.0.0" is the real Debian-shipped
	 * /etc/networks loopback entry (src/netdb/linux/networks.c's own
	 * banner records the exact real-world file this line is drawn
	 * from), n_net == 0x7f000000 in host byte order. */
	ne = getnetbyname("loopnet");
	CHECK(ne != NULL);
	if (ne != NULL) CHECK(ne->n_net == 0x7f000000UL);
	CHECK(getnetbyaddr(0x7f000000UL, AF_INET) != NULL);

	unsetenv("SPICULE_TEST_NETWORKS_PATH");
}
#else
/* See this test's own banner above: NT's setnetent()/getnetent()/
 * endnetent()/getnetbyname()/getnetbyaddr() are unconditional stand-ins
 * with no real /etc/networks backend for a fixture to be walked against. */
static void test_posix_netdb_netent_lookup(void)
{
	printf("SKIP posix-netdb networks database (no real networks "
	       "database backend on this platform -- see "
	       "src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* ==================================================================
 * Not a POSIX-clause fence: real coverage of THIS PASS'S OWN backends
 * (src/netdb/linux/) -- the /etc/hosts parser, the /etc/nsswitch.conf
 * parser, and the UDP DNS stub resolver's real wire-format round trip
 * -- against hermetic fixtures, per this file's own top banner update
 * and src/internal/nss_paths.h's disclosed SPICULE_TEST_*_PATH seam.
 * ================================================================== */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

static void fixture_write(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	CHECK(f != NULL);
	if (!f) return;
	CHECK(fputs(content, f) >= 0);
	fclose(f);
}

/* /etc/hosts (src/netdb/linux/hosts.c), positive and negative lookups,
 * plus AI_CANONNAME -- a small, fully-controlled two-line fixture
 * (plus one comment line, to prove '#' comments are actually skipped
 * rather than merely never appearing in a fixture).
 *
 * Linux-only: getaddrinfo() with a non-numeric node name needs the real
 * /etc/hosts + /etc/nsswitch.conf-driven "hosts" NSS walk this test's own
 * SPICULE_TEST_HOSTS_PATH/SPICULE_TEST_NSSWITCH_PATH fixtures target
 * (src/netdb/linux/hosts.c, src/netdb/linux/nsswitch.c). NT's
 * getaddrinfo() only answers the AI_NUMERICHOST case (see
 * src/netdb/nt/plat_netdb.c); a non-numeric node there is EAI_FAIL
 * regardless of any fixture. */
#if defined(__linux__)
static void test_netdb_hosts_fixture(void)
{
	struct addrinfo hints, *res;
	struct sockaddr_in sin;

	fixture_write("nd-hosts",
		"127.0.0.1 localhost\n"
		"10.20.30.40 myhost.example myhost\n"
		"# a comment line, must not be parsed as a record\n"
		"10.20.30.41 second.example\n");
	fixture_write("nd-nsswitch.conf", "hosts: files dns\npasswd: files\ngroup: files\n");
	CHECK(setenv("SPICULE_TEST_HOSTS_PATH", "nd-hosts", 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", "nd-nsswitch.conf", 1) == 0);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;

	res = NULL;
	CHECK(getaddrinfo("myhost", NULL, &hints, &res) == 0);
	CHECK(res != NULL);
	if (res) {
		memcpy(&sin, res->ai_addr, sizeof sin);
		CHECK(sin.sin_addr.s_addr ==
		      htonl((10u << 24) | (20u << 16) | (30u << 8) | 40u));
		CHECK(res->ai_canonname != NULL &&
		      strcmp(res->ai_canonname, "myhost.example") == 0);
		freeaddrinfo(res);
	}

	res = NULL;
	CHECK(getaddrinfo("second.example", NULL, &hints, &res) == 0);
	if (res) freeaddrinfo(res);

	unsetenv("SPICULE_TEST_HOSTS_PATH");
	unsetenv("SPICULE_TEST_NSSWITCH_PATH");
}
#else
/* See this test's own banner above: NT's getaddrinfo() only answers
 * AI_NUMERICHOST, so a non-numeric node has no hosts-fixture backend
 * to actually be resolved against. */
static void test_netdb_hosts_fixture(void)
{
	printf("SKIP posix-netdb hosts fixture (no real hosts database "
	       "backend on this platform -- see src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* /etc/nsswitch.conf (src/netdb/linux/nsswitch.c): an admin who
 * configures "hosts: files" (dns removed) gets an honest EAI_NONAME
 * for a name that is genuinely nowhere in the fixture hosts file --
 * deterministic, unlike leaving dns enabled and pointing it at
 * nothing, because the miss never falls through to any network step
 * at all.
 *
 * Linux-only: same reasoning as test_netdb_hosts_fixture above -- NT's
 * getaddrinfo() returns EAI_FAIL for any non-numeric node regardless of
 * any nsswitch.conf fixture, never the EAI_NONAME this test asserts. */
#if defined(__linux__)
static void test_netdb_nsswitch_hosts_files_only(void)
{
	struct addrinfo hints, *res = NULL;

	fixture_write("nd-hosts", "127.0.0.1 localhost\n");
	fixture_write("nd-nsswitch.conf", "hosts: files\n");
	CHECK(setenv("SPICULE_TEST_HOSTS_PATH", "nd-hosts", 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", "nd-nsswitch.conf", 1) == 0);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	CHECK(getaddrinfo("nowhere.example", NULL, &hints, &res) == EAI_NONAME);

	unsetenv("SPICULE_TEST_HOSTS_PATH");
	unsetenv("SPICULE_TEST_NSSWITCH_PATH");
}
#else
/* See this test's own banner above: NT's getaddrinfo() cannot produce
 * the EAI_NONAME this test asserts for a non-numeric node -- only
 * EAI_FAIL, regardless of any nsswitch.conf fixture. */
static void test_netdb_nsswitch_hosts_files_only(void)
{
	printf("SKIP posix-netdb nsswitch.conf hosts:files (no real hosts "
	       "database backend on this platform -- see "
	       "src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* gethostbyname(): a real, disclosed legacy extension outside this
 * edition of POSIX (see this file's top banner and include/netdb.h's
 * own banner) -- a second, thinner front door onto the identical
 * hosts-fixture walk the getaddrinfo() tests above already exercise,
 * so this checks the h_errno/struct hostent shape specifically rather
 * than re-proving the lookup itself.
 *
 * Linux-only: src/netdb/nt/plat_netdb.c's gethostbyname() is an
 * unconditional stand-in (always NULL, h_errno = NO_RECOVERY), so
 * neither the positive lookup nor the HOST_NOT_FOUND miss this test
 * asserts is reachable on NT. */
#if defined(__linux__)
static void test_netdb_gethostbyname_fixture(void)
{
	struct hostent *he;
	struct in_addr a;

	fixture_write("nd-hosts", "10.1.2.3 gethost.example ghalias\n");
	fixture_write("nd-nsswitch.conf", "hosts: files\n");
	CHECK(setenv("SPICULE_TEST_HOSTS_PATH", "nd-hosts", 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", "nd-nsswitch.conf", 1) == 0);

	he = gethostbyname("ghalias");
	CHECK(he != NULL);
	if (he) {
		CHECK(he->h_addrtype == AF_INET);
		CHECK(he->h_length == 4);
		CHECK(he->h_addr_list != NULL && he->h_addr_list[0] != NULL);
		memcpy(&a, he->h_addr_list[0], 4);
		CHECK(a.s_addr == htonl((10u << 24) | (1u << 16) | (2u << 8) | 3u));
		CHECK(he->h_aliases != NULL && he->h_aliases[0] == NULL);
	}

	h_errno = 0;
	he = gethostbyname("nowhere.example");
	CHECK(he == NULL);
	CHECK(h_errno == HOST_NOT_FOUND);

	unsetenv("SPICULE_TEST_HOSTS_PATH");
	unsetenv("SPICULE_TEST_NSSWITCH_PATH");
}
#else
/* See this test's own banner above: NT's gethostbyname() is an
 * unconditional stand-in with no real hosts database backend. */
static void test_netdb_gethostbyname_fixture(void)
{
	printf("SKIP posix-netdb gethostbyname fixture (no real hosts "
	       "database backend on this platform -- see "
	       "src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

/* ==================================================================
 * A real UDP round trip against a hermetic fake DNS server -- proves
 * src/netdb/linux/resolv.c's own real socket(2)/connect(2)/sendto(2)/
 * recvfrom(2) syscalls and its RFC 1035 wire-format response parser
 * (including the one label-compression shape a real server's
 * response actually uses: a pointer back to the echoed question name)
 * against genuine bytes on the wire, not just a parser fed by hand.
 *
 * The server side needs raw socket(2)/bind(2)/getsockname(2)/
 * recvfrom(2)/sendto(2) syscalls of its own, following the exact same
 * pattern src/netdb/linux/resolv.c's client side already uses (see
 * that file's own banner for why: the public socket() front door is
 * AF_INET/SOCK_STREAM-only today, so nothing UDP-shaped is reachable
 * through it at all, client or server side). Fork()ed as a genuinely
 * separate process rather than a thread so it has its own address
 * space and cannot be confused with the parent's own env vars/fixture
 * files mid-test.
 *
 * Linux-only: these are raw Linux syscall numbers (see each arch's ND_SYS_*
 * table below), meaningful only because src/netdb/nt/plat_netdb.c's own
 * banner says the real resolver "exists only for native Linux" -- NT's
 * getaddrinfo() is an EAI_FAIL stub, so there is nothing here for a real
 * DNS round trip to prove on that platform. Also a real compile-time
 * necessity for arm64: __aarch64__ is defined for arm64-win32-tcc too, but
 * that backend has no 'svc' instruction encoder at all (it targets NT,
 * which is entered through ntdll thunks, never a raw SVC), so building
 * this unconditionally broke the Windows/arm64 build with a hard "ARM64
 * instruction 'svc' not implemented" compiler error. */
#if defined(__linux__)

#if defined(__aarch64__)
#define ND_SYS_socket      198
#define ND_SYS_bind        200
#define ND_SYS_getsockname 204
#define ND_SYS_sendto      206
#define ND_SYS_recvfrom    207
#define ND_SYS_close       57
#elif defined(__x86_64__)
#define ND_SYS_socket      41
#define ND_SYS_bind        49
#define ND_SYS_getsockname 51
#define ND_SYS_sendto      44
#define ND_SYS_recvfrom    45
#define ND_SYS_close       3
#elif defined(__i386__)
/* i386's direct per-call socket syscalls (not the old socketcall(2)
 * multiplex, __NR_socketcall 102) -- added in Linux 4.3, confirmed
 * against this host's own /nix/store linux-headers-7.1 <asm/
 * unistd_32.h> and arch/x86/entry/syscalls/syscall_32.tbl. Using them
 * is consistent with this tree's existing i386 baseline: src/fcntl/
 * linux/plat_fcntl.c already calls SYS_statx (Linux 4.11) unconditionally
 * on i386, a newer floor than 4.3. */
#define ND_SYS_socket      359
#define ND_SYS_bind        361
#define ND_SYS_getsockname 367
#define ND_SYS_sendto      369
#define ND_SYS_recvfrom    371
#define ND_SYS_close       6
#endif

#if defined(__aarch64__)
static long nd_raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long nd_raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
/* Same "args array in memory" trampoline as crt/linux/crt1.c's own
 * raw_syscall() and src/fcntl/linux/plat_fcntl.c's own raw_syscall() --
 * see either one's banner for why: i386 `int $0x80` wants nr in eax and
 * up to 6 args in ebx/ecx/edx/esi/edi/ebp, but ebx/ebp are also cdecl
 * callee-saved, leaving no register free to stage the syscall number in
 * once all six argument registers are loaded. */
static long nd_raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#endif

/* fake_dns_server(): runs in the forked child. Binds a UDP socket to
 * 127.0.0.1:0 (kernel-assigned ephemeral port), writes that port to
 * `portfd` as plain decimal text so the parent can build a resolv.conf
 * fixture around it (a "nameserver ip:port" testability extension --
 * see src/netdb/linux/resolv.c's parse_resolv_conf()),
 * then answers exactly one query with a hand-built response: the
 * query's own ID, RCODE 0, one answer RR (A, TTL 60, RDATA
 * 203.0.113.55 -- an RFC 5737 TEST-NET-3 address, real network-address
 * shape, guaranteed not to route anywhere) whose owner name is a
 * compression pointer back to the echoed question section rather than
 * a second literal copy of it -- the one compression case a real
 * server's response genuinely uses. */
static void fake_dns_server(int portfd)
{
	long fd, r;
	struct sockaddr_in addr, client;
	unsigned char query[512], resp[512];
	socklen_t clientlen, addrlen;
	int qlen, rlen, port;
	char portbuf[16];

	fd = nd_raw_syscall(ND_SYS_socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0);
	if (fd < 0) _exit(10);

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	r = nd_raw_syscall(ND_SYS_bind, fd, (long)&addr, sizeof addr, 0, 0, 0);
	if (r < 0) _exit(11);

	addrlen = sizeof addr;
	r = nd_raw_syscall(ND_SYS_getsockname, fd, (long)&addr, (long)&addrlen, 0, 0, 0);
	if (r < 0) _exit(12);
	port = ntohs(addr.sin_port);

	{
		int n = 0, p = port, digs[8], i;
		if (p == 0) digs[n++] = 0;
		while (p > 0) { digs[n++] = p % 10; p /= 10; }
		for (i = 0; i < n; i++) portbuf[i] = (char)('0' + digs[n - 1 - i]);
		portbuf[n] = '\n';
		write(portfd, portbuf, (size_t)(n + 1));
	}
	close(portfd);

	clientlen = sizeof client;
	memset(&client, 0, sizeof client);
	r = nd_raw_syscall(ND_SYS_recvfrom, fd, (long)query, sizeof query, 0,
	                    (long)&client, (long)&clientlen);
	if (r < 12) { nd_raw_syscall(ND_SYS_close, fd, 0, 0, 0, 0, 0); _exit(13); }
	qlen = (int)r;

	resp[0] = query[0]; resp[1] = query[1];       /* ID, echoed */
	resp[2] = 0x81; resp[3] = 0x80;               /* QR=1 RD=1 RA=1 RCODE=0 */
	resp[4] = 0x00; resp[5] = 0x01;               /* QDCOUNT=1 */
	resp[6] = 0x00; resp[7] = 0x01;               /* ANCOUNT=1 */
	resp[8] = 0x00; resp[9] = 0x00;               /* NSCOUNT=0 */
	resp[10] = 0x00; resp[11] = 0x00;             /* ARCOUNT=0 */
	memcpy(resp + 12, query + 12, (size_t)(qlen - 12));
	rlen = 12 + (qlen - 12);
	resp[rlen++] = 0xC0; resp[rlen++] = 0x0C;     /* name: pointer to offset 12 */
	resp[rlen++] = 0x00; resp[rlen++] = 0x01;     /* TYPE=A */
	resp[rlen++] = 0x00; resp[rlen++] = 0x01;     /* CLASS=IN */
	resp[rlen++] = 0x00; resp[rlen++] = 0x00; resp[rlen++] = 0x00; resp[rlen++] = 0x3C; /* TTL=60 */
	resp[rlen++] = 0x00; resp[rlen++] = 0x04;     /* RDLENGTH=4 */
	resp[rlen++] = 203; resp[rlen++] = 0; resp[rlen++] = 113; resp[rlen++] = 55;

	nd_raw_syscall(ND_SYS_sendto, fd, (long)resp, rlen, 0, (long)&client, clientlen);
	nd_raw_syscall(ND_SYS_close, fd, 0, 0, 0, 0, 0);
	_exit(0);
}

#endif /* defined(__linux__) */

#if defined(__linux__)
static void test_netdb_dns_udp_roundtrip(void)
{
	int pfd[2];
	pid_t child;
	char linebuf[32];
	ssize_t n;
	unsigned long port = 0;
	int i, status;
	char resolvbuf[64];
	struct addrinfo hints, *res = NULL;

	if (pipe(pfd) != 0) { CHECK(0 && "pipe() failed"); return; }

	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		close(pfd[0]);
		fake_dns_server(pfd[1]);
		_exit(99); /* unreachable: fake_dns_server() always _exit()s */
	}
	close(pfd[1]);

	/* Read "<port>\n" written by the child -- strtoul(), not atoi():
	 * atoi() (src/stdlib/atoi.c) is implemented on top of strtod(),
	 * which on this project's aarch64 native-clang verification build
	 * pulls in a soft-float128 long-double helper this -nostdlib
	 * environment has no compiler-rt to satisfy (see src/netdb/linux/
	 * resolv.c's own identical comment on its "nameserver ip:port"
	 * parser, which hit the exact same real link failure first).
	 * strtoul() has no such dependency. */
	n = read(pfd[0], linebuf, sizeof linebuf - 1);
	close(pfd[0]);
	CHECK(n > 0);
	if (n > 0) {
		linebuf[n] = '\0';
		port = strtoul(linebuf, NULL, 10);
	}
	CHECK(port > 0 && port <= 65535);

	snprintf(resolvbuf, sizeof resolvbuf, "nameserver 127.0.0.1:%lu\n", port);
	fixture_write("nd-resolv.conf", resolvbuf);
	fixture_write("nd-hosts", "127.0.0.1 localhost\n"); /* deliberately no match: force the dns step */
	fixture_write("nd-nsswitch.conf", "hosts: files dns\n");
	CHECK(setenv("SPICULE_TEST_HOSTS_PATH", "nd-hosts", 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", "nd-nsswitch.conf", 1) == 0);
	CHECK(setenv("SPICULE_TEST_RESOLV_PATH", "nd-resolv.conf", 1) == 0);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	i = getaddrinfo("dnstest.example", NULL, &hints, &res);
	CHECK(i == 0);
	if (i == 0 && res) {
		struct sockaddr_in sin;
		memcpy(&sin, res->ai_addr, sizeof sin);
		CHECK(sin.sin_addr.s_addr == htonl((203u << 24) | (0u << 16) | (113u << 8) | 55u));
		freeaddrinfo(res);
	}

	unsetenv("SPICULE_TEST_HOSTS_PATH");
	unsetenv("SPICULE_TEST_NSSWITCH_PATH");
	unsetenv("SPICULE_TEST_RESOLV_PATH");

	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
#else
/* See the fake_dns_server() banner above: outside native Linux there is
 * no real resolver backend for this to prove anything against. */
static void test_netdb_dns_udp_roundtrip(void)
{
	printf("SKIP posix-netdb DNS UDP round trip (no real resolver backend "
	       "on this platform -- see src/netdb/nt/plat_netdb.c)\n");
}
#endif /* defined(__linux__) */

int main(void)
{
	test_posix_netdb_getaddrinfo_loopback();
	test_posix_netdb_getnameinfo_numeric();
	test_posix_netdb_gai_strerror_text();
	test_posix_netdb_getservbyname_wellknown();
	test_posix_netdb_getprotobyname_tcp();
	test_posix_netdb_hostent_sequential_access();
	test_posix_netdb_netent_lookup();

	test_netdb_hosts_fixture();
	test_netdb_nsswitch_hosts_files_only();
	test_netdb_gethostbyname_fixture();
	test_netdb_dns_udp_roundtrip();

	if (!fails) printf("posix-netdb: all tests passed\n");
	return fails != 0;
}
