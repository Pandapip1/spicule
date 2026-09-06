/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private glue between this directory's backends (hosts.c, resolv.c)
 * and their two public front doors (addrinfo.c's getaddrinfo(),
 * hostent.c's gethostbyname()). Not installed, not reachable from
 * outside src/netdb/linux/ -- see include/netdb.h for the actual
 * public contract these are built to serve.
 *
 * This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard and its own declarations
 * so they cannot collide with user code.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_NETDB_INTERNAL_H
#define _NTLIBC_NETDB_INTERNAL_H

#include <stdio.h>
#include <netinet/in.h>

/* __hosts_lookup(): /etc/hosts (or its test-fixture override, see
 * src/internal/nss_paths.h), IPv4 A-record-shaped lines only -- a line
 * whose address field contains ':' is a real IPv6 literal and is
 * skipped cleanly rather than mis-parsed (this pass's getaddrinfo()
 * never returns AF_INET6 results; see include/netdb.h's own banner
 * for why). `name` is matched against a line's canonical name (first
 * name after the address) and every alias after it, case-insensitively
 * (hosts(5): names are conventionally matched the same
 * case-insensitive way DNS already treats them). Writes up to
 * maxaddrs matches (network byte order) into addrs and, if canon is
 * non-NULL, the FIRST matching line's own canonical name into canon
 * (truncated to canonsz, always NUL-terminated when canonsz > 0).
 * Returns the number of addresses found, 0 for a clean miss (name not
 * required, maxaddrs may legitimately be 0 to query hosts.c is
 * matched at all without collecting addresses -- see
 * addrinfo.c's own use of that). */
int __hosts_lookup(const char *name, struct in_addr *addrs, int maxaddrs,
                    char *canon, size_t canonsz)
    __attribute__((nonnull(1)));

/* __hosts_lookup_reverse(): the reverse half of __hosts_lookup() above,
 * added this pass for getnameinfo() (src/netdb/linux/getnameinfo.c) --
 * exactly the "small addition on top of the forward scan" hosts.c's own
 * banner already anticipated when the forward lookup was first built.
 * Same file, same IPv4-only/'#'-comment/case-insensitive rules. Writes
 * the FIRST matching line's own canonical name (the first name token
 * after the address, same as __hosts_lookup()'s own `canon` semantics)
 * into name (truncated to namesz, always NUL-terminated when namesz >
 * 0). Returns 1 on a match, 0 on a clean miss (including the file being
 * absent, same as __hosts_lookup()). */
int __hosts_lookup_reverse(const struct in_addr *addr, char *name, size_t namesz)
    __attribute__((nonnull(1, 2)));

/* __hosts_open_entry()/__hosts_read_entry(): the sequential half of
 * hosts.c's own parser, used by gethostent() (src/netdb/linux/
 * hostent.c) rather than duplicating hosts.c's line-shape rules (IPv6
 * literal skip, '#' comments, canonical name + alias tokenization) a
 * second time. __hosts_read_entry() reads the next valid IPv4 line from
 * `f` (skipping comments/blanks/IPv6 lines exactly like __hosts_lookup()
 * does), writing its address into *addr, its canonical name into name
 * (truncated to namesz) and up to maxaliases of its remaining name
 * tokens into aliases (aliasbuf/aliasbufsz backs their storage; *naliases
 * receives the count actually written). Returns 1 on a line successfully
 * parsed, 0 at EOF. */
int __hosts_read_entry(FILE *f, struct in_addr *addr,
                        char *name, size_t namesz,
                        char *aliasbuf, size_t aliasbufsz,
                        char **aliases, int maxaliases, int *naliases)
    __attribute__((nonnull(1, 2, 3, 5, 7, 9)));

/* __resolv_query_a(): a real minimal UDP DNS A-record stub resolver --
 * see src/netdb/linux/resolv.c's own banner for the exact wire-format
 * scope (UDP only, no TCP fallback, no DNSSEC) and for why this
 * bypasses the public socket()/connect()/send()/recv() front door
 * entirely (that front door is AF_INET/SOCK_STREAM-only today;
 * see <sys/socket.h>'s own banner -- SOCK_DGRAM is staged, separate
 * work this pass does not depend on or duplicate the intent of).
 * Returns the number of A records found (>= 0, 0 for a clean
 * NXDOMAIN/empty-answer response) or -1 with *reason set on any
 * failure -- no reachable nameserver, a timeout, or a real DNS
 * RCODE this resolver understood well enough to distinguish. */
enum __dns_fail {
	__DNS_NOSERVERS,  /* /etc/resolv.conf named no usable nameserver */
	__DNS_TIMEOUT,    /* every nameserver was tried and none answered */
	__DNS_SERVFAIL,   /* RCODE 2: server failure */
	__DNS_NXDOMAIN,   /* RCODE 3: name does not exist (distinct from a clean empty answer) */
	__DNS_FORMERR,    /* RCODE 1: the server rejected this pass's own query as malformed */
	__DNS_REFUSED,    /* RCODE 5 (and RCODE 4/NOTIMP folded in: this pass sends nothing that should trip either) */
	__DNS_IOERR       /* a real socket()/sendto()/recvfrom() syscall failure other than a timeout */
};
int __resolv_query_a(const char *name, struct in_addr *addrs, int maxaddrs,
                      enum __dns_fail *reason)
    __attribute__((nonnull(1, 4)));

/* __hosts_resolve(): the actual "hosts" NSS database walk shared by
 * addrinfo.c's getaddrinfo() and hostent.c's gethostbyname() --
 * consults __nsswitch_order("hosts", ...) (src/internal/nsswitch.h)
 * and tries each configured service (files, dns) in turn until one
 * produces a positive result or a hard failure; a service that is
 * consulted but yields zero addresses is "keep going", matching
 * nsswitch.conf's own NOTFOUND=continue default (see
 * src/netdb/linux/nsswitch.c's banner for why this project does not
 * implement the `[STATUS=action]` override of that default). Returns
 * the address count (>=0; 0 is a clean overall miss) or -1 with *eai
 * set to an EAI_* code (include/netdb.h) on a hard failure from a
 * service that was actually reached (today, only DNS: see
 * src/netdb/linux/hosts_resolve.c for the __dns_fail -> EAI_* map).
 * canon, if non-NULL, receives the first successful service's own
 * canonical name (truncated to canonsz, always NUL-terminated when
 * canonsz > 0; left untouched on a miss or hard failure). */
int __hosts_resolve(const char *name, struct in_addr *addrs, int maxaddrs,
                     char *canon, size_t canonsz, int *eai)
    __attribute__((nonnull(1, 6)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
