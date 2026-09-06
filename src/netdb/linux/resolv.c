/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __resolv_query_a(): the "dns" service for the "hosts" NSS database
 * -- a real, minimal UDP stub resolver. Reads nameservers from
 * /etc/resolv.conf(5) (or its test-fixture override, see
 * src/internal/nss_paths.h), sends a real RFC 1035 A-record query
 * over a real UDP socket, and parses a real response, including
 * RFC 1035 label compression (a pointer to an earlier name in the
 * same message).
 *
 * Scope, deliberately: UDP only, no TCP fallback on a truncated (TC
 * bit) response -- never needed in practice, since this resolver only
 * ever asks for A records. A records (IPv4) only, no AAAA/IPv6 --
 * matches this project's socket layer, which has no AF_INET6
 * transport yet. No DNSSEC: a stub resolver trusting its configured
 * nameserver, the same trust model resolv.conf itself assumes. No
 * search-list/ndots/domain processing -- `name` is queried exactly as
 * given; "search"/"domain"/"options" directives parse without error
 * but do nothing. Bypasses the public socket()/connect()/send()/
 * recv() front door entirely and issues its own raw socket(2)/
 * connect(2)/setsockopt(2)/sendto(2)/recvfrom(2)/close(2) syscalls
 * (same pattern src/socket/linux/plat_socket.c uses), because that
 * front door only supports SOCK_STREAM today.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include "nss_paths.h"
#include "netdb_internal.h"

#if defined(__aarch64__)
#define SYS_close      57
#define SYS_socket     198
#define SYS_connect    203
#define SYS_sendto     206
#define SYS_recvfrom   207
#define SYS_setsockopt 208
#elif defined(__x86_64__)
#define SYS_close      3
#define SYS_socket     41
#define SYS_connect    42
#define SYS_sendto     44
#define SYS_recvfrom   45
#define SYS_setsockopt 54
#elif defined(__i386__)
/* i386's direct-syscall socket numbers (not the legacy socketcall(2)
 * multiplexer, 102) -- confirmed against this host's own /nix/store
 * linux-headers asm/unistd_32.h, same numbers src/socket/linux/
 * plat_socket.c's own i386 branch already uses. */
#define SYS_close      6
#define SYS_socket     359
#define SYS_connect    362
#define SYS_sendto     369
#define SYS_recvfrom   371
#define SYS_setsockopt 366
#else
#error "resolv.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
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
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
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
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
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

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

#define MAX_NAMESERVERS 3
#define DNS_PORT_DEFAULT 53
#define QUERY_TIMEOUT_SEC 2
#define QUERY_ATTEMPTS_PER_SERVER 3

/* "nameserver <ipv4>[:<port>]" lines, up to MAX_NAMESERVERS of them.
 * The "[:<port>]" suffix is NOT real resolv.conf(5) syntax -- it is
 * this file's own disclosed testability extension (see
 * src/internal/nss_paths.h's banner), letting tests point resolv.conf
 * at a fixture server on an unprivileged port without
 * CAP_NET_BIND_SERVICE. A token with more than one ':' is a real IPv6
 * literal (e.g. "::1"); this resolver has no IPv6 transport and skips
 * such a line cleanly. Other directives ("domain", "search",
 * "options", ...) parse without error and are ignored. */
static int parse_resolv_conf(struct sockaddr_in *out)
{
	FILE *f;
	char line[256];
	int n = 0;

	f = fopen(__NSS_RESOLV_PATH(), "r");
	if (!f) return 0;

	while (n < MAX_NAMESERVERS && fgets(line, sizeof line, f) != NULL) {
		char *p = line, *tok, *colon;
		int ncolons = 0;
		char *c;
		int port = DNS_PORT_DEFAULT;
		struct in_addr addr;

		while (*p == ' ' || *p == '\t') p++;
		if (strncmp(p, "nameserver", 10) != 0) continue;
		p += 10;
		if (*p != ' ' && *p != '\t') continue;
		while (*p == ' ' || *p == '\t') p++;
		tok = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
		*p = '\0';
		if (*tok == '\0') continue;

		for (c = tok; *c; c++) if (*c == ':') ncolons++;
		if (ncolons > 1) continue; /* real IPv6 literal: not supported */
		colon = ncolons == 1 ? strchr(tok, ':') : NULL;
		if (colon) {
			unsigned long v;
			*colon = '\0';
			/* strtoul(), not atoi(): atoi() is built on
			 * strtod()'s float parser, which on this project's
			 * aarch64 port needs a soft-float128 helper this
			 * -nostdlib build has no compiler-rt to satisfy -- a
			 * real link failure hit directly, not hypothetical.
			 * strtoul() has no such dependency. */
			v = strtoul(colon + 1, NULL, 10);
			if (v == 0 || v > 65535) continue;
			port = (int)v;
		}
		if (inet_pton(AF_INET, tok, &addr) != 1) continue;

		memset(&out[n], 0, sizeof out[n]);
		out[n].sin_family = AF_INET;
		out[n].sin_addr = addr;
		out[n].sin_port = htons((uint16_t)port);
		n++;
	}
	(void)fclose(f);
	return n;
}

/* build_query(): a single-question A/IN query. Returns the message
 * length, or -1 if `name` cannot be encoded (a label over 63 bytes,
 * or the encoded name over 253 bytes -- RFC 1035 sec 2.3.4's own
 * limits; a name outside them cannot be a real DNS name at all, so
 * this is a clean EAI_NONAME-shaped failure, not an internal error). */
static int build_query(unsigned char *buf, size_t bufsz, const char *name, uint16_t id)
{
	size_t pos;
	const char *p = name;

	if (bufsz < 12) return -1;
	buf[0] = (unsigned char)(id >> 8);
	buf[1] = (unsigned char)id;
	buf[2] = 0x01; /* RD=1 */
	buf[3] = 0x00;
	buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT=1 */
	buf[6] = 0x00; buf[7] = 0x00; /* ANCOUNT=0 */
	buf[8] = 0x00; buf[9] = 0x00; /* NSCOUNT=0 */
	buf[10] = 0x00; buf[11] = 0x00; /* ARCOUNT=0 */
	pos = 12;

	while (*p) {
		size_t labellen = 0;
		const char *label = p;
		while (p[labellen] && p[labellen] != '.') labellen++;
		if (labellen == 0 || labellen > 63) return -1;
		if (pos + 1 + labellen > bufsz - 5) return -1;
		buf[pos++] = (unsigned char)labellen;
		{
			size_t i;
			for (i = 0; i < labellen; i++) buf[pos + i] = (unsigned char)label[i];
		}
		pos += labellen;
		p += labellen;
		if (*p == '.') p++;
		else if (*p != '\0') return -1;
	}
	if (pos + 5 > bufsz) return -1;
	buf[pos++] = 0; /* root label */
	buf[pos++] = 0x00; buf[pos++] = 0x01; /* QTYPE=A */
	buf[pos++] = 0x00; buf[pos++] = 0x01; /* QCLASS=IN */
	return (int)pos;
}

/* skip_name(): advances past one DNS name starting at msg[off],
 * following RFC 1035 sec 4.1.4 compression pointers (0xC0 tag) to
 * find where the name's labels actually are, but returning the
 * offset just past the name AS ENCODED AT `off` in the original
 * stream (i.e. right after the first pointer, if any) -- exactly what
 * a caller needs to continue parsing the fields that follow this name
 * in the message. Bounded against a pointer cycle (real malformed/
 * hostile input, not a real server) by capping the number of jumps. */
static int skip_name(const unsigned char *msg, int msglen, int off)
{
	int pos = off, jumps = 0, consumed = -1;

	for (;;) {
		unsigned c;
		if (pos < 0 || pos >= msglen) return -1;
		c = msg[pos];
		if ((c & 0xC0) == 0xC0) {
			if (pos + 1 >= msglen) return -1;
			if (consumed < 0) consumed = pos + 2;
			if (++jumps > 20) return -1;
			pos = (int)(((c & 0x3F) << 8) | msg[pos + 1]);
			continue;
		}
		if (c & 0xC0) return -1; /* reserved label-length bits */
		if (c == 0) {
			pos += 1;
			if (consumed < 0) consumed = pos;
			return consumed;
		}
		pos += 1 + (int)c;
		if (pos > msglen) return -1;
	}
}

static int be16(const unsigned char *p) { return (p[0] << 8) | p[1]; }

/* Validates the header against `id`, maps a non-zero RCODE to
 * *reason, and on RCODE 0 walks the question section (to skip it)
 * then the answer section, collecting A/IN records. A malformed field
 * past the header stops parsing but keeps what was already collected,
 * rather than discarding real answers over an unrelated RR type or
 * truncated tail this resolver does not need to understand. */
static int parse_response(const unsigned char *msg, int len, uint16_t id,
                           struct in_addr *addrs, int maxaddrs,
                           enum __dns_fail *reason, int *is_nxdomain)
{
	int qdcount, ancount, pos, i, found = 0;
	unsigned rcode;

	*is_nxdomain = 0;
	if (len < 12) { *reason = __DNS_IOERR; return -1; }
	if (be16(msg) != (int)id) return -2; /* not our reply: caller retries the read */
	if ((msg[2] & 0x80) == 0) return -2; /* QR=0: a query, not a response */

	rcode = msg[3] & 0x0F;
	if (rcode == 3) { *is_nxdomain = 1; return 0; }
	if (rcode == 1) { *reason = __DNS_FORMERR; return -1; }
	if (rcode == 2) { *reason = __DNS_SERVFAIL; return -1; }
	if (rcode == 5) { *reason = __DNS_REFUSED; return -1; }
	if (rcode != 0) { *reason = __DNS_SERVFAIL; return -1; }

	qdcount = be16(msg + 4);
	ancount = be16(msg + 6);
	pos = 12;
	for (i = 0; i < qdcount; i++) {
		pos = skip_name(msg, len, pos);
		if (pos < 0 || pos + 4 > len) return found;
		pos += 4; /* QTYPE + QCLASS */
	}
	for (i = 0; i < ancount; i++) {
		int rdlen, type, class;
		pos = skip_name(msg, len, pos);
		if (pos < 0 || pos + 10 > len) return found;
		type = be16(msg + pos);
		class = be16(msg + pos + 2);
		rdlen = be16(msg + pos + 8);
		pos += 10;
		if (pos + rdlen > len) return found;
		if (type == 1 && class == 1 && rdlen == 4 && found < maxaddrs) {
			memcpy(&addrs[found].s_addr, msg + pos, 4);
			found++;
		}
		pos += rdlen;
	}
	return found;
}

static int try_one_server(const struct sockaddr_in *sv, const char *name,
                           struct in_addr *addrs, int maxaddrs,
                           enum __dns_fail *reason)
{
	long fd, r;
	int qlen, attempt;
	unsigned char qbuf[300], rbuf[1500];
	uint16_t id;
	struct { long tv_sec, tv_usec; } tmo;

	/* parse_response()'s `be16(msg) != id` check is the only thing
	 * standing between a spoofed UDP datagram (an off-path attacker
	 * cannot see this query, only guess at it) and a forged answer
	 * being accepted as this query's real response, so id must not be
	 * guessable. A seeded, monotonically incrementing counter (this
	 * function's own prior scheme) is exactly the predictable-
	 * transaction-ID weakness real DNS cache-poisoning attacks exploit:
	 * observe or guess one id and every subsequent query's id is known.
	 * getentropy() gives each query a real, unpredictable one instead. */
	if (getentropy(&id, sizeof id) != 0) { *reason = __DNS_IOERR; return -1; }

	qlen = build_query(qbuf, sizeof qbuf, name, id);
	if (qlen < 0) { *reason = __DNS_IOERR; return -1; }

	fd = raw_syscall(SYS_socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0);
	if (is_sys_error(fd)) { *reason = __DNS_IOERR; return -1; }

	r = raw_syscall(SYS_connect, fd, (long)sv, sizeof *sv, 0, 0, 0);
	if (is_sys_error(r)) { *reason = __DNS_IOERR; raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0); return -1; }

	tmo.tv_sec = QUERY_TIMEOUT_SEC;
	tmo.tv_usec = 0;
	raw_syscall(SYS_setsockopt, fd, 1 /* SOL_SOCKET */, 20 /* SO_RCVTIMEO */,
	            (long)&tmo, sizeof tmo, 0);

	*reason = __DNS_TIMEOUT;
	for (attempt = 0; attempt < QUERY_ATTEMPTS_PER_SERVER; attempt++) {
		int is_nx;

		r = raw_syscall(SYS_sendto, fd, (long)qbuf, qlen, 0, 0, 0);
		if (is_sys_error(r)) { *reason = __DNS_IOERR; break; }

		r = raw_syscall(SYS_recvfrom, fd, (long)rbuf, sizeof rbuf, 0, 0, 0);
		if (is_sys_error(r)) {
			/* EAGAIN/EWOULDBLOCK: SO_RCVTIMEO elapsed with
			 * nothing readable -- a real, expected timeout,
			 * not an I/O error. Anything else genuinely is
			 * (EWOULDBLOCK is the same value as EAGAIN in
			 * this library's <errno.h>, so checking EAGAIN
			 * alone already covers both spellings). */
			if ((int)-r != EAGAIN)
				*reason = __DNS_IOERR;
			break;
		}

		{
			int n = parse_response(rbuf, (int)r, id, addrs, maxaddrs, reason, &is_nx);
			if (n == -2) continue; /* stray packet: keep waiting */
			raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
			if (is_nx) return 0;
			return n;
		}
	}

	raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
	return -1;
}

int __resolv_query_a(const char *name, struct in_addr *addrs, int maxaddrs,
                      enum __dns_fail *reason)
{
	struct sockaddr_in servers[MAX_NAMESERVERS];
	int nservers = parse_resolv_conf(servers);
	int i;

	if (nservers == 0) { *reason = __DNS_NOSERVERS; return -1; }

	for (i = 0; i < nservers; i++) {
		int n = try_one_server(&servers[i], name, addrs, maxaddrs, reason);
		if (n >= 0) return n;
	}
	return -1;
}
