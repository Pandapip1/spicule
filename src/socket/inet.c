/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <arpa/inet.h>: byte-order conversion and address-text helpers.  Every
 * one of these is pure C with no NT dependency at all -- spicule only
 * targets i386/x86_64 (arch/i386, arch/x86_64), both little-endian, so
 * "network byte order" (big-endian, historically) and "host byte
 * order" are never the same and the swap below is unconditional; there
 * is no third architecture here for a compile-time endianness probe to
 * matter for.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ownership_stubs.h"

/* netinet_in.h.html: "extern const struct in6_addr in6addr_any" / "...
 * in6addr_loopback".  Real storage, not a stand-in for a socket
 * transport this tree does not have yet (AF_INET6 sockets remain
 * staged, see <netinet/in.h>'s banner) -- these two are just the
 * all-zero and ::1 byte patterns IN6ADDR_ANY_INIT/IN6ADDR_LOOPBACK_INIT
 * already spell out, given linkage so `&in6addr_any` compiles. */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;

/* htonl.html: "convert...to network byte order". */
uint32_t htonl(uint32_t h)
{
	return ((h & 0x000000ffU) << 24) | ((h & 0x0000ff00U) << 8) |
	       ((h & 0x00ff0000U) >> 8) | ((h & 0xff000000U) >> 24);
}

uint16_t htons(uint16_t h)
{
	return (uint16_t)(((h & 0x00ffU) << 8) | ((h & 0xff00U) >> 8));
}

/* htonl.html: ntohl()/ntohs() "deliver a value converted from network
 * byte order to host byte order" -- the swap is its own inverse. */
uint32_t ntohl(uint32_t n) { return htonl(n); }
uint16_t ntohs(uint16_t n) { return htons(n); }

/* inet_addr.html: dotted forms "a.b.c.d", "a.b.c", "a.b", "a"; each
 * part decimal, octal (leading 0) or hexadecimal (leading 0x/0X);
 * "(in_addr_t)(-1)" (INADDR_NONE) on a malformed string. */
in_addr_t inet_addr(const char *s)
{
	unsigned long parts[4];
	int nparts = 0;
	int parts_left;
	const char *p;
	in_addr_t result = INADDR_NONE;
	int saved_errno = errno;

	/* s is deliberately nullable and checked (tested:
	 * inet_addr(0) == INADDR_NONE). The analyzer still flags `*p`
	 * below -- a false positive: it doesn't narrow nullability across
	 * this function's `goto done;` early exits the way it does across
	 * a plain `if (...) return;`. */
	if (!s) goto done;
	p = s;
	for (parts_left = 4; parts_left > 0; parts_left--) {
		char *end;
		unsigned long v;
		if (*p < '0' || *p > '9') goto done;
		v = strtoul(p, &end, 0); /* base 0: honours "0x"/"0" prefixes, per inet_addr.html */
		if (end == p) goto done;
		parts[nparts++] = v;
		p = end;
		if (*p == '.') {
			p++;
			if (parts_left == 1) goto done;
			continue;
		}
		break;
	}
	if (*p) goto done; /* trailing garbage */

	switch (nparts) { // NOLINT(bugprone-switch-missing-default-case) -- the parser admits only one through four address parts here
	case 1:
		if (parts[0] <= 0xffffffffUL) result = htonl((uint32_t)parts[0]);
		break;
	case 2:
		if (parts[0] <= 0xff && parts[1] <= 0xffffffUL)
			result = htonl(((uint32_t)parts[0] << 24) | (uint32_t)parts[1]);
		break;
	case 3:
		if (parts[0] <= 0xff && parts[1] <= 0xff && parts[2] <= 0xffffUL)
			result = htonl(((uint32_t)parts[0] << 24) |
			               ((uint32_t)parts[1] << 16) | (uint32_t)parts[2]);
		break;
	case 4:
		if (parts[0] <= 0xff && parts[1] <= 0xff && parts[2] <= 0xff && parts[3] <= 0xff)
			result = htonl(((uint32_t)parts[0] << 24) |
			               ((uint32_t)parts[1] << 16) |
			               ((uint32_t)parts[2] << 8) | (uint32_t)parts[3]);
		break;
	}
done:
	errno = saved_errno;
	return result;
}

/* inet_addr.html/inet_ntop.html: inet_ntoa() has no ERRORS/RETURN VALUE
 * failure case in the spec at all -- it "return[s] a pointer to [a]
 * string"; POSIX documents its static buffer explicitly ("need not be
 * reentrant"), so one process-wide buffer is conforming. */
char *inet_ntoa(struct in_addr in)
{
	static char buf[INET_ADDRSTRLEN];
	unsigned char *b = (unsigned char *)&in.s_addr;
	/* INET_ADDRSTRLEN exactly covers four decimal uint8 octets and separators;
	 * inet_ntoa() has no failure return for an impossible truncation. */
	(void)snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
	return buf;
}

static int pton4(const char *src, unsigned char out[4])
{
	unsigned parts[4];
	int i;
	const char *p = src;

	for (i = 0; i < 4; i++) {
		int digits = 0;
		unsigned v = 0;
		if (i) { if (*p != '.') return 0; p++; }
		if (p[0] == '0' && p[1] >= '0' && p[1] <= '9') return 0;
		while (*p >= '0' && *p <= '9') {
			v = v * 10 + (unsigned)(*p - '0');
			if (v > 255 || ++digits > 3) return 0;
			p++;
		}
		if (!digits) return 0;
		parts[i] = v;
	}
	if (*p) return 0;
	for (i = 0; i < 4; i++) out[i] = (unsigned char)parts[i];
	return 1;
}

static int hexval(unsigned char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int pton6(const char *src, unsigned char out[16])
{
	unsigned char tmp[16];
	unsigned char *p = tmp, *end = tmp + sizeof tmp, *compress = 0;
	const char *token = src;
	unsigned value = 0;
	int saw_digit = 0, digits = 0;

	memset(tmp, 0, sizeof tmp);
	if (*src == ':') {
		src++;
		if (*src != ':') return 0;
	}
	token = src;
	while (*src) {
		int h = hexval((unsigned char)*src);
		if (h >= 0) {
			value = (value << 4) | (unsigned)h;
			if (value > 0xffff || ++digits > 4) return 0;
			saw_digit = 1;
			src++;
			continue;
		}
		if (*src == ':') {
			token = ++src;
			if (!saw_digit) {
				if (compress) return 0;
				compress = p;
				continue;
			}
			if (p + 2 > end) return 0;
			*p++ = (unsigned char)(value >> 8);
			*p++ = (unsigned char)value;
			saw_digit = 0;
			digits = 0;
			value = 0;
			/* A terminal colon is only valid when it is the second colon
			 * that established `compress` ("1::").  That case reaches the
			 * no-digit arm on the next iteration; a colon consumed here is
			 * a lone trailing separator ("::1:"). */
			if (!*src) return 0;
			continue;
		}
		if (*src == '.' && saw_digit && p + 4 <= end) {
			if (!pton4(token, p)) return 0;
			p += 4;
			saw_digit = 0;
			break;
		}
		return 0;
	}
	if (saw_digit) {
		if (p + 2 > end) return 0;
		*p++ = (unsigned char)(value >> 8);
		*p++ = (unsigned char)value;
	}
	if (compress) {
		size_t tail = (size_t)(p - compress);
		if (p == end) return 0;
		memmove(end - tail, compress, tail);
		memset(compress, 0, (size_t)((end - tail) - compress));
		p = end;
	}
	if (p != end) return 0;
	memcpy(out, tmp, sizeof tmp);
	return 1;
}

/* inet_ntop.html: AF_INET and AF_INET6; ENOSPC when size is too small,
 * and EAFNOSUPPORT for any other family. */
const char *inet_ntop(int af, const void *__restrict src,
	char *__restrict dst withtok(writable_span(size)), socklen_t size)
{
	char buf[INET6_ADDRSTRLEN];
	const unsigned char *b;
	int n;

	b = (const unsigned char *)src;
	if (af == AF_INET) {
		unsafe_assume_readable_span(src, 4);
		n = snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
	} else if (af == AF_INET6) {
		unsafe_assume_readable_span(src, 16);
		unsigned words[8];
		int i, steps, best = -1, bestlen = 0;
		char *q = buf;
		size_t left = sizeof buf;

		if (!memcmp(b, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12)) {
			n = snprintf(buf, sizeof buf, "::ffff:%u.%u.%u.%u",
			             b[12], b[13], b[14], b[15]);
		} else {
			for (i = 0; i < 8; i++) {
				size_t offset = 2 * (size_t)i;
				words[i] = (unsigned)b[offset] << 8 | b[offset + 1];
			}
			for (i = 0, steps = 0; i < 8 && steps < 8; steps++) {
				int j;
				if (words[i]) { i++; continue; }
				for (j = i; j < 8 && !words[j]; j++);
				if (j - i > bestlen) { best = i; bestlen = j - i; }
				i = j;
			}
			if (bestlen < 2) best = -1;
			for (i = 0, steps = 0; i < 8 && steps < 8; steps++) {
				if (i == best) {
					if (left < 3) { errno = ENOSPC; return 0; }
					*q++ = ':'; *q++ = ':'; left -= 2;
					i += bestlen;
					continue;
				}
				if (i && i != best + bestlen) {
					if (left < 2) { errno = ENOSPC; return 0; }
					*q++ = ':'; left--;
				}
				n = snprintf(q, left, "%x", words[i++]);
				if (n < 0 || (size_t)n >= left) { errno = ENOSPC; return 0; }
				q += n; left -= (size_t)n;
			}
			*q = 0;
			n = (int)(q - buf);
		}
	} else {
		errno = EAFNOSUPPORT;
		return 0;
	}
	if (n < 0 || (size_t)n + 1 > sizeof buf ||
	    (size_t)n + 1 > (size_t)size) { errno = ENOSPC; return 0; }
	memcpy(dst, buf, (size_t)n + 1);
	return dst;
}

/* inet_pton.html: "1"/success, "0"/not a valid presentation string for
 * af, "-1"+EAFNOSUPPORT for an unrecognised af.  The AF_INET parser is
 * strict dotted-quad -- unlike inet_addr(), it does not accept the
 * a/a.b/a.b.c short forms or octal/hex parts -- while AF_INET6 accepts
 * full, compressed and trailing-dotted-quad forms. */
int inet_pton(int af, const char *__restrict src, void *__restrict dst)
{
	unsigned char tmp[16];

	if (af != AF_INET && af != AF_INET6) { errno = EAFNOSUPPORT; return -1; }
	if (!src) return 0;
	if (af == AF_INET) {
		if (!pton4(src, tmp)) return 0;
		unsafe_assume_writable_span(dst, 4);
		memcpy(dst, tmp, 4);
		return 1;
	}
	if (!pton6(src, tmp)) return 0;
	unsafe_assume_writable_span(dst, 16);
	memcpy(dst, tmp, 16);
	return 1;
}

// NOLINTEND(misc-include-cleaner)
