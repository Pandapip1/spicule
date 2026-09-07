/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The address-string half of src/socket: inet_addr, inet_ntoa,
 * inet_ntop, inet_pton, and the four byte-order helpers around them
 * (src/socket/inet.c).  Everything else in that module needs a real AFD
 * device and a live socket, and is a poor fuzz target for that reason --
 * this file is not.  It is four hand-written string parsers and
 * formatters over a caller's buffer, with no OS dependency at all, which
 * is precisely the shape libFuzzer is good at and precisely the shape
 * that has historically hidden buffer arithmetic bugs in every C library
 * that has ever shipped one.
 *
 * THE ORACLE, AND WHERE IT STOPS.  inet_pton(AF_INET) and
 * inet_pton(AF_INET6) are compared byte for byte against the host's,
 * through fuzz/host_oracle.c.  That is a
 * comparison worth making because both sides implement the same
 * specified grammar: inet_pton.html's strict dotted-quad, no short
 * forms, no octal or hexadecimal parts, no leading or trailing space.
 * There is no room for a defensible disagreement, so every disagreement
 * is a finding.
 *
 * inet_addr is deliberately NOT compared against the host's, and the
 * reason is the one test/verification-coverage-accounting.md gives for
 * not oracling regex against glibc: a noisy oracle is worse than none.
 * spicule's inet_addr parses each part with strtoul(base 0), which
 * accepts leading whitespace and a leading sign; glibc's hand-written
 * parser accepts neither.  Both readings of inet_addr.html are
 * arguable -- it says the parts are "interpreted as ... decimal, octal
 * or hexadecimal", which is strtoul's own vocabulary -- so a comparison
 * would produce a stream of arguments about an under-specified corner
 * instead of defects.  What is checked instead are the properties that
 * hold whichever reading is right:
 *
 *   - whenever inet_pton accepts a string, inet_addr must accept it too
 *     and produce the same 32 bits (dotted-quad is a subset of every
 *     reading of inet_addr's grammar);
 *   - inet_ntop of arbitrary IPv4 and IPv6 bytes must round-trip back
 *     through inet_pton to the same bytes, and must never write more
 *     than it was given room for;
 *   - inet_ntop with a size too small must fail with ENOSPC and leave
 *     the destination untouched -- it is the only failure path in the
 *     function that a caller's buffer size can trigger, and the check is
 *     written with a guard byte rather than left to ASan because the
 *     function's own `buf` is large enough that a partial write would
 *     land inside the caller's object, where ASan sees nothing;
 *   - inet_ntoa's static buffer must hold the same text inet_ntop
 *     produces;
 *   - a genuinely unsupported address family must be reported (0/-1 plus
 *     EAFNOSUPPORT), never parsed.
 *
 * Byte order: htonl/htons/ntohl/ntohs are checked for the only property
 * they have independent of the machine -- that each is its own inverse,
 * and that htonl agrees with the byte-wise big-endian layout inet_ntop
 * and inet_pton both use.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

extern int host_inet_pton4(const char *, unsigned char[4]);
extern int host_inet_pton6(const char *, unsigned char[16]);
extern void oracle_mismatch_i(const char *, const char *, long long, long long);
extern void oracle_mismatch_s(const char *, const char *, const char *, const char *);

#define CAP 128

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char s[CAP + 1];
	unsigned char mine[16], theirs[16];
	int r_mine, r_theirs;
	size_t n;

	if (size < 16) return 0;

	/* ---- the four raw bytes: formatting and round-trip ------------- */
	{
		unsigned char raw[4];
		char out[64];
		struct in_addr ia;
		const char *p;
		uint32_t h;

		memcpy(raw, data, 4);
		memset(out, 'Z', sizeof out);
		p = inet_ntop(AF_INET, raw, out, sizeof out);
		if (!p) {
			oracle_mismatch_i("inet_ntop failed with a 64-byte buffer", "", 0, 1);
		} else {
			unsigned char back[4];
			if (strlen(out) >= INET_ADDRSTRLEN)
				oracle_mismatch_i("inet_ntop wrote more than INET_ADDRSTRLEN-1",
				                  out, (long long)strlen(out), INET_ADDRSTRLEN - 1);
			if (inet_pton(AF_INET, out, back) != 1 || memcmp(back, raw, 4) != 0)
				oracle_mismatch_s("inet_ntop/inet_pton do not round-trip", out, out, "");

			/* inet_ntoa must agree with inet_ntop on the same address. */
			memcpy(&ia.s_addr, raw, 4);
			if (strcmp(inet_ntoa(ia), out) != 0)
				oracle_mismatch_s("inet_ntoa disagrees with inet_ntop", out,
				                  inet_ntoa(ia), out);

			/* Exactly one byte short: ENOSPC, and not a byte written. */
			{
				char tight[64];
				size_t len = strlen(out);
				memset(tight, 'Z', sizeof tight);
				errno = 0;
				if (inet_ntop(AF_INET, raw, tight, (socklen_t)len) != 0)
					oracle_mismatch_i("inet_ntop succeeded with a buffer one byte short",
					                  out, (long long)len, 0);
				else if (errno != ENOSPC)
					oracle_mismatch_i("inet_ntop short buffer errno != ENOSPC", out,
					                  errno, ENOSPC);
				if (tight[0] != 'Z')
					oracle_mismatch_i("inet_ntop wrote into a buffer it rejected",
					                  out, tight[0], 'Z');
			}
		}

		/* htonl is its own inverse and matches the big-endian layout
		 * inet_ntop/inet_pton use for the same four bytes. */
		memcpy(&h, raw, 4);
		if (ntohl(htonl(h)) != h)
			oracle_mismatch_i("ntohl(htonl(x)) != x", "", (long long)h,
			                  (long long)ntohl(htonl(h)));
		if ((uint16_t)ntohs(htons((uint16_t)h)) != (uint16_t)h)
			oracle_mismatch_i("ntohs(htons(x)) != x", "", (long long)(uint16_t)h,
			                  (long long)(uint16_t)ntohs(htons((uint16_t)h)));
		{
			uint32_t be = htonl(((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) |
			                    ((uint32_t)raw[2] << 8) | (uint32_t)raw[3]);
			if (memcmp(&be, raw, 4) != 0)
				oracle_mismatch_i("htonl disagrees with the wire byte order", "",
				                  (long long)be, 0);
		}
	}

	/* ---- arbitrary IPv6 bytes: formatting and round-trip ----------- */
	{
		unsigned char back[16];
		char out[64], tight[64];
		const char *p;
		size_t len;

		memset(out, 'Z', sizeof out);
		p = inet_ntop(AF_INET6, data, out, sizeof out);
		if (!p) {
			oracle_mismatch_i("inet_ntop(AF_INET6) failed with a 64-byte buffer",
			                  "", 0, 1);
		} else {
			len = strlen(out);
			if (len >= INET6_ADDRSTRLEN)
				oracle_mismatch_i("inet_ntop(AF_INET6) exceeded INET6_ADDRSTRLEN-1",
				                  out, (long long)len, INET6_ADDRSTRLEN - 1);
			if (inet_pton(AF_INET6, out, back) != 1 || memcmp(back, data, 16) != 0)
				oracle_mismatch_s("IPv6 inet_ntop/inet_pton do not round-trip",
				                  out, out, "");

			memset(tight, 'Z', sizeof tight);
			errno = 0;
			if (inet_ntop(AF_INET6, data, tight, (socklen_t)len) != 0)
				oracle_mismatch_i("IPv6 inet_ntop accepted a short buffer",
				                  out, (long long)len, 0);
			else if (errno != ENOSPC)
				oracle_mismatch_i("IPv6 inet_ntop short-buffer errno",
				                  out, errno, ENOSPC);
			if (tight[0] != 'Z')
				oracle_mismatch_i("IPv6 inet_ntop wrote into a rejected buffer",
				                  out, tight[0], 'Z');
		}
	}

	/* ---- the string: inet_pton against the host, inet_addr against
	 * inet_pton --------------------------------------------------- */
	data += 16; size -= 16;
	n = size < CAP ? size : CAP;
	memcpy(s, data, n);
	s[n] = 0;
	if (memchr(s, 0, n)) return 0;

	memset(mine, 0xAA, sizeof mine);
	memset(theirs, 0xAA, sizeof theirs);
	r_mine = inet_pton(AF_INET, s, mine);
	r_theirs = host_inet_pton4(s, theirs);
	if (r_mine != r_theirs)
		oracle_mismatch_i("inet_pton return value", s, r_mine, r_theirs);
	else if (r_mine == 1 && r_theirs == 1 && memcmp(mine, theirs, 4) != 0)
		oracle_mismatch_i("inet_pton produced different bytes", s,
		                  ((long long)mine[0] << 24) | ((long long)mine[1] << 16) |
		                  ((long long)mine[2] << 8) | mine[3],
		                  ((long long)theirs[0] << 24) | ((long long)theirs[1] << 16) |
		                  ((long long)theirs[2] << 8) | theirs[3]);

	/* A dotted-quad inet_pton accepted is inside every reading of
	 * inet_addr's grammar, so inet_addr must accept it and agree.
	 * That now holds unconditionally: inet_pton() rejects a part with
	 * a leading zero, which is the one shape the two would otherwise
	 * read differently -- inet_pton() would read "099" as decimal 99
	 * while inet_addr() hands the same part to strtoul(base 0), which
	 * takes the leading '0' as introducing octal and rejects the '9',
	 * making inet_addr("0.3.3.099") (in_addr_t)-1. */
	if (r_mine == 1) {
		in_addr_t a = inet_addr(s);
		uint32_t want;
		memcpy(&want, mine, 4);
		if (a != (in_addr_t)want)
			oracle_mismatch_i("inet_addr disagrees with inet_pton on a dotted quad",
			                  s, (long long)a, (long long)want);
	} else {
		(void)inet_addr(s);     /* still driven, just not compared */
	}

	/* IPv6 uses the same specified grammar on both sides. */
	memset(mine, 0xAA, sizeof mine);
	memset(theirs, 0xAA, sizeof theirs);
	r_mine = inet_pton(AF_INET6, s, mine);
	r_theirs = host_inet_pton6(s, theirs);
	if (r_mine != r_theirs)
		oracle_mismatch_i("inet_pton(AF_INET6) return value", s, r_mine, r_theirs);
	else if (r_mine == 1 && memcmp(mine, theirs, 16) != 0)
		oracle_mismatch_i("inet_pton(AF_INET6) produced different bytes", s,
		                  memcmp(mine, theirs, 16), 0);

	/* An unsupported family must be reported, not parsed. */
	{
		unsigned char sink[16];
		char out[64];
		errno = 0;
		if (inet_pton(AF_UNIX, s, sink) != -1 || errno != EAFNOSUPPORT)
			oracle_mismatch_i("inet_pton(AF_UNIX) did not report EAFNOSUPPORT", s,
			                  errno, EAFNOSUPPORT);
		errno = 0;
		if (inet_ntop(AF_UNIX, sink, out, sizeof out) != 0 || errno != EAFNOSUPPORT)
			oracle_mismatch_i("inet_ntop(AF_UNIX) did not report EAFNOSUPPORT", s,
			                  errno, EAFNOSUPPORT);
	}
	return 0;
}
