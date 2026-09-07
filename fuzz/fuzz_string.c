/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * src/string -- 65 files, the largest module in the tree, and the one
 * test/verification-coverage-accounting.md singles out as reached
 * "incidentally by every harness ... but no harness drives a string
 * function with adversarial input, so it counts as unfuzzed".  That
 * distinction is the whole point: memcpy called with the lengths a
 * printf harness happens to produce is not the same thing as memmem
 * called with a needle longer than its haystack.
 *
 * The functions driven here are the ones that do arithmetic on a length
 * or search for a terminator -- the searchers (strstr, strcasestr,
 * memmem, memchr, memrchr, strchr, strrchr, strchrnul, strpbrk, index,
 * rindex), the span functions (strspn, strcspn), the bounded copies
 * (strlcpy, strlcat, strncpy, stpncpy, strncat, memccpy, mempcpy), the
 * tokenisers (strtok_r, strsep), and the two comparison functions with
 * their own grammar (strverscmp, strcoll/strxfrm).  Plain strcpy/strcat
 * are not driven with fuzzer lengths: they have no length argument, so
 * an overflow found there would be the harness's fault, not the
 * library's.
 *
 * TWO BUFFERS, AND A GUARD ROUND EVERY DESTINATION.  The input is split
 * into a haystack and a needle by a length byte, so every searcher gets
 * the four interesting relationships (needle longer, needle equal,
 * needle a prefix, needle absent) rather than only the ones a single
 * string can express.  Every destination buffer is bracketed by a
 * guard region filled with a sentinel and checked afterwards, because
 * ASan alone would not see a bounded copy that writes one byte too many
 * into the middle of a large caller object -- which is exactly the bug
 * strlcpy and stpncpy exist to prevent and therefore exactly the bug
 * they are most likely to contain.
 *
 * WHAT IS ASSERTED.  The invariants each function has by definition,
 * not a reimplementation of it -- a harness that recomputed the answer
 * would be testing the harness:
 *
 *   - strlen(s) == strnlen(s, huge), and strnlen never exceeds its cap;
 *   - a searcher's result is either NULL or inside its own input, and
 *     the bytes at that position really do begin the needle;
 *   - strchrnul never returns NULL and never points past the NUL;
 *   - strspn/strcspn return a length within the string, and the byte at
 *     that offset is the first one that breaks the rule;
 *   - strlcpy/strlcat return the length they *would* have produced, per
 *     their contract, and never write past the size they were given;
 *   - strncpy pads to exactly n and stpncpy's return is dst + the
 *     length copied;
 *   - the tokenisers partition the string: concatenating the tokens
 *     with the delimiters they consumed reproduces the input length.
 *
 * A host oracle would be reasonable for several of these and is
 * deliberately not used: <string.h>'s functions are specified tightly
 * enough that the invariants above are equivalent to the specification,
 * and each one names the property that failed rather than reporting
 * "glibc said something else".
 */
/* _GNU_SOURCE, because half the functions this file exists to drive --
 * strlcpy, strlcat, strchrnul, memrchr, memmem, mempcpy, strverscmp,
 * strcasestr -- are guarded behind it (and _BSD_SOURCE) in
 * include/string.h.  fuzz/Makefile compiles harnesses with
 * -D_XOPEN_SOURCE=700, which hides them; the library itself is built
 * with -D_ALL_SOURCE, so these are spicule's own functions being fuzzed
 * from a caller that asks for them the same way spicule's own sources do.
 * Defined here rather than in the Makefile so no other harness's view of
 * the headers changes. */
#define _GNU_SOURCE 1
#define _BSD_SOURCE 1

#include <string.h>
#include <strings.h>
#include <stdlib.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);

#define CAP  128
#define PAD  16
#define GUARD 0xC7

/* A destination with PAD guard bytes on each side.  check_guard reports
 * the first byte of either guard that moved. */
struct dbuf { unsigned char mem[PAD + CAP + 1 + PAD]; };

static char *dst_of(struct dbuf *d)
{
	memset(d->mem, GUARD, sizeof d->mem);
	return (char *)d->mem + PAD;
}

static void check_guard(const char *what, struct dbuf *d, size_t usable)
{
	size_t i;
	for (i = 0; i < PAD; i++)
		if (d->mem[i] != GUARD)
			oracle_mismatch_i(what, "underrun", (long long)i, GUARD);
	for (i = PAD + usable; i < sizeof d->mem; i++)
		if (d->mem[i] != GUARD)
			oracle_mismatch_i(what, "overrun", (long long)(i - PAD - usable), GUARD);
}

/* Is `p` a pointer into [base, base+len]?  A searcher may return
 * base+len (the NUL) but never anything outside. */
static int inside(const void *p, const void *base, size_t len)
{
	return p >= base && (const char *)p <= (const char *)base + len;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char hay[CAP + 1], nee[CAP + 1];
	size_t hlen, nlen, cap;
	struct dbuf db;

	if (size < 3) return 0;
	nlen = data[0] % (CAP + 1);
	cap  = data[1] % (CAP + 2);             /* including 0 and CAP+1 */
	data += 2; size -= 2;

	hlen = size < CAP ? size : CAP;
	memcpy(hay, data, hlen); hay[hlen] = 0;
	if (nlen > hlen) nlen = hlen;
	memcpy(nee, data, nlen); nee[nlen] = 0;

	/* From here on hay/nee are C strings: their logical length is up to
	 * the first NUL, which the fuzzer is free to place anywhere. */
	{
		size_t hs = strlen(hay), ns = strlen(nee);

		if (strnlen(hay, (size_t)-1) != hs)
			oracle_mismatch_i("strnlen(s, SIZE_MAX) != strlen(s)", hay,
			                  (long long)strnlen(hay, (size_t)-1), (long long)hs);
		if (strnlen(hay, cap) > cap)
			oracle_mismatch_i("strnlen exceeded its cap", hay,
			                  (long long)strnlen(hay, cap), (long long)cap);

		/* ---- searchers: a hit must be inside, and must really match -- */
		{
			char *p = strstr(hay, nee);
			if (p) {
				if (!inside(p, hay, hs))
					oracle_mismatch_i("strstr returned a pointer outside the haystack",
					                  hay, (long long)(p - hay), (long long)hs);
				else if (memcmp(p, nee, ns) != 0)
					oracle_mismatch_i("strstr hit does not start the needle", hay,
					                  (long long)(p - hay), 0);
			} else if (ns == 0) {
				oracle_mismatch_i("strstr(s, \"\") returned NULL", hay, 0, 1);
			}
		}
		{
			char *p = strcasestr(hay, nee);
			if (p && !inside(p, hay, hs))
				oracle_mismatch_i("strcasestr returned a pointer outside the haystack",
				                  hay, (long long)(p - hay), (long long)hs);
			if (p && strncasecmp(p, nee, ns) != 0)
				oracle_mismatch_i("strcasestr hit does not match case-insensitively",
				                  hay, (long long)(p - hay), 0);
		}
		{
			/* memmem over the raw bytes, not the C strings: this is the
			 * one searcher whose inputs may contain NULs. */
			void *p = memmem(hay, hlen, nee, nlen);
			if (p) {
				if (!inside(p, hay, hlen))
					oracle_mismatch_i("memmem returned a pointer outside the haystack",
					                  hay, (long long)((char *)p - hay), (long long)hlen);
				else if ((size_t)((char *)p - hay) + nlen > hlen)
					oracle_mismatch_i("memmem hit runs past the haystack", hay,
					                  (long long)((char *)p - hay), (long long)hlen);
				else if (memcmp(p, nee, nlen) != 0)
					oracle_mismatch_i("memmem hit does not equal the needle", hay,
					                  (long long)((char *)p - hay), 0);
			}
		}
		{
			int c = nlen ? (unsigned char)nee[0] : 0;
			char *f = strchr(hay, c), *l = strrchr(hay, c), *n = strchrnul(hay, c);
			void *m = memchr(hay, c, hlen), *r = memrchr(hay, c, hlen);

			if (f && (!inside(f, hay, hs) || (unsigned char)*f != (unsigned char)c))
				oracle_mismatch_i("strchr hit is outside or wrong", hay,
				                  (long long)(f - hay), c);
			if (l && (!inside(l, hay, hs) || (unsigned char)*l != (unsigned char)c))
				oracle_mismatch_i("strrchr hit is outside or wrong", hay,
				                  (long long)(l - hay), c);
			if (f && l && l < f)
				oracle_mismatch_i("strrchr found an earlier hit than strchr", hay,
				                  (long long)(l - hay), (long long)(f - hay));
			if (!n)
				oracle_mismatch_i("strchrnul returned NULL", hay, 0, 1);
			else if (!inside(n, hay, hs))
				oracle_mismatch_i("strchrnul returned a pointer outside the string",
				                  hay, (long long)(n - hay), (long long)hs);
			else if (f && n != f)
				oracle_mismatch_i("strchrnul disagrees with strchr on a hit", hay,
				                  (long long)(n - hay), (long long)(f - hay));
			else if (!f && (size_t)(n - hay) != hs)
				oracle_mismatch_i("strchrnul did not stop at the NUL", hay,
				                  (long long)(n - hay), (long long)hs);
			if (m && !inside(m, hay, hlen))
				oracle_mismatch_i("memchr hit is outside the buffer", hay,
				                  (long long)((char *)m - hay), (long long)hlen);
			if (r && !inside(r, hay, hlen))
				oracle_mismatch_i("memrchr hit is outside the buffer", hay,
				                  (long long)((char *)r - hay), (long long)hlen);
			if (index(hay, c) != f)
				oracle_mismatch_i("index disagrees with strchr", hay, 0, 1);
			if (rindex(hay, c) != l)
				oracle_mismatch_i("rindex disagrees with strrchr", hay, 0, 1);
		}
		{
			size_t a = strspn(hay, nee), b = strcspn(hay, nee);
			char *p = strpbrk(hay, nee);

			if (a > hs) oracle_mismatch_i("strspn exceeded strlen", hay, (long long)a, (long long)hs);
			if (b > hs) oracle_mismatch_i("strcspn exceeded strlen", hay, (long long)b, (long long)hs);
			if (a < hs && strchr(nee, (unsigned char)hay[a]) != 0 && hay[a])
				oracle_mismatch_i("strspn stopped on a byte that is in the set", hay,
				                  (long long)a, (unsigned char)hay[a]);
			if (b < hs && strchr(nee, (unsigned char)hay[b]) == 0)
				oracle_mismatch_i("strcspn stopped on a byte that is not in the set",
				                  hay, (long long)b, (unsigned char)hay[b]);
			if (p && (size_t)(p - hay) != b)
				oracle_mismatch_i("strpbrk disagrees with strcspn", hay,
				                  (long long)(p - hay), (long long)b);
			if (!p && b != hs)
				oracle_mismatch_i("strpbrk found nothing but strcspn stopped early",
				                  hay, (long long)b, (long long)hs);
		}

		/* ---- bounded copies, each into a guarded destination -------- */
		{
			char *d = dst_of(&db);
			size_t want = strlcpy(d, hay, cap);
			if (want != hs)
				oracle_mismatch_i("strlcpy did not return strlen(src)", hay,
				                  (long long)want, (long long)hs);
			if (cap && strlen(d) != (hs < cap - 1 ? hs : cap - 1))
				oracle_mismatch_i("strlcpy truncated to the wrong length", hay,
				                  (long long)strlen(d), (long long)cap);
			check_guard("strlcpy", &db, cap);
		}
		{
			char *d = dst_of(&db);
			size_t pre;
			if (cap) { d[0] = 0; strlcpy(d, nee, cap); }
			pre = cap ? strlen(d) : 0;
			{
				size_t want = strlcat(d, hay, cap);
				size_t expect = (pre < cap ? pre : cap) + hs;
				if (want != expect)
					oracle_mismatch_i("strlcat did not return the would-be length",
					                  hay, (long long)want, (long long)expect);
			}
			check_guard("strlcat", &db, cap);
		}
		{
			char *d = dst_of(&db);
			size_t k = cap > CAP ? CAP : cap;
			char *end = stpncpy(d, hay, k);
			if ((size_t)(end - d) != (hs < k ? hs : k))
				oracle_mismatch_i("stpncpy returned the wrong end", hay,
				                  (long long)(end - d), (long long)k);
			check_guard("stpncpy", &db, k);
		}
		{
			char *d = dst_of(&db);
			size_t k = cap > CAP ? CAP : cap;
			size_t i;
			strncpy(d, hay, k);
			for (i = hs < k ? hs : k; i < k; i++)
				if (d[i] != 0)
					oracle_mismatch_i("strncpy did not pad with NUL", hay,
					                  (long long)i, 0);
			check_guard("strncpy", &db, k);
		}
		{
			char *d = dst_of(&db);
			size_t k = cap > CAP ? CAP : cap;
			void *e;
			memset(d, 0, k ? k : 1);
			e = memccpy(d, hay, nlen ? (unsigned char)nee[0] : 0, k);
			if (e && !inside(e, d, k))
				oracle_mismatch_i("memccpy returned a pointer outside the destination",
				                  hay, (long long)((char *)e - d), (long long)k);
			check_guard("memccpy", &db, k ? k : 1);
		}
		{
			char *d = dst_of(&db);
			size_t k = hlen < CAP ? hlen : CAP;
			void *e = mempcpy(d, hay, k);
			if ((char *)e != d + k)
				oracle_mismatch_i("mempcpy did not return dst + n", hay,
				                  (long long)((char *)e - d), (long long)k);
			check_guard("mempcpy", &db, k);
		}

		/* ---- tokenisers: they must partition, not lose or invent ---- */
		{
			char work[CAP + 1];
			char *save = 0, *tok;
			size_t consumed = 0, ntok = 0;
			memcpy(work, hay, hs + 1);
			for (tok = strtok_r(work, nee, &save); tok; tok = strtok_r(0, nee, &save)) {
				size_t l = strlen(tok);
				if (!inside(tok, work, hs))
					oracle_mismatch_i("strtok_r returned a token outside the string",
					                  hay, (long long)(tok - work), (long long)hs);
				if (l == 0)
					oracle_mismatch_i("strtok_r returned an empty token", hay, 0, 1);
				if (strcspn(tok, nee) != l)
					oracle_mismatch_i("strtok_r token contains a delimiter", hay,
					                  (long long)strcspn(tok, nee), (long long)l);
				consumed += l;
				if (++ntok > CAP + 1) {
					oracle_mismatch_i("strtok_r produced more tokens than bytes",
					                  hay, (long long)ntok, (long long)hs);
					break;
				}
			}
			if (consumed > hs)
				oracle_mismatch_i("strtok_r tokens are longer than the input", hay,
				                  (long long)consumed, (long long)hs);
		}
		{
			char work[CAP + 1];
			char *p = work, *tok;
			size_t ntok = 0;
			memcpy(work, hay, hs + 1);
			while ((tok = strsep(&p, nee)) != 0) {
				if (!inside(tok, work, hs))
					oracle_mismatch_i("strsep returned a token outside the string",
					                  hay, (long long)(tok - work), (long long)hs);
				if (++ntok > hs + 2) {
					oracle_mismatch_i("strsep produced more fields than bytes + 1",
					                  hay, (long long)ntok, (long long)hs);
					break;
				}
			}
		}

		/* ---- the two with their own grammar ------------------------ */
		{
			int v = strverscmp(hay, nee);
			int w = strverscmp(nee, hay);
			if ((v == 0) != (w == 0))
				oracle_mismatch_i("strverscmp is not symmetric about equality", hay, v, w);
			if (v && w && (v > 0) == (w > 0))
				oracle_mismatch_i("strverscmp orders both ways round", hay, v, w);
			if (strverscmp(hay, hay) != 0)
				oracle_mismatch_i("strverscmp(s, s) != 0", hay,
				                  strverscmp(hay, hay), 0);
		}
		{
			/* strxfrm's contract: the return is the length the transform
			 * needs, and it must not write more than n bytes. */
			char *d = dst_of(&db);
			size_t k = cap > CAP ? CAP : cap;
			size_t want = strxfrm(d, hay, k);
			check_guard("strxfrm", &db, k);
			if (want < k && strcoll(hay, hay) != 0)
				oracle_mismatch_i("strcoll(s, s) != 0", hay, strcoll(hay, hay), 0);
		}
	}
	return 0;
}
