/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* UTF-8 <-> UTF-16 conversion with state.  wchar_t is a 16-bit UTF-16
 * code unit, so a 4-byte UTF-8 sequence yields two wchar_t: mbrtowc
 * returns the high surrogate and consumes the bytes, remembering the low
 * surrogate in the state (__opaque2) to hand back on the next call for
 * zero bytes consumed... except POSIX requires a nonzero return for a
 * nonzero character, so that call consumes nothing and returns (size_t)-3,
 * the same convention glibc/Windows use for "output from state alone".
 *
 * Partial sequences are kept in __opaque1 as (pending code point << 8)
 * | (bytes still needed << 4) | (bytes seen) -- musl-style.
 *
 * wcrtomb likewise remembers a high surrogate in __opaque1 and writes
 * the 4-byte sequence when the low surrogate arrives. */
#include <wchar.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define SURR_HI(c) ((c) >= 0xd800 && (c) < 0xdc00)
#define SURR_LO(c) ((c) >= 0xdc00 && (c) < 0xe000)

size_t __ctype_get_mb_cur_max(void) { return 4; }

int mbsinit(const mbstate_t *st) { return !st || (!st->__opaque1 && !st->__opaque2); }

size_t mbrtowc(wchar_t *__restrict wc, const char *__restrict s, size_t n, mbstate_t *__restrict st)
{
	static mbstate_t internal;
	const unsigned char *p = (const unsigned char *)s;
	unsigned c, cp, need, seen;
	size_t used = 0;
	wchar_t dummy;

	if (!st) st = &internal;
	if (!wc) wc = &dummy;
	if (!s) { s = ""; n = 1; wc = &dummy; p = (const unsigned char *)s; }

	if (st->__opaque2) {       /* a pending low surrogate */
		*wc = (wchar_t)st->__opaque2;
		st->__opaque2 = 0;
		return (size_t)-3;
	}
	if (!n) return (size_t)-2;

	if (st->__opaque1) {
		cp = st->__opaque1 >> 8;
		need = (st->__opaque1 >> 4) & 0xf;
		seen = st->__opaque1 & 0xf;
	} else {
		c = *p++; used = 1;
		if (c < 0x80) { *wc = (wchar_t)c; return c ? 1 : 0; }
		if (c < 0xc2 || c > 0xf4) goto ilseq;
		if (c < 0xe0) { cp = c & 0x1f; need = 1; }
		else if (c < 0xf0) { cp = c & 0x0f; need = 2; }
		else { cp = c & 0x07; need = 3; }
		seen = 1;
	}
	while (need > 0) {
		if (used >= n) {
			st->__opaque1 = (cp << 8) | (need << 4) | seen;
			return (size_t)-2;
		}
		c = *p++; used++;
		if ((c & 0xc0) != 0x80) goto ilseq;
		cp = (cp << 6) | (c & 0x3f);
		need--; seen++;
		/* reject overlongs / surrogates / out of range as early as the
		 * second byte so an invalid prefix is not kept as state. */
		if (seen == 2) {
			unsigned total = need + 2;
			if ((total == 3 && cp < 0x20) || (total == 4 && (cp < 0x10 || cp > 0x10f))) goto ilseq;
		}
	}
	st->__opaque1 = 0;
	if (cp >= 0xd800 && cp < 0xe000) goto ilseq;
	if (cp >= 0x10000) {
		cp -= 0x10000;
		*wc = (wchar_t)(0xd800 + (cp >> 10));
		st->__opaque2 = 0xdc00 + (cp & 0x3ff);
	} else {
		*wc = (wchar_t)cp;
	}
	return used;
ilseq:
	st->__opaque1 = 0;
	errno = EILSEQ;
	return (size_t)-1;
}

size_t mbrlen(const char *__restrict s, size_t n, mbstate_t *__restrict st)
{
	static mbstate_t internal;
	return mbrtowc(0, s, n, st ? st : &internal);
}

size_t wcrtomb(char *__restrict s, wchar_t wc, mbstate_t *__restrict st)
{
	static mbstate_t internal;
	unsigned c = wc, cp;
	if (!st) st = &internal;
	if (!s) { st->__opaque1 = 0; return 1; }
	if (st->__opaque1) {
		unsigned hi = st->__opaque1;
		st->__opaque1 = 0;
		if (!SURR_LO(c)) { errno = EILSEQ; return (size_t)-1; }
		cp = 0x10000 + ((hi - 0xd800) << 10) + (c - 0xdc00);
		s[0] = (char)(0xf0 | (cp >> 18));
		s[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
		s[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
		s[3] = (char)(0x80 | (cp & 0x3f));
		return 4;
	}
	if (SURR_HI(c)) { st->__opaque1 = c; return 0; }
	if (SURR_LO(c)) { errno = EILSEQ; return (size_t)-1; }
	if (c < 0x80) { s[0] = (char)c; return 1; }
	if (c < 0x800) { s[0] = (char)(0xc0 | (c >> 6)); s[1] = (char)(0x80 | (c & 0x3f)); return 2; }
	s[0] = (char)(0xe0 | (c >> 12)); s[1] = (char)(0x80 | ((c >> 6) & 0x3f)); s[2] = (char)(0x80 | (c & 0x3f));
	return 3;
}

size_t mbsrtowcs(wchar_t *__restrict ws, const char **__restrict src, size_t n, mbstate_t *__restrict st)
{
	static mbstate_t internal;
	const char *s = *src;
	size_t out = 0, r;
	/* mbrtowc writes through &wc on every return other than -1 and -2,
	 * both of which are handled below -- except on the one path where it
	 * is handed a null s, which it redirects to a dummy.  *src being null
	 * is a caller error POSIX leaves undefined; initialising here turns it
	 * into a deterministic "empty string" instead of reading garbage. */
	wchar_t wc = 0;

	if (!st) st = &internal;
	for (;;) {
		if (ws && out >= n) break;
		r = mbrtowc(&wc, s, 4, st);
		if (r == (size_t)-1) { if (ws) *src = s; return (size_t)-1; }
		if (r == (size_t)-2) { /* NUL inside a sequence: mbrtowc stops at it as ilseq */
			errno = EILSEQ; if (ws) *src = s; return (size_t)-1;
		}
		if (r == (size_t)-3) r = 0;
		if (ws) ws[out] = wc;
		if (!wc) { if (ws) *src = 0; return out; }
		s += r;
		out++;
	}
	if (ws) *src = s;
	return out;
}

/* include/wchar.h marks src nonnull; that lets the checker explore
 * further into this loop than before, now also flagging `ws[0]`/`ws[1]`
 * (`ws` starts as `*src`, already proven nonnull, but is advanced by
 * pointer arithmetic -- `ws += 2;`/`ws++;` -- each iteration): sound by
 * construction (a NUL-terminated wide string this loop's own `if
 * (!ws[0]) ...` return stops at), just past what this checker's nonnull
 * propagation currently follows across a loop increment -- the same
 * class of residual src/stdlib/qsort.c's swap() now discloses for
 * `x++`/`y++`. wcsnrtombs() below shares the identical shape. */
size_t wcsrtombs(char *__restrict s, const wchar_t **__restrict src, size_t n, mbstate_t *__restrict st)
{
	static mbstate_t internal;
	const wchar_t *ws = *src;
	char buf[4];
	size_t out = 0, r;

	if (!st) st = &internal;
	for (;;) {
		/* a high surrogate followed by its low one is 4 bytes; peek so
		 * that we never write a partial character. */
		if (SURR_HI(ws[0]) && SURR_LO(ws[1])) {
			if (s && out + 4 > n) break;
			r = wcrtomb(buf, ws[0], st);
			if (r == (size_t)-1) { st->__opaque1 = 0; if (s) *src = ws; errno = EILSEQ; return (size_t)-1; }
			r = wcrtomb(buf, ws[1], st);
			if (r == (size_t)-1) { st->__opaque1 = 0; if (s) *src = ws; errno = EILSEQ; return (size_t)-1; }
			if (s) memcpy(s + out, buf, 4);
			out += 4; ws += 2;
			continue;
		}
		r = wcrtomb(buf, ws[0], st);
		if (r == (size_t)-1 || r == 0) { st->__opaque1 = 0; if (s) *src = ws; errno = EILSEQ; return (size_t)-1; }
		if (s && out + r > n) break;
		if (s) memcpy(s + out, buf, r);
		if (!ws[0]) { if (s) *src = 0; return out; }
		out += r; ws++;
	}
	if (s) *src = ws;
	return out;
}

/* mbsnrtowcs(): the bounded form of mbsrtowcs() above, per
 * https://pubs.opengroup.org/onlinepubs/9799919799/functions/mbsnrtowcs.html
 * -- "equivalent to the mbsrtowcs() function, except that the conversion
 * of characters indirectly pointed to by src is limited to at most nmc
 * bytes (the size of the input buffer)".
 *
 * The bound is what makes this more than a wrapper.  mbsrtowcs() above
 * always hands mbrtowc() a fixed n of 4 and can therefore treat a -2
 * ("incomplete") return as EILSEQ, because the only way a 4-byte window
 * over a NUL-terminated string ends mid-character is a NUL inside the
 * sequence.  Here the window is the caller's, so -2 is the ordinary
 * end-of-buffer case and must NOT be an error: mbsnrtowcs.html says "if
 * the input buffer ends with an incomplete character, conversion shall
 * stop at the end of the input buffer; a subsequent call ... shall
 * correctly complete the conversion of that character".  mbrtowc() has
 * already stashed the partial sequence in *st, so stopping is all that
 * is required; *src is advanced past the bytes it consumed, which is
 * "the address just past the last byte processed".
 *
 * mbrtowc() is called before the nmc == 0 test rather than after, and
 * deliberately: it answers a pending low surrogate (its (size_t)-3
 * return, see the file header) from state alone, consuming no bytes, so
 * the second half of a supplementary character must still be delivered
 * when the byte budget is already exhausted.  With nothing pending and
 * nmc == 0 it returns -2 and the loop ends, which is the same outcome an
 * up-front test would have given.
 */
size_t mbsnrtowcs(wchar_t *__restrict ws, const char **__restrict src, size_t nmc, size_t n, mbstate_t *__restrict st) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	static mbstate_t internal;
	const char *s = *src;
	size_t out = 0, r;
	wchar_t wc = 0;

	if (!st) st = &internal;
	for (;;) {
		if (ws && out >= n) break;
		r = mbrtowc(&wc, s, nmc, st);
		if (r == (size_t)-1) { if (ws) *src = s; return (size_t)-1; }
		/* No `nmc = 0` here.  It looks like the natural companion to
		 * `s += nmc`, and it is dead: the break leaves the loop, nmc
		 * is a by-value parameter, and nothing below the loop reads
		 * it.  clang-analyzer's deadcode.DeadStores said so and was
		 * right.  The bound is spent either way -- what carries that
		 * fact out of the loop is s, which is what *src is set from. */
		if (r == (size_t)-2) { s += nmc; break; }
		if (r == (size_t)-3) r = 0;	/* delivered from state, no bytes used */
		if (ws) ws[out] = wc;
		if (!wc) { if (ws) *src = 0; return out; }
		s += r; nmc -= r;
		out++;
	}
	if (ws) *src = s;
	return out;
}

/* wcsnrtombs(): the bounded form of wcsrtombs() above, per
 * https://pubs.opengroup.org/onlinepubs/9799919799/functions/wcsnrtombs.html
 * -- "equivalent to the wcsrtombs() function, except that the conversion
 * is limited to the first nwc wide characters".  Returns a BYTE count,
 * like wcsrtombs().
 *
 * The surrogate-pair lookahead needs an extra guard that wcsrtombs()
 * does not.  There, ws[1] is always safe to read: the input is a
 * null-terminated wide string, so if ws[0] is not the null then ws[1] is
 * within the array.  Here the caller has bounded the input to nwc wide
 * characters and it need not be terminated at all, so peeking at ws[1]
 * to see whether a high surrogate has its partner is only legal when
 * nwc >= 2.  Getting this wrong would read one wchar_t past the caller's
 * buffer on exactly the inputs this function exists for.
 *
 * A high surrogate that is the last wide character within nwc therefore
 * falls through to the single-unit path, where wcrtomb() stashes it and
 * returns 0, and this function reports EILSEQ -- the same answer
 * wcsrtombs() gives for a lone high surrogate.  POSIX does not describe
 * this case because it cannot arise with a 32-bit wchar_t; the choice
 * here is consistency with the sibling function rather than inventing a
 * second convention, and it is deliberate: emitting a partial character
 * is not an option, and silently stopping would make a truncated pair
 * indistinguishable from a completed conversion.
 */
size_t wcsnrtombs(char *__restrict s, const wchar_t **__restrict src, size_t nwc, size_t n, mbstate_t *__restrict st) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	static mbstate_t internal;
	const wchar_t *ws = *src;
	char buf[4];
	size_t out = 0, r;

	if (!st) st = &internal;
	for (;;) {
		if (!nwc) break;
		if (nwc >= 2 && SURR_HI(ws[0]) && SURR_LO(ws[1])) {
			if (s && out + 4 > n) break;
			r = wcrtomb(buf, ws[0], st);
			if (r == (size_t)-1) { st->__opaque1 = 0; if (s) *src = ws; errno = EILSEQ; return (size_t)-1; }
			r = wcrtomb(buf, ws[1], st);
			if (r == (size_t)-1) { st->__opaque1 = 0; if (s) *src = ws; errno = EILSEQ; return (size_t)-1; }
			if (s) memcpy(s + out, buf, 4);
			out += 4; ws += 2; nwc -= 2;
			continue;
		}
		r = wcrtomb(buf, ws[0], st);
		if (r == (size_t)-1 || r == 0) { st->__opaque1 = 0; if (s) *src = ws; errno = EILSEQ; return (size_t)-1; }
		if (s && out + r > n) break;
		if (s) memcpy(s + out, buf, r);
		if (!ws[0]) { if (s) *src = 0; return out; }
		out += r; ws++; nwc--;
	}
	if (s) *src = ws;
	return out;
}

wint_t btowc(int c)
{
	unsigned char b = (unsigned char)c;
	if (c == -1) return WEOF;
	return b < 0x80 ? b : WEOF;
}

int wctob(wint_t c)
{
	return c < 0x80 ? (int)c : -1;
}

// NOLINTEND(misc-include-cleaner)
