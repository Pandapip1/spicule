/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The wide-character stdio family: a thin layer over rw.c's byte
 * primitives and the UTF-8 <-> UTF-16 converter in src/stdlib/mbrtowc.c.
 *
 * A supplementary character is one 4-byte UTF-8 sequence but two
 * wchar_t: mbrtowc() returns the high surrogate having consumed all four
 * bytes and holds the low one in conversion state for a zero-length
 * follow-up call ((size_t)-3), which is why fgetwc() checks state before
 * reading. Symmetrically, wcrtomb() returns 0 for a lone high surrogate,
 * which fputwc() must treat as success, not error.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <wchar.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include "stdio_impl.h"

/* Read one wide character.  WEOF on end-of-file or error, with the
 * stream's eof/err indicator set by the byte layer or here.
 *
 * *nbytes, when not null, is set to how many BYTES the character
 * consumed.  Only src/stdio/scanf.c wants that: it hands look-ahead
 * back by seeking the stream, which is a byte offset, and for a
 * variable-width encoding the byte length of a character is not
 * recoverable from the character.  A pushback slot delivery consumes
 * nothing and reports 0. */
static wint_t getwc_core(FILE *f, int *nbytes)
{
	char b;
	size_t i = 0, r;
	wchar_t wc = 0;

	if (nbytes) *nbytes = 0;
	if (f->nwunget) { f->nwunget = 0; return (wint_t)f->wunget; }

	/* An open_wmemstream() buffer holds wchar_t, so a unit is read as
	 * its own bytes rather than decoded -- the mirror of the write path
	 * below, and for the same reason. */
	if (f->wmem) {
		unsigned char raw[sizeof(wchar_t)];
		for (i = 0; i < sizeof wc; i++) {
			int c = __fgetc(f);
			if (c == EOF) {
				/* A partial unit at the end is not a character. */
				if (i) { errno = EILSEQ; f->err = 1; }
				return WEOF;
			}
			raw[i] = (unsigned char)c;
		}
		memcpy(&wc, raw, sizeof wc);
		if (nbytes) *nbytes = (int)sizeof wc;
		return (wint_t)wc;
	}

	/* A unit owed from a previous surrogate pair, delivered from state
	 * alone.  A zero-length call cannot consume anything, so this is
	 * safe to ask unconditionally. */
	if (mbrtowc(&wc, "", 0, &f->wst_in) == (size_t)-3) return (wint_t)wc;

	for (;;) {
		int c = __fgetc(f);
		if (c == EOF) {
			/* End of input in the middle of a sequence is an
			 * encoding error, not a clean EOF: fgetwc.html says
			 * [EILSEQ] when "the data obtained from the input
			 * stream does not form a valid character". */
			if (i) { errno = EILSEQ; f->err = 1; }
			return WEOF;
		}
		b = (char)c;
		i++;
		if (nbytes) (*nbytes)++;
		r = mbrtowc(&wc, &b, 1, &f->wst_in);
		if (r == (size_t)-1) { f->err = 1; return WEOF; }
		if (r == (size_t)-2) {
			if (i >= MB_LEN_MAX) { errno = EILSEQ; f->err = 1; return WEOF; }
			continue;	/* incomplete: feed another byte */
		}
		return (wint_t)wc;	/* r == 0 is a null wide character, not EOF */
	}
}

/* Write one wide character.  WEOF on error. */
static wint_t putwc_core(wchar_t wc, FILE *f)
{
	char buf[MB_LEN_MAX];
	size_t r, i;

	/* An open_wmemstream() buffer holds wchar_t, not their multibyte
	 * encoding, so this stream's units go out as their own bytes and
	 * never through wcrtomb().  Writing them one byte at a time through
	 * __fputc() keeps the ordinary buffering and growth path -- the
	 * count is always a whole wchar_t, so nothing downstream ever sees
	 * a partial unit.  (A surrogate pair is two units and is stored as
	 * two, unchanged: a wide memory stream is meant to hold exactly
	 * what was written to it.) */
	if (f->wmem) {
		unsigned char raw[sizeof(wchar_t)];
		memcpy(raw, &wc, sizeof wc);
		for (i = 0; i < sizeof wc; i++)
			if (__fputc(raw[i], f) == EOF) return WEOF;
		return (wint_t)wc;
	}

	r = wcrtomb(buf, wc, &f->wst_out);
	if (r == (size_t)-1) { f->err = 1; return WEOF; }	/* wcrtomb set EILSEQ */
	/* r == 0: a high surrogate held for its partner.  Nothing is
	 * written, and fputwc.html still requires wc to be returned -- the
	 * character has been accepted, it is simply not complete yet. */
	for (i = 0; i < r; i++)
		if (__fputc((unsigned char)buf[i], f) == EOF) return WEOF;
	return (wint_t)wc;
}

wint_t fgetwc(FILE *f)
{
	if (!f->wide) f->wide = 1;
	return getwc_core(f, 0);
}

/* Internal: fgetwc() that also reports the byte length consumed.  See
 * getwc_core() above for why anything wants that. */
wint_t __fgetwc_n(FILE *f, int *nbytes)
{
	if (!f->wide) f->wide = 1;
	return getwc_core(f, nbytes);
}

wint_t getwc(FILE *f) { return fgetwc(f); }
wint_t getwchar(void) { return fgetwc(stdin); }

wint_t fputwc(wchar_t wc, FILE *f)
{
	if (!f->wide) f->wide = 1;
	return putwc_core(wc, f);
}

wint_t putwc(wchar_t wc, FILE *f) { return fputwc(wc, f); }
wint_t putwchar(wchar_t wc) { return fputwc(wc, stdout); }

/* ungetwc.html: "push the wide character ... back onto the input
 * stream", one level guaranteed; WEOF is rejected and leaves the stream
 * unchanged; the end-of-file indicator is cleared. */
wint_t ungetwc(wint_t wc, FILE *f)
{
	if (wc == WEOF || !f->readable) return WEOF;
	if (f->nwunget) return WEOF;	/* one level, as guaranteed */
	f->wunget = (wchar_t)wc;
	f->nwunget = 1;
	f->eof = 0;
	if (!f->wide) f->wide = 1;
	return wc;
}

/* fgetws.html: read at most n-1 wide characters, stopping after a
 * <newline> (which is retained) or at end-of-file, then terminate with
 * a null wide character.  A null pointer if end-of-file is reached with
 * nothing read, or on error. */
wchar_t *fgetws(wchar_t *__restrict ws, int n, FILE *__restrict f)
{
	wchar_t *p = ws;

	if (n <= 0) return 0;
	if (!f->wide) f->wide = 1;
	while (n > 1) {
		wint_t c = getwc_core(f, 0);
		if (c == WEOF) {
			if (f->err || p == ws) return 0;
			break;
		}
		*p++ = (wchar_t)c;
		n--;
		if (c == L'\n') break;
	}
	*p = 0;
	return ws;
}

/* fputws.html: write the string, NOT its terminating null wide
 * character.  A non-negative number on success, -1 (EOF) on error. */
int fputws(const wchar_t *__restrict ws, FILE *__restrict f)
{
	if (!f->wide) f->wide = 1;
	for (; *ws; ws++)
		if (putwc_core(*ws, f) == WEOF) return -1;
	return 0;
}

/* fwide.html: set the orientation only if the stream has none; report
 * it either way.  A stream already oriented is never changed, which is
 * why a query (mode == 0) and a losing request are the same code path. */
int fwide(FILE *f, int mode)
{
	if (!f->wide) {
		if (mode > 0) f->wide = 1;
		else if (mode < 0) f->wide = -1;
	}
	return f->wide;
}

// NOLINTEND(misc-include-cleaner)
