/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* The stateless conversions, on top of the restartable ones.  Because a
 * non-BMP character is two wchar_t, mbtowc cannot return it in one
 * wchar_t: it returns the high surrogate and a byte count of 4, and the
 * low surrogate is lost, which is the best a 16-bit wchar_t allows. */
#include <stdlib.h>
#include <wchar.h>
#include <errno.h>
#include <string.h>

int mblen(const char *s, size_t n) { return mbtowc(0, s, n); }

int mbtowc(wchar_t *__restrict wc, const char *__restrict s, size_t n)
{
	mbstate_t st;
	size_t r;
	wchar_t dummy;
	if (!s) return 0;
	memset(&st, 0, sizeof st);
	r = mbrtowc(wc ? wc : &dummy, s, n, &st);
	if (r == (size_t)-2) { errno = EILSEQ; return -1; }
	if (r == (size_t)-1) return -1;
	return (int)r;
}

int wctomb(char *s, wchar_t wc)
{
	mbstate_t st;
	size_t r;
	if (!s) return 0;
	memset(&st, 0, sizeof st);
	r = wcrtomb(s, wc, &st);
	if (r == 0) { errno = EILSEQ; return -1; }  /* lone high surrogate */
	return r == (size_t)-1 ? -1 : (int)r;
}

size_t mbstowcs(wchar_t *__restrict ws, const char *__restrict s, size_t n)
{
	mbstate_t st;
	const char *src = s;
	memset(&st, 0, sizeof st);
	return mbsrtowcs(ws, &src, n, &st);
}

size_t wcstombs(char *__restrict s, const wchar_t *__restrict ws, size_t n)
{
	mbstate_t st;
	const wchar_t *src = ws;
	memset(&st, 0, sizeof st);
	return wcsrtombs(s, &src, n, &st);
}

// NOLINTEND(misc-include-cleaner)
