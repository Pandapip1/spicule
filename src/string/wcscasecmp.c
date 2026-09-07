/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * towlower() (src/ctype/towlower.c) folds only 'A'-'Z'; this tree's single
 * C/POSIX locale is ASCII-only, so every code point from U+0080 up,
 * including lone surrogate halves, folds to itself. That is deliberate,
 * not a gap, and keeps unit-by-unit UTF-16 comparison well defined.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>
#include <wctype.h>
#include <locale.h>

int wcscasecmp(const wchar_t *l, const wchar_t *r)
{
	while (*l && *r && (*l == *r || towlower(*l) == towlower(*r))) {
		l++;
		r++;
	}
	return (int)towlower(*l) - (int)towlower(*r);
}

int wcsncasecmp(const wchar_t *l, const wchar_t *r, size_t n)
{
	if (!n) return 0;
	n--;
	while (*l && *r && n && (*l == *r || towlower(*l) == towlower(*r))) {
		l++;
		r++;
		n--;
	}
	return (int)towlower(*l) - (int)towlower(*r);
}

int wcscasecmp_l(const wchar_t *l, const wchar_t *r, locale_t loc)
{
	(void)loc;
	return wcscasecmp(l, r);
}

int wcsncasecmp_l(const wchar_t *l, const wchar_t *r, size_t n, locale_t loc)
{
	(void)loc;
	return wcsncasecmp(l, r, n);
}

// NOLINTEND(misc-include-cleaner)
