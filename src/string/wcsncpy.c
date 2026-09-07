/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>

wchar_t *wcsncpy(wchar_t *__restrict d, const wchar_t *__restrict s, size_t n)
{
	wchar_t *a = d;
	while (n && *s) {
		*d = *s;
		d++;
		s++;
		n--;
	}
	wmemset(d, 0, n);
	return a;
}

// NOLINTEND(misc-include-cleaner)
