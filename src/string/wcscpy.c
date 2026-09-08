/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>

wchar_t *wcscpy(wchar_t *__restrict d, const wchar_t *__restrict s withtok(null_terminated))
{
	wchar_t *a = d;

	while (*s) {
		*d = *s;
		d++;
		s++;
	}
	*d = 0;
	return a;
}

// NOLINTEND(misc-include-cleaner)
