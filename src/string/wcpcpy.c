/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>

wchar_t *wcpcpy(wchar_t *__restrict d, const wchar_t *__restrict s withtok(null_terminated))
{
	while (*s != L'\0') {
		*d = *s;
		d++;
		s++;
	}
	*d = L'\0';
	return d;
}

wchar_t *wcpncpy(wchar_t *__restrict d withtok(writable_elements(n)),
	const wchar_t *__restrict s, size_t n)
{
	while (n > 0 && *s != L'\0') {
		*d = *s;
		d++;
		s++;
		n--;
	}
	wmemset(d, 0, n);
	return d;
}

// NOLINTEND(misc-include-cleaner)
