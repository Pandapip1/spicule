/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>
#include <string.h>

wchar_t *wmemcpy(
	wchar_t *__restrict d withtok(writable_elements(n)),
	const wchar_t *__restrict s withtok(readable_elements(n)), size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) d[i] = s[i];
	return d;
}

// NOLINTEND(misc-include-cleaner)
