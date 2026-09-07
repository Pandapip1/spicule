/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wcstok()'s third `wchar_t **restrict ptr` argument is not an spicule
 * extension -- it is wcstok's actual POSIX/C99 signature, mirroring
 * strtok_r() rather than strtok(). Don't "fix" it to two arguments.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>

wchar_t *wcstok(wchar_t *__restrict s, const wchar_t *__restrict sep, wchar_t **__restrict p)
{
	if (!s) {
		s = *p;
		if (!s) return 0;
	}
	s += wcsspn(s, sep);
	if (!*s) return *p = 0;
	*p = s + wcscspn(s, sep);
	if (**p) *(*p)++ = 0;
	else *p = 0;
	return s;
}

// NOLINTEND(misc-include-cleaner)
