/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>

wchar_t *wcscat(wchar_t *__restrict dest, const wchar_t *__restrict src)
{
	wcscpy(dest + wcslen(dest), src);
	return dest;
}

// NOLINTEND(misc-include-cleaner)
