/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include "libc.h"
size_t wcslen_(const WCHAR *s)
{
	size_t n = 0;
	while (s[n]) n++;
	return n;
}

// NOLINTEND(misc-include-cleaner)
