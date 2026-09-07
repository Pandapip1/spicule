/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <ctype.h>

__wraps int isalpha(int c)
{
	return ((unsigned)c|32)-'a' < 26;
}

int isalpha_l(int c, locale_t loc)
{
	(void)loc;
	return isalpha(c);
}

// NOLINTEND(misc-include-cleaner)
