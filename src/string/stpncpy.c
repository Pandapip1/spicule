/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>

char *stpncpy(char *__restrict d withtok(writable_span(n)),
	const char *__restrict s, size_t n)
{
	while (n > 0 && *s != '\0') {
		*d = *s;
		d++;
		s++;
		n--;
	}
	memset(d, 0, n);
	return d;
}

// NOLINTEND(misc-include-cleaner)
