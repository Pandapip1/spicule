/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>

char *stpcpy(char *__restrict d, const char *__restrict s withtok(null_terminated))
{
	while (*s != '\0') {
		*d = *s;
		d++;
		s++;
	}
	*d = '\0';
	return d;
}

// NOLINTEND(misc-include-cleaner)
