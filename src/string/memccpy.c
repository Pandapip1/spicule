/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>

void *memccpy(void *__restrict dest, const void *__restrict src, int c, size_t n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char *d = dest;
	const unsigned char *s = src;
	c = (unsigned char)c;
	for (; n; n--) {
		unsigned char byte = *s;
		s++;
		*d = byte;
		d++;
		if (byte == c) return d;
	}
	return 0;
}

// NOLINTEND(misc-include-cleaner)
