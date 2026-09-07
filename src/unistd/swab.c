/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * swab.html: negative nbytes does nothing; odd nbytes copies and swaps
 * nbytes-1 bytes and leaves the last byte's disposition unspecified
 * (copied through unswapped here, the least surprising choice).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>

void swab(const void *__restrict src, void *__restrict dest, ssize_t nbytes) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const unsigned char *s = src;
	unsigned char *d = dest;
	ssize_t i;

	if (nbytes <= 0) return;
	for (i = 0; i + 1 < nbytes; i += 2) {
		d[i] = s[i + 1];
		d[i + 1] = s[i];
	}
	if (i < nbytes) d[i] = s[i];
}

// NOLINTEND(misc-include-cleaner)
