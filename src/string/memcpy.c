/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdint.h>

void *memcpy(void *__restrict dest withtok(writable_span(n))
	withtok(disjoint_span(src, n)),
	const void *__restrict src withtok(readable_span(n)), size_t n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char *d = dest;
	const unsigned char *s = src;

	if (n >= 4*sizeof(size_t) && ((uintptr_t)d & (sizeof(size_t)-1)) == ((uintptr_t)s & (sizeof(size_t)-1))) {
		size_t align_bytes = (sizeof(size_t) -
			((uintptr_t)d & (sizeof(size_t)-1))) & (sizeof(size_t)-1);
		for (size_t i = 0; i < align_bytes; i++) d[i] = s[i];
		d += align_bytes;
		s += align_bytes;
		n -= align_bytes;
		for (; n >= sizeof(size_t);
		     n -= sizeof(size_t), d += sizeof(size_t), s += sizeof(size_t))
			*(size_t *)d = *(const size_t *)s;
	}
	for (size_t i = 0; i < n; i++) d[i] = s[i];
	return dest;
}

// NOLINTEND(misc-include-cleaner)
