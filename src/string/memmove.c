/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include <stdint.h>
#include <features.h>
#include "ownership_stubs.h"

/* If the n-byte spans [a, a+n) and [b, b+n) do NOT overlap, record that fact
 * for the ownership analyzer and report true; otherwise report false. */
__wraps static int mark_if_disjoint(void *a, const void *b, size_t n)
{
	uintptr_t distance = (uintptr_t)b - (uintptr_t)a;
	if (distance - n > -2*n) return 0;
	unsafe_assume_disjoint_span(a, b, n);
	return 1;
}

__wraps void *memmove(void *dest withtok(writable_span(n)),
	const void *src withtok(readable_span(n)), size_t n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char *d = dest;
	const unsigned char *s = src;

	if (d == s) return d;
	if (mark_if_disjoint(d, s, n)) return memcpy(d, s, n);
	if ((uintptr_t)d < (uintptr_t)s) {
		for (size_t i = 0; i < n; i++) d[i] = s[i];
	} else {
		for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1];
	}
	return dest;
}
