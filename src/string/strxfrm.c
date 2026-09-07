/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <locale.h>

size_t strxfrm(char *__restrict dest withtok(writable_span(n)),
	const char *__restrict src withtok(null_terminated), size_t n)
{
	size_t l = strlen(src);
	if (n > l) memcpy(dest, src, l+1);
	else if (n) { memcpy(dest, src, n-1); dest[n-1] = 0; }
	return l;
}

size_t strxfrm_l(char *__restrict dest withtok(writable_span(n)),
	const char *__restrict src withtok(null_terminated), size_t n, locale_t loc)
{
	(void)loc;
	return strxfrm(dest, src, n);
}

// NOLINTEND(misc-include-cleaner)
