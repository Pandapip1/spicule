/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Locale is always C/POSIX, collating in code-unit order (wcscoll.c), so
 * the identity transform trivially satisfies wcscmp(xfrm(a), xfrm(b)) ==
 * wcscoll(a, b) -- deliberate, not an unwritten stub. The return value is
 * the full transformed length even when it doesn't fit, which is what
 * lets a caller null dest to query the size (only valid when n is 0).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>
#include <locale.h>

size_t wcsxfrm(wchar_t *__restrict dest withtok(writable_elements(n)),
	const wchar_t *__restrict src, size_t n)
{
	size_t l = wcslen(src);
	if (n > l) {
		for (size_t i = 0; i <= l; i++) dest[i] = src[i];
	} else if (n) {
		for (size_t i = 0; i + 1 < n; i++) dest[i] = src[i];
		dest[n - 1] = 0;
	}
	return l;
}

size_t wcsxfrm_l(wchar_t *__restrict dest withtok(writable_elements(n)),
	const wchar_t *__restrict src, size_t n, locale_t loc)
{
	(void)loc;
	return wcsxfrm(dest, src, n);
}

// NOLINTEND(misc-include-cleaner)
