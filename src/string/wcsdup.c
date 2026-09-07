/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Byte count is (wcslen+1) * sizeof(wchar_t), not wcslen+1 -- getting
 * that wrong would allocate half the memory needed.
 */
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include "ownership_stubs.h"

withtok(heap_allocated)
wchar_t *wcsdup(const wchar_t *s)
{
	size_t n = (wcslen(s) + 1) * sizeof(wchar_t);
	wchar_t *d = malloc(n);
	if (!d) return 0;
	unsafe_assume_readable_span(s, n);
	return memcpy(d, s, n);
}
