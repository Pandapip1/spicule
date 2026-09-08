/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>

wchar_t *wmemset(wchar_t *d withtok(writable_elements(n)), wchar_t c, size_t n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	wchar_t *ret = d;
	for (size_t i = 0; i < n; i++) d[i] = c;
	return ret;
}
