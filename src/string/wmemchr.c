/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>

wchar_t *wmemchr(const wchar_t *s withtok(readable_elements(n)), wchar_t c, size_t n)
{
	while (n && *s != c) {
		n--;
		s++;
	}
	return n ? (wchar_t *)s : 0;
}
