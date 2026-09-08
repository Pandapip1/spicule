/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>

int wmemcmp(const wchar_t *l withtok(readable_elements(n)),
	const wchar_t *r withtok(readable_elements(n)), size_t n)
{
	while (n && *l == *r) {
		n--;
		l++;
		r++;
	}
	return n ? (int)*l - (int)*r : 0;
}
