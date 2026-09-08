/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>

int wcscmp(const wchar_t *l withtok(null_terminated),
	const wchar_t *r withtok(null_terminated))
{
	while (*l == *r && *l) {
		l++;
		r++;
	}
	return (int)*l - (int)*r;
}
