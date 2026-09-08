/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>

size_t wcslen(const wchar_t *s withtok(null_terminated))
{
	const wchar_t *a = s;
	while (*s) s++;
	return s-a;
}
