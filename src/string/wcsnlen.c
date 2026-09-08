/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>

size_t wcsnlen(const wchar_t *s withtok(readable_elements(n)), size_t n)
{
	const wchar_t *p = wmemchr(s, 0, n);
	return p ? (size_t)(p - s) : n;
}
