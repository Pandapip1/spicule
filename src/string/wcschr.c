/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <wchar.h>
#include "ownership_stubs.h"

withtok(null_terminated)
wchar_t *wcschr(const wchar_t *s withtok(null_terminated), wchar_t c)
{
	wchar_t *result;
	if (!c) {
		result = (wchar_t *)s + wcslen(s);
		unsafe_assume_string_terminated(result);
		return result;
	}
	while (*s && *s != c) s++;
	if (!*s) return 0;
	result = (wchar_t *)s;
	unsafe_assume_string_terminated(result);
	return result;
}
