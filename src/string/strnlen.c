/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

size_t strnlen(const char *s withtok(readable_span(n)), size_t n)
{
	size_t len = 0;

	while (len < n && s[len])
		len++;
	return len;
}
