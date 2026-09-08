/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

void *memchr(const void *src withtok(readable_span(n)), int c, size_t n)
{
	const unsigned char *s = src;
	c = (unsigned char)c;
	while (n > 0 && *s != c) {
		s++;
		n--;
	}
	return n ? (void *)s : 0;
}
