/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <string.h>

void *memrchr(const void *m withtok(readable_span(n)), int c, size_t n)
{
	const unsigned char *s = m;
	c = (unsigned char)c;
	while (n) { n--; if (s[n] == c) return (void *)(s+n); }
	return 0;
}
