/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <string.h>
#include "ownership_stubs.h"

size_t strlcpy(char *restrict d, const char *restrict s, size_t n)
{
	size_t l = strlen(s);
	if (n) {
		size_t c = l < n-1 ? l : n-1;
		unsafe_assume_writable_span(d, c);
		memcpy(d, s, c);
		d[c] = 0;
	}
	return l;
}
