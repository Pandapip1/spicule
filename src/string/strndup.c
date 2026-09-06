/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include <stdlib.h>
#include "libc.h"

withtok(heap_allocated)
char *strndup(const char *s, size_t n)
{
	size_t l = strnlen(s, n), bytes;
	char *d;
	if (!__size_add_checked(l, 1, &bytes)) return 0;
	d = malloc(bytes);
	if (!d) return 0;
	memcpy(d, s, l);
	d[l] = 0;
	return d;
}
