/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include <stdlib.h>
#include "libc.h"
#include "ownership_stubs.h"

withtok(heap_allocated)
withtok(null_terminated)
char *strdup(const char *s withtok(null_terminated))
{
	size_t l = strlen(s), bytes;
	char *d;
	if (!__size_add_checked(l, 1, &bytes)) return 0;
	d = malloc(bytes);
	if (!d) return 0;
	memcpy(d, s, bytes);
	__ownership_string_terminated(d);
	return d;
}
