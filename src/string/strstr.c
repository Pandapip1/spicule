/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include "ownership_stubs.h"

withtok(null_terminated)
char *strstr(const char *h withtok(null_terminated),
	const char *n withtok(null_terminated))
{
	size_t l;
	if (!n[0]) {
		unsafe_assume_string_terminated(h);
		return (char *)h;
	}
	h = strchr(h, *n);
	if (!h || !n[1]) return (char *)h;
	l = strlen(n);
	for (; *h; h++) {
		if (*h == *n && !strncmp(h+1, n+1, l-1)) {
			unsafe_assume_string_terminated(h);
			return (char *)h;
		}
	}
	return 0;
}
