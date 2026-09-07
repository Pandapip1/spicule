/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <string.h>
#include <strings.h>
#include "ownership_stubs.h"

withtok(null_terminated)
char *strcasestr(const char *h withtok(null_terminated),
	const char *n withtok(null_terminated))
{
	size_t l = strlen(n);
	for (; *h; h++) if (!strncasecmp(h, n, l)) {
		unsafe_assume_string_terminated(h);
		return (char *)h;
	}
	return 0;
}
