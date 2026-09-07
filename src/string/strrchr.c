/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <string.h>
#include "ownership_stubs.h"

withtok(null_terminated)
char *strrchr(const char *s withtok(null_terminated), int c)
{
	char *result = memrchr(s, c, strlen(s)+1);
	if (result) unsafe_assume_string_terminated(result);
	return result;
}
