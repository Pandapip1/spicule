/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <string.h>

void explicit_bzero(void *d withtok(writable_span(n)), size_t n)
{
	volatile unsigned char *p = d;
	for (size_t i = 0; i < n; i++) p[i] = 0;
}
