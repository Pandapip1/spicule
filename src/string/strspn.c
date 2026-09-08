/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*sizeof *(a))] op (size_t)1<<((size_t)(b)%(8*sizeof *(a))))

size_t strspn(const char *s withtok(null_terminated),
	const char *c withtok(null_terminated))
{
	size_t byteset[32/sizeof(size_t)];
	size_t n = 0;

	if (!c[0]) return 0;
	if (!c[1]) {
		for (; *s == *c; s++) n++;
		return n;
	}
	memset(byteset, 0, sizeof byteset);
	while (*c) {
		BITOP(byteset, *(unsigned char *)c, |=);
		c++;
	}
	for (; *s && BITOP(byteset, *(unsigned char *)s, &); s++) n++;
	return n;
}
