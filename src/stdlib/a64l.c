/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char digits[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

long a64l(const char *s)
{
	uint32_t x = 0;
	int i;
	const char *d;
	for (i = 0; i < 6 && s[i]; i++) {
		d = strchr(digits, s[i]);
		if (!d) break;
		x |= (uint32_t)(d - digits) << (6 * i);
	}
	return (long)(int32_t)x;
}

char *l64a(long v)
{
	static char buf[7];
	uint32_t x = (uint32_t)v;
	char *p = buf;
	/* OPEN LINT FINDING (spicule.ValidPointer): digits[x & 63] is always
	 * in bounds (digits has 65 bytes, x & 63 is at most 63). Isolated,
	 * this proves clean; with a64l() above it in the same TU (whose
	 * strchr(digits, ...)/pointer-difference use of digits confuses this
	 * extent proof for the unrelated l64a() below), it does not -- a
	 * checker analysis-order artifact, not a real bound issue. */
	while (x) { *p++ = digits[x & 63]; x /= 64; }
	*p = 0;
	return buf;
}
