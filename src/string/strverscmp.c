/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <ctype.h>
#include <string.h>

int strverscmp(const char *l0 withtok(null_terminated),
	const char *r0 withtok(null_terminated))
{
	const unsigned char *l = (const void *)l0;
	const unsigned char *r = (const void *)r0;
	size_t i, dp, j;
	int z = 1;

	/* Find maximal matching prefix and track its maximal digit
	 * suffix and whether those digits are all zeros. */
	for (dp = i = 0; l[i] == r[i]; i++) {
		int c = l[i];
		if (!c) return 0;
		if (!isdigit(c)) {
			dp = i+1;
			z = 1;
		} else if (c != '0') z = 0;
	}

	if (l[dp] != '0' && r[dp] != '0') {
		/* If we're not looking at a digit sequence that began
		 * with a zero, longest digit string is greater. */
		for (j = i; isdigit(l[j]); j++)
			if (!isdigit(r[j])) return 1;
		if (isdigit(r[j])) return -1;
	} else if (z && dp < i && (isdigit(l[i]) || isdigit(r[i]))) {
		/* Otherwise, if common prefix of digit sequence is
		 * all zeros, digits order less than non-digits. */
		return (unsigned char)(l[i]-'0') - (unsigned char)(r[i]-'0');
	}

	return l[i] - r[i];
}
