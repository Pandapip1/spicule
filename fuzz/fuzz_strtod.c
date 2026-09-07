/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * strtod/strtof/strtol, differentially against the host C library.
 *
 * This links the real src/stdlib/strtod.c and src/stdlib/strtol.c -- not a
 * copy of them.  A sanitizer alone would miss the interesting half of what
 * goes wrong in a number parser: strtod("1e442") answering NaN is a wrong
 * result, not a memory error.  So every input is also parsed by glibc
 * (through fuzz/host_oracle.c, which reaches the real strtod via dlsym)
 * and the two answers are compared bit for bit.
 *
 * Differences that are legitimate rather than bugs are listed in
 * differs_legitimately() below, with the reason for each.
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern double host_strtod(const char *, size_t *, int *);
extern float host_strtof(const char *, size_t *, int *);
extern long long host_strtoll(const char *, size_t *, int, int *);
extern void oracle_mismatch_d(const char *, const char *, double, double);
extern void oracle_mismatch_i(const char *, const char *, long long, long long);

static int same_double(double a, double b)
{
	unsigned long long x, y;
	if (a != a && b != b) return 1;            /* both NaN */
	memcpy(&x, &a, 8); memcpy(&y, &b, 8);
	return x == y;
}

static int same_float(float a, float b)
{
	unsigned int x, y;
	if (a != a && b != b) return 1;
	memcpy(&x, &a, 4); memcpy(&y, &b, 4);
	return x == y;
}

/*
 * Excluded from the value comparison, with reasons:
 *  - hex floats ("0x1p3"): the rounding of a hex significand longer than
 *    the mantissa is where the two differ, and it is a separate question
 *    from decimal parsing; test/strto.c covers the ordinary cases.
 *  - "nan(chars)": the payload between the parentheses is implementation
 *    defined, so the bit patterns are allowed to differ.
 * "inf"/"infinity" are NOT excluded -- those must agree.
 */
static int differs_legitimately(const char *s)
{
	const char *p = s;
	while (*p == ' ' || (*p >= 9 && *p <= 13)) p++;
	if (*p == '+' || *p == '-') p++;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) return 1;
	if ((p[0] == 'n' || p[0] == 'N') && strchr(p, '(')) return 1;
	return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char buf[512];
	size_t n = size < sizeof buf - 1 ? size : sizeof buf - 1;
	char *end;
	size_t hoff;
	int herr, i;

	if (!n) return 0;
	memcpy(buf, data, n);
	buf[n] = 0;
	if (memchr(buf, 0, n)) return 0;       /* embedded NUL: not one string */

	/* --- strtod ------------------------------------------------------- */
	{
		double mine, theirs;
		errno = 0;
		mine = strtod(buf, &end);
		i = errno;
		theirs = host_strtod(buf, &hoff, &herr);
		if (!differs_legitimately(buf)) {
			if (!same_double(mine, theirs))
				oracle_mismatch_d("strtod value", buf, mine, theirs);
			if ((size_t)(end - buf) != hoff)
				oracle_mismatch_i("strtod endptr offset", buf,
				                  (long long)(end - buf), (long long)hoff);
			if ((i == ERANGE) != (herr == ERANGE))
				oracle_mismatch_i("strtod errno==ERANGE", buf,
				                  i == ERANGE, herr == ERANGE);
		}
	}

	/* --- strtof ------------------------------------------------------- */
	{
		float mine = strtof(buf, &end), theirs = host_strtof(buf, &hoff, &herr);
		if (!differs_legitimately(buf) && !same_float(mine, theirs))
			oracle_mismatch_d("strtof value", buf, (double)mine, (double)theirs);
	}

	/* --- strtold: no oracle.  The host's long double is 80-bit and the
	 * NT target's is 64-bit, so the two are not comparable; this is a
	 * crash/UB check only. -------------------------------------------- */
	(void)strtold(buf, &end);

	/* --- strtoll, in every base ---------------------------------------
	 * strtoll and not strtol: spicule targets LLP64, so its LONG_MAX is
	 * 0x7fffffff (arch/x86_64/bits/limits.h), while a native build gives
	 * `long` 64 bits.  spicule's strtol therefore saturates at 2^31-1 here
	 * and glibc's does not -- an ABI difference, not a defect, and not
	 * something a native differential test can say anything about.
	 * LLONG_MAX is the same on both, so strtoll is comparable. */
	for (i = 0; i <= 36; i++) {
		long long mine, theirs;
		if (i == 1) continue;
		mine = strtoll(buf, &end, i);
		theirs = host_strtoll(buf, &hoff, i, &herr);
		if (mine != theirs)
			oracle_mismatch_i("strtoll value", buf, mine, theirs);
		if ((size_t)(end - buf) != hoff)
			oracle_mismatch_i("strtoll endptr offset", buf,
			                  (long long)(end - buf), (long long)hoff);
	}
	return 0;
}
