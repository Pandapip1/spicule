/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <math.h>
#include <stdint.h>
#include "ldbl_math.h"

double frexp(double x, int *e)
{
	union { double f; uint64_t i; } u = { x };
	int ee = (int)(u.i >> 52 & 0x7ff);

	if (!ee) {
		if (!x) { *e = 0; return x; }
		u.f = x * 0x1p64;
		ee = (int)(u.i >> 52 & 0x7ff);
		*e = ee - 0x3fe - 64;
		u.i &= 0x800fffffffffffffULL;
		u.i |= 0x3fe0000000000000ULL;
		return u.f;
	}
	if (ee == 0x7ff) { *e = 0; return x; }
	*e = ee - 0x3fe;
	u.i &= 0x800fffffffffffffULL;
	u.i |= 0x3fe0000000000000ULL;
	return u.f;
}

float frexpf(float x, int *e)
{
	union { float f; uint32_t i; } u = { x };
	int ee = (int)(u.i >> 23 & 0xff);

	if (!ee) {
		if (!x) { *e = 0; return x; }
		u.f = x * 0x1p30f;
		ee = (int)(u.i >> 23 & 0xff);
		*e = ee - 0x7e - 30;
		u.i &= 0x807fffff;
		u.i |= 0x3f000000;
		return u.f;
	}
	if (ee == 0xff) { *e = 0; return x; }
	*e = ee - 0x7e;
	u.i &= 0x807fffff;
	u.i |= 0x3f000000;
	return u.f;
}

/* spicule is built with three different `long double` bit layouts - see
 * src/math/fabs.c's own fabsl() banner for why this is a three-way
 * split (SPICULE_LDBL_EXTENDED alone, and no architecture check,
 * conflates x87 and aarch64's binary128 -- exactly the bug that
 * banner describes finding, here too before this fix).
 *
 * Under tcc, "long double" is really just "double" (8 bytes, no 80-bit
 * extended format), so this uses the same 64-bit layout as frexp()
 * above.
 *
 * Under gcc/mingw on i386/x86_64, "long double" is the true 80-bit x87
 * extended format, packed as a little-endian uint64_t explicit-integer-
 * bit mantissa followed by a uint16_t sign+exponent half (see
 * __fpclassifyl's comment in fpclassify.c).  The exponent bias there
 * is 0x3fff (not 0x3ff as for a 64-bit double), and because the
 * mantissa's integer bit is explicit (not implicit as in double), a
 * normalized "mantissa in [0.5, 1)" result is encoded by biasing the
 * exponent to 0x3ffe while leaving the mantissa bits themselves
 * untouched - matching musl's LDBL_MANT_DIG==64 frexpl().
 *
 * On a real aarch64 build, "long double" is IEEE 754 binary128, same
 * 0x3fff bias and hi/lo split as __fpclassifyl()'s own aarch64 branch
 * (fpclassify.c), but -- like double, unlike x87 -- an IMPLICIT leading
 * bit, so normalizing to [0.5, 1) only ever touches the exponent field
 * in `hi`, exactly like the tcc/double branch above just at a
 * different bit offset. The 0x1p120L renormalization shift for the
 * subnormal case matches musl's own ld128 frexpl (src/math/frexpl.c
 * there): binary128's subnormal range needs more headroom than
 * double's 64-bit shift to guarantee landing on a normal exponent in
 * one step (112 fraction bits versus double's 52), and 120 is exactly
 * the shift musl already uses and this fetch (see this file's own
 * "adapted, not reconstructed from memory" discipline, src/math/
 * aarch64_math.h's banner) verified rather than re-derived. */
long double frexpl(long double x, int *e)
{
#if !SPICULE_LDBL_EXTENDED
	union { long double f; uint64_t i; } u = { x };
	int ee = (int)(u.i >> 52 & 0x7ff);

	if (!ee) {
		if (!x) { *e = 0; return x; }
		u.f = x * 0x1p64L;
		ee = (int)(u.i >> 52 & 0x7ff);
		*e = ee - 0x3fe - 64;
		u.i &= 0x800fffffffffffffULL;
		u.i |= 0x3fe0000000000000ULL;
		return u.f;
	}
	if (ee == 0x7ff) { *e = 0; return x; }
	*e = ee - 0x3fe;
	u.i &= 0x800fffffffffffffULL;
	u.i |= 0x3fe0000000000000ULL;
	return u.f;
#elif defined(__i386__) || defined(__x86_64__)
	union { long double f; struct { uint64_t m; uint16_t se; } i; } u = { x };
	int ee = u.i.se & 0x7fff;

	if (!ee) {
		if (!x) { *e = 0; return x; }
		u.f = x * 0x1p120L;
		ee = u.i.se & 0x7fff;
		*e = ee - 0x3ffe - 120;
		u.i.se &= 0x8000;
		u.i.se |= 0x3ffe;
		return u.f;
	}
	if (ee == 0x7fff) {
		*e = 0;
		return x;
	}
	*e = ee - 0x3ffe;
	u.i.se &= 0x8000;
	u.i.se |= 0x3ffe;
	return u.f;
#else
	union { long double f; struct { uint64_t lo, hi; } i; } u = { x };
	int ee = (int)(u.i.hi >> 48 & 0x7fff);

	if (!ee) {
		if (!x) { *e = 0; return x; }
		u.f = x * 0x1p120L;
		ee = (int)(u.i.hi >> 48 & 0x7fff);
		*e = ee - 0x3ffe - 120;
		u.i.hi &= 0x8000ffffffffffffULL;
		u.i.hi |= 0x3ffe000000000000ULL;
		return u.f;
	}
	if (ee == 0x7fff) { *e = 0; return x; }
	*e = ee - 0x3ffe;
	u.i.hi &= 0x8000ffffffffffffULL;
	u.i.hi |= 0x3ffe000000000000ULL;
	return u.f;
#endif
}

// NOLINTEND(misc-include-cleaner)
