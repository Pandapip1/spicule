/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <math.h>
#include <stdint.h>
#include "ldbl_math.h"

double fabs(double x)
{
	union { double f; uint64_t i; } u = { x };
	u.i &= (uint64_t)-1 >> 1;
	return u.f;
}

float fabsf(float x)
{
	union { float f; uint32_t i; } u = { x };
	u.i &= 0x7fffffff;
	return u.f;
}

/* spicule is built with three different `long double` bit layouts - see
 * the SPICULE_LDBL_EXTENDED comment in src/math/ldbl_math.h and, for the
 * three-way split used here specifically, src/internal/
 * ldbl_layout_check.c's own banner (that file's __verify_ldbl_layout()
 * is the startup canary confirming exactly this assumption, and this
 * function now matches its three branches one for one rather than
 * SPICULE_LDBL_EXTENDED's plain boolean, which conflates the second and
 * third of them -- see below).
 *
 * Under tcc, "long double" is really just "double" (8 bytes, no 80-bit
 * extended format), so this is the same bit trick as fabs() above
 * (using a wider layout a native long double would need would read/
 * write past the actual object).
 *
 * Under gcc/mingw on i386/x86_64, "long double" is the true 80-bit x87
 * extended format: the sign bit is the top bit of the little-endian
 * uint16_t sign+exponent half that follows the 64-bit mantissa in
 * memory (see __fpclassifyl's comment in fpclassify.c) - matching
 * musl's LDBL_MANT_DIG==64 fabsl().
 *
 * On a real aarch64 build, "long double" is IEEE 754 binary128
 * ("quad"): SPICULE_LDBL_EXTENDED is ALSO 1 there (__SIZEOF_LONG_DOUBLE__
 * == 16), but the layout is not x87's -- treating it as x87 would mask
 * bit 63 of the LOW 64-bit word (the low fraction bits, a near no-op)
 * and never touch the sign bit at all, which actually lives in the top
 * bit of the HIGH 64-bit word (found exactly this way: fabsl(-3.0L)
 * returning a value whose sign bit was still set, traced to this
 * branch never being reached on this arch). The hi/lo split below is
 * arch/aarch64/src/ld128_convert.c's own confirmed layout, reused
 * rather than re-derived. */
long double fabsl(long double x)
{
#if !SPICULE_LDBL_EXTENDED
	union { long double f; uint64_t i; } u = { x };
	u.i &= (uint64_t)-1 >> 1;
	return u.f;
#elif defined(__i386__) || defined(__x86_64__)
	union { long double f; struct { uint64_t m; uint16_t se; } i; } u = { x };
	u.i.se &= 0x7fff;
	return u.f;
#else
	union { long double f; struct { uint64_t lo, hi; } i; } u = { x };
	u.i.hi &= 0x7fffffffffffffffULL;
	return u.f;
#endif
}

// NOLINTEND(misc-include-cleaner)
