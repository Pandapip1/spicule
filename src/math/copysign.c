/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <math.h>
#include <stdint.h>
#include "ldbl_math.h"

double copysign(double x, double y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	union { double f; uint64_t i; } ux = { x }, uy = { y };
	ux.i = (ux.i & ((uint64_t)-1 >> 1)) | (uy.i & (uint64_t)1 << 63);
	return ux.f;
}

float copysignf(float x, float y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	union { float f; uint32_t i; } ux = { x }, uy = { y };
	ux.i = (ux.i & 0x7fffffff) | (uy.i & 0x80000000u);
	return ux.f;
}

/* spicule is built with three different `long double` bit layouts - see
 * src/math/fabs.c's own fabsl() banner (the sign-flip bug it describes
 * finding applies identically to this function, and the fix below is
 * the same three-way split, reusing src/internal/ldbl_layout_check.c's
 * already-confirmed layouts rather than SPICULE_LDBL_EXTENDED's plain
 * boolean, which conflates x87 and aarch64's binary128).
 *
 * Under tcc, "long double" is really just "double" (8 bytes, no 80-bit
 * extended format), so this is the same bit trick as copysign() above.
 *
 * Under gcc/mingw on i386/x86_64, "long double" is the true 80-bit x87
 * extended format: the sign bit is the top bit of the little-endian
 * uint16_t sign+exponent half that follows the 64-bit mantissa in
 * memory (see __fpclassifyl's comment in fpclassify.c) - matching
 * musl's LDBL_MANT_DIG==64 copysignl().
 *
 * On a real aarch64 build, "long double" is IEEE 754 binary128, whose
 * sign bit lives in the top bit of the HIGH 64-bit word of a hi/lo
 * split (arch/aarch64/src/ld128_convert.c's own layout, reused here). */
long double copysignl(long double x, long double y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
#if !SPICULE_LDBL_EXTENDED
	union { long double f; uint64_t i; } ux = { x }, uy = { y };
	ux.i = (ux.i & ((uint64_t)-1 >> 1)) | (uy.i & (uint64_t)1 << 63);
	return ux.f;
#elif defined(__i386__) || defined(__x86_64__)
	union { long double f; struct { uint64_t m; uint16_t se; } i; } ux = { x }, uy = { y };
	ux.i.se &= 0x7fff;
	ux.i.se |= uy.i.se & 0x8000;
	return ux.f;
#else
	union { long double f; struct { uint64_t lo, hi; } i; } ux = { x }, uy = { y };
	ux.i.hi = (ux.i.hi & 0x7fffffffffffffffULL) | (uy.i.hi & 0x8000000000000000ULL);
	return ux.f;
#endif
}

// NOLINTEND(misc-include-cleaner)
