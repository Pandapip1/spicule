/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <math.h>
#include <stdint.h>
#include "ldbl_math.h"

/* Rather than shift the sign/exponent bits off the top -- which is
 * exactly the "does this discard set bits" pattern
 * -fsanitize=unsigned-shift-base exists to flag, even though it is
 * well-defined modular arithmetic in C -- mask them off instead.  Same
 * bits examined, same result, and nothing here looks like an overflow
 * to begin with. */
int __fpclassify(double x)
{
	union { double f; uint64_t i; } u = { x };
	int e = (int)(u.i >> 52 & 0x7ff);
	if (!e) return u.i & 0x7fffffffffffffffULL ? FP_SUBNORMAL : FP_ZERO;
	if (e == 0x7ff) return u.i & 0xfffffffffffffULL ? FP_NAN : FP_INFINITE;
	return FP_NORMAL;
}

int __fpclassifyf(float x)
{
	union { float f; uint32_t i; } u = { x };
	int e = (int)(u.i >> 23 & 0xff);
	if (!e) return u.i & 0x7fffffffUL ? FP_SUBNORMAL : FP_ZERO;
	if (e == 0xff) return u.i & 0x7fffffUL ? FP_NAN : FP_INFINITE;
	return FP_NORMAL;
}

/* spicule is built with three different `long double` bit layouts - see
 * src/math/fabs.c's own fabsl() banner for the three-way split used
 * here (SPICULE_LDBL_EXTENDED alone conflates x87 and aarch64's
 * binary128; this function now matches src/internal/
 * ldbl_layout_check.c's already-confirmed three layouts one for one).
 *
 * Under tcc, "long double" is really just "double" (8 bytes, no 80-bit
 * extended format), so this classifies the same 64-bit layout as
 * __fpclassify() above.
 *
 * Under gcc/mingw on i386/x86_64, "long double" is the true 80-bit x87
 * extended format: 1 sign bit + 15 exponent bits, packed in memory as a
 * little-endian uint64_t explicit-integer-bit mantissa followed by a
 * uint16_t sign+exponent half, occupying the low 10 bytes of a 12- or
 * 16-byte object.  Layout and classification here match musl's
 * LDBL_MANT_DIG==64 union-ldshape implementation (src/internal/libm.h,
 * src/math/__fpclassifyl.c): a missing explicit integer bit (msb of
 * the mantissa) with a nonzero exponent means the encoding is
 * unsupported/invalid on real x87 hardware and is reported as NaN.
 *
 * On a real aarch64 build, "long double" is IEEE 754 binary128: 1 sign
 * bit + 15 exponent bits + 112 fraction bits (IMPLICIT leading bit,
 * unlike x87's explicit one -- there is no separate "msb of the
 * mantissa" case to check here), split hi/lo the same way
 * arch/aarch64/src/ld128_convert.c's own conversions do: `hi` holds
 * [sign:1][exponent:15][fraction, high 48 bits], `lo` holds the low 64
 * fraction bits. */
int __fpclassifyl(long double x)
{
#if !SPICULE_LDBL_EXTENDED
	union { long double f; uint64_t i; } u = { x };
	int e = (int)(u.i >> 52 & 0x7ff);
	if (!e) return u.i & 0x7fffffffffffffffULL ? FP_SUBNORMAL : FP_ZERO;
	if (e == 0x7ff) return u.i & 0xfffffffffffffULL ? FP_NAN : FP_INFINITE;
	return FP_NORMAL;
#elif defined(__i386__) || defined(__x86_64__)
	union { long double f; struct { uint64_t m; uint16_t se; } i; } u = { x };
	int e = u.i.se & 0x7fff;
	int msb = (int)(u.i.m >> 63);
	if (!e && !msb) return u.i.m ? FP_SUBNORMAL : FP_ZERO;
	if (e == 0x7fff) return (u.i.m & 0x7fffffffffffffffULL) ? FP_NAN : (msb ? FP_INFINITE : FP_NAN);
	if (!msb) return FP_NAN;
	return FP_NORMAL;
#else
	union { long double f; struct { uint64_t lo, hi; } i; } u = { x };
	int e = (int)(u.i.hi >> 48 & 0x7fff);
	uint64_t frac_hi = u.i.hi & 0xffffffffffffULL;
	if (!e) return (frac_hi | u.i.lo) ? FP_SUBNORMAL : FP_ZERO;
	if (e == 0x7fff) return (frac_hi | u.i.lo) ? FP_NAN : FP_INFINITE;
	return FP_NORMAL;
#endif
}

int __signbit(double x)
{
	union { double f; uint64_t i; } u = { x };
	return (int)(u.i >> 63);
}

int __signbitf(float x)
{
	union { float f; uint32_t i; } u = { x };
	return (int)(u.i >> 31);
}

/* same three-way split as __fpclassifyl() above: under the true 80-bit
 * format the sign bit lives in the top bit of the sign+exponent
 * halfword; under aarch64's real binary128 it lives in the top bit of
 * the HIGH 64-bit word of a hi/lo split, not bit 63 of an 8-byte
 * object (SPICULE_LDBL_EXTENDED alone cannot tell those two apart -- see
 * src/math/fabs.c's own fabsl() banner). */
int __signbitl(long double x)
{
#if !SPICULE_LDBL_EXTENDED
	union { long double f; uint64_t i; } u = { x };
	return (int)(u.i >> 63);
#elif defined(__i386__) || defined(__x86_64__)
	union { long double f; struct { uint64_t m; uint16_t se; } i; } u = { x };
	return u.i.se >> 15;
#else
	union { long double f; struct { uint64_t lo, hi; } i; } u = { x };
	return (int)(u.i.hi >> 63);
#endif
}

// NOLINTEND(misc-include-cleaner)
