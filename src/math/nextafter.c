/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* nextafter.html/nexttoward.html: the adjacent representable value of
 * x towards y. Implemented via integer bit-twiddling on the IEEE
 * representation, the same style as src/math/copysign.c/fabs.c: for a
 * nonzero finite x, the raw sign-magnitude bit pattern, read as an
 * unsigned integer with the sign bit masked off, is monotonic in the
 * magnitude of x -- so "one step towards +-infinity" is exactly "the
 * magnitude bits +-1", independent of exponent/mantissa boundaries
 * (each of which the +-1 carries/borrows through correctly, including
 * normal<->subnormal). That holds for the formats whose leading
 * significand bit is implicit -- float and double here; x87 extended
 * spells that bit out, which breaks the monotonicity and is handled
 * explicitly in nextafterl. x==0 is handled separately (there is no "old
 * magnitude" to step from); the result is then classified by comparing
 * the old and new exponent fields for the overflow-to-infinity and
 * underflow-to-subnormal range-error cases. */
#include <math.h>
#include <fenv.h>
#include <stdint.h>
#include "ldbl_math.h"

double nextafter(double x, double y)
{
	union { double f; uint64_t i; } ux = { x }, uy = { y };
	uint64_t ai;
	unsigned oldexp, newexp;

	if (x != x || y != y) return x + y;
	if (x == y) return y;

	if (x == 0.0) {
		ux.i = (uy.i & ((uint64_t)1 << 63)) | (uint64_t)1;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	oldexp = (unsigned)(ux.i >> 52 & 0x7ff);
	if ((x > 0.0) ? (y > x) : (y < x)) ai = ux.i + 1;
	else ai = ux.i - 1;
	newexp = (unsigned)(ai >> 52 & 0x7ff);

	if (newexp == 0x7ff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	ux.i = ai;
	return ux.f;
}

float nextafterf(float x, float y)
{
	union { float f; uint32_t i; } ux = { x }, uy = { y };
	uint32_t ai;
	unsigned oldexp, newexp;

	if (x != x || y != y) return x + y;
	if (x == y) return y;

	if (x == 0.0f) {
		ux.i = (uy.i & 0x80000000u) | 1u;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	oldexp = (ux.i >> 23) & 0xff;
	if ((x > 0.0f) ? (y > x) : (y < x)) ai = ux.i + 1;
	else ai = ux.i - 1;
	newexp = (ai >> 23) & 0xff;

	if (newexp == 0xff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	ux.i = ai;
	return ux.f;
}

/* spicule is built with three different long double bit layouts - see
 * src/math/fabs.c's own fabsl() banner (that function found this exact
 * class of bug: SPICULE_LDBL_EXTENDED's plain boolean conflates x87 and
 * aarch64's binary128, which are both "wider than double" but have
 * completely different bit layouts) and src/internal/
 * ldbl_layout_check.c for the confirmed three-way split this function
 * now matches one for one, rather than SPICULE_LDBL_EXTENDED's boolean.
 *
 * Under tcc, "long double" is really just "double" (8 bytes), so this
 * is the same 64-bit layout as nextafter() above.
 *
 * Under gcc/mingw on i386/x86_64, "long double" is the true 80-bit x87
 * extended format: a 64-bit explicit mantissa followed by a 16-bit
 * sign+exponent half (see __fpclassifyl's comment in fpclassify.c).
 * The step is not a plain +-1 on the pair. Unlike float and double,
 * the 80-bit format states its leading significand bit rather than
 * implying it, so a normal number's mantissa runs over
 * [2^63, 2^64) and never below: the pattern read as one wide integer
 * is not monotonic in magnitude across an exponent boundary, and the
 * step has to put the mantissa back at the right end of that range
 * itself. Going up, the successor of (e, 2^64-1) is (e+1, 2^63);
 * going down, the predecessor of (e, 2^63) is (e-1, 2^64-1). The one
 * asymmetry is at the bottom: e == 0 denotes the subnormals, which
 * share e == 1's scale, so the predecessor of (1, 2^63) is
 * (0, 2^63-1) -- exponent down, mantissa not wrapped -- and going the
 * other way (0, 2^63-1)'s successor is (1, 2^63).
 *
 * Both directions collapse to a test on the mantissa's low 63 bits
 * (LDBL_M_LOW63 below), which are all set at exactly the two mantissas
 * that have no successor at their own exponent -- 2^64-1, and the
 * largest subnormal 2^63-1 -- and all clear at exactly the one that
 * has no predecessor at its own exponent, the least normal 2^63 (m ==
 * 0 is zero, which x == 0 has already taken). So stepping up from
 * either of the first two gives (e+1, 2^63), and stepping down from
 * the third gives (e-1, 2^64-1), or (0, 2^63-1) when that new exponent
 * is 0 and the subnormal end is what is wanted. Everything else is
 * m+-1 at a fixed exponent. It is done this way rather than by
 * treating the pair as one wide integer because tcc has no 96-bit
 * integer type to do that with, and it would not be portable
 * regardless.
 *
 * On a real aarch64 build, "long double" is IEEE 754 binary128
 * ("quad"): SPICULE_LDBL_EXTENDED is ALSO 1 there (__SIZEOF_LONG_DOUBLE__
 * == 16), but the layout is not x87's explicit-leading-bit format --
 * binary128 has an IMPLICIT leading bit, exactly like float/double
 * above, so the "step the magnitude bits by +-1, monotonic across
 * exponent boundaries" argument from nextafter()/nextafterf() applies
 * here too, just over a 128-bit magnitude split into two 64-bit words
 * (arch/aarch64/src/ld128_convert.c's own confirmed layout: low word =
 * low 64 bits of the 112-bit fraction, high word =
 * [sign:1][exponent:15][fraction, high 48 bits]) rather than one
 * native integer -- a manual two-limb increment/decrement, carrying/
 * borrowing between the words exactly like a two-word bignum. */
#define LDBL_M_LOW63 ((((uint64_t)1 << 63) - 1))

long double nextafterl(long double x, long double y)
{
#if !SPICULE_LDBL_EXTENDED
	union { long double f; uint64_t i; } ux = { x }, uy = { y };
	uint64_t ai;
	unsigned oldexp, newexp;

	if (x != x || y != y) return x + y;
	if (x == y) return y;

	if (x == 0.0L) {
		ux.i = (uy.i & ((uint64_t)1 << 63)) | (uint64_t)1;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	oldexp = (unsigned)(ux.i >> 52 & 0x7ff);
	if ((x > 0.0L) ? (y > x) : (y < x)) ai = ux.i + 1;
	else ai = ux.i - 1;
	newexp = (unsigned)(ai >> 52 & 0x7ff);

	if (newexp == 0x7ff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	ux.i = ai;
	return ux.f;
#elif defined(__i386__) || defined(__x86_64__)
	union { long double f; struct { uint64_t m; uint16_t se; } i; } ux = { x }, uy = { y };
	unsigned oldexp, newexp, e;
	int away;

	if (x != x || y != y) return x + y;
	if (x == y) return y;

	if (x == 0.0L) {
		ux.i.se = (uint16_t)(uy.i.se & 0x8000);
		ux.i.m = 1;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	oldexp = ux.i.se & 0x7fff;
	away = (x > 0.0L) ? (y > x) : (y < x);
	if (away) {
		if ((ux.i.m & LDBL_M_LOW63) == LDBL_M_LOW63) {
			e = (unsigned)(oldexp + 1) & 0x7fff;
			ux.i.se = (uint16_t)((ux.i.se & 0x8000) | e);
			ux.i.m = (uint64_t)1 << 63;
		} else {
			ux.i.m++;
		}
	} else {
		if ((ux.i.m & LDBL_M_LOW63) == 0) {
			e = (unsigned)(oldexp - 1) & 0x7fff;
			ux.i.se = (uint16_t)((ux.i.se & 0x8000) | e);
			ux.i.m = e ? (uint64_t)-1 : LDBL_M_LOW63;
		} else {
			ux.i.m--;
		}
	}
	newexp = ux.i.se & 0x7fff;

	if (newexp == 0x7fff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	return ux.f;
#else
	/* aarch64: real IEEE 754 binary128 -- see this function's own
	 * banner above for why the magnitude-bits-are-monotonic argument
	 * applies here (implicit leading bit, like float/double) and why
	 * the step is a manual two-limb (hi/lo) increment/decrement rather
	 * than the single-word +-1 those use. */
	union { long double f; struct { uint64_t lo, hi; } i; } ux = { x }, uy = { y };
	uint64_t mhi, mlo;
	unsigned oldexp, newexp;

	if (x != x || y != y) return x + y;
	if (x == y) return y;

	if (x == 0.0L) {
		ux.i.hi = uy.i.hi & 0x8000000000000000ULL;
		ux.i.lo = 1;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	mhi = ux.i.hi & 0x7fffffffffffffffULL; /* magnitude: sign bit stripped off */
	mlo = ux.i.lo;
	oldexp = (unsigned)(mhi >> 48) & 0x7fff;

	if ((x > 0.0L) ? (y > x) : (y < x)) {
		if (mlo == (uint64_t)-1) { mlo = 0; mhi++; }
		else mlo++;
	} else {
		if (mlo == 0) { mhi--; mlo = (uint64_t)-1; }
		else mlo--;
	}
	newexp = (unsigned)(mhi >> 48) & 0x7fff;

	if (newexp == 0x7fff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	ux.i.hi = (ux.i.hi & 0x8000000000000000ULL) | mhi;
	ux.i.lo = mlo;
	return ux.f;
#endif
}

/* nexttoward: identical semantics to nextafter, except y is always a
 * long double regardless of x's type, so x is compared against y at
 * long double precision rather than after rounding y down to x's
 * type. */
double nexttoward(double x, long double y)
{
	union { double f; uint64_t i; } ux = { x };
	uint64_t ai;
	unsigned oldexp, newexp;
	long double lx = (long double)x;

	if (x != x || y != y) return x + (double)y;
	if (lx == y) return (double)y;

	if (x == 0.0) {
		ux.i = ((y < 0.0L) ? (uint64_t)1 << 63 : (uint64_t)0) | (uint64_t)1;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	oldexp = (unsigned)(ux.i >> 52 & 0x7ff);
	if ((x > 0.0) ? (y > lx) : (y < lx)) ai = ux.i + 1;
	else ai = ux.i - 1;
	newexp = (unsigned)(ai >> 52 & 0x7ff);

	if (newexp == 0x7ff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	ux.i = ai;
	return ux.f;
}

float nexttowardf(float x, long double y)
{
	union { float f; uint32_t i; } ux = { x };
	uint32_t ai;
	unsigned oldexp, newexp;
	long double lx = (long double)x;

	if (x != x || y != y) return x + (float)y;
	if (lx == y) return (float)y;

	if (x == 0.0f) {
		ux.i = ((y < 0.0L) ? 0x80000000u : 0u) | 1u;
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
		return ux.f;
	}

	oldexp = (ux.i >> 23) & 0xff;
	if ((x > 0.0f) ? (y > lx) : (y < lx)) ai = ux.i + 1;
	else ai = ux.i - 1;
	newexp = (ai >> 23) & 0xff;

	if (newexp == 0xff) feraiseexcept(FE_OVERFLOW | FE_INEXACT);
	else if (newexp == 0 && oldexp != 0) feraiseexcept(FE_UNDERFLOW | FE_INEXACT);

	ux.i = ai;
	return ux.f;
}

/* Same type for both arguments -- nexttowardl is nextafterl. */
long double nexttowardl(long double x, long double y) { return nextafterl(x, y); }

// NOLINTEND(misc-include-cleaner)
