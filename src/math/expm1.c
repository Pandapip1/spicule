/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* expm1/log1p via the x87 primitives that exist specifically to avoid
 * the catastrophic cancellation a naive exp(x)-1 / log(1+x) suffers
 * for x near 0:
 *
 *  - f2xm1 computes 2^t-1 directly (no intervening "+1" to round away
 *    x's low bits before the "-1" gets a chance to undo it), but its
 *    operand range is only -1.0 to +1.0 (Intel SDM vol 2A, F2XM1); we
 *    stay well inside that (|x| <= 0.5, so |x*log2(e)| <= ~0.7213)
 *    and fall back to plain expl(x)-1 outside it, where the
 *    cancellation this is all about avoiding cannot happen anyway
 *    (expl(x) is far from 1 there).
 *
 *  - fyl2xp1 computes y*log2(x+1) directly, same idea, valid for
 *    |x| < 1-sqrt(2)/2 (~0.29289, Intel SDM vol 2A, FYL2XP1); outside
 *    that we fall back to plain logl(1+x).
 *
 * Both primitives are documented (Intel SDM) to return a zero with
 * the sign of a zero operand, which is what gives expm1(-0.0) == -0.0
 * and log1p(-0.0) == -0.0 here without any extra sign-of-zero code. */
#include <math.h>
#include <fenv.h>
#include "ldbl_math.h"

static const long double log2e = 1.4426950408889634073599246810019L;
static const long double ln2 = 0.69314718055994530941723212145818L;
/* 1 - sqrt(2)/2, fyl2xp1's documented operand limit. */
static const long double yl2xp1_max = 0.29289321881345247559915563789515L;

#if !defined(__i386__) && !defined(__x86_64__)
/* No f2xm1/fyl2xp1 (or any x87) on this arch -- see src/math/
 * aarch64_math.h's own __aa64_expm1()/__aa64_log1p() for the real
 * algorithms (both computed directly in terms of the catastrophic-
 * cancellation-prone quantity, same as f2xm1/fyl2xp1 are, just via a
 * software series instead of hardware) and ldbl_math.h's own banner for the
 * double-precision-quality scope boundary every helper in this file
 * inherits from narrowing long double to double at the call boundary. */
static long double raw_f2xm1(long double t) { return (long double)__aa64_expm1((double)t); }
static long double raw_yl2xp1(long double x, long double y) // NOLINT(bugprone-easily-swappable-parameters) -- multiplicand and logarithm-base operand have distinct arithmetic roles
{
	(void)y; /* always ln2 at this file's one call site -- see
	          * __aa64_log1p's own comment for why the general y*log2(x+1)
	          * form isn't needed here. */
	return (long double)__aa64_log1p((double)x);
}
#else
/* 2^t - 1 for |t| <= 1 (we only ever call this with |t| <~ 0.7213). */
static long double raw_f2xm1(long double t)
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\tf2xm1\n\t" SPICULE_FSTPL " (%0)" : : "r"(&t) : "memory");
	return t;
}

/* y * log2(x+1), same fldl/fldl/op/fstpl-into-first-operand shape and
 * argument order as ldbl_math.h's __x87_yl2x. */
static long double raw_yl2xp1(long double x, long double y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\t" SPICULE_FLDL " (%1)\n\tfyl2xp1\n\t" SPICULE_FSTPL " (%0)" : : "r"(&y), "r"(&x) : "memory");
	return y;
}
#endif

long double expm1l(long double x)
{
	if (x != x) return x;
	if (fabsl(x) <= 0.5L) return raw_f2xm1(x * log2e);
	return expl(x) - 1.0L;   /* far from 0: no cancellation, and expl already
	                          * clamps/overflows exactly as expm1 needs to */
}

long double log1pl(long double x)
{
	if (x != x) return x;
	if (x < -1.0L) {
		feraiseexcept(FE_INVALID);
		return (long double)NAN;
	}
	if (x == -1.0L) {
		feraiseexcept(FE_DIVBYZERO);
		return -HUGE_VALL;
	}
	if (fabsl(x) < yl2xp1_max) return raw_yl2xp1(x, ln2);
	return logl(1.0L + x);
}

double expm1(double x) { return (double)expm1l(x); }
float expm1f(float x) { return (float)expm1l(x); }
double log1p(double x) { return (double)log1pl(x); }
float log1pf(float x) { return (float)log1pl(x); }

// NOLINTEND(misc-include-cleaner)
