/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
/* M_PI and friends are feature-test gated in include/math.h; same
 * define most other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* src/math/ldbl_math.h's own SPICULE_LDBL_EXTENDED test, reused here rather
 * than <float.h>'s LDBL_MANT_DIG: this tcc's bundled <float.h>
 * unconditionally reports LDBL_MANT_DIG==64 (extended) on i386/x86_64
 * even though tcc's own "long double" is really just a 64-bit double in
 * PE mode -- ldbl_math.h's comment above SPICULE_LDBL_EXTENDED has the full
 * story. __SIZEOF_LONG_DOUBLE__ is the one both compilers get right:
 * this tcc never predefines it (confirmed empirically), gcc/mingw/clang
 * predefine it to the true sizeof (8 here, 12 or 16 there). */
#if defined(__SIZEOF_LONG_DOUBLE__) && __SIZEOF_LONG_DOUBLE__ > 8
#define TEST_LDBL_EXTENDED 1
#else
#define TEST_LDBL_EXTENDED 0
#endif

static int near(double a, double b, double tol)
{
	if (a == b) return 1;
	if (a != a || b != b) return 0;
	if (b == 0) return fabs(a) <= tol;
	return fabs(a - b) <= tol * fabs(b);
}
#define NEAR(a,b) CHECK(near((a), (b), 1e-14))

int main(void)
{
	/* fabs / copysign / signbit */
	CHECK(fabs(-3.5) == 3.5 && fabs(3.5) == 3.5);
	CHECK(fabsf(-1.25f) == 1.25f);
	CHECK(fabsl(-2.5L) == 2.5L);
	CHECK(copysign(3, -1) == -3 && copysign(-3, 1) == 3);
	CHECK(copysignf(2.0f, -0.0f) == -2.0f);
	CHECK(signbit(-0.0) && !signbit(0.0));
	CHECK(signbit(-1.0f) && !signbit(1.0L));

	/* classify */
	CHECK(isnan(NAN) && !isnan(1.0));
	CHECK(isinf(HUGE_VAL) && isinf(-HUGE_VAL) && !isinf(1e308));
	CHECK(isfinite(0.0) && isfinite(1e308) && !isfinite(HUGE_VAL) && !isfinite(NAN));
	CHECK(fpclassify(0.0) == FP_ZERO);
	CHECK(fpclassify(1.0) == FP_NORMAL);
	CHECK(fpclassify(5e-324) == FP_SUBNORMAL);
	CHECK(isnormal(1.0) && !isnormal(5e-324));
	{ double d = nan(""); CHECK(d != d); }

	/* floor/ceil/trunc/round/rint */
	CHECK(floor(2.7) == 2 && floor(-2.7) == -3 && floor(-2.0) == -2);
	CHECK(ceil(2.1) == 3 && ceil(-2.1) == -2);
	CHECK(trunc(2.9) == 2 && trunc(-2.9) == -2);
	CHECK(round(2.5) == 3 && round(-2.5) == -3 && round(2.4) == 2);
	CHECK(round(0.49999999999999994) == 0);   /* the classic +0.5 bug */
	CHECK(rint(2.5) == 2 && rint(3.5) == 4);  /* ties to even */
	CHECK(floorf(1.5f) == 1 && ceill(1.5L) == 2);
	CHECK(lround(2.5) == 3 && lround(-2.5) == -3);
	CHECK(llround(1e15 + 0.5) == 1000000000000001LL);
	CHECK(lrint(2.5) == 2 && lrint(3.5) == 4);
	CHECK(llrint(123456789012345.0) == 123456789012345LL);
	CHECK(floor(1e300) == 1e300 && trunc(-1e300) == -1e300);

	/* sqrt */
	CHECK(sqrt(4) == 2 && sqrt(0) == 0 && sqrt(2.25) == 1.5);
	NEAR(sqrt(2), 1.4142135623730951);
	CHECK(sqrtf(9.0f) == 3.0f && sqrtl(16.0L) == 4.0L);
	{ double d = sqrt(-1); CHECK(d != d); }

	/* fmod */
	CHECK(fmod(7.5, 2) == 1.5 && fmod(-7.5, 2) == -1.5);
	CHECK(fmod(1e300, 3.7) >= 0);
	CHECK(fmodf(5.5f, 2.0f) == 1.5f);
	{ double d = fmod(1, 0); CHECK(d != d); }

	/* frexp/ldexp/scalbn/modf */
	{
		int e;
		double m = frexp(12.0, &e);
		CHECK(m == 0.75 && e == 4);
		m = frexp(0.0, &e);
		CHECK(m == 0 && e == 0);
		m = frexp(5e-324, &e);
		CHECK(m == 0.5 && e == -1073);
	}
	CHECK(ldexp(0.75, 4) == 12.0);
	CHECK(scalbn(1, -1074) == 5e-324);
	CHECK(scalbn(1.5, 1000) == 1.5 * 0x1p1000);
	CHECK(scalbnf(1.0f, -149) > 0);
	/* -16400 used to be the exponent here: correctly a deep underflow to
	 * 0 for a 64-bit long double (subnormal floor around -1074), but
	 * *not* deep enough for a genuine 80-bit extended long double
	 * (subnormal floor around -16445) -- natively that computes a tiny
	 * nonzero subnormal instead of 0, so the check was quietly wrong for
	 * that width rather than merely inapplicable. -100000 is well past
	 * either format's subnormal floor, so this holds at both widths
	 * without needing TEST_LDBL_EXTENDED at all. */
	CHECK(ldexpl(1.0L, -100000) == 0.0L);
	{
		double ip, fr = modf(3.75, &ip);
		CHECK(ip == 3 && fr == 0.75);
		fr = modf(-3.75, &ip);
		CHECK(ip == -3 && fr == -0.75);
		fr = modf(HUGE_VAL, &ip);
		CHECK(ip == HUGE_VAL && fr == 0);
	}

	/* trig */
	CHECK(sin(0) == 0 && cos(0) == 1 && tan(0) == 0);
	NEAR(sin(1.0), 0.8414709848078965);
	NEAR(cos(1.0), 0.5403023058681398);
	NEAR(tan(1.0), 1.5574077246549023);
	NEAR(sin(M_PI / 6), 0.5);
	NEAR(atan(1.0), M_PI / 4);
	NEAR(atan2(1, 1), M_PI / 4);
	NEAR(atan2(1, -1), 3 * M_PI / 4);
	NEAR(atan2(-1, -1), -3 * M_PI / 4);
	CHECK(atan2(0, 1) == 0);
	NEAR(atan2(1, 0), M_PI / 2);
#if !TEST_LDBL_EXTENDED
	/* huge-arg path is self-consistent -- but only a check of sin()'s
	 * own internal precision against *this test's* reference, and that
	 * reference is itself only as good as 2*M_PI computed in double
	 * precision, which is nowhere near enough digits to reduce an
	 * argument the size of 1e19 accurately (the true value of pi needs
	 * ~19-20 digits to matter at this magnitude; M_PI the macro has
	 * them, but naming it in a `double` expression rounds it down to
	 * ~16 first).  With a 64-bit long double (the NT target under tcc),
	 * sin()'s own range reduction is *also* only double precision, so
	 * it matches this equally-imprecise reference by construction.
	 * With a genuine 80-bit extended long double, sin()'s internal
	 * reduce() (src/math/trig.c) is actually more accurate than this
	 * reference is, and the two now legitimately disagree past 1e-14 --
	 * a sign the library got *better*, not a bug, but not something
	 * this test's own reference can confirm.  Skipped rather than
	 * loosened: loosening the tolerance would hide a real regression in
	 * the non-extended case instead. */
	NEAR(sin(1e19), sin(fmod(1e19, 2 * M_PI)));
#endif
	{ double d = sin(HUGE_VAL); CHECK(d != d); }
	/* sinf returns a float, so it can only ever match the true double
	 * value to float precision (~1.2e-7 relative) - the shared 1e-14
	 * NEAR tolerance is for double-precision results and is
	 * unsatisfiable here regardless of implementation, so use a
	 * float-appropriate tolerance directly. */
	CHECK(near(sinf(0.5f), 0.47942553860420301, 1e-6));
	NEAR(cosl(0.5L), 0.87758256189037271612);

	/* exp/log */
	CHECK(exp(0) == 1);
	NEAR(exp(1), M_E);
	NEAR(exp(-1), 0.36787944117144233);
	NEAR(exp(10), 22026.465794806718);
	CHECK(exp(1000) == HUGE_VAL && exp(-1000) == 0);
	{ double d = exp(NAN); CHECK(d != d); }
	CHECK(log(1) == 0);
	NEAR(log(M_E), 1.0);
	NEAR(log(10), M_LN10);
	CHECK(log2(8) == 3 && log2(0x1p50) == 50);
	CHECK(log10(1000) == 3);
	NEAR(log10(2), M_LOG10E * M_LN2);
	CHECK(isinf(log(0)) && log(0) < 0);
	{ double d = log(-1); CHECK(d != d); }
	/* expf returns a float; same float-vs-double tolerance reasoning
	 * as sinf() above. */
	CHECK(near(expf(2.0f), 7.38905609893065, 1e-6));
	NEAR(logl(2.0L), M_LN2);

	/* pow */
	CHECK(pow(2, 10) == 1024);
	CHECK(pow(2, 0.5) == sqrt(2));
	NEAR(pow(10, -3), 1e-3);
	/* the correct double-precision result of pow(1.0000001, 1e7):
	 * 1.0000001 is not exact in binary, so this is
	 * exp2(1e7 * log2(the double nearest 1.0000001)), not
	 * exp(1e7 * ln(the exact decimal 1.0000001)) - those differ
	 * starting at the 9th significant digit, and the old expected
	 * value here was the latter (wrong) computation. */
	NEAR(pow(1.0000001, 1e7), 2.7182816941320818);
	CHECK(pow(-2, 3) == -8 && pow(-2, 2) == 4);
	CHECK(pow(5, 0) == 1 && pow(0, 5) == 0 && pow(1, NAN) == 1);
	CHECK(pow(NAN, 0) == 1);
	{ double d = pow(-2, 0.5); CHECK(d != d); }
	CHECK(pow(0, -2) == HUGE_VAL);
	CHECK(pow(2, 2000) == HUGE_VAL && pow(2, -2000) == 0);
	CHECK(pow(-HUGE_VAL, 3) == -HUGE_VAL && pow(-HUGE_VAL, 2) == HUGE_VAL);

	/* fmax/fmin/hypot */
	CHECK(fmax(1, 2) == 2 && fmin(1, 2) == 1);
	CHECK(fmax(NAN, 3) == 3 && fmin(3, NAN) == 3);
	CHECK(hypot(3, 4) == 5);
	NEAR(hypot(1e300, 1e300), 1.4142135623730951e300);
	CHECK(hypot(HUGE_VAL, NAN) == HUGE_VAL);

	if (!fails) printf("math: all tests passed\n");
	return fails != 0;
}
