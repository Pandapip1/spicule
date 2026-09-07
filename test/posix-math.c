/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of math.h, concentrating on what
 * test/math.c (a broad sanity pass, not clause-cited) does not already
 * pin down: special-value tables (±0, ±Inf, NaN), sign of zero (which
 * == cannot distinguish -- use signbit()), and the math_errhandling /
 * errno contract.  Each assertion cites the clause of
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * it checks.  See test/POSIX-COVERAGE.md's math.h section for the full
 * ledger.
 *
 * POSIX does not mandate a specific accuracy for the transcendental
 * functions (only math_errhandling's special-value table is a "shall"),
 * so this file does not assert ulp figures; where accuracy is worth
 * recording it is printed as information, never as a failing CHECK.
 * Every assertion below is either cited to a "shall" clause or
 * explicitly marked "informational" in a comment.
 *
 * arch/i386 runs the x87 unit at 80-bit internal precision even though
 * spicule's own `long double` is 64-bit on the NT target (see
 * src/math/ldbl_math.h); results can legitimately differ in the last bit(s)
 * between arches for the same reason test/math.c is skipped on host
 * ASan builds (tools/asan-build.sh, not_native()).  Run `make check`
 * on both arches and compare rather than assuming one is correct.
 *
 * Every requirement this file names now gets a test, even one that
 * cannot pass: fenced blocks use three conventions, greppable by the
 * tag right after "#if 0 / * ":
 *   BUG:    a confirmed, real spec violation (should pass once fixed)
 *   N/A:    genuinely impossible on this platform
 *   UNIMPL: not implemented at all here, but implementable
 * A fenced test still contains the real assertions the cited spec
 * clause requires, written as if it would run -- never a hand-wave.
 */
/* M_PI and friends are feature-test gated in include/math.h; same
 * define most other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <errno.h>
#include <fenv.h>
#include <limits.h>
#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static int negzero(double x) { return x == 0.0 && signbit(x); }
static int poszero(double x) { return x == 0.0 && !signbit(x); }

/* ---- fabs.html: RETURN VALUE -- NaN->NaN, ±0->+0, ±Inf->+Inf ---- */
static void test_fabs(void)
{
	CHECK(isnan(fabs(NAN)));
	CHECK(poszero(fabs(0.0)) && poszero(fabs(-0.0)));
	CHECK(fabs(HUGE_VAL) == HUGE_VAL && fabs(-HUGE_VAL) == HUGE_VAL);
	CHECK(isnan(fabsf(NAN)) && isnan(fabsl(NAN)));
	CHECK(poszero(fabsl(-0.0L)));
}

/* ---- copysign.html: RETURN VALUE -- "a value with the magnitude of x
 * and the sign of y" ---- */
static void test_copysign(void)
{
	CHECK(copysign(3.0, -1.0) == -3.0 && copysign(-3.0, 1.0) == 3.0);
	/* magnitude of x is taken even when x is negative/NaN-tagged */
	CHECK(copysign(-5.0, -1.0) == -5.0);
	/* sign of a zero y controls the result's sign */
	CHECK(copysign(4.0, -0.0) == -4.0 && copysign(-4.0, 0.0) == 4.0);
	/* and a zero magnitude x still takes that sign, distinguishable
	 * only via signbit() */
	CHECK(negzero(copysign(0.0, -0.0)));
	CHECK(poszero(copysign(-0.0, 0.0)));
	/* magnitude of a NaN x: still "the magnitude of x" -- result is a
	 * NaN either way, but must not become non-NaN */
	CHECK(isnan(copysign(NAN, -1.0)) && isnan(copysign(NAN, 1.0)));
	/* sign of an Inf y */
	CHECK(copysign(1.0, -HUGE_VAL) == -1.0);
	CHECK(copysignl(3.0L, -1.0L) == -3.0L);
}

/* ---- fpclassify.html / isnan.html / isinf.html / isfinite.html /
 * isnormal.html / signbit.html: classification of each category ---- */
static void test_classify(void)
{
	CHECK(fpclassify(0.0) == FP_ZERO && fpclassify(-0.0) == FP_ZERO);
	CHECK(fpclassify(1.0) == FP_NORMAL);
	CHECK(fpclassify(HUGE_VAL) == FP_INFINITE && fpclassify(-HUGE_VAL) == FP_INFINITE);
	CHECK(fpclassify(NAN) == FP_NAN);
	CHECK(fpclassify(5e-324) == FP_SUBNORMAL && fpclassify(-5e-324) == FP_SUBNORMAL);

	CHECK(isnan(NAN) && !isnan(1.0) && !isnan(HUGE_VAL));
	CHECK(isinf(HUGE_VAL) && isinf(-HUGE_VAL) && !isinf(NAN) && !isinf(1.0));
	CHECK(isfinite(0.0) && isfinite(5e-324) && isfinite(DBL_MAX));
	CHECK(!isfinite(HUGE_VAL) && !isfinite(-HUGE_VAL) && !isfinite(NAN));
	CHECK(isnormal(1.0) && isnormal(DBL_MIN));
	CHECK(!isnormal(5e-324) && !isnormal(0.0) && !isnormal(HUGE_VAL) && !isnormal(NAN));

	/* signbit.html: "NaNs, zeros, and infinities have a sign bit" --
	 * non-zero iff negative, independent of == comparability */
	CHECK(signbit(-0.0) && !signbit(0.0));
	CHECK(signbit(-1.0) && !signbit(1.0));
	CHECK(signbit(-HUGE_VAL) && !signbit(HUGE_VAL));
	CHECK(signbit(copysign(NAN, -1.0)) && !signbit(copysign(NAN, 1.0)));
}

/* ---- floor.html / ceil.html / trunc.html / round.html: NaN->NaN,
 * ±0/±Inf passed through unchanged, and "the result shall have the
 * same sign as x" for a zero result. ---- */
static void test_rounding(void)
{
	CHECK(isnan(floor(NAN)) && isnan(ceil(NAN)) && isnan(trunc(NAN)) && isnan(round(NAN)));
	CHECK(poszero(floor(0.0)) && negzero(floor(-0.0)));
	CHECK(poszero(ceil(0.0)) && negzero(ceil(-0.0)));
	CHECK(poszero(trunc(0.0)) && negzero(trunc(-0.0)));
	CHECK(poszero(round(0.0)) && negzero(round(-0.0)));
	CHECK(floor(HUGE_VAL) == HUGE_VAL && floor(-HUGE_VAL) == -HUGE_VAL);
	CHECK(ceil(HUGE_VAL) == HUGE_VAL && ceil(-HUGE_VAL) == -HUGE_VAL);
	CHECK(trunc(HUGE_VAL) == HUGE_VAL && trunc(-HUGE_VAL) == -HUGE_VAL);
	CHECK(round(HUGE_VAL) == HUGE_VAL && round(-HUGE_VAL) == -HUGE_VAL);

	/* the actual bug-prone cases: a mathematically-zero result whose
	 * sign must still track x, for inputs that are NOT themselves
	 * zero. ceil()/trunc() round a small negative fraction to zero;
	 * round() does too for anything with |x| < 0.5. */
	CHECK(negzero(ceil(-0.5)));
	CHECK(negzero(trunc(-0.5)));
	CHECK(negzero(round(-0.4)));
	CHECK(negzero(ceil(-0.9)));
	CHECK(negzero(trunc(-0.9)));
	/* floor() only returns a zero result for a zero input (any
	 * negative fraction floors to -1, not -0) -- sanity, not a
	 * distinct clause. */
	CHECK(floor(-0.5) == -1.0 && floor(-0.9) == -1.0);

	/* round(): "rounding halfway cases away from zero" */
	CHECK(round(2.5) == 3.0 && round(-2.5) == -3.0 && round(0.5) == 1.0 && round(-0.5) == -1.0);
}

/* ---- sqrt.html: RETURN VALUE / ERRORS -- domain error for x<0 or
 * x==-Inf (NaN), ±0 and +Inf passed through unchanged, NaN->NaN ---- */
static void test_sqrt(void)
{
	CHECK(isnan(sqrt(NAN)));
	CHECK(poszero(sqrt(0.0)) && negzero(sqrt(-0.0)));
	CHECK(sqrt(HUGE_VAL) == HUGE_VAL);
	CHECK(isnan(sqrt(-1.0)));       /* finite x < -0: domain error, NaN */
	CHECK(isnan(sqrt(-HUGE_VAL)));  /* x == -Inf: domain error, NaN */
	CHECK(isnan(sqrtl(-1.0L)) && isnan(sqrtf(-1.0f)));
}

/* ---- fmod.html: RETURN VALUE -- "x - i*y ... the result has the same
 * sign as x and magnitude less than the magnitude of y"; x or y NaN ->
 * NaN; y==0 or x==±Inf -> domain error, NaN; x==±0,y!=0 -> ±0;
 * x finite, y==±Inf -> x. ---- */
static void test_fmod(void)
{
	CHECK(fmod(7.5, 2.0) == 1.5);
	CHECK(fmod(-7.5, 2.0) == -1.5);   /* sign follows the dividend x, not y */
	CHECK(fmod(7.5, -2.0) == 1.5);
	CHECK(fmod(-7.5, -2.0) == -1.5);
	CHECK(isnan(fmod(NAN, 2.0)) && isnan(fmod(2.0, NAN)));
	CHECK(isnan(fmod(1.0, 0.0)) && isnan(fmod(-1.0, 0.0)));  /* y==0: domain error */
	CHECK(isnan(fmod(HUGE_VAL, 2.0)) && isnan(fmod(-HUGE_VAL, 2.0)));  /* x==±Inf: domain error */
	CHECK(poszero(fmod(0.0, 5.0)) && negzero(fmod(-0.0, 5.0)));
	/* x finite, y==±Inf: "x shall be returned" -- exactly, not just
	 * numerically equal (this is the clause the naive "reduce huge
	 * argument via fmod" trick in src/math/trig.c and src/math/pow.c
	 * relies on never mattering for finite y). */
	CHECK(fmod(3.5, HUGE_VAL) == 3.5 && fmod(-3.5, HUGE_VAL) == -3.5);
	CHECK(fmod(3.5, -HUGE_VAL) == 3.5);
	CHECK(fmod(HUGE_VAL, HUGE_VAL) != fmod(HUGE_VAL, HUGE_VAL));  /* still x==Inf -> NaN, not 3.5-style passthrough */
}

/* ---- frexp.html / ldexp.html / scalbn.html: round trips, ±0/NaN/±Inf
 * passthrough, exp==0 passthrough, overflow -> ±HUGE_VAL, underflow at
 * the denormal boundary. ---- */
static void test_frexp_ldexp(void)
{
	int e;
	double m;

	/* frexp: ±0 -> ±0, *exp==0 */
	m = frexp(0.0, &e); CHECK(poszero(m) && e == 0);
	m = frexp(-0.0, &e); CHECK(negzero(m) && e == 0);
	/* frexp: NaN -> NaN (value of *exp unspecified, not checked) */
	m = frexp(NAN, &e); CHECK(isnan(m));
	/* frexp: ±Inf -> x itself (value of *exp unspecified) */
	m = frexp(HUGE_VAL, &e); CHECK(m == HUGE_VAL);
	m = frexp(-HUGE_VAL, &e); CHECK(m == -HUGE_VAL);
	/* frexp: magnitude in [1/2, 1) for a normal, round-trips via
	 * scalbn -- exercised further into the denormal range than
	 * test/math.c's single 5e-324 case */
	m = frexp(DBL_MIN, &e); CHECK(m >= 0.5 && m < 1.0 && scalbn(m, e) == DBL_MIN);
	m = frexp(1e-310, &e); CHECK(m >= 0.5 && m < 1.0 && scalbn(m, e) == 1e-310);  /* subnormal input */

	/* ldexp/scalbn: exp==0 -> x unchanged, including for NaN/Inf/±0 */
	CHECK(ldexp(3.75, 0) == 3.75);
	CHECK(isnan(ldexp(NAN, 0)));
	CHECK(ldexp(HUGE_VAL, 0) == HUGE_VAL);
	CHECK(negzero(ldexp(-0.0, 0)));
	/* ldexp/scalbn: NaN -> NaN, ±0/±Inf -> x, for a nonzero exp too */
	CHECK(isnan(ldexp(NAN, 5)));
	CHECK(poszero(ldexp(0.0, 5)) && negzero(ldexp(-0.0, 5)));
	CHECK(ldexp(HUGE_VAL, 5) == HUGE_VAL && ldexp(-HUGE_VAL, 5) == -HUGE_VAL);
	/* ldexp/scalbn: overflow -> ±HUGE_VAL "according to the sign of x" */
	CHECK(ldexp(DBL_MAX, 1) == HUGE_VAL);
	CHECK(ldexp(-DBL_MAX, 1) == -HUGE_VAL);
	CHECK(scalbn(1.0, 2000) == HUGE_VAL && scalbn(-1.0, 2000) == -HUGE_VAL);
	/* underflow past the smallest subnormal: representable range is
	 * exhausted, so the correct result rounds to a signed zero */
	CHECK(negzero(scalbn(-1.0, -2000)));
	CHECK(poszero(scalbn(1.0, -2000)));
}

/* ---- modf.html: RETURN VALUE -- signed fractional part; NaN -> NaN
 * with *iptr NaN; ±Inf -> ±0 with *iptr ±Inf. ---- */
static void test_modf(void)
{
	double ip, fr;

	fr = modf(NAN, &ip); CHECK(isnan(fr) && isnan(ip));
	fr = modf(HUGE_VAL, &ip); CHECK(poszero(fr) && ip == HUGE_VAL);
	fr = modf(-HUGE_VAL, &ip); CHECK(negzero(fr) && ip == -HUGE_VAL);
	/* sign-of-zero-result case, same shape as ceil/trunc/round above:
	 * the integral part of a small negative fraction is -0, not +0 */
	fr = modf(-0.5, &ip); CHECK(negzero(ip) && fr == -0.5);
	fr = modf(-0.0, &ip); CHECK(negzero(ip) && negzero(fr));
}

/* ---- exp.html: RETURN VALUE -- NaN->NaN, ±0->1, -Inf->+0, +Inf->x;
 * overflow -> HUGE_VAL. ---- */
static void test_exp(void)
{
	CHECK(isnan(exp(NAN)));
	CHECK(exp(0.0) == 1.0 && exp(-0.0) == 1.0);
	CHECK(poszero(exp(-HUGE_VAL)));
	CHECK(exp(HUGE_VAL) == HUGE_VAL);
	CHECK(exp(1000.0) == HUGE_VAL);   /* overflow -> HUGE_VAL, informational: exact threshold not asserted */
	CHECK(poszero(exp(-1000.0)));     /* underflow: 0.0 permitted (IEC 60559 branch) */
}

/* ---- log.html / log2.html / log10.html: RETURN VALUE/ERRORS -- NaN->
 * NaN, x==1->+0, x==+Inf->+Inf (x itself), x==±0-> pole error, -HUGE_VAL,
 * finite x<0 or x==-Inf -> domain error, NaN. ---- */
static void test_log(void)
{
	CHECK(isnan(log(NAN)) && isnan(log2(NAN)) && isnan(log10(NAN)));
	CHECK(poszero(log(1.0)) && poszero(log2(1.0)) && poszero(log10(1.0)));
	CHECK(log(HUGE_VAL) == HUGE_VAL && log2(HUGE_VAL) == HUGE_VAL && log10(HUGE_VAL) == HUGE_VAL);
	/* pole error: ±0 -> -HUGE_VAL (both signs of zero alike -- the
	 * clause does not distinguish +0 from -0 here) */
	CHECK(log(0.0) == -HUGE_VAL && log(-0.0) == -HUGE_VAL);
	CHECK(log2(0.0) == -HUGE_VAL && log10(0.0) == -HUGE_VAL);
	/* domain error: finite negative, and -Inf */
	CHECK(isnan(log(-1.0)) && isnan(log(-HUGE_VAL)));
	CHECK(isnan(log2(-1.0)) && isnan(log10(-1.0)));
}

/* ---- sin.html / cos.html / tan.html: NaN->NaN, ±0->x (sin/tan) or
 * ->1 (cos), ±Inf -> domain error, NaN.
 * atan.html: NaN->NaN, ±0->x, ±Inf->±pi/2.
 * atan2.html: the full sign/zero/Inf table. ---- */
static void test_trig(void)
{
	CHECK(isnan(sin(NAN)) && isnan(cos(NAN)) && isnan(tan(NAN)) && isnan(atan(NAN)));
	CHECK(poszero(sin(0.0)) && negzero(sin(-0.0)));
	CHECK(cos(0.0) == 1.0 && cos(-0.0) == 1.0);
	CHECK(poszero(tan(0.0)) && negzero(tan(-0.0)));
	CHECK(poszero(atan(0.0)) && negzero(atan(-0.0)));
	CHECK(isnan(sin(HUGE_VAL)) && isnan(sin(-HUGE_VAL)));
	CHECK(isnan(cos(HUGE_VAL)) && isnan(cos(-HUGE_VAL)));
	CHECK(isnan(tan(HUGE_VAL)) && isnan(tan(-HUGE_VAL)));
	CHECK(atan(HUGE_VAL) == M_PI / 2 && atan(-HUGE_VAL) == -M_PI / 2);

	CHECK(isnan(atan2(NAN, 1.0)) && isnan(atan2(1.0, NAN)));
	CHECK(poszero(atan2(0.0, 1.0)) && negzero(atan2(-0.0, 1.0)));  /* y==±0, x>0 -> ±0 */
	CHECK(atan2(0.0, -1.0) == M_PI && atan2(-0.0, -1.0) == -M_PI); /* y==±0, x<0 -> ±pi */
	CHECK(atan2(1.0, 0.0) == M_PI / 2 && atan2(-1.0, 0.0) == -M_PI / 2);  /* y!=0, x==+0 */
	CHECK(atan2(1.0, -0.0) == M_PI / 2 && atan2(-1.0, -0.0) == -M_PI / 2);  /* y!=0, x==-0: same as x==+0 */
	CHECK(atan2(HUGE_VAL, 1.0) == M_PI / 2 && atan2(-HUGE_VAL, 1.0) == -M_PI / 2);  /* finite x, y==±Inf */
	CHECK(atan2(1.0, HUGE_VAL) == 0.0 && atan2(1.0, -HUGE_VAL) == M_PI);           /* finite y>0, x==±Inf */
	CHECK(atan2(HUGE_VAL, HUGE_VAL) == M_PI / 4);      /* y==+Inf, x==+Inf -> +pi/4 */
	CHECK(atan2(HUGE_VAL, -HUGE_VAL) == 3 * M_PI / 4);  /* y==+Inf, x==-Inf -> +3pi/4 */
	CHECK(atan2(-HUGE_VAL, HUGE_VAL) == -M_PI / 4);
	CHECK(atan2(-HUGE_VAL, -HUGE_VAL) == -3 * M_PI / 4);
}

/* ---- pow.html: RETURN VALUE/ERRORS -- the full special-value table,
 * worked clause by clause rather than sampled. ---- */
static void test_pow(void)
{
	/* "For any value of x (including NaN), if y is ±0, 1.0" */
	CHECK(pow(2.0, 0.0) == 1.0 && pow(2.0, -0.0) == 1.0 && pow(NAN, 0.0) == 1.0);
	/* "For any value of y (including NaN), if x is +1, 1.0" */
	CHECK(pow(1.0, 5.0) == 1.0 && pow(1.0, NAN) == 1.0 && pow(1.0, HUGE_VAL) == 1.0);
	/* "If x is -1, and y is ±Inf, 1.0" */
	CHECK(pow(-1.0, HUGE_VAL) == 1.0 && pow(-1.0, -HUGE_VAL) == 1.0);
	/* domain error: finite x<0, finite non-integer y -> NaN */
	CHECK(isnan(pow(-2.0, 0.5)));
	/* x or y NaN (not otherwise specified) -> NaN */
	CHECK(isnan(pow(NAN, 2.0)) && isnan(pow(-1.0, NAN)));

	/* x==±0, y odd integer >0 -> ±0; y>0 not odd integer -> +0 */
	CHECK(poszero(pow(0.0, 3.0)) && negzero(pow(-0.0, 3.0)));
	CHECK(poszero(pow(0.0, 4.0)) && poszero(pow(-0.0, 4.0)));
	/* x==±0, y<0: pole error, odd integer -> ±HUGE_VAL, else +HUGE_VAL */
	CHECK(pow(0.0, -3.0) == HUGE_VAL && pow(-0.0, -3.0) == -HUGE_VAL);
	CHECK(pow(0.0, -4.0) == HUGE_VAL && pow(-0.0, -4.0) == HUGE_VAL);

	/* |x|<1, y==-Inf -> +Inf; |x|>1, y==-Inf -> +0 */
	CHECK(pow(0.5, -HUGE_VAL) == HUGE_VAL);
	CHECK(poszero(pow(2.0, -HUGE_VAL)));
	/* |x|<1, y==+Inf -> +0; |x|>1, y==+Inf -> +Inf */
	CHECK(poszero(pow(0.5, HUGE_VAL)));
	CHECK(pow(2.0, HUGE_VAL) == HUGE_VAL);

	/* x==-Inf: y odd int<0 -> -0; y<0 not odd -> +0;
	 *          y odd int>0 -> -Inf; y>0 not odd -> +Inf */
	CHECK(negzero(pow(-HUGE_VAL, -3.0)));
	CHECK(poszero(pow(-HUGE_VAL, -4.0)));
	CHECK(pow(-HUGE_VAL, 3.0) == -HUGE_VAL);
	CHECK(pow(-HUGE_VAL, 4.0) == HUGE_VAL);
	/* x==+Inf: y<0 -> +0, y>0 -> +Inf */
	CHECK(poszero(pow(HUGE_VAL, -2.0)));
	CHECK(pow(HUGE_VAL, 3.0) == HUGE_VAL);

	/* overflow/underflow far from any special value: informational
	 * sign/magnitude sanity, not a distinct clause beyond RETURN
	 * VALUE's overflow->HUGE_VAL text already exercised above */
	CHECK(pow(2.0, 2000.0) == HUGE_VAL && poszero(pow(2.0, -2000.0)));
}

/* ---- fmax.html / fmin.html: RETURN VALUE -- one-NaN-argument returns
 * the other; both-NaN returns NaN. ---- */
static void test_fmaxmin(void)
{
	CHECK(fmax(NAN, 3.0) == 3.0 && fmax(3.0, NAN) == 3.0);
	CHECK(fmin(NAN, 3.0) == 3.0 && fmin(3.0, NAN) == 3.0);
	CHECK(isnan(fmax(NAN, NAN)) && isnan(fmin(NAN, NAN)));
	CHECK(fmax(1.0, 2.0) == 2.0 && fmin(1.0, 2.0) == 1.0);
	/* informational only: POSIX does not specify which zero wins when
	 * comparing +0 and -0 (they compare equal), so this pins down
	 * spicule's own (permitted) choice rather than a "shall" clause --
	 * see src/math/fmax.c's "+0 beats -0" comment. */
	CHECK(poszero(fmax(0.0, -0.0)) && poszero(fmax(-0.0, 0.0)));
	CHECK(negzero(fmin(0.0, -0.0)) && negzero(fmin(-0.0, 0.0)));
}

/* ---- hypot.html: RETURN VALUE -- ±Inf wins even over a NaN co-argument
 * (either order); a non-Inf NaN argument makes the result NaN; overflow
 * -> HUGE_VAL. ---- */
static void test_hypot(void)
{
	CHECK(hypot(HUGE_VAL, NAN) == HUGE_VAL);
	CHECK(hypot(NAN, HUGE_VAL) == HUGE_VAL);   /* symmetric in the arguments */
	CHECK(hypot(-HUGE_VAL, NAN) == HUGE_VAL);
	CHECK(isnan(hypot(NAN, 1.0)) && isnan(hypot(1.0, NAN)));
	CHECK(hypot(3.0, 4.0) == 5.0);
	CHECK(hypot(DBL_MAX, DBL_MAX) == HUGE_VAL);  /* overflow -> HUGE_VAL */

	/* hypot.html RETURN VALUE -- "If x or y is ±Inf, +Inf shall be
	 * returned (even if one of x or y is NaN)."  Both arguments
	 * infinite, neither a NaN: the infinity check must run before (not
	 * only alongside) the NaN check. */
	CHECK(hypot(HUGE_VAL, HUGE_VAL) == HUGE_VAL);
	CHECK(hypot(-HUGE_VAL, -HUGE_VAL) == HUGE_VAL);
	CHECK(hypot(HUGE_VAL, -HUGE_VAL) == HUGE_VAL);
}

/* ---- nan.html: RETURN VALUE -- "a quiet NaN, if available". ---- */
static void test_nan(void)
{
	double d = nan("");
	CHECK(isnan(d));
	CHECK(d != d);   /* quiet NaN still compares unordered, per IEEE 754 */
	CHECK(isnan(nanf("")) && isnan(nanl("")));
}

/* ---- math.h basedefs, math_errhandling: "The following macros shall
 * expand to the integer constants 1 and 2, respectively; MATH_ERRNO
 * MATH_ERREXCEPT" and "If the expression (math_errhandling &
 * MATH_ERREXCEPT) can be non-zero, the implementation shall define the
 * macros FE_DIVBYZERO, FE_INVALID, and FE_OVERFLOW in <fenv.h>." ---- */
static void test_errhandling(void)
{
	volatile double big, tiny, zero, three, negone, result;
	CHECK(MATH_ERRNO == 1 && MATH_ERREXCEPT == 2);
	CHECK(math_errhandling == MATH_ERREXCEPT);

	/* <fenv.h> basedefs: FE_DIVBYZERO, FE_INVALID and FE_OVERFLOW (the
	 * three basedefs/math.h.html names) must exist with these exact
	 * values -- the traditional x86 status-word bit positions, which
	 * is also what feclearexcept()/fetestexcept() below observe on the
	 * real hardware flags. */
	CHECK(FE_INVALID == 0x01 && FE_DIVBYZERO == 0x04 && FE_OVERFLOW == 0x08);
	CHECK(FE_UNDERFLOW == 0x10 && FE_INEXACT == 0x20);
	CHECK(FE_ALL_EXCEPT == (FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT));

	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == 0);

	/* sqrt.html ERRORS: "a domain error occurs" for sqrt(x) with x<0.
	 * -1.0 goes straight to hardware fsqrt (src/math/sqrt.c), which
	 * signals invalid for a negative operand on both arches. */
	negone = -1.0;
	(void)sqrt(negone);
	CHECK(fetestexcept(FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_INVALID) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0);

	/* log.html ERRORS: "a pole error may occur" for log(+-0); fyl2x
	 * signals divide-by-zero for a zero operand (src/math/log.c). */
	zero = 0.0;
	(void)log(zero);
	CHECK(fetestexcept(FE_DIVBYZERO) == FE_DIVBYZERO);
	CHECK(feclearexcept(FE_DIVBYZERO) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0);

	/* DBL_MAX*DBL_MAX overflows -- this is plain compiler-emitted `*`,
	 * not a src/math/ldbl_math.h helper, so on x86_64 it exercises the SSE2
	 * mulsd path (MXCSR) rather than x87; on i386 tcc still emits x87
	 * fmul for `double`.  Either way fetestexcept() must see it.  The
	 * result must actually land in a real `double` (not be discarded):
	 * x87's registers are 80-bit, so overflow relative to *double*'s
	 * narrower exponent range is only detected at the store that
	 * rounds/converts down to 64 bits -- a discarded `(void)(a*b)` can
	 * pop the x87 stack without ever performing that store. */
	big = DBL_MAX;
	result = big * big;
	/* An overflowing result is necessarily also inexact (the true
	 * mathematical product cannot be represented at all), so this
	 * checks only that FE_OVERFLOW is among the raised flags, not
	 * that it is the only one -- then clears everything before the
	 * next case. */
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_OVERFLOW) == FE_OVERFLOW);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0);

	/* A tiny compiler-emitted division that rounds to a subnormal
	 * result signals underflow (and inexact alongside it, same
	 * both-flags-raised-together reasoning as overflow above); same
	 * store-to-a-real-double requirement as above. */
	tiny = DBL_MIN;
	big = 1e16;
	result = tiny / big;
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_UNDERFLOW) == FE_UNDERFLOW);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0);

	/* 1.0/3.0 is not exactly representable -- signals inexact, and
	 * nothing else. */
	three = 3.0;
	result = 1.0 / three;
	CHECK(fetestexcept(FE_ALL_EXCEPT) == FE_INEXACT);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0);
	(void)result;

	/* feraiseexcept()/fesetexceptflag() can set flags directly,
	 * independent of any actual computation. */
	CHECK(feraiseexcept(FE_INVALID | FE_OVERFLOW) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == (FE_INVALID | FE_OVERFLOW));
	{
		fexcept_t saved;
		CHECK(fegetexceptflag(&saved, FE_ALL_EXCEPT) == 0);
		CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
		CHECK(fetestexcept(FE_ALL_EXCEPT) == 0);
		CHECK(fesetexceptflag(&saved, FE_ALL_EXCEPT) == 0);
		CHECK(fetestexcept(FE_ALL_EXCEPT) == (FE_INVALID | FE_OVERFLOW));
	}
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);

	/* fegetround()/fesetround(): default is round-to-nearest; setting
	 * and restoring another mode round-trips. */
	CHECK(fegetround() == FE_TONEAREST);
	CHECK(fesetround(FE_TOWARDZERO) == 0);
	CHECK(fegetround() == FE_TOWARDZERO);
	CHECK(fesetround(FE_TONEAREST) == 0);
	CHECK(fegetround() == FE_TONEAREST);
	CHECK(fesetround(0xdead) == -1);  /* not one of the four modes */

	/* fegetenv()/fesetenv()/feholdexcept()/feupdateenv(): a
	 * saved-and-restored environment round-trips the exception state
	 * exactly as the C99 feupdateenv() contract requires -- raised
	 * exceptions accumulated *during* the held region are merged back
	 * in on top of whatever the caller had pending before. */
	{
		fenv_t env;
		CHECK(feholdexcept(&env) == 0);
		CHECK(fetestexcept(FE_ALL_EXCEPT) == 0);
		zero = 0.0;
		(void)log(zero);  /* raises FE_DIVBYZERO while "held" */
		CHECK(fetestexcept(FE_DIVBYZERO) == FE_DIVBYZERO);
		CHECK(feupdateenv(&env) == 0);
		CHECK(fetestexcept(FE_DIVBYZERO) == FE_DIVBYZERO);
		CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	}

	/* Since MATH_ERRNO is (correctly, per math_errhandling's value)
	 * not required, confirm errno is in fact left alone across a
	 * representative set of domain/pole/range "errors" -- this is
	 * informational (documents actual, conformant-either-way
	 * behaviour), not a distinct "shall" clause. */
	errno = 0;
	(void)sqrt(-1.0);
	(void)log(0.0);
	(void)log(-1.0);
	(void)pow(0.0, -1.0);
	(void)fmod(1.0, 0.0);
	(void)exp(1000.0);
	CHECK(errno == 0);
}

static int negzerof(float x) { return x == 0.0f && signbit(x); }
static int poszerof(float x) { return x == 0.0f && !signbit(x); }
static int negzerol(long double x) { return x == 0.0L && signbit(x); }
static int poszerol(long double x) { return x == 0.0L && !signbit(x); }

/* ---- sin.html/cos.html/tan.html/atan.html/atan2.html, l/f variants:
 * the same special-value tables audited above for the double forms
 * apply verbatim to sinf/sinl, cosf/cosl, tanf/tanl, atanf/atanl,
 * atan2f/atan2l ("shall be equivalent to" the double function).
 * spicule's `long double` is 64-bit on this PE target -- bit-identical
 * layout to `double` (src/math/ldbl_math.h's SPICULE_LDBL_EXTENDED note) --
 * so unlike a genuine 80-bit long double there is no extra internal
 * precision to lose at the l-variant's own store; any float/long
 * double vs. double numeric difference reported here is purely
 * informational (float has less precision by construction; a real
 * 80-bit long double target could differ from double in the last bit
 * for reasons this target cannot exhibit), never a failing assertion. ---- */
static void test_float_ld_variants(void)
{
	CHECK(isnan(sinf(NAN)) && isnan(sinl(NAN)));
	CHECK(isnan(cosf(NAN)) && isnan(cosl(NAN)));
	CHECK(isnan(tanf(NAN)) && isnan(tanl(NAN)));
	CHECK(isnan(atanf(NAN)) && isnan(atanl(NAN)));

	CHECK(poszerof(sinf(0.0f)) && negzerof(sinf(-0.0f)));
	CHECK(poszerol(sinl(0.0L)) && negzerol(sinl(-0.0L)));
	CHECK(cosf(0.0f) == 1.0f && cosf(-0.0f) == 1.0f);
	CHECK(cosl(0.0L) == 1.0L && cosl(-0.0L) == 1.0L);
	CHECK(poszerof(tanf(0.0f)) && negzerof(tanf(-0.0f)));
	CHECK(poszerol(tanl(0.0L)) && negzerol(tanl(-0.0L)));
	CHECK(poszerof(atanf(0.0f)) && negzerof(atanf(-0.0f)));
	CHECK(poszerol(atanl(0.0L)) && negzerol(atanl(-0.0L)));

	/* sin/cos/tan: ±Inf is a domain error -> NaN */
	CHECK(isnan(sinf(HUGE_VALF)) && isnan(sinf(-HUGE_VALF)));
	CHECK(isnan(sinl(HUGE_VALL)) && isnan(sinl(-HUGE_VALL)));
	CHECK(isnan(cosf(HUGE_VALF)) && isnan(cosf(-HUGE_VALF)));
	CHECK(isnan(cosl(HUGE_VALL)) && isnan(cosl(-HUGE_VALL)));
	CHECK(isnan(tanf(HUGE_VALF)) && isnan(tanf(-HUGE_VALF)));
	CHECK(isnan(tanl(HUGE_VALL)) && isnan(tanl(-HUGE_VALL)));

	/* atan.html: ±Inf -> ±pi/2. The l-variant comparisons use a
	 * tolerance, not == : M_PI is a `double` macro (53 bits of
	 * mantissa), so `(long double)M_PI/2` only carries double
	 * precision even where `long double` genuinely has more (the
	 * native `make asan` build, __SIZEOF_LONG_DOUBLE__>8) -- atanl()
	 * itself computes at the type's full precision via fpatan, so an
	 * exact == there would be asserting an accuracy coincidence, not
	 * the spec's actual "±pi/2" clause. 1e-9L is far tighter than any
	 * real bug could hide under yet far looser than the ~1e-17
	 * relative gap M_PI's own truncation can introduce -- on this PE
	 * target (long double == double) it holds with room to spare. */
	CHECK(atanf(HUGE_VALF) == (float)(M_PI / 2) && atanf(-HUGE_VALF) == (float)(-M_PI / 2));
	CHECK(fabsl(atanl(HUGE_VALL) - (long double)M_PI / 2) < 1e-9L);
	CHECK(fabsl(atanl(-HUGE_VALL) - (long double)-M_PI / 2) < 1e-9L);

	/* atan2.html: representative subset of the same table test_trig()
	 * exercises fully for double -- NaN, y==±0 with x>0, and the
	 * finite-y/x==±Inf clauses. Same M_PI-precision caveat as above
	 * for the l-variant pi/pi-fraction comparisons. */
	CHECK(isnan(atan2f(NAN, 1.0f)) && isnan(atan2f(1.0f, NAN)));
	CHECK(isnan(atan2l(NAN, 1.0L)) && isnan(atan2l(1.0L, NAN)));
	CHECK(poszerof(atan2f(0.0f, 1.0f)) && negzerof(atan2f(-0.0f, 1.0f)));
	CHECK(poszerol(atan2l(0.0L, 1.0L)) && negzerol(atan2l(-0.0L, 1.0L)));
	CHECK(atan2f(HUGE_VALF, HUGE_VALF) == (float)(M_PI / 4));
	CHECK(fabsl(atan2l(HUGE_VALL, HUGE_VALL) - (long double)M_PI / 4) < 1e-9L);
	CHECK(atan2f(1.0f, HUGE_VALF) == 0.0f && atan2f(1.0f, -HUGE_VALF) == (float)M_PI);
	CHECK(atan2l(1.0L, HUGE_VALL) == 0.0L);
	CHECK(fabsl(atan2l(1.0L, -HUGE_VALL) - (long double)M_PI) < 1e-9L);

	/* exp.html/log.html/log2.html/log10.html l/f variants: NaN->NaN,
	 * ±0->1 (exp) / +0 (log family pole error), +Inf->x, finite
	 * negative -> domain error NaN. */
	CHECK(isnan(expf(NAN)) && isnan(expl(NAN)));
	CHECK(expf(0.0f) == 1.0f && expf(-0.0f) == 1.0f);
	CHECK(expl(0.0L) == 1.0L && expl(-0.0L) == 1.0L);
	CHECK(expf(HUGE_VALF) == HUGE_VALF && expl(HUGE_VALL) == HUGE_VALL);
	CHECK(poszerof(expf(-HUGE_VALF)) && poszerol(expl(-HUGE_VALL)));

	CHECK(isnan(logf(NAN)) && isnan(logl(NAN)) && isnan(log2f(NAN)) && isnan(log2l(NAN)) && isnan(log10f(NAN)) && isnan(log10l(NAN)));
	CHECK(poszerof(logf(1.0f)) && poszerol(logl(1.0L)));
	CHECK(logf(HUGE_VALF) == HUGE_VALF && logl(HUGE_VALL) == HUGE_VALL);
	CHECK(logf(0.0f) == -HUGE_VALF && logl(0.0L) == -HUGE_VALL);   /* pole error */
	CHECK(isnan(logf(-1.0f)) && isnan(logl(-1.0L)));               /* domain error */

	/* pow.html l/f variants: representative subset (full ~20-clause
	 * table already worked for double in test_pow()) -- the y==±0
	 * and x==1 identities, and the domain-error case. */
	CHECK(powf(2.0f, 0.0f) == 1.0f && powl(2.0L, 0.0L) == 1.0L);
	CHECK(powf(1.0f, NAN) == 1.0f && powl(1.0L, (long double)NAN) == 1.0L);
	CHECK(isnan(powf(-2.0f, 0.5f)) && isnan(powl(-2.0L, 0.5L)));
}

/* ---- lround.html/llround.html/lrint.html/llrint.html/rint.html:
 * clause-by-clause (not just the round-trip spot checks test/math.c
 * already has). No f/l-suffixed variants (lroundf/lroundl/lrintf/
 * lrintl/llroundf/llroundl/llrintf/llrintl/rintf/rintl) are audited
 * separately below, in test_lround_lrint_variants(). ---- */
static void test_lround_lrint(void)
{
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);

	/* NaN input: RETURN VALUE says "domain error ... unspecified
	 * value returned" -- only the required FE_INVALID (math_errhandling
	 * here is unconditionally MATH_ERREXCEPT, so this is a real "shall")
	 * is checked, never the unspecified return value itself. Confirmed
	 * live to hold on both arches. */
	(void)lround(NAN);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)llround(NAN);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)lrint(NAN);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)llrint(NAN);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);

	/* lround/llround: "rounding halfway cases away from zero,
	 * regardless of the current rounding direction" -- unlike
	 * lrint/llrint/rint below, these do NOT consult fegetround(). */
	CHECK(fesetround(FE_TOWARDZERO) == 0);
	CHECK(lround(2.5) == 3 && lround(-2.5) == -3);
	CHECK(llround(2.5) == 3 && llround(-2.5) == -3);
	CHECK(fesetround(FE_TONEAREST) == 0);

	/* lrint/llrint/rint: RETURN VALUE -- "using the current rounding
	 * direction" (rint.html), genuinely testable now that <fenv.h>
	 * exists.  Ties-to-even at the default FE_TONEAREST. */
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	CHECK(lrint(2.5) == 2 && lrint(3.5) == 4);
	CHECK(llrint(2.5) == 2 && llrint(3.5) == 4);
	CHECK(rint(2.5) == 2.0 && rint(3.5) == 4.0);

	CHECK(fesetround(FE_UPWARD) == 0);
	CHECK(lrint(2.1) == 3 && llrint(2.1) == 3 && rint(2.1) == 3.0);
	CHECK(fesetround(FE_DOWNWARD) == 0);
	CHECK(lrint(2.9) == 2 && llrint(2.9) == 2 && rint(2.9) == 2.0);
	CHECK(fesetround(FE_TOWARDZERO) == 0);
	CHECK(lrint(-2.9) == -2 && rint(-2.9) == -2.0);
	CHECK(fesetround(FE_TONEAREST) == 0);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);

	/* rint.html: NaN->NaN, ±0->x, ±Inf->x passthrough -- rint's
	 * `double` return type can actually represent these, unlike
	 * lrint/llrint's integer types (which hit the NaN/Inf domain-error
	 * clause checked above instead). */
	CHECK(isnan(rint(NAN)));
	CHECK(poszero(rint(0.0)) && negzero(rint(-0.0)));
	CHECK(rint(HUGE_VAL) == HUGE_VAL && rint(-HUGE_VAL) == -HUGE_VAL);

	/* rint.html: "may raise the inexact floating-point exception if
	 * the result differs in value from the argument" -- confirmed live
	 * that spicule's frndint-based rint() does so. */
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	CHECK(rint(2.5) == 2.0);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INEXACT) == FE_INEXACT);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);

	/* lround.html/llround.html/lrint.html/llrint.html ERRORS -- "A
	 * domain error shall occur ... if x is ... infinite, or the
	 * correct value is not representable as an integer", and
	 * math_errhandling here is unconditionally MATH_ERREXCEPT
	 * (include/math.h), so FE_INVALID must be raised for these cases
	 * too, exactly as it already is for a NaN argument above.
	 *
	 * BUG found and fixed: src/math/round.c used to do
	 * this via a raw `(long)roundl(x)` / `(long long)
	 * __x87_rndint(x,-1)` cast -- undefined behaviour in C itself for
	 * a NaN or out-of-range operand, and inconsistent in practice: it
	 * happened to raise FE_INVALID on x86_64 (the compiler's
	 * cvttsd2si/fistp does that for free) but NOT on i386, where
	 * lround(+Inf) raised FE_DIVBYZERO instead of FE_INVALID and the
	 * finite-but-unrepresentable cases (lround(1e30), lrint(1e30),
	 * llrint(1e300)) raised nothing at all -- apparently because the
	 * cast there routed through arch/i386/src/int64.c's runtime
	 * int64-conversion helper, which did not reproduce x86_64's
	 * incidental exception behaviour. Fixed by checking the rounded
	 * value's range explicitly before ever casting it, and calling
	 * feraiseexcept(FE_INVALID) directly -- well-defined and
	 * consistent on both arches now (confirmed live). */
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)lround(HUGE_VAL);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)lround(-HUGE_VAL);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)lround(1e30);   /* finite, but not representable as long */
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)lrint(HUGE_VAL);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)lrint(1e30);
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	(void)llrint(1e300);   /* finite, but not representable as long long */
	CHECK((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) == FE_INVALID);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
}

/* ---- Functions src/math/ did not implement until now: asin/acos,
 * sinh/cosh/tanh, asinh/acosh/atanh, cbrt, expm1/log1p, erf/erfc,
 * lgamma/tgamma, the Bessel functions, remainder/remquo,
 * nextafter/nexttoward, fdim, fma, ilogb/logb, nearbyint, scalbln, and
 * the f/l-suffixed lround/lrint family below. Each assertion is cited
 * to its own spec page. ---- */

/* asin.html/acos.html RETURN VALUE/ERRORS -- NaN->NaN;
 * ±0->x (asin only; acos(+1)->+0); finite |x|>1 -> domain error,
 * NaN; ±Inf -> domain error, NaN (both). asin/acos are not
 * declared by include/math.h at all. */
static void test_asin_acos(void)
{
	CHECK(isnan(asin(NAN)) && isnan(acos(NAN)));
	CHECK(poszero(asin(0.0)) && negzero(asin(-0.0)));
	CHECK(poszero(acos(1.0)));
	CHECK(isnan(asin(1.5)) && isnan(asin(-1.5)));      /* finite |x|>1 */
	CHECK(isnan(acos(1.5)) && isnan(acos(-1.5)));
	CHECK(isnan(asin(HUGE_VAL)) && isnan(asin(-HUGE_VAL)));
	CHECK(isnan(acos(HUGE_VAL)) && isnan(acos(-HUGE_VAL)));
	CHECK(asin(1.0) == M_PI / 2 && asin(-1.0) == -M_PI / 2);
}

/* sinh.html/cosh.html/tanh.html RETURN VALUE/ERRORS --
 * NaN->NaN; sinh/tanh: ±0/±Inf->x; cosh: ±0->1, ±Inf->+Inf;
 * sinh/cosh overflow -> range error, ±HUGE_VAL. Not declared by
 * include/math.h. */
#if SPICULE_TEST(PASS, posix_math_sinh_large_negative_is_finite) /* sinh() stays finite for ordinary finite arguments below
	 * about -38.  sinh.html RETURN VALUE: "Upon successful completion,
	 * these functions shall return the hyperbolic sine of x."  The only
	 * sanctioned +-HUGE_VAL return is the range error ERRORS names,
	 * "The result overflows" -- and sinh(-40) is about -1.1769e17,
	 * which is not remotely an overflow of a double, or even of a
	 * float.
	 *
	 * Mechanism: src/math/sinh.c evaluates the identity
	 *
	 *     0.5L * (t + t / (t + 1.0L)),   t = expm1l(x)
	 *
	 * which is exact at the small-|x| end and unusable at the negative
	 * end.  For |x| > 0.5 src/math/expm1.c computes expm1l as
	 * expl(x) - 1.0L; once e^x falls below 2**-54 -- x below roughly
	 * -37.4 with this target's 53-bit long double -- that subtraction
	 * rounds to exactly -1.0.  Then t + 1.0L is exactly +0.0, t/(t+1.0L)
	 * is -1/0, and the whole expression is -Inf, with FE_DIVBYZERO
	 * raised on the way out.
	 *
	 * The overflow guard above it does not catch this: it tests
	 * `t == HUGE_VALL`, which is the *positive* end, where expm1l
	 * genuinely overflowed.  The negative end has no guard at all, and
	 * sinh(-1000.0) passes today only by coincidence -- there -Inf
	 * happens to be the answer the overflow clause requires anyway.
	 *
	 * The fix is the usual one for this identity: for sufficiently
	 * negative x, use -0.5 * expl(-x) (or fall back to the exp-based
	 * form) rather than dividing by t + 1.
	 *
	 * Re-enable when sinh() stays finite where the true value is. */
static void test_sinh_large_negative_is_finite(void)
{
	double r = sinh(-40.0);

	/* the true value is -1.1769287308472616e17 */
	CHECK(isfinite(r));
	CHECK(r < -1.17e17 && r > -1.18e17);

	/* sinhf() is (float)sinhl(), so it inherits the same division */
	CHECK(isfinite(sinhf(-40.0f)));

	/* and the positive end must keep working */
	CHECK(isfinite(sinh(40.0)));
}
#endif

static void test_hyperbolic(void)
{
	CHECK(isnan(sinh(NAN)) && isnan(cosh(NAN)) && isnan(tanh(NAN)));
	CHECK(poszero(sinh(0.0)) && negzero(sinh(-0.0)));
	CHECK(cosh(0.0) == 1.0 && cosh(-0.0) == 1.0);
	CHECK(poszero(tanh(0.0)) && negzero(tanh(-0.0)));
	CHECK(sinh(HUGE_VAL) == HUGE_VAL && sinh(-HUGE_VAL) == -HUGE_VAL);
	CHECK(cosh(HUGE_VAL) == HUGE_VAL && cosh(-HUGE_VAL) == HUGE_VAL);
	CHECK(tanh(HUGE_VAL) == 1.0 && tanh(-HUGE_VAL) == -1.0);
	CHECK(sinh(1000.0) == HUGE_VAL);    /* overflow -> range error, HUGE_VAL */
	CHECK(cosh(1000.0) == HUGE_VAL);
}

/* asinh.html/acosh.html/atanh.html RETURN VALUE/ERRORS --
 * NaN->NaN; asinh: ±0/±Inf->x; acosh: x==1->+0, x==+Inf->+Inf,
 * x<1 or x==-Inf -> domain error, NaN; atanh: ±0->x, ±1 -> pole
 * error ±HUGE_VAL, finite |x|>1 or ±Inf -> domain error, NaN.
 * Not declared by include/math.h. */
static void test_inverse_hyperbolic(void)
{
	CHECK(isnan(asinh(NAN)) && isnan(acosh(NAN)) && isnan(atanh(NAN)));
	CHECK(poszero(asinh(0.0)) && negzero(asinh(-0.0)));
	CHECK(asinh(HUGE_VAL) == HUGE_VAL && asinh(-HUGE_VAL) == -HUGE_VAL);
	CHECK(poszero(acosh(1.0)));
	CHECK(acosh(HUGE_VAL) == HUGE_VAL);
	CHECK(isnan(acosh(0.5)) && isnan(acosh(-HUGE_VAL)));   /* x<1, x==-Inf */
	CHECK(poszero(atanh(0.0)) && negzero(atanh(-0.0)));
	CHECK(atanh(1.0) == HUGE_VAL && atanh(-1.0) == -HUGE_VAL);   /* pole error */
	CHECK(isnan(atanh(1.5)) && isnan(atanh(-1.5)));               /* finite |x|>1 */
	CHECK(isnan(atanh(HUGE_VAL)) && isnan(atanh(-HUGE_VAL)));     /* ±Inf domain error */
}

/* cbrt.html RETURN VALUE -- "No errors are defined."
 * NaN->NaN, ±0/±Inf->x. Not declared by include/math.h. */
static void test_cbrt(void)
{
	CHECK(isnan(cbrt(NAN)));
	CHECK(poszero(cbrt(0.0)) && negzero(cbrt(-0.0)));
	CHECK(cbrt(HUGE_VAL) == HUGE_VAL && cbrt(-HUGE_VAL) == -HUGE_VAL);
	CHECK(cbrt(27.0) == 3.0 && cbrt(-27.0) == -3.0);
}

/* expm1.html/log1p.html RETURN VALUE/ERRORS -- expm1:
 * NaN->NaN, ±0->±0, -Inf->-1, +Inf->x, overflow -> range error,
 * HUGE_VAL. log1p: NaN->NaN, ±0/+Inf->x, x==-1 -> pole error,
 * -HUGE_VAL, x<-1 or x==-Inf -> domain error, NaN. Not declared
 * by include/math.h. */
static void test_expm1_log1p(void)
{
	CHECK(isnan(expm1(NAN)) && isnan(log1p(NAN)));
	CHECK(poszero(expm1(0.0)) && negzero(expm1(-0.0)));
	CHECK(expm1(-HUGE_VAL) == -1.0);
	CHECK(expm1(HUGE_VAL) == HUGE_VAL);
	CHECK(expm1(1000.0) == HUGE_VAL);   /* overflow -> range error */
	CHECK(poszero(log1p(0.0)) && negzero(log1p(-0.0)));
	CHECK(log1p(HUGE_VAL) == HUGE_VAL);
	CHECK(log1p(-1.0) == -HUGE_VAL);    /* pole error */
	CHECK(isnan(log1p(-2.0)) && isnan(log1p(-HUGE_VAL)));   /* domain error */
}

/* erf.html/erfc.html RETURN VALUE/ERRORS -- erf: NaN->
 * NaN, ±0->±0, ±Inf->±1; erfc: NaN->NaN, +Inf->+0, -Inf->2.
 * Not declared by include/math.h. */
static void test_erf_erfc(void)
{
	CHECK(isnan(erf(NAN)) && isnan(erfc(NAN)));
	CHECK(poszero(erf(0.0)) && negzero(erf(-0.0)));
	CHECK(erf(HUGE_VAL) == 1.0 && erf(-HUGE_VAL) == -1.0);
	CHECK(poszero(erfc(HUGE_VAL)));
	CHECK(erfc(-HUGE_VAL) == 2.0);
}

/* lgamma.html/tgamma.html RETURN VALUE/ERRORS -- lgamma:
 * non-positive integer -> pole error, +HUGE_VAL; overflow ->
 * range error, ±HUGE_VAL; NaN->NaN; x==1 or 2 -> +0; ±Inf ->
 * +Inf. tgamma (IEC 60559 branch, which math_errhandling==2
 * commits spicule to): negative integer -> domain error, NaN;
 * ±0 -> pole error, ±HUGE_VAL; overflow -> range error,
 * ±HUGE_VAL; NaN->NaN; +Inf->+Inf; -Inf -> domain error, NaN.
 * Not declared by include/math.h. */
static void test_gamma(void)
{
	CHECK(isnan(lgamma(NAN)) && isnan(tgamma(NAN)));
	CHECK(lgamma(0.0) == HUGE_VAL && lgamma(-1.0) == HUGE_VAL);   /* pole error */
	CHECK(poszero(lgamma(1.0)) && poszero(lgamma(2.0)));
	CHECK(lgamma(HUGE_VAL) == HUGE_VAL);
	CHECK(tgamma(HUGE_VAL) == HUGE_VAL);
	CHECK(isnan(tgamma(-HUGE_VAL)));            /* domain error */
	CHECK(isnan(tgamma(-2.0)));                 /* negative integer: domain error */
	CHECK(tgamma(0.0) == HUGE_VAL);             /* +0: pole error, sign of x */
	CHECK(tgamma(-0.0) == -HUGE_VAL);           /* -0: pole error, sign of x */
}

/* j0.html/j1.html/jn.html (Bessel, first kind) and
 * y0.html/y1.html/yn.html (second kind) RETURN VALUE/ERRORS --
 * NaN->NaN for all six; j-family: |x| too large or underflow ->
 * 0, range error may occur; y-family: x<0 -> -HUGE_VAL or NaN,
 * domain error may occur; x==0 -> -HUGE_VAL, pole error may
 * occur; overflow -> -HUGE_VAL or 0, range error may occur.
 * None of the six are declared by include/math.h. */
static void test_bessel(void)
{
	double j, y;

	CHECK(isnan(j0(NAN)) && isnan(j1(NAN)) && isnan(jn(2, NAN)));
	CHECK(isnan(y0(NAN)) && isnan(y1(NAN)) && isnan(yn(2, NAN)));
	CHECK(j0(0.0) == 1.0);                 /* informational: known closed value */
	CHECK(y0(0.0) == -HUGE_VAL);           /* x==0: pole error */
	CHECK(isnan(y0(-1.0)) || y0(-1.0) == -HUGE_VAL);   /* x<0: domain error, either return permitted */
	/* Both negative-order identities used to evaluate -INT_MIN.  The
	 * positive extreme separately overflowed Miller's int starting order. */
	CHECK(jn(INT_MIN, 0.0) == 0.0);
	CHECK(jn(INT_MIN, 1.0) == 0.0);
	CHECK(jn(INT_MAX, 1.0) == 0.0);
	CHECK(yn(INT_MIN, 1.0) == -HUGE_VAL);
	/* Large finite x avoids the small-x underflow/overflow shortcuts.  The
	 * first pair exercises the bounded Hankel path; the second pair is the
	 * uniform asymptotic's x==n turning point.  All four used to enter a
	 * recurrence with more than two billion iterations. */
	j = jn(INT_MIN, 1e20);
	y = yn(INT_MIN, 1e20);
	CHECK(isfinite(j) && fabs(j) < 1.0);
	CHECK(isfinite(y) && fabs(y) < 1.0);
	j = jn(INT_MAX, (double)INT_MAX);
	y = yn(INT_MIN, 2147483648.0);
	CHECK(isfinite(j) && j > 0.0);
	CHECK(isfinite(y) && y < 0.0);
}

/* remainder.html RETURN VALUE/ERRORS -- x REM y (IEEE
 * remainder, round-to-nearest quotient, unlike fmod's
 * round-toward-zero quotient); x or y NaN -> NaN; x==±Inf or
 * y==±0 (other non-NaN) -> domain error, NaN.
 * remquo.html: same remainder value plus *quo set to a value
 * congruent to the true quotient mod 2^n, n>=3, sign of x/y;
 * *quo unspecified when y==0. Neither declared by
 * include/math.h. */
/* remainder_impl must reduce directly rather than first forming x/y.
 * A rounded quotient loses the low bits needed for the remainder, and an
 * overflowing quotient used to become a NaN-to-int conversion in remquo.
 * These finite inputs drive the complete multi-iteration FPREM1 path. */
static void test_remainder_large_quotient(void)
{
	int q;

	/* DBL_MAX is an exact multiple of 0.5, so the remainder is zero --
	 * and must certainly be finite. */
	CHECK(remainder(1.7976931348623157e308, 0.5) == 0.0);

	/* the defining bound, for a quotient too large to survive rounding */
	CHECK(fabs(remainder(12345678901234567.0, 3.0)) <= 1.5);
	CHECK(fabs(remainder(1.0, 1e-300)) <= 0.5e-300);

	/* remquo() must not hand back an infinity, nor an int cast from NaN */
	q = 12345;
	CHECK(isfinite(remquo(1.7976931348623157e308, 0.5, &q)));
}

static void test_remainder_remquo(void)
{
	int quo;
	CHECK(isnan(remainder(NAN, 2.0)) && isnan(remainder(2.0, NAN)));
	CHECK(isnan(remainder(HUGE_VAL, 2.0)));          /* x==±Inf: domain error */
	CHECK(isnan(remainder(2.0, 0.0)));               /* y==±0, x non-NaN: domain error */
	CHECK(remainder(5.5, 2.0) == -0.5);              /* round-to-nearest quotient (3), unlike fmod(5.5,2.0)==1.5 */
	CHECK(isnan(remquo(NAN, 2.0, &quo)) && isnan(remquo(2.0, NAN, &quo)));
	CHECK(isnan(remquo(HUGE_VAL, 2.0, &quo)));
	CHECK(isnan(remquo(2.0, 0.0, &quo)));
	CHECK(remquo(5.5, 2.0, &quo) == -0.5 && (quo & 7) == 3);  /* quotient congruent mod 8 (n>=3) */
}

/* nextafter.html/nexttoward.html RETURN VALUE/ERRORS --
 * x==y -> y (converted to type of x); x or y NaN -> NaN; finite
 * x, correct value overflows -> range error, ±HUGE_VAL same
 * sign as x; correct value subnormal/underflows -> range error,
 * correct value or 0.0. Neither declared by include/math.h. */
static void test_nextafter(void)
{
	CHECK(nextafter(1.0, 1.0) == 1.0);
	CHECK(isnan(nextafter(NAN, 1.0)) && isnan(nextafter(1.0, NAN)));
	CHECK(nextafter(DBL_MAX, HUGE_VAL) == HUGE_VAL);        /* overflow -> range error */
	CHECK(nextafter(1.0, 2.0) > 1.0);                        /* moves toward y */
	CHECK(nextafter(1.0, 0.0) < 1.0);
	CHECK(poszero(nextafter(DBL_MIN, 0.0)) || nextafter(DBL_MIN, 0.0) > 0.0);  /* underflow: correct value or 0.0 */
	CHECK(nexttoward(1.0, 2.0L) > 1.0);
	CHECK(isnan(nexttoward(NAN, 1.0L)));
}

/* fdim.html RETURN VALUE/ERRORS -- "the positive
 * difference" max(x-y,+0); NaN if either argument is NaN;
 * overflow of a positive difference -> range error, HUGE_VAL.
 * Not declared by include/math.h. */
static void test_fdim(void)
{
	CHECK(fdim(5.0, 3.0) == 2.0);
	CHECK(poszero(fdim(3.0, 5.0)));   /* x<y: positive difference is +0 */
	CHECK(isnan(fdim(NAN, 1.0)) && isnan(fdim(1.0, NAN)));
	CHECK(fdim(DBL_MAX, -DBL_MAX) == HUGE_VAL);   /* overflow -> range error */
}

/* fma.html RETURN VALUE/ERRORS -- (x*y)+z rounded once;
 * x or y NaN -> NaN; x*y==0*Inf-shape (exact 0 times exact Inf)
 * with z non-NaN -> domain error, NaN; x*y exact Inf and z an
 * oppositely-signed Inf -> domain error, NaN; x*y finite and z
 * NaN (and x*y not the 0*Inf shape) -> NaN. Not declared by
 * include/math.h. */
static void test_fma(void)
{
	CHECK(fma(2.0, 3.0, 4.0) == 10.0);
	CHECK(isnan(fma(NAN, 1.0, 1.0)) && isnan(fma(1.0, NAN, 1.0)));
	CHECK(isnan(fma(0.0, HUGE_VAL, 1.0)));               /* 0*Inf shape, z non-NaN: domain error */
	CHECK(isnan(fma(HUGE_VAL, 1.0, -HUGE_VAL)));         /* x*y==+Inf, z==-Inf: domain error */
	CHECK(isnan(fma(2.0, 3.0, NAN)));                    /* x*y finite, z NaN */
}

/* ilogb.html/logb.html RETURN VALUE/ERRORS -- logb:
 * x==±0 -> pole error, -HUGE_VAL; NaN->NaN; ±Inf->+Inf. ilogb:
 * equivalent to (int)logb(x) with three reserved out-of-band
 * results for the cases an int cannot hold logb's answer:
 * x==0 -> FP_ILOGB0 (domain error, XSI); NaN -> FP_ILOGBNAN
 * (domain error, XSI); ±Inf -> INT_MAX (domain error, XSI).
 * Neither declared by include/math.h. */
static void test_ilogb_logb(void)
{
	CHECK(isnan(logb(NAN)));
	CHECK(logb(0.0) == -HUGE_VAL && logb(-0.0) == -HUGE_VAL);   /* pole error */
	CHECK(logb(HUGE_VAL) == HUGE_VAL && logb(-HUGE_VAL) == HUGE_VAL);
	CHECK(logb(8.0) == 3.0);   /* 8 == 1.0 * 2^3 */
	CHECK(ilogb(0.0) == FP_ILOGB0);
	CHECK(ilogb(NAN) == FP_ILOGBNAN);
	CHECK(ilogb(HUGE_VAL) == INT_MAX);
	CHECK(ilogb(8.0) == 3);
}

/* nearbyint.html RETURN VALUE/ERRORS -- "No errors are
 * defined." Rounds using the current rounding direction like
 * rint(), but explicitly "without raising the inexact
 * floating-point exception" -- the one clause that
 * distinguishes it from rint(), directly testable via <fenv.h>.
 * Not declared by include/math.h. */
static void test_nearbyint(void)
{
	CHECK(isnan(nearbyint(NAN)));
	CHECK(poszero(nearbyint(0.0)) && negzero(nearbyint(-0.0)));
	CHECK(nearbyint(HUGE_VAL) == HUGE_VAL && nearbyint(-HUGE_VAL) == -HUGE_VAL);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	CHECK(nearbyint(2.5) == 2.0);
	CHECK(fetestexcept(FE_INEXACT) == 0);   /* the distinguishing clause vs. rint() */
}

/* scalbln.html RETURN VALUE/ERRORS -- x * FLT_RADIX^n;
 * NaN->NaN; ±0/±Inf->x; n==0->x; overflow -> range error,
 * ±HUGE_VAL; underflow -> range error, 0.0 or correct value.
 * Not declared by include/math.h. */
static void test_scalbln(void)
{
	CHECK(isnan(scalbln(NAN, 5)));
	CHECK(poszero(scalbln(0.0, 5)) && negzero(scalbln(-0.0, 5)));
	CHECK(scalbln(HUGE_VAL, 5) == HUGE_VAL && scalbln(-HUGE_VAL, 5) == -HUGE_VAL);
	CHECK(scalbln(3.75, 0) == 3.75);
	CHECK(scalbln(1.0, 2000L) == HUGE_VAL && scalbln(-1.0, 2000L) == -HUGE_VAL);   /* overflow */
	CHECK(poszero(scalbln(1.0, -2000L)));   /* underflow */
}

/* rint.html/lround.html/lrint.html f/l-suffixed variants
 * -- rintf/rintl, lroundf/lroundl, lrintf/lrintl, llroundf/
 * llroundl, llrintf/llrintl -- carry the same clauses audited
 * for the double forms in test_lround_lrint() above. None of
 * the ten are declared by include/math.h: only the plain
 * `double`-argument rint/lround/llround/lrint/llrint exist. */
static void test_lround_lrint_variants(void)
{
	CHECK(isnan(rintf(NAN)) && isnan(rintl(NAN)));
	CHECK(rintf(HUGE_VALF) == HUGE_VALF && rintl(HUGE_VALL) == HUGE_VALL);
	CHECK(lroundf(2.5f) == 3 && lroundl(2.5L) == 3);
	CHECK(lrintf(2.5f) == 2 && lrintl(2.5L) == 2);   /* ties to even, default mode */
	CHECK(llroundf(2.5f) == 3 && llroundl(2.5L) == 3);
	CHECK(llrintf(2.5f) == 2 && llrintl(2.5L) == 2);
}

/* ---- exp2.html: RETURN VALUE -- "the base-2 exponential of x".
 * NaN -> NaN; +-0 -> 1; +Inf -> +Inf; -Inf -> +0; overflow -> range
 * error and +-HUGE_VAL; underflow -> range error and a value no
 * greater than DBL_MIN.  ERRORS lists only those two range errors, so
 * exp2 has no domain error at all: every real argument has an answer.
 * The exact-power assertions are "shall" material, not accuracy
 * probes: 2^n for small integer n is exactly representable in double,
 * so an exactly-equal comparison is the right test there. ---- */
static void test_exp2(void)
{
	CHECK(isnan(exp2(NAN)));
	CHECK(exp2(0.0) == 1.0 && exp2(-0.0) == 1.0);
	CHECK(exp2(HUGE_VAL) == HUGE_VAL);
	CHECK(poszero(exp2(-HUGE_VAL)));

	/* exact powers of two, both signs of exponent */
	CHECK(exp2(1.0) == 2.0 && exp2(2.0) == 4.0 && exp2(10.0) == 1024.0);
	CHECK(exp2(-1.0) == 0.5 && exp2(-2.0) == 0.25);
	CHECK(exp2(0.5) > 1.414213 && exp2(0.5) < 1.414214);   /* sqrt(2) */

	/* the largest finite and the smallest normal double are both exact
	 * powers of two away from 1, so these pin the ends of the range
	 * without asserting an accuracy figure */
	CHECK(isfinite(exp2(1023.0)) && exp2(1023.0) > 0.0);
	CHECK(exp2(1024.0) == HUGE_VAL);   /* one step past the top exponent */
	CHECK(exp2((double)(DBL_MIN_EXP - 1)) == DBL_MIN);

	/* range errors: overflow -> HUGE_VAL, underflow -> 0.0 permitted
	 * (the IEC 60559 branch, as test_exp() records for exp()) */
	CHECK(exp2(5000.0) == HUGE_VAL);
	CHECK(poszero(exp2(-5000.0)));

	/* subnormal results are reached by rounding at the store, not by a
	 * special case -- 2^-1060 is subnormal but not zero */
	CHECK(fpclassify(exp2(-1060.0)) == FP_SUBNORMAL);
	CHECK(exp2(-1060.0) > 0.0);

	/* f/l variants carry the identical clause */
	CHECK(isnan(exp2f(NAN)) && isnan(exp2l(NAN)));
	CHECK(exp2f(0.0f) == 1.0f && exp2l(0.0L) == 1.0L);
	CHECK(exp2f(3.0f) == 8.0f && exp2l(3.0L) == 8.0L);
	CHECK(exp2f(HUGE_VALF) == HUGE_VALF && exp2l(HUGE_VALL) == HUGE_VALL);
	CHECK(poszerof(exp2f(-HUGE_VALF)) && poszerol(exp2l(-HUGE_VALL)));
	CHECK(exp2f(200.0f) == HUGE_VALF);   /* overflows float */

	/* exp2(x) and exp(x*ln2) agree: informational only, POSIX mandates
	 * no accuracy for either, but a gross implementation error (wrong
	 * base, missing argument reduction) would show up here */
	CHECK(fabs(exp2(7.3) - exp(7.3 * M_LN2)) < 1e-10 * exp2(7.3));
}

/* ---- fmax.html / fmin.html, f/l variants: fmaxf/fmaxl/fminf/fminl
 * carry the same RETURN VALUE clause as the double forms -- "If just
 * one argument is a NaN, the other argument shall be returned.  If x
 * and y are NaN, a NaN shall be returned."  No ERRORS are defined.
 * The ±0 assertions below are informational in exactly the sense
 * test_fmaxmin() records for the double forms: POSIX does not say
 * which zero wins, so these pin down spicule's own permitted choice
 * (+0 for fmax, -0 for fmin) and check that the f/l variants agree
 * with the double one rather than each having drifted separately. ---- */
static void test_fmaxmin_variants(void)
{
	CHECK(fmaxf(NAN, 3.0f) == 3.0f && fmaxf(3.0f, NAN) == 3.0f);
	CHECK(fminf(NAN, 3.0f) == 3.0f && fminf(3.0f, NAN) == 3.0f);
	CHECK(isnan(fmaxf(NAN, NAN)) && isnan(fminf(NAN, NAN)));
	CHECK(fmaxf(1.0f, 2.0f) == 2.0f && fminf(1.0f, 2.0f) == 1.0f);
	CHECK(fmaxf(-2.0f, -1.0f) == -1.0f && fminf(-2.0f, -1.0f) == -2.0f);

	CHECK(fmaxl(NAN, 3.0L) == 3.0L && fmaxl(3.0L, NAN) == 3.0L);
	CHECK(fminl(NAN, 3.0L) == 3.0L && fminl(3.0L, NAN) == 3.0L);
	CHECK(isnan(fmaxl(NAN, NAN)) && isnan(fminl(NAN, NAN)));
	CHECK(fmaxl(1.0L, 2.0L) == 2.0L && fminl(1.0L, 2.0L) == 1.0L);
	CHECK(fmaxl(-2.0L, -1.0L) == -1.0L && fminl(-2.0L, -1.0L) == -2.0L);

	/* infinities are ordinary operands here, not special cases */
	CHECK(fmaxf(HUGE_VALF, 1.0f) == HUGE_VALF && fminf(-HUGE_VALF, 1.0f) == -HUGE_VALF);
	CHECK(fmaxl(HUGE_VALL, 1.0L) == HUGE_VALL && fminl(-HUGE_VALL, 1.0L) == -HUGE_VALL);
	CHECK(fmaxf(-HUGE_VALF, NAN) == -HUGE_VALF);
	CHECK(fmaxl(-HUGE_VALL, NAN) == -HUGE_VALL);

	CHECK(poszerof(fmaxf(0.0f, -0.0f)) && poszerof(fmaxf(-0.0f, 0.0f)));
	CHECK(negzerof(fminf(0.0f, -0.0f)) && negzerof(fminf(-0.0f, 0.0f)));
	CHECK(poszerol(fmaxl(0.0L, -0.0L)) && poszerol(fmaxl(-0.0L, 0.0L)));
	CHECK(negzerol(fminl(0.0L, -0.0L)) && negzerol(fminl(-0.0L, 0.0L)));

	/* a float variant must not round its result through double, and
	 * an l variant must not round through double either: a value
	 * exactly representable in the argument type comes back bit-equal */
	CHECK(fmaxf(FLT_MIN, 0.0f) == FLT_MIN && fminf(FLT_MAX, HUGE_VALF) == FLT_MAX);
	CHECK(fmaxl(LDBL_MIN, 0.0L) == LDBL_MIN && fminl(LDBL_MAX, HUGE_VALL) == LDBL_MAX);
}

/* ---------------------------------------------------------------------
 * The math.h f/l tail: the 70 names test/POSIX-GAP-ACCOUNTING.md lists
 * as implemented with no assertion anywhere in the test/ tree.  Item 3 of that
 * file's successor queue, and the last of the original 112.
 *
 * Every one of these shares a manual page with the double form audited
 * above -- POSIX gives acos(), acosf() and acosl() one page and one
 * RETURN VALUE/ERRORS table, the f/l entries differing only in argument
 * and return type -- so each block below cites the same
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * page as its double counterpart and asserts the same clauses at the
 * other two types.  What is genuinely new here is not the clause but the
 * type: a special-value table can be right for `double` and wrong for
 * `float` (a wrong-width constant, a promotion that quietly routes the
 * f-form through the double body and back, a HUGE_VALF vs HUGE_VAL mixup)
 * and nothing in this tree had ever looked.
 *
 * `long double` is the same width as `double` on this NT target (see the
 * file banner and src/math/ldbl_math.h), so the l-forms are expected to agree
 * exactly with the doubles here; on the native `make asan` build they
 * need not, which is why nothing below compares an l-result against a
 * double-typed constant that would lose bits.
 *
 * Pure computation with no platform component: Wine is a fully sound
 * oracle for this entire section.
 * ------------------------------------------------------------------ */

/* asin.html/acos.html at float and long double. */
static void test_asin_acos_variants(void)
{
	CHECK(isnan(asinf(NAN)) && isnan(acosf(NAN)));
	CHECK(isnan(asinl(NAN)) && isnan(acosl(NAN)));
	CHECK(poszerof(asinf(0.0f)) && negzerof(asinf(-0.0f)));
	CHECK(poszerol(asinl(0.0L)) && negzerol(asinl(-0.0L)));
	CHECK(poszerof(acosf(1.0f)) && poszerol(acosl(1.0L)));
	/* finite |x| > 1: domain error -> NaN */
	CHECK(isnan(asinf(1.5f)) && isnan(asinf(-1.5f)));
	CHECK(isnan(asinl(1.5L)) && isnan(asinl(-1.5L)));
	CHECK(isnan(acosf(1.5f)) && isnan(acosf(-1.5f)));
	CHECK(isnan(acosl(1.5L)) && isnan(acosl(-1.5L)));
	CHECK(isnan(asinf(HUGE_VALF)) && isnan(acosf(-HUGE_VALF)));
	CHECK(isnan(asinl(HUGE_VALL)) && isnan(acosl(-HUGE_VALL)));
	/* asin(±1) == ±pi/2; see the M_PI-precision note in
	 * test_float_ld_variants() for why the l-form uses a tolerance. */
	CHECK(asinf(1.0f) == (float)(M_PI / 2) && asinf(-1.0f) == (float)(-M_PI / 2));
	CHECK(fabsl(asinl(1.0L) - (long double)M_PI / 2) < 1e-9L);
}

/* sinh.html/cosh.html/tanh.html at float and long double. */
static void test_hyperbolic_variants(void)
{
	CHECK(isnan(sinhf(NAN)) && isnan(coshf(NAN)) && isnan(tanhf(NAN)));
	CHECK(isnan(sinhl(NAN)) && isnan(coshl(NAN)) && isnan(tanhl(NAN)));
	CHECK(poszerof(sinhf(0.0f)) && negzerof(sinhf(-0.0f)));
	CHECK(poszerol(sinhl(0.0L)) && negzerol(sinhl(-0.0L)));
	CHECK(coshf(0.0f) == 1.0f && coshf(-0.0f) == 1.0f);
	CHECK(coshl(0.0L) == 1.0L && coshl(-0.0L) == 1.0L);
	CHECK(poszerof(tanhf(0.0f)) && negzerof(tanhf(-0.0f)));
	CHECK(poszerol(tanhl(0.0L)) && negzerol(tanhl(-0.0L)));
	CHECK(sinhf(HUGE_VALF) == HUGE_VALF && sinhf(-HUGE_VALF) == -HUGE_VALF);
	CHECK(sinhl(HUGE_VALL) == HUGE_VALL && sinhl(-HUGE_VALL) == -HUGE_VALL);
	CHECK(coshf(HUGE_VALF) == HUGE_VALF && coshf(-HUGE_VALF) == HUGE_VALF);
	CHECK(coshl(HUGE_VALL) == HUGE_VALL && coshl(-HUGE_VALL) == HUGE_VALL);
	CHECK(tanhf(HUGE_VALF) == 1.0f && tanhf(-HUGE_VALF) == -1.0f);
	CHECK(tanhl(HUGE_VALL) == 1.0L && tanhl(-HUGE_VALL) == -1.0L);
	/* overflow -> range error, ±HUGE_VAL{F,L}.  The float threshold is
	 * far lower than the double one, which is exactly the sort of thing
	 * a shared-body f-wrapper can get wrong: 200 overflows a float but
	 * is nowhere near overflowing a double. */
	CHECK(sinhf(200.0f) == HUGE_VALF && coshf(200.0f) == HUGE_VALF);
	CHECK(sinhl(100000.0L) == HUGE_VALL && coshl(100000.0L) == HUGE_VALL);
}

/* asinh.html/acosh.html/atanh.html at float and long double. */
static void test_inverse_hyperbolic_variants(void)
{
	CHECK(isnan(asinhf(NAN)) && isnan(acoshf(NAN)) && isnan(atanhf(NAN)));
	CHECK(isnan(asinhl(NAN)) && isnan(acoshl(NAN)) && isnan(atanhl(NAN)));
	CHECK(poszerof(asinhf(0.0f)) && negzerof(asinhf(-0.0f)));
	CHECK(poszerol(asinhl(0.0L)) && negzerol(asinhl(-0.0L)));
	CHECK(asinhf(HUGE_VALF) == HUGE_VALF && asinhf(-HUGE_VALF) == -HUGE_VALF);
	CHECK(asinhl(HUGE_VALL) == HUGE_VALL && asinhl(-HUGE_VALL) == -HUGE_VALL);
	CHECK(poszerof(acoshf(1.0f)) && poszerol(acoshl(1.0L)));
	CHECK(acoshf(HUGE_VALF) == HUGE_VALF && acoshl(HUGE_VALL) == HUGE_VALL);
	CHECK(isnan(acoshf(0.5f)) && isnan(acoshf(-HUGE_VALF)));
	CHECK(isnan(acoshl(0.5L)) && isnan(acoshl(-HUGE_VALL)));
	CHECK(poszerof(atanhf(0.0f)) && negzerof(atanhf(-0.0f)));
	CHECK(poszerol(atanhl(0.0L)) && negzerol(atanhl(-0.0L)));
	/* x == ±1: pole error -> ±HUGE_VAL{F,L} */
	CHECK(atanhf(1.0f) == HUGE_VALF && atanhf(-1.0f) == -HUGE_VALF);
	CHECK(atanhl(1.0L) == HUGE_VALL && atanhl(-1.0L) == -HUGE_VALL);
	CHECK(isnan(atanhf(1.5f)) && isnan(atanhf(-1.5f)));
	CHECK(isnan(atanhl(1.5L)) && isnan(atanhl(-1.5L)));
	CHECK(isnan(atanhf(HUGE_VALF)) && isnan(atanhl(-HUGE_VALL)));
}

/* cbrt.html at float and long double: "No errors are defined";
 * NaN->NaN, ±0/±Inf->x. */
static void test_cbrt_variants(void)
{
	CHECK(isnan(cbrtf(NAN)) && isnan(cbrtl(NAN)));
	CHECK(poszerof(cbrtf(0.0f)) && negzerof(cbrtf(-0.0f)));
	CHECK(poszerol(cbrtl(0.0L)) && negzerol(cbrtl(-0.0L)));
	CHECK(cbrtf(HUGE_VALF) == HUGE_VALF && cbrtf(-HUGE_VALF) == -HUGE_VALF);
	CHECK(cbrtl(HUGE_VALL) == HUGE_VALL && cbrtl(-HUGE_VALL) == -HUGE_VALL);
	CHECK(cbrtf(27.0f) == 3.0f && cbrtf(-27.0f) == -3.0f);
	CHECK(cbrtl(27.0L) == 3.0L && cbrtl(-27.0L) == -3.0L);
}

/* expm1.html/log1p.html at float and long double. */
static void test_expm1_log1p_variants(void)
{
	CHECK(isnan(expm1f(NAN)) && isnan(log1pf(NAN)));
	CHECK(isnan(expm1l(NAN)) && isnan(log1pl(NAN)));
	CHECK(poszerof(expm1f(0.0f)) && negzerof(expm1f(-0.0f)));
	CHECK(poszerol(expm1l(0.0L)) && negzerol(expm1l(-0.0L)));
	CHECK(expm1f(-HUGE_VALF) == -1.0f && expm1l(-HUGE_VALL) == -1.0L);
	CHECK(expm1f(HUGE_VALF) == HUGE_VALF && expm1l(HUGE_VALL) == HUGE_VALL);
	CHECK(expm1f(200.0f) == HUGE_VALF);		/* overflow at float width */
	CHECK(expm1l(100000.0L) == HUGE_VALL);
	CHECK(poszerof(log1pf(0.0f)) && negzerof(log1pf(-0.0f)));
	CHECK(poszerol(log1pl(0.0L)) && negzerol(log1pl(-0.0L)));
	CHECK(log1pf(HUGE_VALF) == HUGE_VALF && log1pl(HUGE_VALL) == HUGE_VALL);
	CHECK(log1pf(-1.0f) == -HUGE_VALF && log1pl(-1.0L) == -HUGE_VALL);   /* pole error */
	CHECK(isnan(log1pf(-2.0f)) && isnan(log1pf(-HUGE_VALF)));
	CHECK(isnan(log1pl(-2.0L)) && isnan(log1pl(-HUGE_VALL)));
}

/* erf.html/erfc.html at float and long double. */
static void test_erf_erfc_variants(void)
{
	CHECK(isnan(erff(NAN)) && isnan(erfcf(NAN)));
	CHECK(isnan(erfl(NAN)) && isnan(erfcl(NAN)));
	CHECK(poszerof(erff(0.0f)) && negzerof(erff(-0.0f)));
	CHECK(poszerol(erfl(0.0L)) && negzerol(erfl(-0.0L)));
	CHECK(erff(HUGE_VALF) == 1.0f && erff(-HUGE_VALF) == -1.0f);
	CHECK(erfl(HUGE_VALL) == 1.0L && erfl(-HUGE_VALL) == -1.0L);
	CHECK(poszerof(erfcf(HUGE_VALF)) && poszerol(erfcl(HUGE_VALL)));
	CHECK(erfcf(-HUGE_VALF) == 2.0f && erfcl(-HUGE_VALL) == 2.0L);
	/* Informational, never a CHECK: erfc(0) is exactly 1 mathematically,
	 * but POSIX mandates no accuracy for it (this file's banner), and
	 * src/math/erf.c's approximation returns 0.9999999990 at double and
	 * long-double width while the float form rounds to exactly 1.0f.
	 * Asserting == 1.0 here would be asserting an accuracy coincidence,
	 * not a clause -- and would have "failed" for the wrong reason. */
	printf("info: erfcf(0)=%.9g erfcl(0)=%.20Lg (POSIX mandates no accuracy)\n",
	       (double)erfcf(0.0f), erfcl(0.0L));
}

/* lgamma.html/tgamma.html at float and long double. */
static void test_gamma_variants(void)
{
	CHECK(isnan(lgammaf(NAN)) && isnan(tgammaf(NAN)));
	CHECK(isnan(lgammal(NAN)) && isnan(tgammal(NAN)));
	CHECK(lgammaf(0.0f) == HUGE_VALF && lgammaf(-1.0f) == HUGE_VALF);   /* pole error */
	CHECK(lgammal(0.0L) == HUGE_VALL && lgammal(-1.0L) == HUGE_VALL);
	CHECK(poszerof(lgammaf(1.0f)) && poszerof(lgammaf(2.0f)));
	CHECK(poszerol(lgammal(1.0L)) && poszerol(lgammal(2.0L)));
	CHECK(lgammaf(HUGE_VALF) == HUGE_VALF && lgammal(HUGE_VALL) == HUGE_VALL);
	CHECK(tgammaf(HUGE_VALF) == HUGE_VALF && tgammal(HUGE_VALL) == HUGE_VALL);
	CHECK(isnan(tgammaf(-HUGE_VALF)) && isnan(tgammal(-HUGE_VALL)));    /* domain error */
	CHECK(isnan(tgammaf(-2.0f)) && isnan(tgammal(-2.0L)));              /* negative integer */
	/* ±0 -> pole error, ±HUGE_VAL with the sign of x */
	CHECK(tgammaf(0.0f) == HUGE_VALF && tgammaf(-0.0f) == -HUGE_VALF);
	CHECK(tgammal(0.0L) == HUGE_VALL && tgammal(-0.0L) == -HUGE_VALL);
	/* tgamma(n) == (n-1)! for a small integer n.  Checked with a
	 * tolerance, not ==, for the same reason as erfc above: POSIX
	 * mandates no accuracy, and src/math/gamma.c's approximation lands a
	 * few ulp short of 24 at double/long-double width.  The tolerance is
	 * far tighter than any real defect could hide under, and its point
	 * is to catch an f/l form that dropped a conversion or routed
	 * through the wrong body -- not to pin the last bit. */
	CHECK(fabsf(tgammaf(5.0f) - 24.0f) < 1e-4f);
	CHECK(fabsl(tgammal(5.0L) - 24.0L) < 1e-6L);
}

/* fmod.html at long double (fmodf is already reached by test_fmod()'s
 * float half above).  RETURN VALUE/ERRORS: x REM y with a
 * round-toward-zero quotient; ±0 with y!=0 -> ±0; y==±0 with x non-NaN
 * -> domain error, NaN; x==±Inf -> domain error, NaN; y==±Inf with x
 * finite -> x. */
static void test_fmod_variants(void)
{
	CHECK(isnan(fmodl(NAN, 2.0L)) && isnan(fmodl(2.0L, NAN)));
	CHECK(poszerol(fmodl(0.0L, 2.0L)) && negzerol(fmodl(-0.0L, 2.0L)));
	CHECK(isnan(fmodl(2.0L, 0.0L)) && isnan(fmodl(2.0L, -0.0L)));    /* y==±0 */
	CHECK(isnan(fmodl(HUGE_VALL, 2.0L)) && isnan(fmodl(-HUGE_VALL, 2.0L)));
	CHECK(fmodl(2.5L, HUGE_VALL) == 2.5L);                            /* y==±Inf, x finite */
	/* round-toward-zero quotient, unlike remainderl()'s round-to-nearest */
	CHECK(fmodl(5.5L, 2.0L) == 1.5L);
	CHECK(fmodl(-5.5L, 2.0L) == -1.5L);				/* sign of x */
}

/* frexp.html/ldexp.html/modf.html at float and long double.
 * frexp.html: the result is in [0.5, 1) and value == result * 2^*exp;
 * "If value is 0, 0 shall be returned and 0 stored in *exp"; ±Inf/NaN
 * are returned unchanged with *exp unspecified.  ldexp.html: x * 2^exp;
 * NaN->NaN, ±0/±Inf->x, exp==0->x, overflow -> range error ±HUGE_VAL.
 * modf.html: the signed fractional part, with the integral part stored
 * through iptr; ±0 -> ±0 with ±0 stored; ±Inf -> ±0 with ±Inf stored. */
static void test_frexp_ldexp_modf_variants(void)
{
	int e;
	float ff, fi;
	long double lf, li;

	e = 12345;
	ff = frexpf(8.0f, &e);
	CHECK(ff == 0.5f && e == 4);
	CHECK(ff >= 0.5f && ff < 1.0f);
	e = 12345;
	lf = frexpl(8.0L, &e);
	CHECK(lf == 0.5L && e == 4);
	/* "If value is 0, 0 shall be returned and 0 stored in *exp" -- and
	 * the sign of the zero is preserved. */
	e = 12345;
	CHECK(poszerof(frexpf(0.0f, &e)) && e == 0);
	e = 12345;
	CHECK(negzerof(frexpf(-0.0f, &e)) && e == 0);
	e = 12345;
	CHECK(poszerol(frexpl(0.0L, &e)) && e == 0);
	e = 12345;
	CHECK(negzerol(frexpl(-0.0L, &e)) && e == 0);
	/* ±Inf and NaN come back unchanged (*exp unspecified, so unchecked) */
	CHECK(frexpf(HUGE_VALF, &e) == HUGE_VALF);
	CHECK(isnan(frexpf(NAN, &e)));
	CHECK(frexpl(-HUGE_VALL, &e) == -HUGE_VALL);
	CHECK(isnan(frexpl(NAN, &e)));
	/* round trip: value == frexp result * 2^exp */
	ff = frexpf(-3.75f, &e);
	CHECK(ldexpf(ff, e) == -3.75f);

	CHECK(isnan(ldexpf(NAN, 3)));
	CHECK(poszerof(ldexpf(0.0f, 3)) && negzerof(ldexpf(-0.0f, 3)));
	CHECK(ldexpf(HUGE_VALF, 3) == HUGE_VALF && ldexpf(-HUGE_VALF, 3) == -HUGE_VALF);
	CHECK(ldexpf(3.75f, 0) == 3.75f);
	CHECK(ldexpf(1.0f, 2) == 4.0f && ldexpf(1.0f, -2) == 0.25f);
	/* overflow at *float* width, not double width */
	CHECK(ldexpf(1.0f, 200) == HUGE_VALF && ldexpf(-1.0f, 200) == -HUGE_VALF);

	fi = 12345.0f;
	ff = modff(3.75f, &fi);
	CHECK(ff == 0.75f && fi == 3.0f);
	ff = modff(-3.75f, &fi);
	CHECK(ff == -0.75f && fi == -3.0f);		/* fraction carries x's sign */
	li = 12345.0L;
	lf = modfl(-3.75L, &li);
	CHECK(lf == -0.75L && li == -3.0L);
	/* ±0 -> ±0, with ±0 stored */
	CHECK(poszerof(modff(0.0f, &fi)) && poszerof(fi));
	CHECK(negzerof(modff(-0.0f, &fi)) && negzerof(fi));
	CHECK(poszerol(modfl(0.0L, &li)) && poszerol(li));
	CHECK(negzerol(modfl(-0.0L, &li)) && negzerol(li));
	/* ±Inf -> ±0, with ±Inf stored */
	CHECK(poszerof(modff(HUGE_VALF, &fi)) && fi == HUGE_VALF);
	CHECK(negzerof(modff(-HUGE_VALF, &fi)) && fi == -HUGE_VALF);
	CHECK(poszerol(modfl(HUGE_VALL, &li)) && li == HUGE_VALL);
	/* NaN -> NaN, with NaN stored */
	CHECK(isnan(modff(NAN, &fi)) && isnan(fi));
	CHECK(isnan(modfl(NAN, &li)) && isnan(li));
}

/* ceil.html/floor.html/round.html/trunc.html at the widths whose
 * variants nothing had called: ceilf, floorl, roundf, truncf, truncl.
 * All four pages define no errors and specify the rounding direction;
 * round() breaks halfway cases away from zero, unlike rint(). */
static void test_rounding_variants(void)
{
	CHECK(isnan(ceilf(NAN)) && isnan(floorl(NAN)));
	CHECK(isnan(roundf(NAN)) && isnan(truncf(NAN)) && isnan(truncl(NAN)));
	CHECK(poszerof(ceilf(0.0f)) && negzerof(ceilf(-0.0f)));
	CHECK(poszerol(floorl(0.0L)) && negzerol(floorl(-0.0L)));
	CHECK(poszerof(roundf(0.0f)) && negzerof(roundf(-0.0f)));
	CHECK(poszerof(truncf(0.0f)) && negzerof(truncf(-0.0f)));
	CHECK(poszerol(truncl(0.0L)) && negzerol(truncl(-0.0L)));
	CHECK(ceilf(HUGE_VALF) == HUGE_VALF && ceilf(-HUGE_VALF) == -HUGE_VALF);
	CHECK(floorl(HUGE_VALL) == HUGE_VALL && floorl(-HUGE_VALL) == -HUGE_VALL);
	CHECK(roundf(HUGE_VALF) == HUGE_VALF && truncl(-HUGE_VALL) == -HUGE_VALL);

	CHECK(ceilf(1.1f) == 2.0f && ceilf(-1.1f) == -1.0f);
	CHECK(floorl(1.9L) == 1.0L && floorl(-1.1L) == -2.0L);
	CHECK(truncf(1.9f) == 1.0f && truncf(-1.9f) == -1.0f);
	CHECK(truncl(1.9L) == 1.0L && truncl(-1.9L) == -1.0L);
	/* "rounding halfway cases away from zero" -- the clause that makes
	 * round() different from rint()/nearbyint(), which round to even */
	CHECK(roundf(0.5f) == 1.0f && roundf(-0.5f) == -1.0f);
	CHECK(roundf(1.5f) == 2.0f && roundf(2.5f) == 3.0f);
	/* a negative result that rounds to zero must keep the sign */
	CHECK(negzerof(roundf(-0.4f)) && negzerof(truncf(-0.4f)));
	CHECK(negzerol(truncl(-0.4L)) && negzerol(floorl(-0.0L)));
}

/* hypot.html at float and long double.  The clause worth the trip is the
 * NaN/Inf ordering: "If x or y is ±Inf, +Inf shall be returned even if
 * one of x or y is NaN." */
static void test_hypot_variants(void)
{
	CHECK(hypotf(3.0f, 4.0f) == 5.0f);
	CHECK(hypotl(3.0L, 4.0L) == 5.0L);
	CHECK(hypotf(HUGE_VALF, NAN) == HUGE_VALF && hypotf(NAN, -HUGE_VALF) == HUGE_VALF);
	CHECK(hypotl(HUGE_VALL, NAN) == HUGE_VALL && hypotl(NAN, -HUGE_VALL) == HUGE_VALL);
	CHECK(isnan(hypotf(NAN, 1.0f)) && isnan(hypotf(1.0f, NAN)));
	CHECK(isnan(hypotl(NAN, 1.0L)) && isnan(hypotl(1.0L, NAN)));
	CHECK(hypotf(0.0f, -3.0f) == 3.0f && hypotl(-0.0L, 3.0L) == 3.0L);
	/* overflow -> range error, HUGE_VAL{F,L}, at each type's own width */
	CHECK(hypotf(FLT_MAX, FLT_MAX) == HUGE_VALF);
}

/* ilogb.html/logb.html at float and long double.  ilogb's three
 * out-of-band results (FP_ILOGB0, FP_ILOGBNAN, INT_MAX) are the same
 * int-typed constants at every width, which is exactly what makes a
 * per-width check worth having. */
static void test_ilogb_logb_variants(void)
{
	CHECK(isnan(logbf(NAN)) && isnan(logbl(NAN)));
	CHECK(logbf(0.0f) == -HUGE_VALF && logbf(-0.0f) == -HUGE_VALF);   /* pole error */
	CHECK(logbl(0.0L) == -HUGE_VALL && logbl(-0.0L) == -HUGE_VALL);
	CHECK(logbf(HUGE_VALF) == HUGE_VALF && logbf(-HUGE_VALF) == HUGE_VALF);
	CHECK(logbl(HUGE_VALL) == HUGE_VALL && logbl(-HUGE_VALL) == HUGE_VALL);
	CHECK(logbf(8.0f) == 3.0f && logbl(8.0L) == 3.0L);
	CHECK(logbf(0.5f) == -1.0f && logbl(0.5L) == -1.0L);

	CHECK(ilogbf(0.0f) == FP_ILOGB0 && ilogbl(0.0L) == FP_ILOGB0);
	CHECK(ilogbf(NAN) == FP_ILOGBNAN && ilogbl(NAN) == FP_ILOGBNAN);
	CHECK(ilogbf(HUGE_VALF) == INT_MAX && ilogbl(HUGE_VALL) == INT_MAX);
	CHECK(ilogbf(8.0f) == 3 && ilogbl(8.0L) == 3);
	/* "equivalent to (int)logb(x)" for the in-range cases */
	CHECK(ilogbf(0.5f) == (int)logbf(0.5f));
	CHECK(ilogbl(0.5L) == (int)logbl(0.5L));
}

/* nearbyint.html at float and long double, including the clause that
 * distinguishes it from rint(): "without raising the inexact
 * floating-point exception". */
static void test_nearbyint_variants(void)
{
	CHECK(isnan(nearbyintf(NAN)) && isnan(nearbyintl(NAN)));
	CHECK(poszerof(nearbyintf(0.0f)) && negzerof(nearbyintf(-0.0f)));
	CHECK(poszerol(nearbyintl(0.0L)) && negzerol(nearbyintl(-0.0L)));
	CHECK(nearbyintf(HUGE_VALF) == HUGE_VALF && nearbyintf(-HUGE_VALF) == -HUGE_VALF);
	CHECK(nearbyintl(HUGE_VALL) == HUGE_VALL && nearbyintl(-HUGE_VALL) == -HUGE_VALL);
	CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
	CHECK(nearbyintf(2.5f) == 2.0f);		/* default rounding: to even */
	CHECK(nearbyintl(2.5L) == 2.0L);
	CHECK(fetestexcept(FE_INEXACT) == 0);
}

/* nextafter.html/nexttoward.html at float and long double.  nexttoward's
 * second argument is `long double` at every width, which is the shape
 * most likely to be got wrong by a mechanical f-wrapper. */
static void test_nextafter_variants(void)
{
	CHECK(nextafterf(1.0f, 1.0f) == 1.0f);
	CHECK(nextafterl(1.0L, 1.0L) == 1.0L);
	CHECK(isnan(nextafterf(NAN, 1.0f)) && isnan(nextafterf(1.0f, NAN)));
	CHECK(isnan(nextafterl(NAN, 1.0L)) && isnan(nextafterl(1.0L, NAN)));
	CHECK(nextafterf(1.0f, 2.0f) > 1.0f && nextafterf(1.0f, 0.0f) < 1.0f);
	CHECK(nextafterl(1.0L, 2.0L) > 1.0L && nextafterl(1.0L, 0.0L) < 1.0L);
	/* one step and back is the identity */
	CHECK(nextafterf(nextafterf(1.0f, 2.0f), 0.0f) == 1.0f);
	CHECK(nextafterl(nextafterl(1.0L, 2.0L), 0.0L) == 1.0L);
	/* overflow -> range error, ±HUGE_VALF at *float* width */
	CHECK(nextafterf(FLT_MAX, HUGE_VALF) == HUGE_VALF);
	CHECK(nextafterf(-FLT_MAX, -HUGE_VALF) == -HUGE_VALF);
	/* underflow: "the correct value (if representable) or 0.0" */
	CHECK(poszerof(nextafterf(FLT_MIN, 0.0f)) || nextafterf(FLT_MIN, 0.0f) > 0.0f);

	CHECK(nexttowardf(1.0f, 1.0L) == 1.0f);		/* x == y -> y, in x's type */
	CHECK(isnan(nexttowardf(NAN, 1.0L)) && isnan(nexttowardf(1.0f, NAN)));
	CHECK(nexttowardf(1.0f, 2.0L) > 1.0f && nexttowardf(1.0f, 0.0L) < 1.0f);
	CHECK(nexttowardf(FLT_MAX, HUGE_VALL) == HUGE_VALF);
	CHECK(nexttowardl(1.0L, 1.0L) == 1.0L);
	CHECK(isnan(nexttowardl(NAN, 1.0L)) && isnan(nexttowardl(1.0L, NAN)));
	CHECK(nexttowardl(1.0L, 2.0L) > 1.0L && nexttowardl(1.0L, 0.0L) < 1.0L);
	/* nexttowardf and nextafterf must agree where both are defined */
	CHECK(nexttowardf(1.0f, 2.0L) == nextafterf(1.0f, 2.0f));
}

/* remainder.html/remquo.html at float and long double. */
static void test_remainder_remquo_variants(void)
{
	int quo;

	CHECK(isnan(remainderf(NAN, 2.0f)) && isnan(remainderf(2.0f, NAN)));
	CHECK(isnan(remainderl(NAN, 2.0L)) && isnan(remainderl(2.0L, NAN)));
	CHECK(isnan(remainderf(HUGE_VALF, 2.0f)) && isnan(remainderl(HUGE_VALL, 2.0L)));
	CHECK(isnan(remainderf(2.0f, 0.0f)) && isnan(remainderl(2.0L, 0.0L)));
	/* round-to-nearest quotient (3), unlike fmodf(5.5,2.0)==1.5 */
	CHECK(remainderf(5.5f, 2.0f) == -0.5f);
	CHECK(remainderl(5.5L, 2.0L) == -0.5L);

	quo = 12345;
	CHECK(isnan(remquof(NAN, 2.0f, &quo)) && isnan(remquof(2.0f, NAN, &quo)));
	CHECK(isnan(remquol(NAN, 2.0L, &quo)) && isnan(remquol(2.0L, NAN, &quo)));
	CHECK(isnan(remquof(HUGE_VALF, 2.0f, &quo)) && isnan(remquol(HUGE_VALL, 2.0L, &quo)));
	CHECK(isnan(remquof(2.0f, 0.0f, &quo)) && isnan(remquol(2.0L, 0.0L, &quo)));
	/* "a value whose sign is the sign of x/y and whose magnitude is
	 * congruent modulo 2^n to the magnitude of the integral quotient",
	 * n >= 3 */
	CHECK(remquof(5.5f, 2.0f, &quo) == -0.5f && (quo & 7) == 3);
	CHECK(remquol(5.5L, 2.0L, &quo) == -0.5L && (quo & 7) == 3);
	CHECK(remquof(-5.5f, 2.0f, &quo) == 0.5f && quo < 0);	/* sign of x/y */
	CHECK(remquof(5.5f, -2.0f, &quo) == -0.5f && quo < 0);
	/* the remainder agrees with remainderf's, as the page requires */
	CHECK(remquof(5.5f, 2.0f, &quo) == remainderf(5.5f, 2.0f));
	CHECK(remquol(5.5L, 2.0L, &quo) == remainderl(5.5L, 2.0L));
}

/* fdim.html and fma.html at float and long double. */
static void test_fdim_fma_variants(void)
{
	CHECK(fdimf(5.0f, 3.0f) == 2.0f && fdiml(5.0L, 3.0L) == 2.0L);
	CHECK(poszerof(fdimf(3.0f, 5.0f)) && poszerol(fdiml(3.0L, 5.0L)));
	CHECK(isnan(fdimf(NAN, 1.0f)) && isnan(fdimf(1.0f, NAN)));
	CHECK(isnan(fdiml(NAN, 1.0L)) && isnan(fdiml(1.0L, NAN)));
	/* overflow -> range error, HUGE_VAL{F,L}, at each type's own width */
	CHECK(fdimf(FLT_MAX, -FLT_MAX) == HUGE_VALF);

	CHECK(fmaf(2.0f, 3.0f, 4.0f) == 10.0f && fmal(2.0L, 3.0L, 4.0L) == 10.0L);
	CHECK(isnan(fmaf(NAN, 1.0f, 1.0f)) && isnan(fmaf(1.0f, NAN, 1.0f)));
	CHECK(isnan(fmal(NAN, 1.0L, 1.0L)) && isnan(fmal(1.0L, NAN, 1.0L)));
	CHECK(isnan(fmaf(0.0f, HUGE_VALF, 1.0f)));			/* 0*Inf, z non-NaN */
	CHECK(isnan(fmal(0.0L, HUGE_VALL, 1.0L)));
	CHECK(isnan(fmaf(HUGE_VALF, 1.0f, -HUGE_VALF)));		/* +Inf + -Inf */
	CHECK(isnan(fmal(HUGE_VALL, 1.0L, -HUGE_VALL)));
	CHECK(isnan(fmaf(2.0f, 3.0f, NAN)) && isnan(fmal(2.0L, 3.0L, NAN)));
	CHECK(poszerof(fmaf(0.0f, 1.0f, 0.0f)) && negzerof(fmaf(-0.0f, 1.0f, -0.0f)));
}

/* scalbn.html/scalbln.html at the widths whose variants nothing had
 * called: scalbnl, scalblnf, scalblnl.  x * FLT_RADIX^n; NaN->NaN;
 * ±0/±Inf->x; n==0->x; overflow -> range error ±HUGE_VAL; underflow ->
 * range error, 0.0 or the correct value. */
static void test_scalb_variants(void)
{
	CHECK(isnan(scalbnl(NAN, 5)) && isnan(scalblnf(NAN, 5L)) && isnan(scalblnl(NAN, 5L)));
	CHECK(poszerol(scalbnl(0.0L, 5)) && negzerol(scalbnl(-0.0L, 5)));
	CHECK(poszerof(scalblnf(0.0f, 5L)) && negzerof(scalblnf(-0.0f, 5L)));
	CHECK(poszerol(scalblnl(0.0L, 5L)) && negzerol(scalblnl(-0.0L, 5L)));
	CHECK(scalbnl(HUGE_VALL, 5) == HUGE_VALL && scalbnl(-HUGE_VALL, 5) == -HUGE_VALL);
	CHECK(scalblnf(HUGE_VALF, 5L) == HUGE_VALF && scalblnl(-HUGE_VALL, 5L) == -HUGE_VALL);
	CHECK(scalbnl(3.75L, 0) == 3.75L && scalblnf(3.75f, 0L) == 3.75f && scalblnl(3.75L, 0L) == 3.75L);
	CHECK(scalbnl(1.0L, 2) == 4.0L && scalblnf(1.0f, 2L) == 4.0f && scalblnl(1.0L, -2L) == 0.25L);
	/* overflow at each type's own width: 200 overflows a float and does
	 * not come close to overflowing a long double */
	CHECK(scalblnf(1.0f, 200L) == HUGE_VALF && scalblnf(-1.0f, 200L) == -HUGE_VALF);
	CHECK(scalbnl(1.0L, 20000) == HUGE_VALL && scalblnl(-1.0L, 20000L) == -HUGE_VALL);
	/* underflow -> 0.0 or the correct value */
	CHECK(poszerof(scalblnf(1.0f, -200L)) || scalblnf(1.0f, -200L) > 0.0f);
	CHECK(poszerol(scalbnl(1.0L, -20000)) || scalbnl(1.0L, -20000) > 0.0L);
}

/* isgreater.html and its five siblings (isgreaterequal.html,
 * isless.html, islessequal.html, islessgreater.html,
 * isunordered.html).  These are the six names in the never-asserted
 * math.h list that are not f/l variants of anything: they are macros,
 * defined in include/math.h.
 *
 * DESCRIPTION: "unlike (x) > (y), isgreater(x, y) shall not raise the
 * invalid floating-point exception when x and y are unordered" -- the
 * whole reason the macros exist, and directly testable through <fenv.h>.
 * RETURN VALUE: "the value of (x) > (y).  If x or y is NaN, 0 shall be
 * returned."  isunordered() returns "1 if its arguments are unordered, 0
 * otherwise".  ERRORS: "No errors are defined." */
static void test_compare_macros(void)
{
	CHECK(isgreater(2.0, 1.0) == 1 && isgreater(1.0, 2.0) == 0 && isgreater(1.0, 1.0) == 0);
	CHECK(isgreaterequal(2.0, 1.0) == 1 && isgreaterequal(1.0, 1.0) == 1 && isgreaterequal(1.0, 2.0) == 0);
	CHECK(isless(1.0, 2.0) == 1 && isless(2.0, 1.0) == 0 && isless(1.0, 1.0) == 0);
	CHECK(islessequal(1.0, 2.0) == 1 && islessequal(1.0, 1.0) == 1 && islessequal(2.0, 1.0) == 0);
	CHECK(islessgreater(1.0, 2.0) == 1 && islessgreater(2.0, 1.0) == 1 && islessgreater(1.0, 1.0) == 0);
	CHECK(isunordered(1.0, 2.0) == 0);

	/* "If x or y is NaN, 0 shall be returned" -- for all five ordered
	 * macros, in both argument positions.  islessgreater() is the one
	 * that must not be confused with !=, which is true for NaN. */
	CHECK(isgreater(NAN, 1.0) == 0 && isgreater(1.0, NAN) == 0);
	CHECK(isgreaterequal(NAN, 1.0) == 0 && isgreaterequal(1.0, NAN) == 0);
	CHECK(isless(NAN, 1.0) == 0 && isless(1.0, NAN) == 0);
	CHECK(islessequal(NAN, 1.0) == 0 && islessequal(1.0, NAN) == 0);
	CHECK(islessgreater(NAN, 1.0) == 0 && islessgreater(1.0, NAN) == 0);
	CHECK(islessgreater(NAN, NAN) == 0);
	/* isunordered: 1 when either (or both) is NaN */
	CHECK(isunordered(NAN, 1.0) == 1 && isunordered(1.0, NAN) == 1 && isunordered(NAN, NAN) == 1);

	/* ±Inf is ordered against everything but NaN */
	CHECK(isgreater(HUGE_VAL, 1.0) == 1 && isless(-HUGE_VAL, 1.0) == 1);
	CHECK(isunordered(HUGE_VAL, -HUGE_VAL) == 0);

	/* The distinguishing clause: no FE_INVALID for unordered operands,
	 * where a plain > would raise it.
	 *
	 * The NaN is hoisted into a volatile *before* the flags are cleared
	 * on purpose.  include/math.h defines NAN as (0.0f/0.0f), and that
	 * division is itself what raises FE_INVALID here -- evaluating the
	 * macro inside the guarded region sets the very flag being measured
	 * and would fail this test for a reason that has nothing to do with
	 * the comparison macros.  (C99 wants NAN to be a constant
	 * expression, which would be folded and raise nothing; it is not
	 * folded on this toolchain.  That is a header/codegen matter, not a
	 * POSIX conformance clause about these macros, so it is noted here
	 * rather than fenced.)  `one` is volatile for the same reason: to
	 * keep the whole comparison out of the constant folder. */
	{
		volatile double qnan = NAN, one = 1.0;
		CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
		CHECK(isgreater(qnan, one) == 0);
		CHECK(isgreaterequal(qnan, one) == 0);
		CHECK(isless(qnan, one) == 0);
		CHECK(islessequal(qnan, one) == 0);
		CHECK(islessgreater(qnan, one) == 0);
		CHECK(isunordered(qnan, one) == 1);
		CHECK(fetestexcept(FE_INVALID) == 0);
	}

	/* they work at float and long double too, not just double */
	CHECK(isgreater(2.0f, 1.0f) == 1 && isunordered((float)NAN, 1.0f) == 1);
	CHECK(isless(1.0L, 2.0L) == 1 && isunordered((long double)NAN, 1.0L) == 1);
}


/* ==== <fenv.h>, clause by clause ==========================================
 *
 * test_errhandling() above reaches most of this header incidentally, on
 * its way to math.h's math_errhandling contract: it pins the macro
 * values, the flags against real hardware exceptions (sqrt(-1),
 * log(0), DBL_MAX*DBL_MAX, DBL_MIN/1e16, 1.0/3.0), one
 * fegetexceptflag/fesetexceptflag round trip, one fegetround/fesetround
 * round trip, and feholdexcept/feupdateenv(&env). What follows are the
 * clauses of the eleven functions' own spec pages that nothing checked
 * -- test/POSIX-GAP-ACCOUNTING.md lists <fenv.h> as one of the headers
 * test/POSIX-COVERAGE.md's priority order never named at all.
 *
 * The environment captured at the very top of main() is used below;
 * every one of these functions can perturb the FPU, so "the environment
 * installed at program startup" cannot be sampled from here.
 */
/* Captured as the very first thing main() does; see test_fenv_dfl_env_is_startup_env(). */
fenv_t g_startup_env;
int g_startup_env_ok;

/* The x87 control word is the first two bytes of the FSTENV image that
 * fenv_t wraps, on both arches. Read through unsigned char rather than
 * fenv_t's members, which are implementation-private. Rounding control
 * (bits 10-11) is masked off: fesetround() legitimately changes it, and
 * the clauses below are about the rest of the word. */
static unsigned fenv_x87_cw_no_rc(const fenv_t *e)
{
	const unsigned char *b = (const unsigned char *)e;
	return ((unsigned)b[1] << 8 | b[0]) & ~0x0c00u;
}

/* AArch64's counterpart: fenv_t's first four bytes are FPCR (rounding
 * mode, trap enables, and the mode bits like FZ that neither reaches --
 * see arch/aarch64/bits/fenv.h). Read through unsigned char for the
 * same reason as above: fenv_t's members are implementation-private. */
static unsigned int fenv_aarch64_fpcr(const fenv_t *e)
{
	const unsigned char *b = (const unsigned char *)e;
	return (unsigned int)b[0] | (unsigned int)b[1] << 8 |
	       (unsigned int)b[2] << 16 | (unsigned int)b[3] << 24;
}

#if defined(__aarch64__)
/* mrs/msr operate on 64-bit Xn registers; narrowing through `unsigned
 * long` rather than handing clang a 32-bit operand directly is the same
 * choice src/math/fenv.c's own read_fpcr()/write_fpcr() make, for the
 * same reason (avoids a register/operand width mismatch). */
static unsigned int test_read_fpcr(void)
{
	unsigned long v;
	__asm__ __volatile__("mrs %0, fpcr" : "=r"(v));
	return (unsigned int)v;
}

static void test_write_fpcr(unsigned int v)
{
	unsigned long vv = v;
	__asm__ __volatile__("msr fpcr, %0" : : "r"(vv));
}
#endif

/* feclearexcept.html/feraiseexcept.html/fetestexcept.html/
 * fegetexceptflag.html RETURN VALUE, the clause each of the five flag
 * functions states for a zero argument:
 *   feclearexcept: "shall return zero if ... the argument is zero"
 *   feraiseexcept: "shall return zero if ... excepts is zero"
 *   fesetexceptflag: "shall return zero if excepts is zero or if all
 *     the specified exceptions were successfully set"
 * and fetestexcept's "bitwise-inclusive OR of the ... macros
 * corresponding to the ... exceptions included in excepts", which for
 * an empty subset is zero. A zero argument is the degenerate case an
 * implementation that forgot to mask its input gets wrong. */
static void test_fenv_zero_argument(void)
{
	fexcept_t f;

	feclearexcept(FE_ALL_EXCEPT);
	feraiseexcept(FE_INVALID);		/* something is set, so "returns 0" is not vacuous */
	CHECK(feclearexcept(0) == 0);
	CHECK(fetestexcept(FE_INVALID) == FE_INVALID);	/* ... and cleared nothing */
	CHECK(feraiseexcept(0) == 0);
	CHECK(fetestexcept(FE_INVALID) == FE_INVALID);	/* ... and raised nothing */
	CHECK(fetestexcept(0) == 0);
	CHECK(fegetexceptflag(&f, 0) == 0);
	CHECK(fesetexceptflag(&f, 0) == 0);
	feclearexcept(FE_ALL_EXCEPT);
}

/* fetestexcept.html RETURN VALUE: "shall return the value of the
 * bitwise-inclusive OR of the floating-point exception macros
 * corresponding to the currently set floating-point exceptions
 * included in excepts." The "included in excepts" half -- that the
 * result is a *subset* of the argument, not the whole status word --
 * is what distinguishes a correct implementation from one that ignores
 * its argument, and it was not checked. */
static void test_fenv_testexcept_subset(void)
{
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(feraiseexcept(FE_INVALID | FE_OVERFLOW) == 0);
	CHECK(fetestexcept(FE_DIVBYZERO) == 0);		/* not raised: not reported */
	CHECK(fetestexcept(FE_INVALID) == FE_INVALID);
	CHECK(fetestexcept(FE_INVALID | FE_DIVBYZERO) == FE_INVALID);	/* subset, not the word */
	CHECK(fetestexcept(FE_ALL_EXCEPT) == (FE_INVALID | FE_OVERFLOW));
	feclearexcept(FE_ALL_EXCEPT);
}

/* feraiseexcept.html DESCRIPTION: "The feraiseexcept() function shall
 * attempt to raise the supported floating-point exceptions represented
 * by the excepts argument" and "Whether the feraiseexcept() function
 * additionally raises the inexact floating-point exception whenever it
 * raises the overflow or underflow floating-point exception is
 * implementation-defined." Both halves recorded: exactly what was
 * asked for becomes set, and this implementation's answer to the
 * implementation-defined question is "no". */
static void test_fenv_raise_exact_set(void)
{
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(feraiseexcept(FE_OVERFLOW) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == FE_OVERFLOW);	/* no gratuitous FE_INEXACT */
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(feraiseexcept(FE_OVERFLOW | FE_INEXACT) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == (FE_OVERFLOW | FE_INEXACT));
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(feraiseexcept(FE_UNDERFLOW) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == FE_UNDERFLOW);
	feclearexcept(FE_ALL_EXCEPT);
}

/* fegetround.html DESCRIPTION: "The fesetround() function shall
 * establish the rounding direction represented by its argument round.
 * If the argument is not equal to the value of a rounding direction
 * macro, the rounding direction is not changed." test_errhandling()
 * checks that a bad value returns non-zero; the "not changed" half --
 * the part that matters, since a failed call that had already written
 * a partial control word would silently corrupt the mode -- was not
 * checked. All four macros are exercised, not just one.
 *
 * basedefs/fenv.h.html additionally requires the four macros to have
 * "distinct non-negative values". */
static void test_fenv_round_modes(void)
{
	static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
	int i, j;

	for (i = 0; i < 4; i++) {
		CHECK(modes[i] >= 0);
		for (j = i + 1; j < 4; j++) CHECK(modes[i] != modes[j]);
	}
	for (i = 0; i < 4; i++) {
		CHECK(fesetround(modes[i]) == 0);
		CHECK(fegetround() == modes[i]);
		/* "the rounding direction is not changed" */
		CHECK(fesetround(0xdead) != 0);
		CHECK(fegetround() == modes[i]);
	}
	CHECK(fesetround(FE_TONEAREST) == 0);
}

/* fegetround.html DESCRIPTION again: the rounding direction is the one
 * arithmetic actually obeys, so the checkable content of fesetround()
 * is not that fegetround() agrees with it -- both could read the same
 * wrong register -- but that a plain `double` division changes result.
 * This is the assertion that would have caught a fesetround() which
 * programmed only the x87 control word while tcc/x86_64 emits SSE
 * (divsd) for `double` arithmetic; include/fenv.h's own banner
 * documents that split, and src/math/fenv.c does program MXCSR, but
 * nothing pinned it. `volatile` defeats constant folding. */
static void test_fenv_round_affects_arithmetic(void)
{
	volatile double a = 1.0, b = 3.0, nearest, up, down;

	CHECK(fesetround(FE_TONEAREST) == 0);
	nearest = a / b;
	CHECK(fesetround(FE_UPWARD) == 0);
	up = a / b;
	CHECK(fesetround(FE_DOWNWARD) == 0);
	down = a / b;
	CHECK(fesetround(FE_TONEAREST) == 0);
	CHECK(up > down);
	CHECK(nearest >= down && nearest <= up);
}

/* fegetenv.html/fesetenv.html DESCRIPTION: fesetenv() "shall attempt
 * to establish the floating-point environment represented by the
 * object pointed to by envp", where that object "shall be set by a
 * call to fegetenv() or feholdexcept(), or equal a floating-point
 * environment macro"; and it "does not raise floating-point
 * exceptions, but only installs the state of the floating-point status
 * flags represented through its argument." Nothing asserted fesetenv()
 * directly at all -- a full round trip, including the status flags
 * riding along inside the environment. */
static void test_fenv_env_roundtrip(void)
{
	fenv_t saved, mid, back;

	CHECK(fegetenv(&saved) == 0);

	feclearexcept(FE_ALL_EXCEPT);
	CHECK(fesetround(FE_DOWNWARD) == 0);
	CHECK(feraiseexcept(FE_DIVBYZERO | FE_INEXACT) == 0);
	CHECK(fegetenv(&mid) == 0);

	/* Perturb everything the captured environment describes ... */
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(fesetround(FE_UPWARD) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == 0);

	/* ... then put it back, and find both halves restored. */
	CHECK(fesetenv(&mid) == 0);
	CHECK(fegetround() == FE_DOWNWARD);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == (FE_DIVBYZERO | FE_INEXACT));

	CHECK(fegetenv(&back) == 0);
	CHECK(fenv_x87_cw_no_rc(&back) == fenv_x87_cw_no_rc(&mid));

	CHECK(fesetenv(&saved) == 0);
	CHECK(fesetround(FE_TONEAREST) == 0);
	feclearexcept(FE_ALL_EXCEPT);
}

/* feupdateenv.html DESCRIPTION: "The feupdateenv() function shall
 * attempt to save the currently raised floating-point exceptions in
 * its automatic storage, attempt to install the floating-point
 * environment represented by the object pointed to by envp, and then
 * attempt to raise the saved floating-point exceptions."
 *
 * test_errhandling() covers feupdateenv(&env) where env was captured
 * with feholdexcept() -- but feholdexcept() saves an environment whose
 * status flags may already carry the exceptions being tested, so a
 * feupdateenv() that installed the environment and forgot to re-raise
 * could still pass. FE_DFL_ENV is the strict form: it has no status
 * flags at all, so anything set afterwards can only have come from the
 * re-raise. */
static void test_fenv_updateenv_reraises(void)
{
	fenv_t held;

	feclearexcept(FE_ALL_EXCEPT);
	CHECK(feholdexcept(&held) == 0);
	CHECK(feraiseexcept(FE_INVALID | FE_INEXACT) == 0);
	CHECK(feupdateenv(FE_DFL_ENV) == 0);
	CHECK(fetestexcept(FE_ALL_EXCEPT) == (FE_INVALID | FE_INEXACT));
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(fesetround(FE_TONEAREST) == 0);
}

/* The same clause, but pinning WHEN the default environment is captured
 * rather than what it contains.
 *
 * test_fenv_dfl_env_is_startup_env() below compares FE_DFL_ENV against
 * the environment main() recorded, which catches a WRONG default (the
 * hardcoded 0x037F this library used to install) but NOT a default
 * captured too late: a capture taken at first use records whatever the
 * environment happened to be by then and enshrines it as "startup".
 * Mutation-testing showed that gap directly -- removing crt1's
 * __fenv_init() call left that test passing.
 *
 * So this one perturbs the environment FIRST -- widening x87 precision
 * control to 64-bit, which nothing else in this file does -- and then
 * requires FE_DFL_ENV to still describe the startup state.  A capture
 * taken at first use would have recorded the widened value here and the
 * comparison would fail.
 *
 * It must therefore run BEFORE every other test that touches FE_DFL_ENV
 * (test_fenv_updateenv_reraises() among them), or the first-use capture
 * would already have happened somewhere clean and the discriminator
 * would be spent.  Its position in main() is part of the assertion; see
 * the note there.
 *
 * Precision control is the field to perturb because it is the one the
 * old hardcoded constant got wrong, and because fesetround() cannot
 * reach it -- so no other test can disturb this one by accident. */
static void test_fenv_dfl_env_captured_at_startup(void)
{
	fenv_t e;

	CHECK(g_startup_env_ok);
#if defined(__i386__) || defined(__x86_64__)
	{
		unsigned short orig, cw;

		__asm__ __volatile__("fnstcw %0" : "=m"(orig));
		cw = (unsigned short)(orig | 0x0300u);	/* PC = 64-bit (extended) */
		__asm__ __volatile__("fldcw %0" : : "m"(cw));

		CHECK(fesetenv(FE_DFL_ENV) == 0);
		CHECK(fegetenv(&e) == 0);
		CHECK((fenv_x87_cw_no_rc(&e) & 0x0300u) ==
		      (fenv_x87_cw_no_rc(&g_startup_env) & 0x0300u));

		/* restore exactly what was found on entry -- process-global state */
		__asm__ __volatile__("fldcw %0" : : "m"(orig));
	}
#elif defined(__aarch64__)
	{
		unsigned int orig, fpcr;

		/* FPCR has no x87-style precision control, but FZ (flush-to-zero,
		 * bit 24) plays the same role this test needs: a mode bit
		 * fesetround() cannot reach. */
		orig = test_read_fpcr();
		fpcr = orig | (1u << 24);
		test_write_fpcr(fpcr);

		CHECK(fesetenv(FE_DFL_ENV) == 0);
		CHECK(fegetenv(&e) == 0);
		CHECK((fenv_aarch64_fpcr(&e) & (1u << 24)) ==
		      (fenv_aarch64_fpcr(&g_startup_env) & (1u << 24)));

		/* restore exactly what was found on entry -- process-global state */
		test_write_fpcr(orig);
	}
#endif
}

static void test_fenv_dfl_env_is_startup_env(void)
{
	fenv_t dfl;
	CHECK(g_startup_env_ok);
	CHECK(fesetenv(FE_DFL_ENV) == 0);
	CHECK(fegetenv(&dfl) == 0);
	CHECK(fenv_x87_cw_no_rc(&dfl) == fenv_x87_cw_no_rc(&g_startup_env));
}

static void test_fenv_getenv_does_not_modify(void)
{
	fenv_t e;
#if defined(__i386__) || defined(__x86_64__)
	unsigned short cw, orig;
#endif

	/* Save the control word found on entry and restore exactly it at the
	 * end.  Exception masking is process-global hardware state, and a
	 * test that changes it owes the rest of the run an exact restore.
	 *
	 * AND DO NOT "RESTORE" WITH fesetenv(&e).  `e` was captured AFTER
	 * this test unmasked divide-by-zero, so installing it puts the
	 * process back into the unmasked state rather than the one found on
	 * entry -- and now that fegetenv() faithfully preserves the control
	 * word (it used to mask everything as an FNSTENV side effect, which
	 * silently made `e` safe to install), FLDENV of an environment whose
	 * divide-by-zero is unmasked AND whose status word has the
	 * corresponding flag pending raises the exception on the spot.  That
	 * is a hardware FPE inside fesetenv(), not a failed assertion:
	 * observed natively under tools/asan-build.sh as
	 * "AddressSanitizer: FPE ... in fesetenv".
	 *
	 * So the round trip is deliberately NOT exercised here;
	 * test_fenv_env_roundtrip() covers fesetenv() on an environment that
	 * is safe to install. */
#if defined(__i386__) || defined(__x86_64__)
	__asm__ __volatile__("fnstcw %0" : "=m"(orig));
	cw = orig & (unsigned short)~0x04u;	/* unmask divide-by-zero (ZM) */
	__asm__ __volatile__("fldcw %0" : : "m"(cw));

	CHECK(fegetenv(&e) == 0);

	__asm__ __volatile__("fnstcw %0" : "=m"(cw));
	CHECK((cw & 0x04) == 0);		/* fegetenv must not have masked it */

	__asm__ __volatile__("fldcw %0" : : "m"(orig));
#elif defined(__aarch64__)
	{
		unsigned int fpcr, orig32;

		/* fegetenv() here is two plain mrs reads (src/math/fenv.c's own
		 * aarch64 banner), so it has no FNSTENV-style side effect to
		 * undo -- but the check is worth keeping as real coverage
		 * against a regression, mirroring the x86 case above with
		 * FPCR's DZE trap-enable bit (9) in place of the x87 ZM mask
		 * bit: unmasked here means the bit is SET, not clear. */
		orig32 = test_read_fpcr();
		fpcr = orig32 | (1u << 9);
		test_write_fpcr(fpcr);

		CHECK(fegetenv(&e) == 0);

		fpcr = test_read_fpcr();
		CHECK((fpcr & (1u << 9)) != 0);	/* fegetenv must not have masked it */

		test_write_fpcr(orig32);
	}
#endif
}

static void test_fenv_holdexcept_installs_nonstop(void)
{
#ifdef __x86_64__
	fenv_t h;
	unsigned int mx, orig;

	/* Save the ORIGINAL MXCSR, and restore it at the end rather than
	 * relying on fesetenv(&h).
	 *
	 * This matters and is not defensive tidiness: `h` is captured by
	 * feholdexcept() AFTER this test has unmasked divide-by-zero, so
	 * restoring it puts the process back into the UNMASKED state.  Every
	 * later test in this file then runs with SSE divide-by-zero trapping,
	 * and the first 1.0/0.0 in any of them kills the process -- no
	 * output, no summary, just a nonzero exit.  Exception masking is
	 * process-global hardware state, so a test that changes it owes the
	 * rest of the run an exact restore of what it found. */
	__asm__ __volatile__("stmxcsr %0" : "=m"(orig));
	mx = orig & ~0x200u;			/* unmask divide-by-zero in SSE */
	__asm__ __volatile__("ldmxcsr %0" : : "m"(mx));

	CHECK(feholdexcept(&h) == 0);

	__asm__ __volatile__("stmxcsr %0" : "=m"(mx));
	CHECK((mx & 0x1f80u) == 0x1f80u);

	CHECK(fesetenv(&h) == 0);
	__asm__ __volatile__("ldmxcsr %0" : : "m"(orig));
#elif defined(__aarch64__)
	fenv_t h;
	unsigned int fpcr, orig;

	/* Same test, FPCR's five trap-enable bits (8-12, see
	 * src/math/fenv.c's aarch64 feholdexcept()) in place of MXCSR's six
	 * mask bits -- and the opposite polarity: non-stop mode is these
	 * bits CLEAR, not set. */
	orig = test_read_fpcr();
	fpcr = orig & ~(1u << 9);		/* unmask (trap-enable) divide-by-zero */
	test_write_fpcr(fpcr);

	CHECK(feholdexcept(&h) == 0);

	fpcr = test_read_fpcr();
	CHECK((fpcr & (0x1fu << 8)) == 0);

	CHECK(fesetenv(&h) == 0);
	test_write_fpcr(orig);
#endif
}

int main(void)
{
	g_startup_env_ok = (fegetenv(&g_startup_env) == 0);
	test_fabs();
	test_copysign();
	test_classify();
	test_rounding();
	test_sqrt();
	test_fmod();
	test_frexp_ldexp();
	test_modf();
	test_exp();
	test_log();
	test_trig();
	test_pow();
	test_fmaxmin();
	test_fmaxmin_variants();
	test_exp2();
	test_hypot();
	test_nan();
	test_errhandling();
	/* FIRST among the fenv tests, deliberately: it perturbs the
	 * environment and then requires FE_DFL_ENV to still report the
	 * startup state, which only discriminates while no earlier test has
	 * touched FE_DFL_ENV.  Moving it later silently voids it. */
	test_fenv_dfl_env_captured_at_startup();
	test_fenv_zero_argument();
	test_fenv_testexcept_subset();
	test_fenv_raise_exact_set();
	test_fenv_round_modes();
	test_fenv_round_affects_arithmetic();
	test_fenv_env_roundtrip();
	test_fenv_updateenv_reraises();
	test_fenv_dfl_env_is_startup_env();
	test_fenv_getenv_does_not_modify();
	test_fenv_holdexcept_installs_nonstop();
	test_float_ld_variants();
	test_lround_lrint();
	test_asin_acos();
	test_hyperbolic();
	test_inverse_hyperbolic();
	test_cbrt();
	test_expm1_log1p();
	test_erf_erfc();
	test_gamma();
	test_bessel();
	test_remainder_large_quotient();
	test_remainder_remquo();
	test_nextafter();
	test_fdim();
	test_fma();
	test_ilogb_logb();
	test_nearbyint();
	test_scalbln();
	test_lround_lrint_variants();
	test_asin_acos_variants();
	test_hyperbolic_variants();
	test_inverse_hyperbolic_variants();
	test_cbrt_variants();
	test_expm1_log1p_variants();
	test_erf_erfc_variants();
	test_gamma_variants();
	test_fmod_variants();
	test_frexp_ldexp_modf_variants();
	test_rounding_variants();
	test_hypot_variants();
	test_ilogb_logb_variants();
	test_nearbyint_variants();
	test_nextafter_variants();
	test_remainder_remquo_variants();
	test_fdim_fma_variants();
	test_scalb_variants();
	test_compare_macros();

	if (!fails) printf("posix-math: all tests passed\n");
	return fails != 0;
}
