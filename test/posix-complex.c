/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Coverage fences for <complex.h>, which spicule does not have.
 * POSIX.1-2017 (IEEE Std 1003.1-2017, The Open Group Base
 * Specifications Issue 7, 2018 Edition), served at
 * https://pubs.opengroup.org/onlinepubs/9699919799/ ; clause text read
 * from Ubuntu's manpages-posix-dev 2017a-2, which reprints that
 * edition verbatim (pubs.opengroup.org is unreachable from here).
 *
 * ==================== the gap ========================================
 *
 * 66 interfaces -- the second-largest single block after <pthread.h> in
 * the cross-index behind test/posix-pthread.c, and the largest that is
 * pure computation over memory with no kernel involvement whatsoever:
 * 22 base functions in three precisions each.  cabs carg cimag creal
 * conj cproj csqrt cexp clog cpow ccos csin ctan ccosh csinh ctanh
 * cacos casin catan cacosh casinh catanh, each also as `f` and `l`.
 * None of the 66 is mentioned anywhere in the test/ tree.
 *
 * These are mandatory: every page carries the same header sentence --
 * "The functionality described on this reference page is aligned with
 * the ISO C standard ... This volume of POSIX.1-2017 defers to the ISO
 * C standard" -- so they are base C99, not an option this target may
 * decline.  spicule already claims C99 (`config.mak`'s CFLAGS_C99FSE is
 * `-std=c99`) and already has a substantial <math.h> with a
 * clause-cited audit in test/posix-math.c and test/math.c.  The
 * asymmetry between the real and complex halves of C99's mathematics is
 * the finding: one is audited, the other has no test at all.
 *
 * The 66 divide sharply by cost, and that is worth recording because it
 * changes what "unimplemented" means for each group:
 *
 *   creal cimag conj cproj carg cabs   -- extraction, sign flips, and
 *     one hypot()/atan2() call.  src/math/hypot.c and src/math/trig.c
 *     already supply both.  Essentially free.
 *   csqrt cexp clog cpow              -- expressible in exp/log/
 *     hypot/atan2, all present.
 *   ccos csin ctan ccosh csinh ctanh  -- expressible in the real
 *     trig/hyperbolic pair, both present.
 *   cacos casin catan cacosh casinh catanh -- the branch cuts are the
 *     real work; these are where a naive identity gets the sign wrong
 *     on the cut, which is exactly why they are fenced with
 *     branch-cut-specific assertions below rather than round-trips.
 *
 * ==================== what a caller observes today ===================
 *
 * There is no include/complex.h, so every fence dies on its own
 * #include -- the interface is ABSENT, which is UNIMPL rather than BUG.
 * tools/test-policy.py --pedantic re-decides each; this comment does
 * not.  Note also that the C99 imaginary types are a separate matter:
 * __STDC_IEC_559_COMPLEX__ and <complex.h>'s `imaginary`/`_Imaginary_I`
 * are conditional even in ISO C, so nothing here depends on them --
 * every fence builds its values from CMPLX-free arithmetic on `I`, or
 * from the real and imaginary parts directly.
 *
 * Tolerance: these are transcendental results, so equality is asserted
 * through a bounded absolute difference (CLOSE below) except where the
 * clause states an exact value or an exact sign, which is asserted
 * exactly.  That split is deliberate -- a tolerance on a clause that
 * says "shall return ... +0" would hide the bug the clause exists for.
 */

/* M_PI and friends (used below in carg/cexp/casin/etc.'s assertions) are
 * feature-test gated in include/math.h; same define most other tests in
 * test/ already carry for the same reason (see test/posix-glob.c's
 * comment on this exact define, and test/posix-math.c's copy of it). */
#define _GNU_SOURCE
#include <stdio.h>

#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ==================================================================
 * Decomposition and the algebraic operations --
 * .../functions/creal.html, cimag.html, conj.html, cproj.html,
 * carg.html, cabs.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_complex_creal_cimag_conj)
#include <complex.h>
#include <math.h>

#define CLOSE(a, b) (fabs((a) - (b)) < 1e-9)

static void test_posix_complex_creal_cimag_conj(void)
{
	/* tcc rejects `_Complex` outright at parse time (see include/
	 * complex.h's header comment) and sets __STDC_NO_COMPLEX__ rather
	 * than defining `complex`/I -- so this whole probe body, which
	 * needs real complex-typed locals, has nothing it can build under
	 * __TINYC__.  Guarding on the standard feature-test macro instead
	 * of __TINYC__ directly keeps this correct for any future compiler
	 * that also lacks complex support. */
#ifndef __STDC_NO_COMPLEX__
	double complex z = 3.0 + 4.0 * I;
	double complex c;

	/* creal.html: "These functions shall compute the real part of z ...
	 * shall return the real part value."  cimag.html, the same for the
	 * imaginary part.  These two are exact: they are selections, not
	 * computations. */
	CHECK(creal(z) == 3.0);
	CHECK(cimag(z) == 4.0);
	CHECK(crealf((float complex)z) == 3.0f);
	CHECK(cimagf((float complex)z) == 4.0f);
	CHECK(creall((long double complex)z) == 3.0L);
	CHECK(cimagl((long double complex)z) == 4.0L);

	/* conj.html: "shall compute the complex conjugate of z, by
	 * reversing the sign of its imaginary part."  Exact, and stated as
	 * a sign operation rather than a value. */
	c = conj(z);
	CHECK(creal(c) == 3.0);
	CHECK(cimag(c) == -4.0);
	CHECK(cimag(conj(conj(z))) == 4.0);
	CHECK(cimagf(conjf((float complex)z)) == -4.0f);
	CHECK(cimagl(conjl((long double complex)z)) == -4.0L);

	/* "reversing the sign" applies to a zero imaginary part too: the
	 * conjugate of a real is that real with -0.0 imaginary, and that
	 * signed zero is what every branch cut below is decided by. */
	CHECK(signbit(cimag(conj(1.0 + 0.0 * I))) != 0);

	/* cabs.html: "shall compute the complex absolute value (also
	 * called norm, modulus, or magnitude) of z."  3-4-5. */
	CHECK(CLOSE(cabs(z), 5.0));
	CHECK(CLOSE(cabs(-3.0 - 4.0 * I), 5.0));
	CHECK(cabs(0.0 + 0.0 * I) == 0.0);
	CHECK(fabsf(cabsf((float complex)z) - 5.0f) < 1e-5f);
	CHECK(fabsl(cabsl((long double complex)z) - 5.0L) < 1e-9L);

	/* carg.html: "shall compute the argument (also called phase angle)
	 * of z, with a branch cut along the negative real axis ... shall
	 * return the value of the argument in the interval [-pi, +pi]." */
	CHECK(carg(1.0 + 0.0 * I) == 0.0);
	CHECK(CLOSE(carg(0.0 + 1.0 * I), M_PI / 2));
	CHECK(CLOSE(carg(-1.0 + 0.0 * I), M_PI));
	/* The cut itself: approaching the negative real axis from below
	 * gives -pi, from above +pi.  This is the assertion the branch cut
	 * exists for, and it is where a naive atan2 argument order fails. */
	CHECK(CLOSE(carg(-1.0 - 0.0 * I), -M_PI));
	CHECK(carg(z) > 0.0 && carg(z) < M_PI / 2);
	CHECK(fabsf(cargf(0.0f + 1.0f * I) - (float)(M_PI / 2)) < 1e-5f);
	CHECK(fabsl(cargl(0.0L + 1.0L * I) - (long double)(M_PI / 2)) < 1e-9L);

	/* cproj.html: "shall compute a projection of z onto the Riemann
	 * sphere: z projects to z, except that all complex infinities
	 * (even those with one infinite part and one NaN part) project to
	 * positive infinity on the real axis." */
	c = cproj(z);
	CHECK(creal(c) == 3.0 && cimag(c) == 4.0);
	c = cproj(INFINITY - 4.0 * I);
	CHECK(isinf(creal(c)) && creal(c) > 0.0);
	CHECK(cimag(c) == 0.0);
	/* "If z has an infinite part, then cproj(z) shall be equivalent to
	 * INFINITY + I * copysign(0.0, cimag(z))" -- the sign of the zero
	 * carries the sign of the original imaginary part. */
	c = cproj(-INFINITY - 4.0 * I);
	CHECK(isinf(creal(c)) && creal(c) > 0.0);
	CHECK(signbit(cimag(c)) != 0);
	CHECK(isinf(crealf(cprojf(INFINITY + 0.0f * I))));
	CHECK(isinf(creall(cprojl(INFINITY + 0.0L * I))));
#endif /* !__STDC_NO_COMPLEX__ */
}
#endif

/* ==================================================================
 * Exponential, logarithm, power and square root --
 * .../functions/cexp.html, clog.html, cpow.html, csqrt.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_complex_cexp_clog_cpow_csqrt)
#include <complex.h>
#include <math.h>

#define CLOSE(a, b) (fabs((a) - (b)) < 1e-9)

static void test_posix_complex_cexp_clog_cpow_csqrt(void)
{
	/* See test_posix_complex_creal_cimag_conj's comment above: tcc has
	 * no _Complex at all, and __STDC_NO_COMPLEX__ is the standard way
	 * this header (include/complex.h) says so. */
#ifndef __STDC_NO_COMPLEX__
	double complex c;

	/* cexp.html: "shall compute the complex exponent of z, defined as
	 * e**z."  Euler: e**(i*pi) = -1, and e**0 = 1. */
	c = cexp(0.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 1.0) && CLOSE(cimag(c), 0.0));
	c = cexp(0.0 + M_PI * I);
	CHECK(CLOSE(creal(c), -1.0) && CLOSE(cimag(c), 0.0));
	c = cexp(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), M_E) && CLOSE(cimag(c), 0.0));

	/* clog.html: "shall compute the complex natural (base e) logarithm
	 * of z, with a branch cut along the negative real axis ... in the
	 * range of a strip mathematically unbounded along the real axis
	 * and in the interval [-i*pi, +i*pi] along the imaginary axis." */
	c = clog(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 0.0));
	c = clog(-1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), M_PI));
	/* The cut, from the other side: the imaginary part is -pi, and the
	 * range clause makes both ends attainable. */
	c = clog(-1.0 - 0.0 * I);
	CHECK(CLOSE(cimag(c), -M_PI));
	/* clog(z) real part is log|z|, so a 3-4-5 point gives log 5. */
	c = clog(3.0 + 4.0 * I);
	CHECK(CLOSE(creal(c), log(5.0)));
	CHECK(cimag(c) > -M_PI && cimag(c) <= M_PI);

	/* csqrt.html: "shall compute the complex square root of z, with a
	 * branch cut along the negative real axis ... in the range of the
	 * right half-plane (including the imaginary axis)."  sqrt(-1) = i,
	 * and it must be +i, not -i, because the result is in the RIGHT
	 * half-plane -- the sign of the zero decides it. */
	c = csqrt(-1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 1.0));
	c = csqrt(-1.0 - 0.0 * I);
	CHECK(CLOSE(cimag(c), -1.0));
	c = csqrt(4.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 2.0) && CLOSE(cimag(c), 0.0));
	/* Right half-plane means the real part is never negative. */
	CHECK(creal(csqrt(-3.0 + 4.0 * I)) >= 0.0);

	/* cpow.html: "shall compute the complex power function x**y, with
	 * a branch cut for the first parameter along the negative real
	 * axis." */
	c = cpow(2.0 + 0.0 * I, 10.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 1024.0) && CLOSE(cimag(c), 0.0));
	c = cpow(-1.0 + 0.0 * I, 0.5 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 1.0));

	/* The f and l precisions exist and agree to their own precision. */
	CHECK(fabsf(crealf(cexpf(0.0f + 0.0f * I)) - 1.0f) < 1e-5f);
	CHECK(fabsf(cimagf(csqrtf(-1.0f + 0.0f * I)) - 1.0f) < 1e-5f);
	CHECK(fabsl(creall(clogl(1.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(cpowl(2.0L + 0.0L * I, 10.0L + 0.0L * I))
		    - 1024.0L) < 1e-6L);
	/* The other precision of each of the same four functions, so all
	 * eight of cexp/clog/cpow/csqrt's f and l forms are exercised, not
	 * just one of each pair. */
	CHECK(fabsl(creall(cexpl(0.0L + 0.0L * I)) - 1.0L) < 1e-9L);
	CHECK(fabsf(crealf(clogf(1.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsf(crealf(cpowf(2.0f + 0.0f * I, 10.0f + 0.0f * I))
		    - 1024.0f) < 1e-2f);
	CHECK(fabsl(cimagl(csqrtl(-1.0L + 0.0L * I)) - 1.0L) < 1e-9L);
#endif /* !__STDC_NO_COMPLEX__ */
}
#endif

/* ==================================================================
 * Circular and hyperbolic trigonometry --
 * .../functions/ccos.html, csin.html, ctan.html, ccosh.html,
 * csinh.html, ctanh.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_complex_ctrig_and_chyperbolic)
#include <complex.h>
#include <math.h>

#define CLOSE(a, b) (fabs((a) - (b)) < 1e-9)

static void test_posix_complex_ctrig_and_chyperbolic(void)
{
	/* See test_posix_complex_creal_cimag_conj's comment above: tcc has
	 * no _Complex at all, and __STDC_NO_COMPLEX__ is the standard way
	 * this header (include/complex.h) says so. */
#ifndef __STDC_NO_COMPLEX__
	double complex c;

	/* ccos.html / csin.html / ctan.html: "shall compute the complex
	 * cosine / sine / tangent of z."  On the real axis each must agree
	 * with its <math.h> sibling, which this tree already has and
	 * already audits -- that agreement is the strongest statement
	 * available without pinning an implementation. */
	c = ccos(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), cos(1.0)) && CLOSE(cimag(c), 0.0));
	c = csin(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), sin(1.0)) && CLOSE(cimag(c), 0.0));
	c = ctan(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), tan(1.0)) && CLOSE(cimag(c), 0.0));

	/* ccosh.html / csinh.html / ctanh.html, likewise. */
	c = ccosh(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), cosh(1.0)) && CLOSE(cimag(c), 0.0));
	c = csinh(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), sinh(1.0)) && CLOSE(cimag(c), 0.0));
	c = ctanh(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), tanh(1.0)) && CLOSE(cimag(c), 0.0));

	/* The identities that make the circular and hyperbolic families
	 * one family, which is what distinguishes a real implementation
	 * from six independent approximations: cos(iy) = cosh(y) and
	 * sin(iy) = i*sinh(y). */
	c = ccos(0.0 + 1.0 * I);
	CHECK(CLOSE(creal(c), cosh(1.0)) && CLOSE(cimag(c), 0.0));
	c = csin(0.0 + 1.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), sinh(1.0)));

	/* Parity, stated exactly rather than to a tolerance: cos and cosh
	 * are even, sin and sinh odd, in the complex plane as on the line. */
	CHECK(creal(ccos(1.0 + 1.0 * I)) == creal(ccos(-1.0 - 1.0 * I)));
	CHECK(creal(csin(1.0 + 1.0 * I)) == -creal(csin(-1.0 - 1.0 * I)));

	/* ctan = csin/ccos, at a point where the quotient is well away
	 * from a pole. */
	c = ctan(0.5 + 0.5 * I);
	CHECK(CLOSE(creal(c), creal(csin(0.5 + 0.5 * I) / ccos(0.5 + 0.5 * I))));
	CHECK(CLOSE(cimag(c), cimag(csin(0.5 + 0.5 * I) / ccos(0.5 + 0.5 * I))));

	CHECK(fabsf(crealf(ccosf(0.0f + 0.0f * I)) - 1.0f) < 1e-5f);
	CHECK(fabsf(crealf(csinhf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsl(creall(ctanl(0.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(ccoshl(0.0L + 0.0L * I)) - 1.0L) < 1e-9L);
	CHECK(fabsl(creall(ctanhl(0.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsf(crealf(ccoshf(0.0f + 0.0f * I)) - 1.0f) < 1e-5f);
	CHECK(fabsf(crealf(ctanf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsl(creall(csinl(0.0L + 0.0L * I))) < 1e-9L);
	/* The other precision of ccos/csin/csinh/ctanh, so all four have
	 * both their f and l forms exercised here alongside their d forms
	 * above, the same completeness ccosh/ctanh/csin got below except
	 * they were the missing half in each pair. */
	CHECK(fabsl(creall(ccosl(0.0L + 0.0L * I)) - 1.0L) < 1e-9L);
	CHECK(fabsf(crealf(csinf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsl(creall(csinhl(0.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsf(crealf(ctanhf(0.0f + 0.0f * I))) < 1e-5f);
#endif /* !__STDC_NO_COMPLEX__ */
}
#endif

/* ==================================================================
 * The inverse functions, and their branch cuts --
 * .../functions/cacos.html, casin.html, catan.html, cacosh.html,
 * casinh.html, catanh.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_complex_inverse_branch_cuts)
#include <complex.h>
#include <math.h>

#define CLOSE(a, b) (fabs((a) - (b)) < 1e-9)

static void test_posix_complex_inverse_branch_cuts(void)
{
	/* See test_posix_complex_creal_cimag_conj's comment above: tcc has
	 * no _Complex at all, and __STDC_NO_COMPLEX__ is the standard way
	 * this header (include/complex.h) says so. */
#ifndef __STDC_NO_COMPLEX__
	double complex c;

	/* casin.html: "shall compute the complex arc sine of z, with
	 * branch cuts outside the interval [-1, +1] along the real axis
	 * ... in the range of a strip mathematically unbounded along the
	 * imaginary axis and in the interval [-pi/2, +pi/2] along the real
	 * axis." */
	c = casin(0.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 0.0));
	c = casin(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), M_PI / 2));
	c = casin(0.5 + 0.0 * I);
	CHECK(CLOSE(creal(c), asin(0.5)));
	/* The range clause, on a point off the real axis. */
	c = casin(2.0 + 3.0 * I);
	CHECK(creal(c) >= -M_PI / 2 - 1e-9 && creal(c) <= M_PI / 2 + 1e-9);

	/* cacos.html: "with branch cuts outside the interval [-1, +1]
	 * along the real axis ... in the range of a strip ... and in the
	 * interval [0, pi] along the real axis" -- non-negative real part,
	 * which is a sign statement and asserted as one. */
	c = cacos(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0));
	c = cacos(0.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), M_PI / 2));
	c = cacos(-1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), M_PI));
	c = cacos(2.0 + 3.0 * I);
	CHECK(creal(c) >= 0.0 && creal(c) <= M_PI + 1e-9);

	/* catan.html: "with branch cuts outside the interval [-i, +i]
	 * along the imaginary axis ... in the interval [-pi/2, +pi/2]
	 * along the real axis." */
	c = catan(0.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 0.0));
	c = catan(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), M_PI / 4));
	c = catan(1000.0 + 0.0 * I);
	CHECK(creal(c) > 0.0 && creal(c) < M_PI / 2);

	/* cacosh.html: "with a branch cut at values less than 1 along the
	 * real axis ... in the range of a half-strip of NON-NEGATIVE
	 * values along the real axis and in the interval [-i*pi, +i*pi]
	 * along the imaginary axis." */
	c = cacosh(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 0.0));
	c = cacosh(2.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), acosh(2.0)) && CLOSE(cimag(c), 0.0));
	c = cacosh(-2.0 + 3.0 * I);
	CHECK(creal(c) >= 0.0);
	CHECK(cimag(c) >= -M_PI - 1e-9 && cimag(c) <= M_PI + 1e-9);

	/* casinh.html: "with branch cuts outside the interval [-i, +i]
	 * along the imaginary axis ... in the interval [-i*pi/2, +i*pi/2]
	 * along the imaginary axis." */
	c = casinh(0.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 0.0));
	c = casinh(1.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), asinh(1.0)));
	c = casinh(2.0 + 3.0 * I);
	CHECK(cimag(c) >= -M_PI / 2 - 1e-9 && cimag(c) <= M_PI / 2 + 1e-9);

	/* catanh.html: "with branch cuts outside the interval [-1, +1]
	 * along the real axis ... in the interval [-i*pi/2, +i*pi/2] along
	 * the imaginary axis." */
	c = catanh(0.0 + 0.0 * I);
	CHECK(CLOSE(creal(c), 0.0) && CLOSE(cimag(c), 0.0));
	c = catanh(0.5 + 0.0 * I);
	CHECK(CLOSE(creal(c), atanh(0.5)) && CLOSE(cimag(c), 0.0));
	c = catanh(2.0 + 3.0 * I);
	CHECK(cimag(c) >= -M_PI / 2 - 1e-9 && cimag(c) <= M_PI / 2 + 1e-9);

	/* All six exist in the float and long-double precisions too. */
	CHECK(fabsf(crealf(casinf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsf(crealf(catanf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsf(crealf(cacosf(1.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsf(crealf(cacoshf(1.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsf(crealf(casinhf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsf(crealf(catanhf(0.0f + 0.0f * I))) < 1e-5f);
	CHECK(fabsl(creall(casinl(0.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(catanl(0.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(cacosl(1.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(cacoshl(1.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(casinhl(0.0L + 0.0L * I))) < 1e-9L);
	CHECK(fabsl(creall(catanhl(0.0L + 0.0L * I))) < 1e-9L);
#endif /* !__STDC_NO_COMPLEX__ */
}
#endif

int main(void)
{
	/* Every case here is fenced: include/ has no complex.h, so none of
	 * these translation units resolve.  tools/test-policy.py
	 * --pedantic re-decides each one; the day the header appears, each
	 * fence must be re-adjudicated against what is actually computed,
	 * and the branch-cut assertions above are the ones that will
	 * decide whether it was implemented or approximated. */
	if (!fails) printf("posix-complex: all tests passed\n");
	return fails != 0;
}
