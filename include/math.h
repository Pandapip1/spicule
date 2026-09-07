/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _MATH_H
#define _MATH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_float_t
#define __NEED_double_t
#include <bits/alltypes.h>

#define HUGE_VALF (1.0f/0.0f)
#define HUGE_VAL  (1.0/0.0)
#define HUGE_VALL (1.0L/0.0L)
#define INFINITY  HUGE_VALF
#define NAN       (0.0f/0.0f)

#define FP_NAN       0
#define FP_INFINITE  1
#define FP_ZERO      2
#define FP_SUBNORMAL 3
#define FP_NORMAL    4

/* Pure bit-pattern classification via union reinterpretation, not an FPU
 * comparison, so no hardware FP exception is possible. */
int __fpclassify(double) __attribute__((__pure__));
int __fpclassifyf(float) __attribute__((__pure__));
int __fpclassifyl(long double) __attribute__((__pure__));
int __signbit(double) __attribute__((__pure__));
int __signbitf(float) __attribute__((__pure__));
int __signbitl(long double) __attribute__((__pure__));

#define fpclassify(x) ( \
	sizeof(x) == sizeof(float) ? __fpclassifyf(x) : \
	sizeof(x) == sizeof(double) ? __fpclassify(x) : \
	__fpclassifyl(x) )

#define isinf(x) (fpclassify(x) == FP_INFINITE)
#define isnan(x) (fpclassify(x) == FP_NAN)
#define isnormal(x) (fpclassify(x) == FP_NORMAL)
#define isfinite(x) (fpclassify(x) > FP_INFINITE)

#define signbit(x) ( \
	sizeof(x) == sizeof(float) ? __signbitf(x) : \
	sizeof(x) == sizeof(double) ? __signbit(x) : \
	__signbitl(x) )

#define isunordered(x,y) (isnan((x)) ? ((void)(y),1) : isnan((y)))
#define isless(x,y) (!isunordered(x,y) && (x) < (y))
#define islessequal(x,y) (!isunordered(x,y) && (x) <= (y))
#define islessgreater(x,y) (!isunordered(x,y) && ((x) < (y) || (x) > (y)))
#define isgreater(x,y) (!isunordered(x,y) && (x) > (y))
#define isgreaterequal(x,y) (!isunordered(x,y) && (x) >= (y))

#define MATH_ERRNO  1
#define MATH_ERREXCEPT 2
/* errno is never touched by any src/math/ function; <fenv.h>'s exception
 * flags are the real, hardware-backed error signal -- see that header. */
#define math_errhandling 2

#define FP_ILOGBNAN (-1-0x7fffffff)
#define FP_ILOGB0 FP_ILOGBNAN

/* Sign-bit masking via union, same as __fpclassify above. */
double      fabs(double) __attribute__((__pure__));
float       fabsf(float) __attribute__((__pure__));
long double fabsl(long double) __attribute__((__pure__));
double      floor(double);
float       floorf(float);
long double floorl(long double);
double      ceil(double);
float       ceilf(float);
long double ceill(long double);
double      trunc(double);
float       truncf(float);
long double truncl(long double);
double      round(double);
float       roundf(float);
long double roundl(long double);
double      sqrt(double);
float       sqrtf(float);
long double sqrtl(long double);
double      fmod(double, double);
float       fmodf(float, float);
long double fmodl(long double, long double);
#ifdef SPICULE_ARITHMETIC_ANALYSIS
#define __arith_output_excludes_min(argument) \
	__attribute__((annotate("spicule_arith_output_excludes_min:" #argument)))
#else
#define __arith_output_excludes_min(argument)
#endif
double      frexp(double, int *) __attribute__((nonnull(2))) __arith_output_excludes_min(1);
float       frexpf(float, int *) __attribute__((nonnull(2))) __arith_output_excludes_min(1);
long double frexpl(long double, int *) __attribute__((nonnull(2))) __arith_output_excludes_min(1);
#undef __arith_output_excludes_min
double      ldexp(double, int);
float       ldexpf(float, int);
long double ldexpl(long double, int);
double      scalbn(double, int);
float       scalbnf(float, int);
long double scalbnl(long double, int);
double      modf(double, double *) __attribute__((nonnull(2)));
float       modff(float, float *) __attribute__((nonnull(2)));
long double modfl(long double, long double *) __attribute__((nonnull(2)));
double      pow(double, double);
float       powf(float, float);
long double powl(long double, long double);
double      exp(double);
float       expf(float);
long double expl(long double);
double      exp2(double);
float       exp2f(float);
long double exp2l(long double);
double      log(double);
float       logf(float);
long double logl(long double);
double      log10(double);
float       log10f(float);
long double log10l(long double);
double      log2(double);
float       log2f(float);
long double log2l(long double);
double      sin(double);
float       sinf(float);
long double sinl(long double);
double      cos(double);
float       cosf(float);
long double cosl(long double);
double      tan(double);
float       tanf(float);
long double tanl(long double);
double      atan(double);
float       atanf(float);
long double atanl(long double);
double      atan2(double, double);
float       atan2f(float, float);
long double atan2l(long double, long double);
double      asin(double);
float       asinf(float);
long double asinl(long double);
double      acos(double);
float       acosf(float);
long double acosl(long double);
double      sinh(double);
float       sinhf(float);
long double sinhl(long double);
double      cosh(double);
float       coshf(float);
long double coshl(long double);
double      tanh(double);
float       tanhf(float);
long double tanhl(long double);
double      asinh(double);
float       asinhf(float);
long double asinhl(long double);
double      acosh(double);
float       acoshf(float);
long double acoshl(long double);
double      atanh(double);
float       atanhf(float);
long double atanhl(long double);
double      cbrt(double);
float       cbrtf(float);
long double cbrtl(long double);
double      expm1(double);
float       expm1f(float);
long double expm1l(long double);
double      log1p(double);
float       log1pf(float);
long double log1pl(long double);
double      erf(double);
float       erff(float);
long double erfl(long double);
double      erfc(double);
float       erfcf(float);
long double erfcl(long double);
double      lgamma(double);
float       lgammaf(float);
long double lgammal(long double);
double      tgamma(double);
float       tgammaf(float);
long double tgammal(long double);
double      j0(double);
double      j1(double);
double      jn(int, double);
double      y0(double);
double      y1(double);
double      yn(int, double);
double      remainder(double, double);
float       remainderf(float, float);
long double remainderl(long double, long double);
double      remquo(double, double, int *);
float       remquof(float, float, int *);
long double remquol(long double, long double, int *);
double      nextafter(double, double);
float       nextafterf(float, float);
long double nextafterl(long double, long double);
double      nexttoward(double, long double);
float       nexttowardf(float, long double);
long double nexttowardl(long double, long double);
double      fdim(double, double);
float       fdimf(float, float);
long double fdiml(long double, long double);
double      fma(double, double, double);
float       fmaf(float, float, float);
long double fmal(long double, long double, long double);
int         ilogb(double);
int         ilogbf(float);
int         ilogbl(long double);
double      logb(double);
float       logbf(float);
long double logbl(long double);
double      nearbyint(double);
float       nearbyintf(float);
long double nearbyintl(long double);
double      scalbln(double, long);
float       scalblnf(float, long);
long double scalblnl(long double, long);
float       rintf(float);
long double rintl(long double);
long        lroundf(float);
long        lroundl(long double);
long long   llroundf(float);
long long   llroundl(long double);
long        lrintf(float);
long        lrintl(long double);
long long   llrintf(float);
long long   llrintl(long double);
float       hypotf(float, float);
long double hypotl(long double, long double);
double      fmax(double, double);
float       fmaxf(float, float);
long double fmaxl(long double, long double);
double      fmin(double, double);
float       fminf(float, float);
long double fminl(long double, long double);
/* Magnitude/sign-bit combination via union, same as fabs above. */
double      copysign(double, double) __attribute__((__pure__));
float       copysignf(float, float) __attribute__((__pure__));
long double copysignl(long double, long double) __attribute__((__pure__));
double      nan(const char *);
float       nanf(const char *);
long double nanl(const char *);
double      hypot(double, double);
double      rint(double);
long        lround(double);
long long   llround(double);
long        lrint(double);
long long   llrint(double);

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define M_E             2.7182818284590452354
#define M_LOG2E         1.4426950408889634074
#define M_LOG10E        0.43429448190325182765
#define M_LN2           0.69314718055994530942
#define M_LN10          2.30258509299404568402
#define M_PI            3.14159265358979323846
#define M_PI_2          1.57079632679489661923
#define M_PI_4          0.78539816339744830962
#define M_1_PI          0.31830988618379067154
#define M_2_PI          0.63661977236758134308
#define M_2_SQRTPI      1.12837916709551257390
#define M_SQRT2         1.41421356237309504880
#define M_SQRT1_2       0.70710678118654752440
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
