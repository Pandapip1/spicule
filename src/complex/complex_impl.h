/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internals shared by every file in this directory.
 *
 * ==================== why no complex*complex operator appears below ===
 *
 * A caller writing `double complex a, b; a / b;` gets, from clang/gcc,
 * a call to a compiler-rt/libgcc runtime helper (__divdc3, __muldc3,
 * and the float/long-double siblings __divsc3/__mulsc3/__divtc3/
 * __multc3 -- confirmed empirically: `-S` on a throwaway a/b, a*b for
 * each precision under this tree's exact CFLAGS emits exactly these
 * `bl` targets, nothing else). This tree is -nostdlib (Makefile) and
 * links no libgcc/compiler-rt, so those symbols do not exist here --
 * the same gap arch/aarch64/src/ld128_convert.c's own banner describes
 * for __extenddftf2 and friends, and this file answers it the same way
 * that one does: by making sure the gap is never reached rather than by
 * filling it.
 *
 * For double complex specifically, this file DOES supply __divdc3 (see
 * below) -- test/posix-complex.c's own fenced cases divide two complex
 * results directly (`csin(z) / ccos(z)`), so something has to satisfy
 * that at link time, and the C99 Annex G.5.2 algorithm it implements is
 * itself a real, useful library entry point for any other double
 * complex division this freestanding target's callers write, not merely
 * a test-shaped patch. __muldc3 is NOT supplied: complex multiplication
 * has no divide-by-zero/overflow pitfall the way division does (a plain
 * componentwise `ac-bd, ad+bc` already satisfies Annex G.5.1 for finite
 * operands, and the paragraph exists mainly to describe how an infinity
 * or NaN component should behave, which this tree's own code never
 * needs to rely on the compiler's synthesized __muldc3 to get right --
 * see below), and nothing in this tree or in test/posix-complex.c's
 * fenced cases ever multiplies two already-complex values together.
 * float and long double complex division (__divsc3/__divtc3) are
 * likewise not supplied: nothing in this tree or in the fenced tests
 * divides two float complex or two long double complex values, and on
 * aarch64 long double is real IEEE binary128 -- a compiler-synthesized
 * __divtc3 there pulls in __multf3/__subtf3/__addtf3/__unordtf2, genuine
 * quad-precision soft-float arithmetic, which arch/aarch64/src/
 * ld128_convert.c's own banner already states, in so many words, this
 * tree deliberately avoids building entirely ("real arithmetic on long
 * double values ... is a much larger undertaking this tree avoids
 * entirely by construction ... and is not needed by anything that links
 * today"). Adding __divtc3 here would be reopening exactly that scope,
 * for a case nothing exercises.
 *
 * So every function below is written to need none of this in the first
 * place: construct results via CMPLX/CMPLXF/CMPLXL (or, equivalently,
 * `creal(z) + cimag(z)*I`, where the second operand of that `*` is
 * always the real constant on one side -- real-times-complex, which
 * Annex G.5.1p3 asks implementations to fold to a plain scale rather
 * than a full complex multiply, and which this tree's own probe of the
 * generated assembly confirms clang already does, at every optimization
 * level including -O0, with no runtime call at all); do real-valued
 * multiply/divide/etc. on the real and imaginary parts extracted via
 * creal()/cimag(); and for the float/long-double precisions, get there
 * by a plain complex-to-complex CONVERSION -- `(float complex)some_
 * double_complex_value` -- which C99 6.3.1.6 defines as an ordinary
 * per-component real conversion, not an operator, and which the same
 * assembly probe confirms costs nothing beyond the real conversions
 * already needed anyway (on aarch64, __extenddftf2/__trunctfdf2 for the
 * long double precision, both already provided by
 * arch/aarch64/src/ld128_convert.c; float<->double costs no call at
 * all, native hardware). This is the same "narrow to double, compute,
 * widen back" discipline src/math/aarch64_math.h's own banner states as
 * this tree's deliberate, permanent long double policy -- applied here
 * one level up, at the complex layer: every `f`/`l` entry point in this
 * directory is a thin CMPLX-precision cast around the one double
 * algorithm, never an independent computation.
 */
#ifndef SPICULE_COMPLEX_IMPL_H
#define SPICULE_COMPLEX_IMPL_H

#include <complex.h>
#include <math.h>

/* cexp/ccosh/csinh (C99 Annex G.6.3.1, G.6.2.4, G.6.2.6) all need
 * "exp(x) scaled by a power of two chosen to dodge exp()'s own overflow
 * for x in roughly [709.78, 1454.9]" -- the classic FreeBSD/musl
 * s_cexp.c/k_exp.c technique, but implemented here directly on top of
 * this library's own exp()/scalbn() rather than by re-deriving their
 * hi/lo-word bit-splitting: scalbn() is already exact for any integer
 * shift, including ones that walk the result through the subnormal
 * range or all the way to zero/infinity (src/math/aarch64_math.h's own
 * __aa64_scalbn banner), so there is nothing the manual bit-splitting
 * buys here that a second real function call does not already give,
 * and doing it this way costs strictly fewer roundings (one exp() call,
 * one scalbn() call, versus the four-term product the original chains
 * together) rather than more.
 *
 * kln2 = 1799 * ln(2): shifts the dangerous [709.78, 1454.9] input range
 * down to [-537.2, 207.9] before calling exp(), where the result is a
 * representable (if tiny) double; __cplx_scaled_exp then restores the
 * missing factor of 2^(1799+expt) via scalbn(). expt is the caller's
 * own extra power-of-two request (ccosh/csinh pass -1 for their "* 0.5"
 * scaling; cexp passes 0). */
static inline double __cplx_scaled_exp(double x, int expt)
{
	static const double kln2 = 1246.97177782734161156; /* 1799 * ln 2 */
	return scalbn(exp(x - kln2), 1799 + expt);
}

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
