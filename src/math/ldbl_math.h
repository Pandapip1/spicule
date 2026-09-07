/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * long double-precision arithmetic helpers shared by the math sources
 * -- named ldbl_math.h rather than x87.h (this file's name until a
 * later pass renamed it) because half its job, on any arch besides
 * i386/x86_64, is delegating to src/math/aarch64_math.h's own real
 * algorithms instead: every __x87_* name below exists on every arch
 * this tree builds for, x87 hardware or not, precisely so the
 * portable math sources including this header never need to know
 * which case they are in.
 *
 * On i386/x86_64, everything goes through memory with a pointer in a
 * general register, which is the one asm shape that is identical on
 * both (double/float arguments arrive in xmm registers on x86_64, so
 * they are moved via these long double temporaries anyway).
 *
 * spicule targets Windows NT only, but it is built with two different
 * compilers with two different, incompatible ideas of what "long
 * double" is:
 *
 *  - Under this tcc's -win32 targets (which define TCC_TARGET_PE), tcc
 *    treats "long double" as an alias for "double" (matching the MSVC
 *    ABI): sizeof(long double) == 8 here, not the 10/12/16-byte 80-bit
 *    extended format.  So every memory transfer of a long double must
 *    use the double-precision (8-byte) fld/fst opcodes (fldl/fstpl):
 *    the 80-bit tbyte ones (fldt/fstpt) would write 10 bytes into an
 *    8-byte C object and corrupt whatever is next to it on the stack.
 *
 *  - Under mingw-w64 gcc (the configure-time fallback compiler, see
 *    ./configure), "long double" is genuinely gcc's native 80-bit x87
 *    extended precision format, occupying the low 10 significant bytes
 *    of a 12-byte (i386) or 16-byte (x86_64) object - the padding
 *    exists only for alignment.  There, the memory transfer must use
 *    the 80-bit tbyte opcodes (fldt/fstpt); the 8-byte ones would
 *    truncate/misread the value.
 *
 * SPICULE_LDBL_EXTENDED (defined below) selects between the two at
 * compile time, and is the one test every long double bit-layout
 * assumption in src/math should use - see fpclassify.c, frexp.c,
 * copysign.c and fabs.c.  It is driven by __SIZEOF_LONG_DOUBLE__,
 * which gcc/mingw predefine to the true sizeof(long double) (12 or 16)
 * and which this tcc does not predefine at all (confirmed empirically:
 * this tcc build has no __*LONG_DOUBLE__ macros and sizeof(long
 * double) == 8; note its bundled <float.h> is misleading here - it
 * unconditionally sets LDBL_MANT_DIG to 64 for __i386__/__x86_64__ as
 * if long double were extended precision, which is wrong for this
 * particular PE-mode tcc build, so LDBL_MANT_DIG must NOT be used for
 * this test).
 *
 * The x87 stack registers are still 80 bits wide internally, so a
 * single helper's intermediate arithmetic (kept on the FPU stack
 * across multiple instructions, e.g. __x87_exp2's split into
 * integer/fraction) still happens at full 80-bit precision under tcc;
 * it is only the round trip through memory, at each helper's boundary,
 * that is limited to double precision there.  Under gcc, the round
 * trip through memory is itself full 80-bit precision, so there is no
 * such extra rounding at all.
 *
 * Accuracy notes (Intel SDM vol 1, ch 8): fsqrt, frndint and fscale are
 * correctly rounded; fprem is exact; fsin/fcos/fptan/fpatan/fyl2x/f2xm1
 * are accurate to within 1 ulp of the 80-bit format over their defined
 * ranges (the classic caveat is fsin's internal 66-bit pi, which costs
 * accuracy only for arguments very close to a multiple of pi).  Since
 * results are computed in 80 bits internally and rounded once to
 * double (or float) at the store, the results here are well within
 * 1 ulp for ordinary arguments. */
#ifndef LDBL_MATH_H
#define LDBL_MATH_H

#include "ldbl_format.h"

#if SPICULE_LDBL_EXTENDED
#define SPICULE_FLDL "fldt"
#define SPICULE_FSTPL "fstpt"
#else
#define SPICULE_FLDL "fldl"
#define SPICULE_FSTPL "fstpl"
#endif

#if !defined(__i386__) && !defined(__x86_64__)
/* No x87 (or any hardware transcendental unit) on this arch at all --
 * see src/math/aarch64_math.h's own banner for the real algorithms and
 * the double-precision-quality scope boundary every one of these
 * wrappers inherits by narrowing long double to double at the call
 * boundary. SPICULE_LDBL_EXTENDED is still meaningful here (this arch's
 * real long double is IEEE binary128, __SIZEOF_LONG_DOUBLE__==16, so
 * it reads as 1) -- it is fpclassify.c/frexp.c/copysign.c/fabs.c's
 * concern, about long double's STORAGE layout, entirely orthogonal to
 * what precision these particular helpers COMPUTE at. */
#include "aarch64_math.h"

static long double __x87_sqrt(long double x) { return (long double)__aa64_sqrt((double)x); }
static long double __x87_rndint(long double x, int rc) { return (long double)__aa64_rndint((double)x, rc); }
static long double __x87_fmod(long double x, long double y) { return (long double)__aa64_fmod((double)x, (double)y); }
static long double __x87_remainder(long double x, long double y, int *quo) { return (long double)__aa64_remquo((double)x, (double)y, quo); }
static long double __x87_sin(long double x) { return (long double)__aa64_sin((double)x); }
static long double __x87_cos(long double x) { return (long double)__aa64_cos((double)x); }
static long double __x87_tan(long double x) { return (long double)__aa64_tan((double)x); }
static long double __x87_atan2(long double y, long double x) { return (long double)__aa64_atan2((double)y, (double)x); }
static long double __x87_yl2x(long double x, long double y) { return (long double)__aa64_yl2x((double)x, (double)y); }
static long double __x87_exp2(long double t) { return (long double)__aa64_exp2((double)t); }
static long double __x87_scalbn(long double x, int n) { return (long double)__aa64_scalbn((double)x, n); }

#else

static long double __x87_sqrt(long double x)
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\tfsqrt\n\t" SPICULE_FSTPL " (%0)" : : "r"(&x) : "memory");
	return x;
}

/* frndint under rounding control rc: 0 nearest, 1 down, 2 up, 3 trunc;
 * rc < 0 means the current mode. */
static long double __x87_rndint(long double x, int rc) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned short cw, cw2;
	if (rc < 0) {
		__asm__ __volatile__(SPICULE_FLDL " (%0)\n\tfrndint\n\t" SPICULE_FSTPL " (%0)" : : "r"(&x) : "memory");
		return x;
	}
	/* A real "=m" output rather than the pointer-in-a-register shape the
	 * rest of this header uses: fnstcw takes a plain memory operand on
	 * both arches, and spelling it as an output is what makes it visible
	 * -- to a reader and to clang's analyzer -- that this instruction is
	 * what initialises cw. */
	__asm__ __volatile__("fnstcw %0" : "=m"(cw));
	cw2 = (unsigned short)((cw & ~0x0c00) | (rc << 10));
	__asm__ __volatile__("fldcw (%0)\n\t" SPICULE_FLDL " (%1)\n\tfrndint\n\t" SPICULE_FSTPL " (%1)\n\tfldcw (%2)"
		: : "r"(&cw2), "r"(&x), "r"(&cw) : "memory");
	return x;
}

static long double __x87_fmod(long double x, long double y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__asm__ __volatile__(
		SPICULE_FLDL " (%1)\n\t"
		SPICULE_FLDL " (%0)\n\t"
		"1:\n\t"
		"fprem\n\t"
		"fnstsw %%ax\n\t"
		"testb $4, %%ah\n\t"
		"jnz 1b\n\t"
		SPICULE_FSTPL " (%0)\n\t"
		"fstp %%st(0)"
		: : "r"(&x), "r"(&y) : "ax", "memory");
	return x;
}

/* IEEE remainder via FPREM1.  On the final iteration x87 exposes the
 * low three quotient bits as C0/C3/C1 = Q2/Q1/Q0. */
static long double __x87_remainder(long double x, long double y, int *quo) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned short sw;
	__asm__ __volatile__(
		SPICULE_FLDL " (%2)\n\t"
		SPICULE_FLDL " (%1)\n\t"
		"1:\n\t"
		"fprem1\n\t"
		"fnstsw %%ax\n\t"
		"testb $4, %%ah\n\t"
		"jnz 1b\n\t"
		SPICULE_FSTPL " (%1)\n\t"
		"fstp %%st(0)"
		: "=&a"(sw) : "r"(&x), "r"(&y) : "memory");
	if (quo)
		*quo = ((sw >> 9) & 1) | ((sw >> 13) & 2) | ((sw >> 6) & 4);
	return x;
}

static long double __x87_sin(long double x)
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\tfsin\n\t" SPICULE_FSTPL " (%0)" : : "r"(&x) : "memory");
	return x;
}

static long double __x87_cos(long double x)
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\tfcos\n\t" SPICULE_FSTPL " (%0)" : : "r"(&x) : "memory");
	return x;
}

static long double __x87_tan(long double x)
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\tfptan\n\tfstp %%st(0)\n\t" SPICULE_FSTPL " (%0)" : : "r"(&x) : "memory");
	return x;
}

/* fpatan: atan2(y, x), full quadrant handling in hardware. */
static long double __x87_atan2(long double y, long double x) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\t" SPICULE_FLDL " (%1)\n\tfpatan\n\t" SPICULE_FSTPL " (%0)" : : "r"(&y), "r"(&x) : "memory");
	return y;
}

/* y * log2(x) via fyl2x. */
static long double __x87_yl2x(long double x, long double y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__asm__ __volatile__(SPICULE_FLDL " (%0)\n\t" SPICULE_FLDL " (%1)\n\tfyl2x\n\t" SPICULE_FSTPL " (%0)" : : "r"(&y), "r"(&x) : "memory");
	return y;
}

/* 2^t for finite t well inside the exponent range: split into integer
 * and fraction (round to nearest, so |f| <= 1/2, inside f2xm1's domain),
 * 2^f via f2xm1, scale by 2^n via fscale. */
static long double __x87_exp2(long double t)
{
	__asm__ __volatile__(
		SPICULE_FLDL " (%0)\n\t"
		"fld %%st(0)\n\t"
		"frndint\n\t"
		"fxch %%st(1)\n\t"
		"fsub %%st(1), %%st(0)\n\t"
		"f2xm1\n\t"
		"fld1\n\t"
		"faddp\n\t"
		"fscale\n\t"
		"fstp %%st(1)\n\t"
		SPICULE_FSTPL " (%0)"
		: : "r"(&t) : "memory");
	return t;
}

/* x * 2^n exactly (fscale truncates st1, so feed it an integer). */
static long double __x87_scalbn(long double x, int n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long double d = (long double)n;
	__asm__ __volatile__(
		SPICULE_FLDL " (%1)\n\t"
		SPICULE_FLDL " (%0)\n\t"
		"fscale\n\t"
		SPICULE_FSTPL " (%0)\n\t"
		"fstp %%st(0)"
		: : "r"(&x), "r"(&d) : "memory");
	return x;
}

#endif /* !__i386__ && !__x86_64__ */

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
