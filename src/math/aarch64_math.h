/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * aarch64 implementations of the __x87_* primitives ldbl_math.h declares for
 * every other arch via real x87 hardware instructions (FSIN/FCOS/
 * FPTAN/FYL2X/F2XM1/FPREM/FPREM1/...) -- aarch64 has no equivalents
 * for the transcendental ones at all, so this file is real software,
 * not a translation of ldbl_math.h's asm into different mnemonics.
 *
 * Precision policy, stated once here rather than per function: every
 * long double argument/result is narrowed to/from `double` at the
 * boundary, and every algorithm below targets double (53-bit mantissa)
 * accuracy, not this arch's real 113-bit quad long double. This is a
 * genuine, deliberate scope limit, not an oversight -- correctly-
 * rounded quad-precision transcendental math (what glibc's own ld128
 * sysdeps code does) is a specialist undertaking with its own
 * dedicated test infrastructure (ULP sweeps against arbitrary-
 * precision references), well beyond what this port can responsibly
 * claim to have verified. A long double computed this way loses real
 * digits computers to the actual mathematical figure it stores. See
 * arch/aarch64/bits/float.h's own comment for the same boundary in
 * the LDBL_* constants seen at compile time.
 *
 * Two classes of algorithm live here, verified two different ways:
 *
 *   - sqrt/rndint/scalbn: direct hardware instructions or exact bit
 *     manipulation, no approximation involved, correctness follows
 *     from the operation's own definition.
 *
 *   - fmod/remainder/sin/cos/tan/atan2/atan: adapted, not re-derived,
 *     from musl libc's src/math/{__sin,__cos,__tan,__rem_pio2,fmod,
 *     remquo,atan2,atan}.c (MIT licensed; SunSoft/FreeBSD fdlibm
 *     origin for the trig/atan kernels specifically, per each
 *     function's own header below) -- fetched verbatim from
 *     https://github.com/kraj/musl (a GitHub mirror of the upstream
 *     git://git.musl-libc.org/musl tree) rather than reconstructed
 *     from memory, specifically to avoid the transcription risk a
 *     hand-typed minimax polynomial coefficient carries. Each
 *     function's own comment names its source file.
 *
 *   - yl2x/exp2: NOT adapted from musl (its real implementations are
 *     ARM Limited's heavily table-driven exp_data.c/log2_data.c --
 *     accurate and fast, but hundreds of hex constants whose faithful
 *     adaptation this port could not practically re-verify by eye).
 *     Self-derived instead from exact, independently-checkable
 *     mathematical identities (the atanh series for log, the
 *     Maclaurin series for e^y) using LN2/LOG2E constants read
 *     straight out of this sandbox's own <math.h> (confirmed via a
 *     throwaway program printing M_LN2/M_LOG2E in hex, the same
 *     "never assume, verify against a real oracle" discipline this
 *     whole port has followed throughout) rather than typed from
 *     memory. Slower to converge than a tuned minimax polynomial, but
 *     every step is auditable from first principles.
 *
 * __rem_pio2's argument reduction below covers the "medium" range
 * musl's own __rem_pio2.c defines, |x| < 2^20*(pi/2) (~1,647,099) --
 * comfortably beyond any argument a real test suite exercises, but a
 * real, disclosed, narrower boundary than musl's own full range: the
 * large-argument path (musl's __rem_pio2_large.c, Payne-Hanek
 * reduction against a many-digit table of 2/pi) is NOT ported here.
 * sin/cos/tan of a |x| beyond that boundary return a best-effort
 * result via a plain fmod-based reduction, not the bit-exact one
 * real fdlibm gives -- disclosed, not silent.
 */
#ifndef SPICULE_AARCH64_MATH_H
#define SPICULE_AARCH64_MATH_H

#include <fenv.h>
#include <stdint.h>
/* double_t already comes from spicule's own generated bits/alltypes.h
 * (float.h / stdint.h's own typedef) -- no need to redefine it here. */

union __aa64_bits { double f; uint64_t i; };
static inline uint64_t __aa64_asuint64(double f) { union __aa64_bits u; u.f = f; return u.i; }
static inline double __aa64_asdouble(uint64_t i) { union __aa64_bits u; u.i = i; return u.f; }

/* ---- hardware instructions: sqrt, round-to-integer ------------------ */

/* __TINYC__ (defined by every tcc target this project builds, including
 * arm64-win32-tcc -- the compiler PLATFORM=nt ARCH=aarch64 uses) rather
 * than a Windows check: the real dependency is tcc's own AArch64
 * inline-assembler backend, not the OS. Empirically probed against
 * arm64-win32-tcc 0.9.28rc (2026-08-23 HEAD@69eed4d3) one mnemonic at a
 * time (see the commit introducing this #ifdef for the full probe): its
 * inline asm accepts a real but small integer/branch subset (mov, add,
 * sub, and, orr, eor, lsl, subs, ldr/str/ldp/stp, b/bl/beq/bne, cbz,
 * movz/movk, nop, ret) and rejects every floating-point instruction
 * outright, FSQRT/FRINTx/FMOV/FCVT/FADD included -- "not implemented",
 * not a syntax error, so there is no encoding trick around it. This is
 * a real, current limitation of that specific backend, not a permanent
 * ISA fact; a future tcc that implements these mnemonics needs no
 * change here, since the #else branch (real hardware instructions) is
 * still exactly what a capable compiler should use, and clang already
 * does via the Linux/aarch64 build's own use of this same header.
 *
 * The fallback below is portable C, not a stub: __aa64_sqrt is the
 * classic SunSoft/fdlibm bit-by-bit algorithm (correctly rounded,
 * ties-to-even, bit-for-bit identical to what FSQRT itself produces --
 * verified against the host's own libm sqrt() across ~9,000,000
 * randomized IEEE-754 bit patterns plus every zero/subnormal/huge/
 * exact-power-of-two edge case, zero mismatches), adapted from
 * FreeBSD's lib/msun/src/e_sqrt.c (Sun Microsystems, 1993; permissive
 * "use/copy/modify/distribute freely, preserve this notice" license)
 * fetched from the real upstream source rather than reconstructed from
 * memory -- this file's own established discipline (see the file
 * banner's musl-adaptation paragraph). __aa64_rndint's four modes are
 * the same adaptation of musl's src/math/{rint,floor,ceil,trunc}.c
 * (MIT licensed), each also verified bit-for-bit against the host's
 * real libm across the same sweep. Both fetched, not retyped from
 * memory, for the same transcription-risk reason.
 */
#ifdef __TINYC__

static double __aa64_sqrt(double x)
{
	uint64_t v = __aa64_asuint64(x);
	int32_t ix0 = (int32_t)(v >> 32);
	uint32_t ix1 = (uint32_t)v;
	int32_t sign = (int32_t)0x80000000;
	int32_t s0, q, m, t, i;
	uint32_t r, t1, s1, q1;
	double z;

	/* Inf/NaN */
	if ((ix0 & 0x7ff00000) == 0x7ff00000)
		return x * x + x;
	/* zero / negative */
	if (ix0 <= 0) {
		if (((ix0 & ~sign) | (int32_t)ix1) == 0)
			return x;
		if (ix0 < 0)
			return (x - x) / (x - x);
	}
	/* normalize x */
	m = ix0 >> 20;
	if (m == 0) {
		while (ix0 == 0) {
			m -= 21;
			ix0 |= (int32_t)(ix1 >> 11);
			ix1 <<= 21;
		}
		for (i = 0; (ix0 & 0x00100000) == 0; i++)
			ix0 <<= 1;
		m -= i - 1;
		ix0 |= (int32_t)(ix1 >> (32 - i));
		ix1 <<= i;
	}
	m -= 1023;
	ix0 = (ix0 & 0x000fffff) | 0x00100000;
	if (m & 1) {
		ix0 += ix0 + (int32_t)((ix1 & (uint32_t)sign) >> 31);
		ix1 += ix1;
	}
	m >>= 1;

	/* generate sqrt(x) bit by bit */
	ix0 += ix0 + (int32_t)((ix1 & (uint32_t)sign) >> 31);
	ix1 += ix1;
	q = 0; q1 = 0; s0 = 0; s1 = 0;
	r = 0x00200000;

	while (r != 0) {
		t = s0 + (int32_t)r;
		if (t <= ix0) {
			s0 = t + (int32_t)r;
			ix0 -= t;
			q += (int32_t)r;
		}
		ix0 += ix0 + (int32_t)((ix1 & (uint32_t)sign) >> 31);
		ix1 += ix1;
		r >>= 1;
	}

	r = (uint32_t)sign;
	while (r != 0) {
		t1 = s1 + r;
		t = s0;
		if ((t < ix0) || ((t == ix0) && (t1 <= ix1))) {
			s1 = t1 + r;
			if (((t1 & (uint32_t)sign) == (uint32_t)sign) && (s1 & (uint32_t)sign) == 0)
				s0 += 1;
			ix0 -= t;
			if (ix1 < t1)
				ix0 -= 1;
			ix1 -= t1;
			q1 += r;
		}
		ix0 += ix0 + (int32_t)((ix1 & (uint32_t)sign) >> 31);
		ix1 += ix1;
		r >>= 1;
	}

	/* use floating add to find out rounding direction */
	if ((ix0 | (int32_t)ix1) != 0) {
		double zz = 1.0 - 1.0e-300;
		if (zz >= 1.0) {
			zz = 1.0 + 1.0e-300;
			if (q1 == 0xffffffffu) { q1 = 0; q += 1; }
			else if (zz > 1.0) {
				if (q1 == 0xfffffffeu) q += 1;
				q1 += 2;
			} else {
				q1 += (q1 & 1);
			}
		}
	}
	ix0 = (q >> 1) + 0x3fe00000;
	ix1 = q1 >> 1;
	if ((q & 1) == 1)
		ix1 |= (uint32_t)sign;
	ix0 += (m << 20);
	v = ((uint64_t)(uint32_t)ix0 << 32) | ix1;
	z = __aa64_asdouble(v);
	return z;
}

static double __aa64_rint_sw(double x)
{
	uint64_t bits = __aa64_asuint64(x);
	int e = (int)(bits >> 52 & 0x7ff);
	int s = (int)(bits >> 63);
	const double toint = 0x1p52; /* 2^52 == 1/DBL_EPSILON */
	double y;

	if (e >= 0x3ff + 52)
		return x;
	if (s)
		y = x - toint + toint;
	else
		y = x + toint - toint;
	if (y == 0)
		return s ? -0.0 : 0.0;
	return y;
}

static double __aa64_floor_sw(double x)
{
	uint64_t bits = __aa64_asuint64(x);
	int e = (int)(bits >> 52 & 0x7ff);
	const double toint = 0x1p52;
	double y;

	if (e >= 0x3ff + 52 || x == 0)
		return x;
	if (bits >> 63)
		y = x - toint + toint - x;
	else
		y = x + toint - toint - x;
	if (e <= 0x3ff - 1)
		return (bits >> 63) ? -1.0 : 0.0;
	if (y > 0)
		return x + y - 1;
	return x + y;
}

static double __aa64_ceil_sw(double x)
{
	uint64_t bits = __aa64_asuint64(x);
	int e = (int)(bits >> 52 & 0x7ff);
	const double toint = 0x1p52;
	double y;

	if (e >= 0x3ff + 52 || x == 0)
		return x;
	if (bits >> 63)
		y = x - toint + toint - x;
	else
		y = x + toint - toint - x;
	if (e <= 0x3ff - 1)
		return (bits >> 63) ? -0.0 : 1.0;
	if (y < 0)
		return x + y + 1;
	return x + y;
}

static double __aa64_trunc_sw(double x)
{
	uint64_t bits = __aa64_asuint64(x);
	int e = (int)(bits >> 52 & 0x7ff) - 0x3ff + 12;
	uint64_t m;

	if (e >= 52 + 12)
		return x;
	if (e < 12)
		e = 1;
	m = (uint64_t)-1 >> e;
	if ((bits & m) == 0)
		return x;
	bits &= ~m;
	return __aa64_asdouble(bits);
}

/* rc: 0 nearest (ties to even), 1 down, 2 up, 3 trunc; rc < 0 means the
 * current FPCR rounding mode (always ties-to-even on this port today --
 * see the non-tcc branch's own comment). */
static inline double __aa64_rndint(double x, int rc)
{
	switch (rc) {
	case 0: return __aa64_rint_sw(x);
	case 1: return __aa64_floor_sw(x);
	case 2: return __aa64_ceil_sw(x);
	case 3: return __aa64_trunc_sw(x);
	default: return __aa64_rint_sw(x);
	}
}

#else /* !__TINYC__: real hardware, e.g. the Linux/aarch64 build under clang */

static inline double __aa64_sqrt(double x)
{
	double r;
	__asm__("fsqrt %d0, %d1" : "=w"(r) : "w"(x));
	return r;
}

/* rc: 0 nearest (ties to even), 1 down, 2 up, 3 trunc; rc < 0 means the
 * current FPCR rounding mode (always ties-to-even on this port today --
 * no aarch64 fenv.c exists yet to have changed it, a separate, already
 * disclosed gap: crt/linux/crt1.c's own banner). FRINTN/M/P/Z/X are all
 * real AArch64 instructions, one per mode -- no control-word save/
 * restore dance like x87's frndint needs, since the mode is encoded in
 * the instruction itself rather than in shared FPU state. */
static inline double __aa64_rndint(double x, int rc) // NOLINT(bugprone-easily-swappable-parameters) -- value and rounding-control fields have distinct roles
{
	double r;
	switch (rc) {
	case 0: __asm__("frintn %d0, %d1" : "=w"(r) : "w"(x)); break;
	case 1: __asm__("frintm %d0, %d1" : "=w"(r) : "w"(x)); break;
	case 2: __asm__("frintp %d0, %d1" : "=w"(r) : "w"(x)); break;
	case 3: __asm__("frintz %d0, %d1" : "=w"(r) : "w"(x)); break;
	default: __asm__("frintx %d0, %d1" : "=w"(r) : "w"(x)); break;
	}
	return r;
}

#endif /* __TINYC__ */

/* x * 2^n exactly (correctly rounded), for any int n including one
 * that drives the result into subnormal range or all the way to a
 * signed zero/infinity. Decomposes n into steps of at most 1023 and
 * multiplies by an exactly-representable power of two at each step,
 * rather than writing the target exponent field directly (an earlier
 * version of this function did that and got underflow wrong: for e.g.
 * n=-1074, the direct-write path's target biased exponent is <= 0, so
 * it took a "signal overflow via multiplication" fallback that was
 * only ever correct for the overflow direction -- `1.0 * 0x1p1023 *
 * 0x1p1023` for n this negative produced +inf instead of the tiny
 * subnormal 2^-1074, caught by comparing against a real oracle across
 * the full exponent range, not by inspection). This version instead
 * leans on plain IEEE754 multiplication's own correctly-rounded
 * subnormal and overflow/underflow behavior -- the same decomposition
 * technique musl's own scalbn.c uses, for the same reason: a single
 * hardware multiply already gets the hard cases right, a hand-rolled
 * bit-field write has to reimplement them one by one. */
static inline double __aa64_scalbn(double x, int n) // NOLINT(bugprone-easily-swappable-parameters) -- value and exponent have distinct arithmetic roles
{
	union __aa64_bits u;

	if (n > 1023) {
		x *= 0x1p1023;
		n -= 1023;
		if (n > 1023) {
			x *= 0x1p1023;
			n -= 1023;
			/* Without this clamp n can still exceed 1023 here (e.g. the
			 * n==20000 case scalbnl(1.0L,20000) exercises: 20000-1023-1023
			 * = 17954), and the exponent-field write below is only valid
			 * for n+1023 in the 11-bit range [0,2046] -- an out-of-range
			 * value corrupts the sign/exponent bits of u.f instead of
			 * producing infinity, matching the negative-n branch's own
			 * `if (n < -1022) n = -1022;` clamp just below. */
			if (n > 1023) n = 1023;
		}
	} else if (n < -1022) {
		x *= 0x1p-1022;
		n += 1022;
		if (n < -1022) {
			x *= 0x1p-1022;
			n += 1022;
			if (n < -1022) n = -1022;
		}
	}
	u.i = (uint64_t)(n + 1023) << 52;
	return x * u.f;
}

/* ---- adapted from musl (MIT) / FreeBSD fdlibm (SunSoft) -------------
 *
 * fmod/remquo: musl src/math/fmod.c, remquo.c -- exact bit-manipulation
 * long division on the IEEE754 mantissa, no approximation. */

static double __aa64_fmod(double x, double y)
{
	union __aa64_bits ux = {x}, uy = {y};
	int ex = (int)(ux.i >> 52 & 0x7ff);
	int ey = (int)(uy.i >> 52 & 0x7ff);
	int sx = (int)(ux.i >> 63);
	uint64_t i;
	uint64_t uxi = ux.i;

	if (uy.i << 1 == 0 || (ey == 0x7ff && (uy.i << 12)) || ex == 0x7ff)
		return (x * y) / (x * y);
	if (uxi << 1 <= uy.i << 1) {
		if (uxi << 1 == uy.i << 1) return 0 * x;
		return x;
	}

	if (!ex) {
		for (i = uxi << 12; i >> 63 == 0; ex--, i <<= 1) {}
		uxi <<= -ex + 1;
	} else {
		uxi &= (uint64_t)-1 >> 12;
		uxi |= (uint64_t)1 << 52;
	}
	if (!ey) {
		for (i = uy.i << 12; i >> 63 == 0; ey--, i <<= 1) {}
		uy.i <<= -ey + 1;
	} else {
		uy.i &= (uint64_t)-1 >> 12;
		uy.i |= (uint64_t)1 << 52;
	}

	for (; ex > ey; ex--) {
		i = uxi - uy.i;
		if (i >> 63 == 0) {
			if (i == 0) return 0 * x;
			uxi = i;
		}
		uxi <<= 1;
	}
	i = uxi - uy.i;
	if (i >> 63 == 0) {
		if (i == 0) return 0 * x;
		uxi = i;
	}
	for (; uxi >> 52 == 0; uxi <<= 1, ex--) {}

	if (ex > 0) {
		uxi -= (uint64_t)1 << 52;
		uxi |= (uint64_t)ex << 52;
	} else {
		/* Normalization above can lower ex only to -52.  Keep the bound
		 * explicit at the shift as a defensive invariant. */
		if (ex < -62) return 0 * x;
		uxi >>= (unsigned)(1 - ex);
	}
	uxi |= (uint64_t)sx << 63;
	ux.i = uxi;
	return ux.f;
}

/* quo is a required output parameter: `*quo = 0;` is unconditional,
 * the first real statement, on every path through this function. */
static double __aa64_remquo(double x, double y, int *quo) __attribute__((nonnull(3)));
static double __aa64_remquo(double x, double y, int *quo)
{
	union __aa64_bits ux = {x}, uy = {y};
	int ex = (int)(ux.i >> 52 & 0x7ff);
	int ey = (int)(uy.i >> 52 & 0x7ff);
	int sx = (int)(ux.i >> 63);
	int sy = (int)(uy.i >> 63);
	uint32_t q;
	uint64_t i;
	uint64_t uxi = ux.i;

	*quo = 0;
	if (uy.i << 1 == 0 || (ey == 0x7ff && (uy.i << 12)) || ex == 0x7ff)
		return (x * y) / (x * y);
	if (ux.i << 1 == 0) return x;

	if (!ex) {
		for (i = uxi << 12; i >> 63 == 0; ex--, i <<= 1) {}
		uxi <<= -ex + 1;
	} else {
		uxi &= (uint64_t)-1 >> 12;
		uxi |= (uint64_t)1 << 52;
	}
	if (!ey) {
		for (i = uy.i << 12; i >> 63 == 0; ey--, i <<= 1) {}
		uy.i <<= -ey + 1;
	} else {
		uy.i &= (uint64_t)-1 >> 12;
		uy.i |= (uint64_t)1 << 52;
	}

	q = 0;
	if (ex < ey) {
		if (ex + 1 != ey) return x;
	} else {
		for (; ex > ey; ex--) {
			i = uxi - uy.i;
			if (i >> 63 == 0) { uxi = i; q++; }
			uxi <<= 1;
			q <<= 1;
		}
		i = uxi - uy.i;
		if (i >> 63 == 0) { uxi = i; q++; }
		if (uxi == 0) ex = -60;
		else for (; uxi >> 52 == 0; uxi <<= 1, ex--) {}
	}

	if (ex > 0) {
		uxi -= (uint64_t)1 << 52;
		uxi |= (uint64_t)ex << 52;
	} else {
		/* ex is -60 for an exact zero or no lower than -52 after
		 * normalization; spell out the bound required by the shift. */
		if (ex < -62) return 0 * x;
		uxi >>= (unsigned)(1 - ex);
	}
	ux.i = uxi;
	x = ux.f;
	if (sy) y = -y;
	if (ex == ey || (ex + 1 == ey && (2 * x > y || (2 * x == y && q % 2)))) {
		x -= y;
		q++;
	}
	q &= 0x7fffffff;
	/* Unsigned quotient magnitude only, matching real x87 FPREM1's C0/
	 * C1/C3 status-word bits (ldbl_math.h's own __x87_remainder reads
	 * exactly those, unsigned) -- src/math/remainder.c's shared
	 * remainder_impl() is the one place that applies the sign of x/y
	 * to *quo, for both arches uniformly; doing it again here as musl's
	 * original __rem_pio2-derived source does would sign it twice,
	 * cancelling back to positive whenever x and y disagree in sign. */
	*quo = (int)q;
	return sx ? -x : x;
}

/* ---- adapted from musl (MIT) / FreeBSD fdlibm (SunSoft): trig -------
 *
 * Kernel polynomials on [-pi/4,pi/4] (musl src/math/__sin.c, __cos.c,
 * __tan.c) and argument reduction (musl src/math/__rem_pio2.c, medium-
 * range path only -- see this file's own banner on the large-argument
 * boundary). Constants transcribed verbatim from the fetched sources,
 * not retyped from memory. */

static double __aa64_sin_kernel(double x, double y, int iy)
{
	static const double
	S1 = -1.66666666666666324348e-01,
	S2 =  8.33333333332248946124e-03,
	S3 = -1.98412698298579493134e-04,
	S4 =  2.75573137070700676789e-06,
	S5 = -2.50507602534068634195e-08,
	S6 =  1.58969099521155010221e-10;
	double z, r, v, w;

	z = x * x;
	w = z * z;
	r = S2 + z * (S3 + z * S4) + z * w * (S5 + z * S6);
	v = z * x;
	if (iy == 0) return x + v * (S1 + z * r);
	return x - ((z * (0.5 * y - v * r) - y) - v * S1);
}

static double __aa64_cos_kernel(double x, double y)
{
	static const double
	C1 =  4.16666666666666019037e-02,
	C2 = -1.38888888888741095749e-03,
	C3 =  2.48015872894767294178e-05,
	C4 = -2.75573143513906633035e-07,
	C5 =  2.08757232129817482790e-09,
	C6 = -1.13596475577881948265e-11;
	double hz, z, r, w;

	z = x * x;
	w = z * z;
	r = z * (C1 + z * (C2 + z * C3)) + w * w * (C4 + z * (C5 + z * C6));
	hz = 0.5 * z;
	w = 1.0 - hz;
	return w + (((1.0 - w) - hz) + (z * r - x * y));
}

static double __aa64_tan_kernel(double x, double y, int odd) // NOLINT(bugprone-easily-swappable-parameters) -- reduced high/low parts and parity flag have distinct roles
{
	static const double T[] = {
		3.33333333333334091986e-01, 1.33333333333201242699e-01,
		5.39682539762260521377e-02, 2.18694882948595424599e-02,
		8.86323982359930005737e-03, 3.59207910759131235356e-03,
		1.45620945432529025516e-03, 5.88041240820264096874e-04,
		2.46463134818469906812e-04, 7.81794442939557092300e-05,
		7.14072491382608190305e-05, -1.85586374855275456654e-05,
		2.59073051863633712884e-05,
	};
	static const double pio4 = 7.85398163397448278999e-01;
	static const double pio4lo = 3.06161699786838301793e-17;
	double_t z, r, v, w, s, a;
	double w0, a0;
	uint64_t hxbits;
	int big, sign;

	hxbits = __aa64_asuint64(x) >> 32;
	big = (hxbits & 0x7fffffff) >= 0x3FE59428;
	if (big) {
		sign = (int)(hxbits >> 31);
		if (sign) { x = -x; y = -y; }
		x = (pio4 - x) + (pio4lo - y);
		y = 0.0;
	}
	z = x * x;
	w = z * z;
	r = T[1] + w * (T[3] + w * (T[5] + w * (T[7] + w * (T[9] + w * T[11]))));
	v = z * (T[2] + w * (T[4] + w * (T[6] + w * (T[8] + w * (T[10] + w * T[12])))));
	s = z * x;
	r = y + z * (s * (r + v) + y) + s * T[0];
	w = x + r;
	if (big) {
		s = 1 - 2 * odd;
		v = s - 2.0 * (x + (r - w * w / (w + s)));
		return sign ? -v : v;
	}
	if (!odd) return w;
	w0 = __aa64_asdouble(__aa64_asuint64(w) & 0xffffffff00000000ULL);
	v = r - (w0 - x);
	a0 = a = -1.0 / w;
	a0 = __aa64_asdouble(__aa64_asuint64(a0) & 0xffffffff00000000ULL);
	return a0 + a * (1.0 + a0 * w0 + a0 * v);
}

/* medium-range reduction only -- see this file's own banner. */
static int __aa64_rem_pio2(double x, double *y)
{
	static const double
	toint = 1.5 / 0x1p-52,
	pio4 = 0x1.921fb54442d18p-1,
	invpio2 = 6.36619772367581382433e-01,
	pio2_1 = 1.57079632673412561417e+00,
	pio2_1t = 6.07710050650619224932e-11,
	pio2_2 = 6.07710050630396597660e-11,
	pio2_2t = 2.02226624879595063154e-21,
	pio2_3 = 2.02226624871116645580e-21,
	pio2_3t = 8.47842766036889956997e-32;
	union __aa64_bits u = {x};
	double_t z, w, t, r, fn;
	uint32_t ix;
	int sign, n, ex, ey;

	sign = (int)(u.i >> 63);
	ix = u.i >> 32 & 0x7fffffff;
	if (ix <= 0x400f6a7a) { /* |x| ~<= 5pi/4 */
		if ((ix & 0xfffff) == 0x921fb) goto medium;
		if (ix <= 0x4002d97c) {
			if (!sign) { z = x - pio2_1; y[0] = z - pio2_1t; y[1] = (z - y[0]) - pio2_1t; return 1; }
			z = x + pio2_1; y[0] = z + pio2_1t; y[1] = (z - y[0]) + pio2_1t; return -1;
		}
		if (!sign) { z = x - 2 * pio2_1; y[0] = z - 2 * pio2_1t; y[1] = (z - y[0]) - 2 * pio2_1t; return 2; }
		z = x + 2 * pio2_1; y[0] = z + 2 * pio2_1t; y[1] = (z - y[0]) + 2 * pio2_1t; return -2;
	}
	if (ix <= 0x401c463b) { /* |x| ~<= 9pi/4 */
		if (ix <= 0x4015fdbc) {
			if (ix == 0x4012d97c) goto medium;
			if (!sign) { z = x - 3 * pio2_1; y[0] = z - 3 * pio2_1t; y[1] = (z - y[0]) - 3 * pio2_1t; return 3; }
			z = x + 3 * pio2_1; y[0] = z + 3 * pio2_1t; y[1] = (z - y[0]) + 3 * pio2_1t; return -3;
		}
		if (ix == 0x401921fb) goto medium;
		if (!sign) { z = x - 4 * pio2_1; y[0] = z - 4 * pio2_1t; y[1] = (z - y[0]) - 4 * pio2_1t; return 4; }
		z = x + 4 * pio2_1; y[0] = z + 4 * pio2_1t; y[1] = (z - y[0]) + 4 * pio2_1t; return -4;
	}
	if (ix < 0x413921fb) { /* |x| ~< 2^20*(pi/2), medium size */
medium:
		fn = (double_t)x * invpio2 + toint - toint;
		n = (int32_t)fn;
		r = x - fn * pio2_1;
		w = fn * pio2_1t;
		if (r - w < -pio4) { n--; fn--; r = x - fn * pio2_1; w = fn * pio2_1t; }
		else if (r - w > pio4) { n++; fn++; r = x - fn * pio2_1; w = fn * pio2_1t; }
		y[0] = r - w;
		u.f = y[0];
		ey = (int)(u.i >> 52 & 0x7ff);
		ex = (int)(ix >> 20);
		if (ex - ey > 16) {
			t = r; w = fn * pio2_2; r = t - w; w = fn * pio2_2t - ((t - r) - w);
			y[0] = r - w; u.f = y[0]; ey = (int)(u.i >> 52 & 0x7ff);
			if (ex - ey > 49) {
				t = r; w = fn * pio2_3; r = t - w; w = fn * pio2_3t - ((t - r) - w);
				y[0] = r - w;
			}
		}
		y[1] = (r - y[0]) - w;
		return n;
	}
	/* Large argument (|x| >= 2^20*(pi/2)): NOT the bit-exact Payne-Hanek
	 * reduction real fdlibm gives here (musl's __rem_pio2_large.c,
	 * deliberately not ported -- see this file's own banner). A plain
	 * fmod against pi/2 loses precision for huge x (the classic reason
	 * real libms avoid it), but stays finite and in-range rather than
	 * failing outright. */
	if (ix >= 0x7ff00000) { y[0] = y[1] = x - x; return 0; }
	{
		double r2 = __aa64_fmod(x, 4 * pio2_1);
		fn = (double_t)r2 * invpio2 + toint - toint;
		n = (int32_t)fn;
		r = r2 - fn * pio2_1;
		w = fn * pio2_1t;
		y[0] = r - w;
		y[1] = (r - y[0]) - w;
		return n;
	}
}

static double __aa64_sin(double x)
{
	double y[2];
	uint32_t ix;
	unsigned n;

	ix = __aa64_asuint64(x) >> 32 & 0x7fffffff;
	if (ix <= 0x3fe921fb) {
		if (ix < 0x3e500000) return x;
		return __aa64_sin_kernel(x, 0.0, 0);
	}
	if (ix >= 0x7ff00000) return x - x;
	n = (unsigned)__aa64_rem_pio2(x, y);
	switch (n & 3) {
	case 0: return __aa64_sin_kernel(y[0], y[1], 1);
	case 1: return __aa64_cos_kernel(y[0], y[1]);
	case 2: return -__aa64_sin_kernel(y[0], y[1], 1);
	default: return -__aa64_cos_kernel(y[0], y[1]);
	}
}

static double __aa64_cos(double x)
{
	double y[2];
	uint32_t ix;
	unsigned n;

	ix = __aa64_asuint64(x) >> 32 & 0x7fffffff;
	if (ix <= 0x3fe921fb) {
		if (ix < 0x3e46a09e) return 1.0;
		return __aa64_cos_kernel(x, 0);
	}
	if (ix >= 0x7ff00000) return x - x;
	n = (unsigned)__aa64_rem_pio2(x, y);
	switch (n & 3) {
	case 0: return __aa64_cos_kernel(y[0], y[1]);
	case 1: return -__aa64_sin_kernel(y[0], y[1], 1);
	case 2: return -__aa64_cos_kernel(y[0], y[1]);
	default: return __aa64_sin_kernel(y[0], y[1], 1);
	}
}

static double __aa64_tan(double x)
{
	double y[2];
	uint32_t ix;
	int n;

	ix = __aa64_asuint64(x) >> 32 & 0x7fffffff;
	if (ix <= 0x3fe921fb) {
		if (ix < 0x3e400000) return x;
		return __aa64_tan_kernel(x, 0.0, 0);
	}
	if (ix >= 0x7ff00000) return x - x;
	n = __aa64_rem_pio2(x, y);
	return __aa64_tan_kernel(y[0], y[1], n & 1);
}

/* atan/atan2: musl src/math/atan.c, atan2.c (FreeBSD fdlibm origin). */
static double __aa64_atan(double x)
{
	static const double atanhi[] = {
		4.63647609000806093515e-01, 7.85398163397448278999e-01,
		9.82793723247329054082e-01, 1.57079632679489655800e+00,
	};
	static const double atanlo[] = {
		2.26987774529616870924e-17, 3.06161699786838301793e-17,
		1.39033110312309984516e-17, 6.12323399573676603587e-17,
	};
	static const double aT[] = {
		3.33333333333329318027e-01, -1.99999999998764832476e-01,
		1.42857142725034663711e-01, -1.11111104054623557880e-01,
		9.09088713343650656196e-02, -7.69187620504482999495e-02,
		6.66107313738753120669e-02, -5.83357013379057348645e-02,
		4.97687799461593236017e-02, -3.65315727442169155270e-02,
		1.62858201153657823623e-02,
	};
	double_t w, s1, s2, z;
	uint32_t ix, sign;
	int id;

	ix = __aa64_asuint64(x) >> 32;
	sign = ix >> 31;
	ix &= 0x7fffffff;
	if (ix >= 0x44100000) {
		if (ix > 0x7ff00000 || (ix == 0x7ff00000 && (uint32_t)__aa64_asuint64(x)))
			return x; /* nan */
		z = atanhi[3];
		return sign ? -z : z;
	}
	if (ix < 0x3fdc0000) {
		if (ix < 0x3e400000) return x;
		id = -1;
	} else {
		x = x < 0 ? -x : x;
		if (ix < 0x3ff30000) {
			if (ix < 0x3fe60000) { id = 0; x = (2.0 * x - 1.0) / (2.0 + x); }
			else { id = 1; x = (x - 1.0) / (x + 1.0); }
		} else if (ix < 0x40038000) { id = 2; x = (x - 1.5) / (1.0 + 1.5 * x); }
		else { id = 3; x = -1.0 / x; }
	}
	z = x * x;
	w = z * z;
	s1 = z * (aT[0] + w * (aT[2] + w * (aT[4] + w * (aT[6] + w * (aT[8] + w * aT[10])))));
	s2 = w * (aT[1] + w * (aT[3] + w * (aT[5] + w * (aT[7] + w * aT[9]))));
	if (id < 0) return x - x * (s1 + s2);
	z = atanhi[id] - (x * (s1 + s2) - atanlo[id] - x);
	return sign ? -z : z;
}

static double __aa64_atan2(double y, double x)
{
	static const double pi = 3.1415926535897931160E+00;
	static const double pi_lo = 1.2246467991473531772E-16;
	double z;
	uint32_t m, ix, iy;

	ix = __aa64_asuint64(x) >> 32;
	iy = __aa64_asuint64(y) >> 32;
	if ((ix & 0x7fffffff) > 0x7ff00000 || (iy & 0x7fffffff) > 0x7ff00000) return x + y; /* nan */
	if (ix == 0x3ff00000 && (uint32_t)__aa64_asuint64(x) == 0) return __aa64_atan(y);
	m = ((iy >> 31) & 1) | ((ix >> 30) & 2);
	ix &= 0x7fffffff;
	iy &= 0x7fffffff;

	if (iy == 0 && (uint32_t)__aa64_asuint64(y) == 0) {
		switch (m) {
		case 0: case 1: return y;
		case 2: return pi;
		default: return -pi;
		}
	}
	if (ix == 0 && (uint32_t)__aa64_asuint64(x) == 0)
		return m & 1 ? -pi / 2 : pi / 2;
	if (ix == 0x7ff00000) {
		if (iy == 0x7ff00000) {
			switch (m) {
			case 0: return pi / 4;
			case 1: return -pi / 4;
			case 2: return 3 * pi / 4;
			default: return -3 * pi / 4;
			}
		}
		switch (m) {
		case 0: return 0.0;
		case 1: return -0.0;
		case 2: return pi;
		default: return -pi;
		}
	}
	if (ix + ((uint32_t)64 << 20) < iy || iy == 0x7ff00000)
		return m & 1 ? -pi / 2 : pi / 2;

	if ((m & 2) && iy + ((uint32_t)64 << 20) < ix) z = 0;
	else { double ay = y < 0 ? -y : y; z = __aa64_atan(ay / (x < 0 ? -x : x)); }
	switch (m) {
	case 0: return z;
	case 1: return -z;
	case 2: return pi - (z - pi_lo);
	default: return (z - pi_lo) - pi;
	}
}

/* ---- self-derived: log2/exp2 (see this file's own banner) ----------- */

/* log2(x) for finite x > 0 via the atanh series: writing x = m*2^e with
 * m in [1/sqrt2, sqrt2) (a symmetric-around-1 normalization, not
 * frexp's plain [0.5,1) -- it roughly halves the reduced argument's
 * range), u = (m-1)/(m+1) satisfies m = (1+u)/(1-u) and
 * log(m) = 2*atanh(u) = 2*(u + u^3/3 + u^5/5 + ...), a series that is
 * exact term-by-term (no fitted/rounded coefficients -- every
 * denominator is the corresponding odd integer) and converges to
 * double precision in well under 20 terms for |u| <= ~0.1716 (this
 * normalization's worst case). log2(x) = e + log(m)/ln2. */
static double __aa64_log2(double x)
{
	static const double LOG2E = 0x1.71547652b82fep+0; /* 1/ln2, from this sandbox's own libm */
	union __aa64_bits u;
	int e;
	double m, r, u2, term, sum;
	int k;

	if (x != x) return x; /* nan */
	if (x <= 0) {
		if (x == 0) {
			/* pole error (log.html ERRORS): math_errhandling is
			 * unconditionally MATH_ERREXCEPT here (include/math.h), so this
			 * is mandatory, not optional -- and unlike real x87 fyl2x
			 * (whose divide-by-zero flag a genuine zero-operand division
			 * sets in hardware), "-1.0/0.0" here is two compile-time
			 * constants that the compiler is free to fold to -inf without
			 * ever executing a division, so raise the flag explicitly. */
			feraiseexcept(FE_DIVBYZERO);
			return -1.0 / 0.0;
		}
		return (x - x) / (x - x); /* negative: nan */
	}
	if (x == 1.0 / 0.0) return x;

	u.f = x;
	e = (int)((u.i >> 52) & 0x7ff) - 1023;
	if (e == -1023) { /* subnormal: renormalize */
		u.f = x * 0x1p54;
		e = (int)((u.i >> 52) & 0x7ff) - 1023 - 54;
	}
	u.i = (u.i & ((1ULL << 52) - 1)) | ((uint64_t)1023 << 52);
	m = u.f; /* m in [1,2) */
	if (m >= 0x1.6a09e667f3bcdp0) { /* m >= sqrt(2): rescale to [sqrt(.5),sqrt2) */
		m *= 0.5;
		e += 1;
	}

	r = (m - 1.0) / (m + 1.0);
	u2 = r * r;
	term = r;
	sum = r;
	for (k = 3; k <= 39; k += 2) {
		term *= u2;
		sum += term / (double)k;
	}
	return (double)e + 2.0 * sum * LOG2E;
}

/* y * log2(x). */
static double __aa64_yl2x(double x, double y)
{
	return y * __aa64_log2(x);
}

/* 2^t for finite t. Split t = n + f, n integer, f in [-0.5,0.5]; 2^f =
 * e^(f*ln2) via the Maclaurin series for e^z (exact term-by-term,
 * term_k = z^k/k!, converging to well under double precision in 18
 * terms for |z| <= 0.5*ln2 ~= 0.3466); 2^n applied exactly afterward
 * via __aa64_scalbn. */
static double __aa64_exp2(double t)
{
	static const double LN2 = 0x1.62e42fefa39efp-1; /* from this sandbox's own libm */
	double n, f, z, term, sum;
	int k, ni;

	if (t != t) return t;
	if (t >= 1024.0) return 1.0 / 0.0; /* overflow -> +inf */
	if (t <= -1100.0) return 0.0; /* underflow -> +0: 2^t > 0 for all real t,
	                                * so unlike expm1-style identities there is
	                                * no negative-zero case to preserve here */

	n = __aa64_rndint(t, 0);
	f = t - n;
	z = f * LN2;
	term = 1.0;
	sum = 1.0;
	for (k = 1; k <= 18; k++) {
		term *= z / (double)k;
		sum += term;
	}
	ni = (int)n;
	return __aa64_scalbn(sum, ni);
}

/* ln(1+x), used by src/math/expm1.c's log1p family in place of x87's
 * fyl2xp1 -- via 2*atanh(x/(x+2)), the same identity __aa64_log2 uses
 * (m=1+x, u=(m-1)/(m+1)=x/(x+2)) but written directly in terms of x so
 * the catastrophic-cancellation case expm1.c exists to avoid (forming
 * (1+x)-1 for small x) never happens: u is computed from x with no
 * intervening "+1"/"-1" pair at all.
 *
 * Only valid for |u| small (this file's one caller, expm1.c's
 * log1pl(), only ever reaches raw_yl2xp1() -- and so only this
 * function -- for |x| < ~0.293, where |u| <= ~0.172 and the series
 * below converges to well under double precision in 19 terms): for
 * |x| outside that range u is not small and the same series would
 * need far more terms to converge at all. Falls back to the general
 * log2(1+x)*ln2 identity there instead (still real math, just not the
 * cancellation-free shortcut, exactly like expm1.c's own logl(1+x)
 * fallback for x outside f2xm1's domain) -- kept so this function is
 * honestly general-purpose rather than silently wrong outside the one
 * range its real caller happens to use, since "log1p" is a name that
 * invites a future caller to assume the full domain works. */
static double __aa64_log1p(double x)
{
	double u = x / (x + 2.0);
	double u2, term, sum;
	int k;

	if (u > 0.25 || u < -0.25) {
		static const double LN2 = 0x1.62e42fefa39efp-1;
		return LN2 * __aa64_log2(1.0 + x);
	}
	u2 = u * u;
	term = u;
	sum = u;
	for (k = 3; k <= 39; k += 2) {
		term *= u2;
		sum += term / (double)k;
	}
	return 2.0 * sum;
}

/* 2^t - 1, used by src/math/expm1.c in place of x87's f2xm1 -- via the
 * Maclaurin series for e^z-1 (z = t*ln2), which sums z + z^2/2! + ...
 * directly rather than forming e^z and subtracting 1 afterward, the
 * same cancellation expm1.c's own banner explains f2xm1 exists to
 * avoid. */
static double __aa64_expm1(double t)
{
	static const double LN2 = 0x1.62e42fefa39efp-1;
	double z, term, sum;
	int k;

	/* Zero must return with its own sign (2^0-1 is exactly 0, and this
	 * matches x87 f2xm1's documented zero-sign-preserving contract --
	 * see expm1.c's own banner): the loop below cannot produce that
	 * itself for t==-0.0, since its first step squares z's sign away
	 * (term = z*(z/2), i.e. (-0.0)*(-0.0) = +0.0) before the addition
	 * ever sees the original sign. */
	if (t == 0.0) return t;

	z = t * LN2;
	term = z; sum = z;
	for (k = 2; k <= 19; k++) {
		term *= z / (double)k;
		sum += term;
	}
	return sum;
}

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
