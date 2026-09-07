/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __extenddftf2()/__trunctfdf2()/__trunctfsf2() -- the compiler-rt/libgcc
 * software-float conversion routines between IEEE 754 binary128 ("quad",
 * what `long double` really is on aarch64) and binary64/binary32
 * (`double`/`float`).
 *
 * WHY THIS FILE HAS TO EXIST: this build is -nostdlib, so no libgcc or
 * compiler-rt is linked in, and clang emits calls to these three exact
 * symbols for any `long double` <-> `double`/`float` conversion since
 * aarch64 has no quad-precision hardware. src/math/ldbl_math.h's
 * wrappers and src/stdlib/strtod.c's strtox() both narrow to `double`
 * at their boundaries rather than computing in quad directly, and still
 * need these three symbols to link (confirmed: multiple LTP tests
 * failed to link without them, pulled in transitively through
 * strtod.o/scalbn.o).
 *
 * SCOPE: only these three. __extendsftf2 (float -> long double) is not
 * needed anywhere in this tree; real arithmetic on long double values
 * (__addtf3, __multf3, ...) is avoided entirely by the narrow-compute-
 * widen policy above.
 *
 * LAYOUT: binary128 is 16 bytes, little-endian on this arch: the low 8
 * bytes hold the low 64 bits of the 112-bit stored fraction; the high
 * 8 bytes hold [sign:1][exponent:15, bias 16383][fraction, high 48
 * bits].
 *
 * VERIFICATION: checked against a host oracle (GCC's native
 * `_Float128` and its own real __extenddftf2/__trunctfdf2/__trunctfsf2)
 * across hand-picked boundaries plus randomized fuzzing, zero mismatches
 * (NaN payload bits excepted -- IEEE 754 doesn't mandate how those
 * propagate across a precision change, only that the result is some
 * NaN).
 */
#include <stdint.h>
#include "rtlib.h"   /* this file's own prototypes: nothing in the tree
                      * calls these by name, but rtlib.h still declares
                      * compiler-generated-call functions like these */

union spicule_tf128 {
	long double f;
	struct { uint64_t lo, hi; } u;
};

static uint64_t tf_shr(uint64_t x, int n) { return (n <= 0) ? x : (n >= 64) ? 0 : (x >> n); }
static uint64_t tf_shl(uint64_t x, int n) { return (n <= 0) ? x : (n >= 64) ? 0 : (x << n); }

/* Bit `pos` (0 = LSB) of the conceptual 128-bit value (hi:lo). */
static int tf_bit(uint64_t hi, uint64_t lo, int pos) // NOLINT(bugprone-easily-swappable-parameters) -- hi and lo are distinct halves of the binary128 value
{
	if (pos < 0) return 0;
	if (pos < 64) return (int)((lo >> pos) & 1);
	return (int)(tf_shr(hi, pos - 64) & 1);
}

/* Is any bit in [pos-1:0] of (hi:lo) set? (pos <= 0: no such bits) */
static int tf_any_below(uint64_t hi, uint64_t lo, int pos) // NOLINT(bugprone-easily-swappable-parameters) -- hi and lo are distinct halves of the binary128 value
{
	uint64_t mask_lo, mask_hi;
	if (pos <= 0) return 0;
	if (pos >= 128) return (hi | lo) != 0;
	if (pos <= 64) {
		mask_lo = (pos == 64) ? ~0ULL : ((1ULL << pos) - 1);
		return (lo & mask_lo) != 0;
	}
	mask_hi = (pos - 64 >= 64) ? ~0ULL : ((1ULL << (pos - 64)) - 1);
	return lo != 0 || (hi & mask_hi) != 0;
}

/* (hi:lo) right-shifted by n bits (0 <= n), low 64 bits of the result --
 * all any caller here needs, since every destination mantissa (52 or 23
 * bits) fits well inside it once shifted this far right. */
static uint64_t tf_shr128_lo(uint64_t hi, uint64_t lo, int n)
{
	if (n <= 0) return lo;
	if (n < 64) return (lo >> n) | tf_shl(hi, 64 - n);
	return tf_shr(hi, n - 64);
}

/* Round-to-nearest-even: does adding 1 to `mant` (the caller's job, note
 * the possible carry-out) follow from this guard/sticky pair? */
static int tf_round_up(uint64_t mant, int guard, int sticky) // NOLINT(bugprone-easily-swappable-parameters) -- guard and sticky have distinct rounding roles
{
	if (!guard) return 0;
	if (sticky) return 1;
	return (int)(mant & 1);   /* exact tie: round to even */
}

/* ---- __extenddftf2: double -> long double, always exact --------------- */
long double __extenddftf2(double a)
{
	union { double f; uint64_t i; } d;
	union spicule_tf128 r;
	uint64_t sign, exp11, frac52, exp15, hi48, lo64, frac;
	int shift;

	d.f = a;
	sign = d.i >> 63;
	exp11 = (d.i >> 52) & 0x7FFULL;
	frac52 = d.i & 0xFFFFFFFFFFFFFULL;

	if (exp11 == 0 && frac52 == 0) {
		r.u.hi = sign << 63;
		r.u.lo = 0;
		return r.f;
	}
	if (exp11 == 0x7FFULL) {
		/* Infinity (frac52 == 0) or NaN: exponent saturates, payload
		 * widens with the same zero-padding shift every finite value
		 * gets below -- see this file's own banner on why the exact
		 * NaN payload bits are not otherwise significant. */
		exp15 = 0x7FFFULL;
		hi48 = frac52 >> 4;
		lo64 = (frac52 & 0xFULL) << 60;
	} else if (exp11 == 0) {
		/* Subnormal double: renormalize. Quad's exponent range is so
		 * much larger that the identical value is always NORMAL
		 * there (LDBL_MIN_EXP/LDBL_MAX_EXP, arch/aarch64/bits/
		 * float.h, dwarf DBL_MIN_EXP/DBL_MAX_EXP by orders of
		 * magnitude). */
		shift = 0;
		frac = frac52;
		while (!(frac & (1ULL << 51))) { frac <<= 1; shift++; }
		/* bit51 is now the implicit leading one (the loop's own exit
		 * condition) -- drop it AND re-align the remaining bits up
		 * to fill the vacated top bit: a plain mask alone would leave
		 * a spurious zero at the top and halve the reconstructed
		 * value. */
		frac = (frac << 1) & 0xFFFFFFFFFFFFFULL;
		exp15 = (uint64_t)(16383 - 1023 - shift);
		hi48 = frac >> 4;
		lo64 = (frac & 0xFULL) << 60;
	} else {
		exp15 = exp11 - 1023ULL + 16383ULL;
		hi48 = frac52 >> 4;
		lo64 = (frac52 & 0xFULL) << 60;
	}
	r.u.hi = (sign << 63) | (exp15 << 48) | hi48;
	r.u.lo = lo64;
	return r.f;
}

/* ---- __trunctfdf2: long double (binary128) -> double, correctly rounded */
double __trunctfdf2(long double a)
{
	union spicule_tf128 t;
	union { double f; uint64_t i; } r;
	uint64_t sign, exp15, frac_hi48, frac_lo64, sig_hi, mant, nan_frac;
	int live_exp, total_shift, guard, sticky;

	t.f = a;
	sign = t.u.hi >> 63;
	exp15 = (t.u.hi >> 48) & 0x7FFFULL;
	frac_hi48 = t.u.hi & 0xFFFFFFFFFFFFULL;
	frac_lo64 = t.u.lo;

	if (exp15 == 0x7FFFULL) {
		if (frac_hi48 == 0 && frac_lo64 == 0) {
			r.i = (sign << 63) | (0x7FFULL << 52);   /* infinity */
			return r.f;
		}
		nan_frac = (frac_hi48 << 4) | (frac_lo64 >> 60);
		if (!nan_frac) nan_frac = 1;   /* never collapse a real NaN to Inf */
		r.i = (sign << 63) | (0x7FFULL << 52) | nan_frac;
		return r.f;
	}
	if (exp15 == 0) {
		/* Quad zero, or a quad subnormal: a true quad subnormal's
		 * largest possible magnitude (just under LDBL_MIN,
		 * ~3.36e-4932) is still many orders of magnitude below
		 * DBL_TRUE_MIN (~4.94e-324), so correctly rounding ANY such
		 * value to double produces the same answer as rounding exact
		 * zero would: signed zero. Not an approximation -- the two
		 * cases are provably identical outcomes. */
		r.i = sign << 63;
		return r.f;
	}

	live_exp = (int)exp15 - 16383;
	sig_hi = (1ULL << 48) | frac_hi48;   /* implicit leading one + top 48
	                                      * fraction bits: the 113-bit
	                                      * significand's bits [112:64] */

	if (live_exp > 1023) {
		r.i = (sign << 63) | (0x7FFULL << 52);   /* overflow: infinity */
		return r.f;
	}

	total_shift = (live_exp >= -1022) ? 60 : 60 + (-1022 - live_exp);

	if (total_shift > 113) {
		r.i = sign << 63;   /* underflows below even the smallest
		                     * subnormal's rounding boundary: zero */
		return r.f;
	}

	mant = tf_shr128_lo(sig_hi, frac_lo64, total_shift) & 0xFFFFFFFFFFFFFULL;
	guard = tf_bit(sig_hi, frac_lo64, total_shift - 1);
	sticky = tf_any_below(sig_hi, frac_lo64, total_shift - 1);

	if (tf_round_up(mant, guard, sticky)) {
		mant++;
		if (mant == (1ULL << 52)) {
			/* Carried out of the mantissa. Normal-target result:
			 * the ordinary "round up to the next power of two" --
			 * bump the exponent, mant reads 0, correct (the new
			 * implicit 1 needs no stored bit). Subnormal-target
			 * result: the carry promoted it all the way to the
			 * smallest NORMAL double (2^-1022) -- the same
			 * "exponent field += 1, mant = 0" step handles this
			 * too, since biased exponent 1 with mant 0 is exactly
			 * that value. */
			mant = 0;
			if (total_shift == 60) {
				live_exp++;
			} else {
				total_shift = 60;
				live_exp = -1022;
			}
		}
	}

	if (live_exp > 1023) {
		r.i = (sign << 63) | (0x7FFULL << 52);   /* rounded up into overflow */
		return r.f;
	}

	exp15 = (total_shift == 60) ? (uint64_t)(live_exp + 1023) : 0;
	r.i = (sign << 63) | (exp15 << 52) | mant;
	return r.f;
}

/* ---- __trunctfsf2: long double (binary128) -> float, correctly rounded */
float __trunctfsf2(long double a)
{
	union spicule_tf128 t;
	union { float f; uint32_t i; } r;
	uint64_t sign, exp15, frac_hi48, frac_lo64, sig_hi, nan_frac;
	uint32_t mant;
	int live_exp, total_shift, guard, sticky;

	t.f = a;
	sign = t.u.hi >> 63;
	exp15 = (t.u.hi >> 48) & 0x7FFFULL;
	frac_hi48 = t.u.hi & 0xFFFFFFFFFFFFULL;
	frac_lo64 = t.u.lo;

	if (exp15 == 0x7FFFULL) {
		if (frac_hi48 == 0 && frac_lo64 == 0) {
			r.i = ((uint32_t)sign << 31) | (0xFFUL << 23);
			return r.f;
		}
		nan_frac = (uint32_t)((frac_hi48 << 4 | frac_lo64 >> 60) >> 29);
		if (!nan_frac) nan_frac = 1;
		r.i = ((uint32_t)sign << 31) | (0xFFUL << 23) | (uint32_t)nan_frac;
		return r.f;
	}
	if (exp15 == 0) {
		/* Same reasoning as __trunctfdf2()'s identical branch, scaled
		 * to float: a quad subnormal's largest magnitude is still
		 * far below FLT_TRUE_MIN. */
		r.i = (uint32_t)sign << 31;
		return r.f;
	}

	live_exp = (int)exp15 - 16383;
	sig_hi = (1ULL << 48) | frac_hi48;

	if (live_exp > 127) {
		r.i = ((uint32_t)sign << 31) | (0xFFUL << 23);
		return r.f;
	}

	/* Float's mantissa is 23 bits, so the fixed discard for an
	 * in-range normal result is 112-23 = 89 bits, not __trunctfdf2()'s
	 * 60 -- same structure throughout, just float's 8-bit exponent
	 * (bias 127) and 23-bit mantissa in place of double's. */
	total_shift = (live_exp >= -126) ? 89 : 89 + (-126 - live_exp);

	if (total_shift > 113) {
		r.i = (uint32_t)sign << 31;
		return r.f;
	}

	mant = (uint32_t)(tf_shr128_lo(sig_hi, frac_lo64, total_shift) & 0x7FFFFFUL);
	guard = tf_bit(sig_hi, frac_lo64, total_shift - 1);
	sticky = tf_any_below(sig_hi, frac_lo64, total_shift - 1);

	if (tf_round_up(mant, guard, sticky)) {
		mant++;
		if (mant == (1UL << 23)) {
			mant = 0;
			if (total_shift == 89) {
				live_exp++;
			} else {
				total_shift = 89;
				live_exp = -126;
			}
		}
	}

	if (live_exp > 127) {
		r.i = ((uint32_t)sign << 31) | (0xFFUL << 23);
		return r.f;
	}

	exp15 = (total_shift == 89) ? (uint64_t)(live_exp + 127) : 0;
	r.i = ((uint32_t)sign << 31) | ((uint32_t)exp15 << 23) | mant;
	return r.f;
}
