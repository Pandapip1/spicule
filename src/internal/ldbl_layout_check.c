/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __verify_ldbl_layout(): a startup canary for the one assumption every
 * `long double` bit-twiddling function in src/math (ldbl_math.h,
 * fpclassify.c, frexp.c, copysign.c, fabs.c) rests on -- that
 * SPICULE_LDBL_EXTENDED (src/internal/ldbl_format.h) correctly predicts
 * which physical bit layout this build's compiler actually uses for
 * `long double`. C itself guarantees none of that layout (see
 * ldbl_format.h's own banner), so the prediction is inferred from one
 * compiler-reported number, __SIZEOF_LONG_DOUBLE__ -- and this project
 * has already shipped a real bug from trusting a `long double` layout
 * assumption without checking it (git history: LDBL_MANT_DIG/LDBL_MAX
 * hardcoded to the 80-bit values unconditionally, silently wrong under
 * tcc's alias-to-double ABI). Rather than trust the inference a second
 * time, this function actually LOOKS: it writes three real `long
 * double` constants with well-known values, reads back the raw bits
 * through the same union-punning idiom fpclassify.c already uses, and
 * compares them against the bit pattern SPICULE_LDBL_EXTENDED and this
 * translation unit's target architecture together predict. If they
 * disagree, every one of those math functions would silently compute
 * wrong results (best case) or read/write past the end of a `long
 * double` object (worst case, ldbl_math.h's own banner: an 80-bit
 * tbyte store into an 8-byte object corrupts whatever is next to it on
 * the stack) -- so this is checked before any of them can run, not
 * exercised as a test suite entry someone has to remember to run.
 *
 * Three constants, not one, and not arbitrarily chosen:
 *
 *   1.0L  sign=0, unbiased exponent=0, mantissa/fraction=0 -- the
 *         simplest possible encoding, but specifically the one that
 *         tells an explicit-integer-bit format (x87) apart from an
 *         implicit-leading-bit format (IEEE binary64/binary128): the
 *         stored significand is all-bits-1-then-0 under the former and
 *         all-bits-0 under the latter for this exact value, so getting
 *         that convention backwards is caught immediately, not just a
 *         difference that happens to cancel out.
 *   2.0L  same mantissa/fraction pattern as 1.0L (0), but the exponent
 *         field is one more than 1.0L's -- confirms the exponent field
 *         is actually being read as an exponent (at the right bit
 *         position, right width) rather than 1.0L's check having
 *         passed by coincidence on an all-zero-everything pattern.
 *   0.75L = 1.5 x 2^-1: sign=0, exponent BELOW the bias point (unlike
 *         the other two), and -- unlike either of them -- a nonzero,
 *         non-power-of-two-boundary fraction (binary 0.75 = 1.1b x
 *         2^-1, so exactly the top fraction bit is set and every other
 *         fraction bit is 0). Catches a wrong bit-order or
 *         wrong-field-boundary bug that an all-zero-fraction value
 *         could never expose.
 *
 * Shape: each branch below declares its own `struct ldbl_bits` (the
 * physical layout genuinely differs in width -- 8, 10/12, or 16 bytes
 * -- so unioning them all against one fixed-width type would leave
 * indeterminate padding on the narrower formats, read back and
 * compared as if it meant something), a one-line `ldbl_bits_eq()` for
 * that shape, and a `ldbl_expect[]` table of nothing but the three
 * real expected constants -- computed by hand from the definitions
 * above (IEEE-754/x87 bias 16383 for the extended formats, bias 1023
 * for the tcc-alias-to-double case) and cross-checked against
 * fpclassify.c's own worked example for 1.0L's x87 encoding before
 * being trusted here. The actual verification logic -- union-punning
 * each probe value and comparing it against its expected entry -- is
 * written exactly once, below, shared by every branch.
 */
#include <stdint.h>
#include "libc.h"
#include "ldbl_format.h"

/* The three probe values every branch checks, declared once: one place
 * this could be gotten wrong, not three. */
static const long double ldbl_probe[3] = { 1.0L, 2.0L, 0.75L };

#if !SPICULE_LDBL_EXTENDED
/* tcc's -win32 targets: `long double` is a plain 8-byte alias for
 * `double` (IEEE binary64, bias 1023, implicit leading bit). Same
 * union shape src/math/fpclassify.c's own __fpclassify() uses for
 * plain double. */
struct ldbl_bits { uint64_t i; };
static int ldbl_bits_eq(struct ldbl_bits a, struct ldbl_bits b) { return a.i == b.i; }
static const struct ldbl_bits ldbl_expect[3] = {
	{ 0x3FF0000000000000ULL },  /* 1.0L */
	{ 0x4000000000000000ULL },  /* 2.0L */
	{ 0x3FE8000000000000ULL },  /* 0.75L */
};

#elif defined(__i386__) || defined(__x86_64__)
/* Real x87 80-bit extended precision (mingw-w64 gcc's `long double`):
 * a 64-bit mantissa with an EXPLICIT integer bit, followed by a 16-bit
 * sign+exponent half (bias 16383) -- Intel SDM vol 1 ch 8. Exact same
 * union shape and field names as fpclassify.c's own
 * SPICULE_LDBL_EXTENDED branch, deliberately, so a reader who has
 * already read that function recognizes this layout immediately. */
struct ldbl_bits { uint64_t m; uint16_t se; };
static int ldbl_bits_eq(struct ldbl_bits a, struct ldbl_bits b) { return a.m == b.m && a.se == b.se; }
static const struct ldbl_bits ldbl_expect[3] = {
	/* 1.0L:  exponent field 0x3FFF (bias 16383, unbiased 0), explicit
	 *        integer bit set, fraction 0. */
	{ 0x8000000000000000ULL, 0x3FFF },
	/* 2.0L:  exponent field 0x4000 (unbiased +1), same mantissa. */
	{ 0x8000000000000000ULL, 0x4000 },
	/* 0.75L = 1.1b x 2^-1: exponent field 0x3FFE (unbiased -1),
	 * explicit integer bit set, top fraction bit set. */
	{ 0xC000000000000000ULL, 0x3FFE },
};

#else
/* Real IEEE 754 binary128 ("quad") -- confirmed on aarch64. 1 sign bit
 * + 15-bit exponent (bias 16383, same width as x87's but NOT the same
 * format: binary128 uses an IMPLICIT leading bit, unlike x87's
 * explicit one) + 112 fraction bits. Split as two uint64_t words,
 * little-endian: `lo` holds the low 64 fraction bits, `hi` holds
 * [sign:1][exponent:15][fraction, high 48 bits] -- the exact same
 * split arch/aarch64/src/ld128_convert.c's own real, fuzz-verified
 * binary128 conversion routines already use; deliberately reusing that
 * one confirmed-correct layout rather than re-deriving a second,
 * possibly-inconsistent one here. */
struct ldbl_bits { uint64_t lo, hi; };
static int ldbl_bits_eq(struct ldbl_bits a, struct ldbl_bits b) { return a.lo == b.lo && a.hi == b.hi; }
static const struct ldbl_bits ldbl_expect[3] = {
	/* 1.0L: exponent field 0x3FFF in the top 15 bits below the sign
	 * bit, i.e. hi == 0x3FFFn<<48; fraction (lo and the low 48 bits of
	 * hi) all zero -- IEEE's implicit leading bit. */
	{ 0, 0x3FFF000000000000ULL },
	/* 2.0L: exponent field 0x4000, same all-zero fraction. */
	{ 0, 0x4000000000000000ULL },
	/* 0.75L = 1.1b x 2^-1: exponent field 0x3FFE, and the single set
	 * fraction bit lands in the top bit of hi's 48-bit fraction field
	 * (bit 47 of hi, i.e. 0x0000800000000000). */
	{ 0, 0x3FFE800000000000ULL },
};
#endif

int __verify_ldbl_layout(void) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
{
	int i, ok = 1;
	for (i = 0; i < 3; i++) {
		union { long double f; struct ldbl_bits b; } u = { ldbl_probe[i] };
		ok &= ldbl_bits_eq(u.b, ldbl_expect[i]);
	}
	return ok;
}
