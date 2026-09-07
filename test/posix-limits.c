/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the numeric-limits/integer-type
 * headers: limits.h, float.h, stdint.h, inttypes.h, plus the inttypes.h
 * functions strtoimax/strtoumax/imaxabs/imaxdiv (src/stdlib/strtol.c,
 * src/stdlib/abs.c, src/stdlib/div.c). None of these had a clause-cited
 * audit before. See test/posix-coverage/limits.md for the
 * full ledger. Each assertion cites the clause of
 * https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/<hdr>.html
 * (or .../functions/<name>.html) it checks.
 *
 * Two rules this file holds to throughout (see the task brief):
 *
 *  1. Where POSIX gives a floor/ceiling ("Minimum Acceptable Value",
 *     "Maximum Acceptable Value"), assert the *direction* the spec
 *     states, not spicule's exact number -- otherwise the test is a
 *     change-detector, not a conformance check.
 *
 *  2. Where a value is genuinely arch-dependent (this target is LLP64:
 *     `long` is 32-bit on both i386 and x86_64 PE, but pointer-width
 *     types -- size_t/ssize_t/intptr_t/ptrdiff_t -- are 32-bit on i386
 *     and 64-bit on x86_64; wchar_t is 16-bit UTF-16 on both), the
 *     expected value is derived from sizeof()/the type's own arithmetic
 *     rather than hardcoded, so one assertion covers both arches.
 *
 * The one place that derivation itself is impossible: `long`'s actual
 * *compiler*-chosen width. spicule deliberately keeps `long` 32-bit on
 * both PE arches (LONG_BIT, LONG_MAX/MIN, ULONG_MAX), which is a real
 * width for this tcc's -win32/-win64 targets (confirmed empirically:
 * __SIZEOF_LONG__ is 4 under both), but a *native* gcc/clang building
 * this same header for `make asan` makes the compiler's own `long` 8
 * bytes on x86_64 while these headers still say 32-bit -- an expected,
 * documented divergence between the NT target and the native asan
 * harness (see tools/asan-build.sh's `math`/`strto` entries; NOT a bug
 * to fix, since spicule has no native x86_64 target at all). Rather than
 * add another tools/asan-build.sh not_native() entry and lose this
 * file's other, unrelated coverage under `make asan`, the few
 * assertions that actually depend on the compiler's own `long` being
 * 32-bit are guarded by `__SIZEOF_LONG__` (which this tcc predefines,
 * same trick src/math/ldbl_math.h uses for __SIZEOF_LONG_DOUBLE__) so they
 * simply do not run when the real compiler disagrees.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>	/* ptrdiff_t */
#include <limits.h>
#include <float.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>	/* ssize_t */
#include <signal.h>	/* sig_atomic_t */
#include <errno.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ==================================================================
 * limits.h -- https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html
 * ================================================================== */

/* ---- Numerical Limits table: exact values and Minimum/Maximum
 * Acceptable Value floors/ceilings ---- */
static void test_limits_numerical(void)
{
	/* "CHAR_BIT: Value: 8" -- an exact requirement, not a floor. */
	CHECK(CHAR_BIT == 8);

	/* "SCHAR_MIN: Value: -128", "SCHAR_MAX: Value: +127",
	 * "UCHAR_MAX: Value: 255" -- exact, C99 requires two's complement
	 * plain bytes here (no padding: UCHAR_MAX == 2^CHAR_BIT - 1). */
	CHECK(SCHAR_MIN == -128 && SCHAR_MAX == 127 && UCHAR_MAX == 255);

	/* "CHAR_MIN: Value: {UCHAR_MAX} or {SCHAR_MIN}" (0 or -128),
	 * "CHAR_MAX: Value: {SCHAR_MAX} or {UCHAR_MAX}" -- whichever plain
	 * `char` actually is, checked against its own signedness. */
	if ((char)-1 < 0) {
		CHECK(CHAR_MIN == SCHAR_MIN && CHAR_MAX == SCHAR_MAX);
	} else {
		CHECK(CHAR_MIN == 0 && CHAR_MAX == UCHAR_MAX);
	}

	/* SHRT_MAX/MIN, USHRT_MAX: "Minimum/Maximum Acceptable Value"
	 * floors -- direction only. */
	CHECK(SHRT_MAX >= 32767);
	CHECK(SHRT_MIN <= -32767);
	CHECK(USHRT_MAX >= 65535);

	/* INT_MAX/MIN, UINT_MAX: same, direction only. */
	CHECK(INT_MAX >= 2147483647);
	CHECK(INT_MIN <= -2147483647);
	CHECK(UINT_MAX >= 4294967295U);

	/* LONG_MAX/MIN: "Minimum/Maximum Acceptable Value +2147483647 /
	 * -2147483647" -- the *floor* POSIX requires of every conforming
	 * `long`, deliberately not the exact value: this target keeps
	 * `long` 32-bit by design (LLP64), which already exceeds the
	 * floor, so this assertion holds regardless of arch. */
	CHECK(LONG_MAX >= 2147483647L);
	CHECK(LONG_MIN <= -2147483647L);
	CHECK(ULONG_MAX >= 4294967295UL);

	/* LLONG_MAX/MIN, ULLONG_MAX: floors. */
	CHECK(LLONG_MAX >= 9223372036854775807LL);
	CHECK(LLONG_MIN <= -9223372036854775807LL);
	CHECK(ULLONG_MAX >= 18446744073709551615ULL);

	/* MB_LEN_MAX: "Minimum Acceptable Value: 1". */
	CHECK(MB_LEN_MAX >= 1);

	/* WORD_BIT, LONG_BIT: "Minimum Acceptable Value: 32" each. */
	CHECK(WORD_BIT >= 32);
	CHECK(LONG_BIT >= 32);
}

/* ---- Internal consistency: the macros must match what the *actual*
 * types do, not just satisfy the floor in isolation. This is where
 * width mismatches hide -- see the LLONG/LONG/SSIZE bugs sought by the
 * task brief. Every expected value below is derived from sizeof() or
 * the type's own -1/overflow behaviour, not hardcoded, so these hold
 * on both i386 and x86_64 without needing an arch split. ---- */
static void test_limits_consistency(void)
{
	/* UINT_MAX == (unsigned)-1: C99 6.2.6.2 defines unsigned wraparound
	 * this way; if UINT_MAX did not match, every unsigned comparison
	 * against it would be wrong. */
	CHECK(UINT_MAX == (unsigned)-1);
	CHECK(ULLONG_MAX == (unsigned long long)-1);

	/* INT_MIN <= -INT_MAX (two's complement: exactly -INT_MAX-1) --
	 * the direction the Numerical Limits table states for *_MIN
	 * relative to *_MAX, plus the exact two's-complement identity,
	 * which int8_t/int16_t/int32_t/int64_t below also assume. */
	CHECK(INT_MIN <= -INT_MAX);
	CHECK((unsigned)INT_MAX == UINT_MAX / 2);
	CHECK(LLONG_MIN <= -LLONG_MAX);
	CHECK((unsigned long long)LLONG_MAX == ULLONG_MAX / 2);

	/* sizeof(int)*CHAR_BIT is consistent with INT_MAX/UINT_MAX: for an
	 * n-bit two's-complement int, INT_MAX == 2^(n-1)-1. Computed in
	 * uintmax_t so the shift count (<=63) is always in range. */
	CHECK((uintmax_t)INT_MAX == ((uintmax_t)1 << (sizeof(int) * CHAR_BIT - 1)) - 1);
	CHECK((uintmax_t)UINT_MAX == ((uintmax_t)1 << (sizeof(unsigned) * CHAR_BIT)) - 1);
	CHECK(WORD_BIT == (int)(sizeof(int) * CHAR_BIT));

	/* LLONG_MAX/ULLONG_MAX vs the real sizeof(long long): `long long`
	 * is 64-bit under every compiler this project uses (tcc's PE
	 * targets and the native asan compiler alike -- see
	 * arch/{i386,x86_64}/bits/alltypes.h.in's `_Int64`), so this needs no guard. */
	CHECK((uintmax_t)LLONG_MAX == ((uintmax_t)1 << (sizeof(long long) * CHAR_BIT - 1)) - 1);
	CHECK((uintmax_t)ULLONG_MAX == ((uintmax_t)1 << (sizeof(long long) * CHAR_BIT - 1) << 1) - 1);

	/* `long` itself: only meaningful when the *compiler's* long is
	 * really 32-bit, which is true for both tcc PE targets but not for
	 * a native x86_64 asan build -- see the file banner. */
#if !defined(__SIZEOF_LONG__) || __SIZEOF_LONG__ == 4
	CHECK(ULONG_MAX == (unsigned long)-1);
	CHECK(LONG_MIN <= -LONG_MAX);
	CHECK((unsigned long)LONG_MAX == ULONG_MAX / 2);
	CHECK(LONG_BIT == (int)(sizeof(long) * CHAR_BIT));
	CHECK((uintmax_t)LONG_MAX == ((uintmax_t)1 << (sizeof(long) * CHAR_BIT - 1)) - 1);
#endif

	/* SSIZE_MAX: "Maximum value for an object of type ssize_t."  Not a
	 * floor here -- it must equal ssize_t's real maximum, derived from
	 * sizeof(ssize_t) rather than hardcoded so this covers both the
	 * 32-bit ssize_t on i386 and the 64-bit one on x86_64 (ssize_t is
	 * `_Addr`, the pointer-width type -- see arch/{i386,x86_64}/bits/alltypes.h.in
	 * -- not `long`, despite the historical `ssize_t`/`ssize` name).
	 *
	 * BUG found and fixed: include/limits.h used to say
	 * `#define SSIZE_MAX LONG_MAX`, which is only correct on i386
	 * (where ssize_t is `int`, same 32-bit range as `long` here). On
	 * x86_64 ssize_t is `long long` (64-bit) but LONG_MAX is still the
	 * 32-bit LLP64 value, so SSIZE_MAX silently capped a 64-bit type's
	 * documented maximum at 2^31-1. Fixed by moving SSIZE_MAX into
	 * arch/{i386,x86_64}/bits/limits.h with the correct per-arch literal
   * (arch/i386/bits/limits.h: 0x7fffffff; arch/x86_64/bits/limits.h:
	 * 0x7fffffffffffffffLL). This assertion is the regression test. */
	CHECK((uintmax_t)SSIZE_MAX == ((uintmax_t)1 << (sizeof(ssize_t) * CHAR_BIT - 1)) - 1);

	/* SSIZE_MAX must still satisfy the POSIX floor regardless of arch:
	 * "Minimum Acceptable Value: {_POSIX_SSIZE_MAX}". */
	CHECK(SSIZE_MAX >= _POSIX_SSIZE_MAX);
}

/* ---- Pathname/runtime-invariant macros: direction only, against the
 * implementation's own _POSIX_ / _POSIX2_ floors (verified separately
 * below to equal the spec's literal floors). ---- */
static void test_limits_pathname(void)
{
	CHECK(NAME_MAX >= _POSIX_NAME_MAX);
	CHECK(PATH_MAX >= _POSIX_PATH_MAX);
	CHECK(PIPE_BUF >= _POSIX_PIPE_BUF);
	CHECK(SYMLOOP_MAX >= _POSIX_SYMLOOP_MAX);
	CHECK(NGROUPS_MAX >= _POSIX_NGROUPS_MAX);
	CHECK(OPEN_MAX >= _POSIX_OPEN_MAX);
	CHECK(ARG_MAX >= _POSIX_ARG_MAX);
	CHECK(TZNAME_MAX >= _POSIX_TZNAME_MAX);
	CHECK(TTY_NAME_MAX >= _POSIX_TTY_NAME_MAX);
	CHECK(HOST_NAME_MAX >= _POSIX_HOST_NAME_MAX);
	/* FILESIZEBITS: "Minimum Acceptable Value: 32". */
	CHECK(FILESIZEBITS >= 32);
	/* IOV_MAX: the XSI floor is {_XOPEN_IOV_MAX}, which <limits.h> now
	 * defines -- so the macro is used rather than the spec's literal.
	 * This line previously read `CHECK(IOV_MAX >= 16)` under a comment
	 * saying the constant was "not defined as a macro by spicule", which
	 * is how that gap stayed invisible: an audit hit the absence, worked
	 * around it with a literal, and left no fence and no ledger row, so
	 * from outside it was indistinguishable from "checked, fine". */
	CHECK(IOV_MAX >= _XOPEN_IOV_MAX);
}

/* ---- _POSIX_ / _POSIX2_ "Minimum Values" table: these are exact
 * required floors (every conforming implementation sets them to
 * precisely the spec's number, since they name the guaranteed-portable
 * minimum a strictly conforming application may rely on, not
 * spicule's own capability) -- a representative cross-section, spot-
 * checked directly against the fetched spec table; the remainder were
 * verified by inspection to match and are not each re-asserted here to
 * avoid a 40-line wall of identical-shaped CHECKs. ---- */
static void test_limits_posix_floors(void)
{
	CHECK(_POSIX_ARG_MAX == 4096);
	CHECK(_POSIX_CHILD_MAX == 25);
	CHECK(_POSIX_LINK_MAX == 8);
	CHECK(_POSIX_MAX_CANON == 255);
	CHECK(_POSIX_MAX_INPUT == 255);
	CHECK(_POSIX_NAME_MAX == 14);
	CHECK(_POSIX_NGROUPS_MAX == 8);
	CHECK(_POSIX_OPEN_MAX == 20);
	CHECK(_POSIX_PATH_MAX == 256);
	CHECK(_POSIX_PIPE_BUF == 512);
	CHECK(_POSIX_SSIZE_MAX == 32767);
	CHECK(_POSIX_STREAM_MAX == 8);
	CHECK(_POSIX_SYMLOOP_MAX == 8);
	CHECK(_POSIX_TZNAME_MAX == 6);
	CHECK(_POSIX_TTY_NAME_MAX == 9);
	CHECK(_POSIX_HOST_NAME_MAX == 255);
	CHECK(_POSIX2_BC_BASE_MAX == 99);
	CHECK(_POSIX2_LINE_MAX == 2048);
	CHECK(_POSIX2_RE_DUP_MAX == 255);
	/* _POSIX_CLOCKRES_MIN: "Value: 20 000 000" (ns) -- exact. */
	CHECK(_POSIX_CLOCKRES_MIN == 20000000);

	/* CHILD_MAX and ATEXIT_MAX are Runtime Invariant Values that "may
	 * be omitted if the corresponding value is equal to or greater
	 * than the stated minimum, but is indeterminate." spicule reports
	 * CHILD_MAX only via sysconf(_SC_CHILD_MAX) (src/unistd/sysconf.c,
	 * out of this audit's scope) and defines neither macro -- both
	 * omissions are spec-conformant, not gaps. */
}

/* ==================================================================
 * float.h -- https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/float.h.html
 * ================================================================== */

static void test_float_radix_and_rounds(void)
{
	/* FLT_RADIX: "Number of base b... Minimum Acceptable Value: 2." */
	CHECK(FLT_RADIX >= 2);
	/* FLT_ROUNDS: "-1, 0, 1, 2, 3" is the full defined domain. */
	CHECK(FLT_ROUNDS >= -1 && FLT_ROUNDS <= 3);
	/* FLT_EVAL_METHOD: "-1, 0, 1, 2" is the full defined domain (this
	 * is as far as this file can check it: which value is *correct*
	 * for a given compiler's actual expression-evaluation behaviour
	 * needs disassembly, not a portable C assertion, so that part is
	 * left unverified rather than guessed at). */
	CHECK(FLT_EVAL_METHOD >= -1 && FLT_EVAL_METHOD <= 2);
}

/* ---- DIG/MANT_DIG/MIN_EXP/MAX_EXP/MIN/MAX/EPSILON floors, per type,
 * plus the exact defining relationship for EPSILON: "the difference
 * between 1 and the least value greater than 1 that is representable"
 * (float.h.html, DBL_EPSILON row). ---- */
static void test_float_flt(void)
{
	CHECK(FLT_DIG >= 6);
	CHECK(FLT_MANT_DIG >= 1);
	CHECK(FLT_MIN_10_EXP <= -37);
	CHECK(FLT_MAX_10_EXP >= 37);
	CHECK(FLT_MAX >= 1E+37F);
	CHECK(FLT_MIN <= 1E-37F);
	CHECK(FLT_EPSILON <= 1E-5F);

	/* the defining property, not just the floor: 1+eps != 1, but
	 * 1+eps/2 == 1 (eps is the *least* such gap). */
	CHECK(1.0F + FLT_EPSILON != 1.0F);
	CHECK(1.0F + FLT_EPSILON / 2 == 1.0F);
}

static void test_float_dbl(void)
{
	CHECK(DBL_DIG >= 10);
	CHECK(DBL_MANT_DIG >= 1);
	CHECK(DBL_MIN_10_EXP <= -37);
	CHECK(DBL_MAX_10_EXP >= 37);
	CHECK(DBL_MAX >= 1E+37);
	CHECK(DBL_MIN <= 1E-37);
	CHECK(DBL_EPSILON <= 1E-9);

	/* "1.0 + DBL_EPSILON != 1.0 while 1.0 + DBL_EPSILON/2 == 1.0" --
	 * from the task brief, and the direct test of the EPSILON
	 * definition quoted above. */
	CHECK(1.0 + DBL_EPSILON != 1.0);
	CHECK(1.0 + DBL_EPSILON / 2 == 1.0);

	/* DECIMAL_DIG: "Minimum Acceptable Value: 10", and by definition
	 * (C99 5.2.4.2.2p11) must be >= the widest type's DECIMAL_DIG,
	 * i.e. >= DBL_DECIMAL_DIG here (DBL_DECIMAL_DIG isn't POSIX/C89 but
	 * spicule defines it; check the ordering it implies instead). */
	CHECK(DECIMAL_DIG >= 10);
	CHECK(DECIMAL_DIG >= DBL_DIG);
}

/* ---- LDBL_*: the LLP64/long-double split from the task brief. `long
 * double` is 64-bit (an alias for `double`) under this tcc on the NT
 * target, but genuinely 80-bit under the mingw-w64/gcc fallback
 * compiler and under native gcc/clang (`make asan`) -- see
 * src/math/ldbl_math.h's SPICULE_LDBL_EXTENDED and this file's #if below,
 * which uses the identical __SIZEOF_LONG_DOUBLE__ test.
 *
 * BUG found and fixed: arch/i386/bits/float.h and
 * arch/x86_64/bits/float.h unconditionally defined LDBL_MANT_DIG==64,
 * LDBL_MAX==1.19e+4932L, etc (the 80-bit values) regardless of
 * compiler. Under this tcc that is simply wrong: an 8-byte `long
 * double` cannot hold 1.19e+4932L (LDBL_MAX silently becomes +Inf at
 * the literal's own initialization) and does not have 64 bits of
 * mantissa precision (LDBL_EPSILON claimed ~2^-63 precision a 53-bit
 * mantissa cannot deliver). Fixed by conditionally selecting between
 * the 80-bit values and DBL_*-equivalent values, gated on
 * __SIZEOF_LONG_DOUBLE__ exactly as SPICULE_LDBL_EXTENDED is. This
 * function is the regression test: it holds for *either* branch,
 * because it is written entirely in terms of sizeof(long double) and
 * the type's own arithmetic, never a hardcoded width. */
static void test_float_ldbl(void)
{
	CHECK(LDBL_DIG >= 10);
	CHECK(LDBL_MANT_DIG >= 1);
	CHECK(LDBL_MIN_10_EXP <= -37);
	CHECK(LDBL_MAX_10_EXP >= 37);
	CHECK(LDBL_MAX >= 1E+37L);
	CHECK(LDBL_MIN <= 1E-37L);
	CHECK(LDBL_EPSILON <= 1E-9L);
	CHECK(1.0L + LDBL_EPSILON != 1.0L);
	CHECK(1.0L + LDBL_EPSILON / 2 == 1.0L);

	/* sizeof(long double) actually agrees with which branch the
	 * header took -- ties the fix directly to the real, compiled type
	 * rather than trusting the same #if the header itself used. */
#if defined(__SIZEOF_LONG_DOUBLE__) && __SIZEOF_LONG_DOUBLE__ > 8
	CHECK(sizeof(long double) > sizeof(double));
	CHECK(LDBL_MANT_DIG > DBL_MANT_DIG);
#else
	/* tcc/NT target: long double really is double. */
	CHECK(sizeof(long double) == sizeof(double));
	CHECK(LDBL_MANT_DIG == DBL_MANT_DIG);
	CHECK(LDBL_MAX == DBL_MAX);
	CHECK(LDBL_MIN == DBL_MIN);
	CHECK(LDBL_EPSILON == (long double)DBL_EPSILON);
#endif
}

/* ==================================================================
 * stdint.h -- https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/stdint.h.html
 * ================================================================== */

/* ---- Exact-width types: "defined if and only if the implementation
 * directly supports [a type of] width N, no padding bits, and (for the
 * signed type) a two's complement representation" -- so where they
 * exist (int8/16/32/64_t and unsigned) they must be exactly that wide
 * with no padding, and *_MIN and *_MAX must be exactly +-2^(N-1)/2^N-1. ---- */
static void test_stdint_exact_width(void)
{
	CHECK(sizeof(int8_t) == 1 && sizeof(uint8_t) == 1);
	CHECK(sizeof(int16_t) == 2 && sizeof(uint16_t) == 2);
	CHECK(sizeof(int32_t) == 4 && sizeof(uint32_t) == 4);
	CHECK(sizeof(int64_t) == 8 && sizeof(uint64_t) == 8);

	/* No padding + two's complement, tested the same way as
	 * test_limits_consistency: *_MAX and *_MIN must match the exact bit
	 * width, not just be "close". */
	CHECK((uintmax_t)INT8_MAX == 0x7f && INT8_MIN == -128 && (uintmax_t)UINT8_MAX == 0xff);
	CHECK((uintmax_t)INT16_MAX == 0x7fff && INT16_MIN == -32768 && (uintmax_t)UINT16_MAX == 0xffff);
	CHECK((uintmax_t)INT32_MAX == 0x7fffffff && INT32_MIN == (-2147483647 - 1) && (uintmax_t)UINT32_MAX == 0xffffffffU);
	CHECK((uintmax_t)INT64_MAX == 0x7fffffffffffffffULL);
	CHECK(INT64_MIN == (-9223372036854775807LL - 1));
	CHECK(UINT64_MAX == 0xffffffffffffffffULL);

	/* No padding, no sign-magnitude/ones'-complement surprises: (u)-1
	 * must equal *_MAX for the unsigned type, at exactly that width. */
	CHECK((uint8_t)-1 == UINT8_MAX);
	CHECK((uint16_t)-1 == UINT16_MAX);
	CHECK((uint32_t)-1 == UINT32_MAX);
	CHECK((uint64_t)-1 == UINT64_MAX);
}

/* ---- least/fast types: magnitude floors only (POSIX: "not less than"
 * the exact-width floor for that N), and the actual sizeof() must be
 * large enough to hold that floor -- checked via the *_MAX macro
 * matching sizeof() exactly, since spicule picks concrete types for
 * these (int_leastN_t == intN_t; int_fast16/32_t widened to 32 bits;
 * int_fast8/64_t == int8/64_t) rather than synthesizing new ones. ---- */
static void test_stdint_least_fast(void)
{
	CHECK(INT_LEAST8_MAX >= INT8_MAX && (uintmax_t)UINT_LEAST8_MAX >= UINT8_MAX);
	CHECK(INT_LEAST16_MAX >= INT16_MAX && (uintmax_t)UINT_LEAST16_MAX >= UINT16_MAX);
	CHECK(INT_LEAST32_MAX >= INT32_MAX && (uintmax_t)UINT_LEAST32_MAX >= UINT32_MAX);
	CHECK(INT_LEAST64_MAX >= INT64_MAX && UINT_LEAST64_MAX >= UINT64_MAX);

	CHECK(INT_FAST8_MAX >= INT8_MAX && (uintmax_t)UINT_FAST8_MAX >= UINT8_MAX);
	CHECK(INT_FAST16_MAX >= INT16_MAX && (uintmax_t)UINT_FAST16_MAX >= UINT16_MAX);
	CHECK(INT_FAST32_MAX >= INT32_MAX && (uintmax_t)UINT_FAST32_MAX >= UINT32_MAX);
	CHECK(INT_FAST64_MAX >= INT64_MAX && UINT_FAST64_MAX >= UINT64_MAX);

	/* Every least/fast *_MAX macro must match its own type's actual
	 * arithmetic range -- not just satisfy the floor while secretly
	 * being some other width. */
	CHECK((uintmax_t)(int_least8_t)INT_LEAST8_MAX == (uintmax_t)INT_LEAST8_MAX);
	CHECK((uintmax_t)(int_fast32_t)INT_FAST32_MAX == (uintmax_t)INT_FAST32_MAX);
	CHECK((uintmax_t)(uint_fast32_t)UINT_FAST32_MAX == (uintmax_t)UINT_FAST32_MAX);
}

/* ---- intmax_t/uintmax_t: "shall be capable of representing any value
 * of any signed/unsigned integer type"; the minimum-magnitude floors
 * are -(2^63-1)..2^63-1 / 0..2^64-1. ---- */
static void test_stdint_max(void)
{
	CHECK(INTMAX_MAX >= 9223372036854775807LL);
	CHECK(INTMAX_MIN <= -9223372036854775807LL);
	CHECK(UINTMAX_MAX >= 18446744073709551615ULL);
	CHECK((uintmax_t)INTMAX_MAX == UINTMAX_MAX / 2);
	CHECK(sizeof(intmax_t) >= sizeof(long long));
	CHECK(sizeof(uintmax_t) >= sizeof(unsigned long long));
}

/* ---- intptr_t/uintptr_t/ptrdiff_t/size_t: the LLP64 pointer-width
 * split. All four are `_Addr`-family types
 * (arch/{i386,x86_64}/bits/alltypes.h.in): `int` on i386, `long long`
 * on x86_64. Verified against sizeof(void*)/the type's own arithmetic,
 * not a per-arch hardcoded literal, so one build of this file (either
 * arch) checks itself. ---- */
static void test_stdint_pointer_width(void)
{
	CHECK(sizeof(intptr_t) == sizeof(void *));
	CHECK(sizeof(uintptr_t) == sizeof(void *));
	CHECK(sizeof(size_t) == sizeof(void *));
	CHECK(sizeof(ptrdiff_t) == sizeof(void *));

	CHECK((uintmax_t)INTPTR_MAX == ((uintmax_t)1 << (sizeof(intptr_t) * CHAR_BIT - 1)) - 1);
	CHECK(INTPTR_MIN == -INTPTR_MAX - 1);
	CHECK(UINTPTR_MAX == (uintptr_t)-1);
	CHECK((uintmax_t)PTRDIFF_MAX == ((uintmax_t)1 << (sizeof(ptrdiff_t) * CHAR_BIT - 1)) - 1);
	CHECK(PTRDIFF_MIN == -PTRDIFF_MAX - 1);
	CHECK(SIZE_MAX == (size_t)-1);

	/* POSIX floors: intptr_t/uintptr_t/ptrdiff_t/size_t all need to be
	 * at least wide enough for the stdint.h-mandated minimums. */
	CHECK(PTRDIFF_MAX >= 65535);
	CHECK(SIZE_MAX >= 65535);
}

/* ---- wchar_t: this target's other headline LLP64-adjacent divergence
 * -- 16-bit UTF-16, not the 32-bit-on-Linux value most code assumes.
 * WCHAR_MIN/MAX must match the *actual* wchar_t (unsigned short here),
 * derived from sizeof(wchar_t), not hardcoded to either convention. ---- */
static void test_stdint_wchar(void)
{
	CHECK(sizeof(wchar_t) == 2);
	if ((wchar_t)-1 < (wchar_t)0) {
		/* signed wchar_t: floor is +-127. */
		CHECK(WCHAR_MAX >= 127);
		CHECK(WCHAR_MIN <= -127);
	} else {
		/* unsigned wchar_t (spicule's case: 16-bit UTF-16 code unit). */
		CHECK(WCHAR_MAX >= 255);
		CHECK(WCHAR_MIN == 0);
	}
	/* exact match to the real 16-bit unsigned type, not just the
	 * floor -- (wchar_t)-1 is the type's actual maximum. */
	CHECK((uintmax_t)WCHAR_MAX == (uintmax_t)(wchar_t)-1);

	/* WINT_MIN/MAX floor: signed +-32767 or unsigned 0..65535; spicule's
	 * wint_t is `unsigned` (32-bit, include/alltypes.h.in), wider than
	 * wchar_t itself (a wint_t must be able to hold WEOF as well as
	 * every wchar_t value). */
	CHECK((uintmax_t)WINT_MAX >= 65535U);
	CHECK(WINT_MIN == 0U);

	/* SIG_ATOMIC_MIN/MAX floor: signed +-127 or unsigned 0..255;
	 * spicule's sig_atomic_t is `int` (include/alltypes.h.in). */
	CHECK(SIG_ATOMIC_MAX >= 127);
	CHECK(SIG_ATOMIC_MIN <= -127);
	CHECK((uintmax_t)SIG_ATOMIC_MAX == ((uintmax_t)1 << (sizeof(sig_atomic_t) * CHAR_BIT - 1)) - 1);
}

/* ---- INTN_C/UINTN_C/INTMAX_C/UINTMAX_C: "a constant expression
 * suitable for use in #if"; must produce a value of (at least) the
 * corresponding least/max type -- checked by feeding a value that only
 * fits if the macro actually widened, and by #if-testing the macro
 * itself (the RETURN VALUE clause literally requires #if-usability). ---- */
#if UINT64_C(18446744073709551615) != 18446744073709551615ULL
#error "UINT64_C is not usable in #if, or produces the wrong value"
#endif
#if INTMAX_C(-1) != -1
#error "INTMAX_C is not usable in #if"
#endif
static void test_stdint_c_macros(void)
{
	/* runtime companion to the #if checks above: the macro's value
	 * survives arithmetic at its documented width without truncating. */
	CHECK(UINT64_C(18446744073709551615) == UINT64_MAX);
	CHECK(INT64_C(-9223372036854775807) - 1 == INT64_MIN);
	CHECK(UINTMAX_C(18446744073709551615) == UINTMAX_MAX);
	CHECK(sizeof(INT64_C(1)) >= sizeof(int64_t));
	CHECK(sizeof(UINTMAX_C(1)) >= sizeof(uintmax_t));
}

/* ==================================================================
 * inttypes.h -- https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/inttypes.h.html
 *
 * "Each macro name has the general form of PRI (character string
 * literals for fprintf()/fwprintf()) or SCN (for fscanf()/fwscanf()),
 * followed by the conversion specifier, ... followed by a name
 * corresponding to a similar type name in <stdint.h>." What matters
 * here is not that these exist (they always would compile as *some*
 * string) but that the length modifier they embed genuinely matches
 * the argument type the compiler passes for that stdint.h type -- a
 * wrong modifier is invisible to the compiler and silently reads/
 * writes the wrong number of bytes off the va_list. Every macro below
 * is round-tripped through a real sprintf/sscanf, not just compiled. ---- */

static void test_inttypes_pri_fixed(void)
{
	char buf[64];

	sprintf(buf, "%" PRId8, (int8_t)-100);   CHECK(strcmp(buf, "-100") == 0);
	sprintf(buf, "%" PRIu8, (uint8_t)200);   CHECK(strcmp(buf, "200") == 0);
	sprintf(buf, "%" PRIx8, (uint8_t)0xab);  CHECK(strcmp(buf, "ab") == 0);
	sprintf(buf, "%" PRId16, (int16_t)-30000); CHECK(strcmp(buf, "-30000") == 0);
	sprintf(buf, "%" PRIu16, (uint16_t)60000); CHECK(strcmp(buf, "60000") == 0);
	sprintf(buf, "%" PRId32, (int32_t)-2000000000); CHECK(strcmp(buf, "-2000000000") == 0);
	sprintf(buf, "%" PRIu32, (uint32_t)4000000000U); CHECK(strcmp(buf, "4000000000") == 0);
	sprintf(buf, "%" PRId64, (int64_t)-9000000000000000000LL);
	CHECK(strcmp(buf, "-9000000000000000000") == 0);
	sprintf(buf, "%" PRIu64, (uint64_t)18000000000000000000ULL);
	CHECK(strcmp(buf, "18000000000000000000") == 0);
	sprintf(buf, "%" PRIx64, (uint64_t)0x0123456789abcdefULL);
	CHECK(strcmp(buf, "123456789abcdef") == 0);
}

static void test_inttypes_scn_fixed(void)
{
	int8_t i8; uint8_t u8; int16_t i16; uint16_t u16;
	int32_t i32; uint32_t u32; int64_t i64; uint64_t u64;

	CHECK(sscanf("-100", "%" SCNd8, &i8) == 1 && i8 == -100);
	CHECK(sscanf("200", "%" SCNu8, &u8) == 1 && u8 == 200);
	CHECK(sscanf("-30000", "%" SCNd16, &i16) == 1 && i16 == -30000);
	CHECK(sscanf("60000", "%" SCNu16, &u16) == 1 && u16 == 60000);
	CHECK(sscanf("-2000000000", "%" SCNd32, &i32) == 1 && i32 == -2000000000);
	CHECK(sscanf("4000000000", "%" SCNu32, &u32) == 1 && u32 == 4000000000U);
	CHECK(sscanf("-9000000000000000000", "%" SCNd64, &i64) == 1
		&& i64 == -9000000000000000000LL);
	CHECK(sscanf("18000000000000000000", "%" SCNu64, &u64) == 1
		&& u64 == 18000000000000000000ULL);
}

/* least/fast families round-trip the same way; a wrong length modifier
 * in any of these is exactly the "invisible to the compiler" class of
 * bug the task brief warns about. */
static void test_inttypes_pri_scn_least_fast(void)
{
	char buf[64];
	int_least64_t il64; uint_fast64_t uf64;
	int_fast32_t if32;

	sprintf(buf, "%" PRIdLEAST64, (int_least64_t)-1234567890123LL);
	CHECK(strcmp(buf, "-1234567890123") == 0);
	CHECK(sscanf(buf, "%" SCNdLEAST64, &il64) == 1 && il64 == -1234567890123LL);

	sprintf(buf, "%" PRIuFAST64, (uint_fast64_t)9999999999ULL);
	CHECK(strcmp(buf, "9999999999") == 0);
	CHECK(sscanf(buf, "%" SCNuFAST64, &uf64) == 1 && uf64 == 9999999999ULL);

	sprintf(buf, "%" PRIdFAST32, (int_fast32_t)-123456789);
	CHECK(strcmp(buf, "-123456789") == 0);
	CHECK(sscanf(buf, "%" SCNdFAST32, &if32) == 1 && if32 == -123456789);
}

/* PRI*MAX/PRI*PTR: the intmax_t and pointer-width families. On this
 * LLP64 target intmax_t is always 64-bit `long long` (both arches) but
 * intptr_t/uintptr_t are the pointer-width type -- 32-bit on i386,
 * 64-bit on x86_64 -- so PRIdPTR is exactly the length modifier most
 * likely to be wrong on one arch and not the other (task brief item
 * 4). Round-tripped through the actual `intptr_t`, whatever width that
 * is on this arch, rather than a fixed literal. */
static void test_inttypes_pri_scn_max_ptr(void)
{
	char buf[64];
	intmax_t im; uintmax_t um;
	intptr_t ip; uintptr_t up;

	sprintf(buf, "%" PRIdMAX, (intmax_t)-9000000000000000000LL);
	CHECK(strcmp(buf, "-9000000000000000000") == 0);
	CHECK(sscanf(buf, "%" SCNdMAX, &im) == 1 && im == -9000000000000000000LL);

	sprintf(buf, "%" PRIuMAX, (uintmax_t)18000000000000000000ULL);
	CHECK(strcmp(buf, "18000000000000000000") == 0);
	CHECK(sscanf(buf, "%" SCNuMAX, &um) == 1 && um == 18000000000000000000ULL);

	/* intptr_t round trip at the type's actual max/min for this arch
	 * -- this is the assertion that would catch "%ld" used where the
	 * type is really a 64-bit `long long` on x86_64, or vice versa. */
	sprintf(buf, "%" PRIdPTR, INTPTR_MAX);
	CHECK(sscanf(buf, "%" SCNdPTR, &ip) == 1 && ip == INTPTR_MAX);
	sprintf(buf, "%" PRIdPTR, INTPTR_MIN);
	CHECK(sscanf(buf, "%" SCNdPTR, &ip) == 1 && ip == INTPTR_MIN);
	sprintf(buf, "%" PRIuPTR, UINTPTR_MAX);
	CHECK(sscanf(buf, "%" SCNuPTR, &up) == 1 && up == UINTPTR_MAX);
	sprintf(buf, "%" PRIxPTR, UINTPTR_MAX);
	CHECK(sscanf(buf, "%" SCNxPTR, &up) == 1 && up == UINTPTR_MAX);
}

/* ==================================================================
 * strtoimax/strtoumax/imaxabs/imaxdiv --
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/strtoimax.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/imaxabs.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/imaxdiv.html
 * src/stdlib/strtol.c (strtoimax/strtoumax share strtox() with
 * strtol/strtoul/strtoll/strtoull), src/stdlib/abs.c (imaxabs),
 * src/stdlib/div.c (imaxdiv).
 * ================================================================== */

/* ---- strtoimax.html RETURN VALUE/ERRORS: ERANGE + saturation at
 * INTMAX_MAX/INTMAX_MIN/UINTMAX_MAX, EINVAL for an unsupported base
 * ("shall fail", not "may fail"), endptr placement. DESCRIPTION:
 * "equivalent to strtol()/.../strtoull(), except ... converted to
 * intmax_t/uintmax_t". ---- */
static void test_strtoimax_errors(void)
{
	char *end;

	/* ERANGE + saturation: one past INTMAX_MAX overflows to INTMAX_MAX. */
	errno = 0; end = 0;
	CHECK(strtoimax("99999999999999999999999", &end, 10) == INTMAX_MAX
		&& errno == ERANGE && *end == '\0');

	/* one past INTMAX_MIN, i.e. more negative than representable,
	 * saturates to INTMAX_MIN. */
	errno = 0; end = 0;
	CHECK(strtoimax("-99999999999999999999999", &end, 10) == INTMAX_MIN
		&& errno == ERANGE && *end == '\0');

	/* UINTMAX_MAX saturation for strtoumax. */
	errno = 0; end = 0;
	CHECK(strtoumax("99999999999999999999999", &end, 10) == UINTMAX_MAX
		&& errno == ERANGE && *end == '\0');

	/* exact boundary values convert cleanly, no ERANGE. */
	{
		char nbuf[32];
		sprintf(nbuf, "%" PRIdMAX, INTMAX_MAX);
		errno = 0; end = 0;
		CHECK(strtoimax(nbuf, &end, 10) == INTMAX_MAX && errno == 0 && *end == '\0');
		sprintf(nbuf, "%" PRIdMAX, INTMAX_MIN);
		errno = 0; end = 0;
		CHECK(strtoimax(nbuf, &end, 10) == INTMAX_MIN && errno == 0 && *end == '\0');
		sprintf(nbuf, "%" PRIuMAX, UINTMAX_MAX);
		errno = 0; end = 0;
		CHECK(strtoumax(nbuf, &end, 10) == UINTMAX_MAX && errno == 0 && *end == '\0');
	}

	/* EINVAL: "the value of base is not supported" is a required
	 * failure (ERRORS "shall fail"), not merely a RETURN VALUE note --
	 * mirrors the pre-existing strtol coverage in test/posix-stdlib.c,
	 * repeated here since strtoimax/strtoumax are a separate src/ area
	 * from strtol. */
	{
		const char *s = "123";
		errno = 0; end = 0;
		CHECK(strtoimax(s, &end, 1) == 0 && errno == EINVAL && end == s);
		errno = 0; end = 0;
		CHECK(strtoumax(s, &end, 37) == 0 && errno == EINVAL && end == s);
	}

	/* no-conversion: endptr set to nptr, 0 returned, when nothing
	 * numeric is found (RETURN VALUE: "If no conversion could be
	 * performed, zero shall be returned"). */
	{
		const char *s = "   xyz";
		errno = 0; end = 0;
		CHECK(strtoimax(s, &end, 10) == 0 && end == s);
	}

	/* base 0: octal/hex/decimal prefix auto-detection, same subject-
	 * sequence rules as strtol (DESCRIPTION: "equivalent to ...
	 * strtol()"). */
	CHECK(strtoimax("0x2A", 0, 0) == 42);
	CHECK(strtoimax("052", 0, 0) == 42);
	CHECK(strtoimax("42", 0, 0) == 42);

	/* errno unchanged on a clean conversion (inherited from the same
	 * "shall not change errno if successful" contract as strtol). */
	errno = 12345;
	CHECK(strtoimax("42", 0, 10) == 42 && errno == 12345);
	errno = 12345;
	CHECK(strtoumax("42", 0, 10) == 42 && errno == 12345);
}

/* ---- imaxabs.html: RETURN VALUE "absolute value"; DESCRIPTION "If the
 * result cannot be represented, the behavior is undefined" --
 * explicitly imaxabs(INTMAX_MIN) is *not* asserted here (task brief:
 * "do not assert on it -- say why"): -INTMAX_MIN overflows intmax_t,
 * which is undefined behaviour in C regardless of what src/stdlib/
 * abs.c's `a > 0 ? a : -a` happens to compute for it on this compiler,
 * so any expected value this test could name would just be asserting
 * that UB. ---- */
static void test_imaxabs(void)
{
	CHECK(imaxabs(0) == 0);
	CHECK(imaxabs(42) == 42);
	CHECK(imaxabs(-42) == 42);
	CHECK(imaxabs(INTMAX_MAX) == INTMAX_MAX);
	CHECK(imaxabs(-(INTMAX_MAX)) == INTMAX_MAX);
	/* imaxabs(INTMAX_MIN): deliberately not tested -- see above. */
}

/* ---- imaxdiv.html: RETURN VALUE -- quot/rem such that (from the
 * general integer-division contract this shares with div()/ldiv(),
 * C99 7.20.6.2p2, "quot*denom + rem == numer" and truncation toward
 * zero) both hold for every sign combination. ---- */
static void test_imaxdiv(void)
{
	imaxdiv_t r;

	r = imaxdiv(7, 2);   CHECK(r.quot == 3 && r.rem == 1);
	r = imaxdiv(-7, 2);  CHECK(r.quot == -3 && r.rem == -1);
	r = imaxdiv(7, -2);  CHECK(r.quot == -3 && r.rem == 1);
	r = imaxdiv(-7, -2); CHECK(r.quot == 3 && r.rem == -1);
	r = imaxdiv(0, 5);   CHECK(r.quot == 0 && r.rem == 0);

	/* the general relationship, for a handful of arbitrary sign
	 * combinations including near INTMAX_MAX/MIN. */
	{
		intmax_t n, d;
		int i;
		intmax_t ns[] = { 123456789, -123456789, INTMAX_MAX, INTMAX_MIN + 1, 1, -1 };
		intmax_t ds[] = { 7, -7, 3, -3, 1000000007LL };
		for (i = 0; i < 6; i++) {
			n = ns[i];
			d = ds[i % 5];
			r = imaxdiv(n, d);
			CHECK(r.quot * d + r.rem == n);
			/* truncation toward zero: |quot| is the floor of |n/d|. */
			CHECK((r.quot >= 0) == ((n >= 0) == (d >= 0)) || r.quot == 0);
		}
	}
}

/* ==================================================================
 * <limits.h> header content -- the mandatory constants spicule does not
 * define.  Audit group U (XBD header contents); see
 * test/POSIX-COVERAGE.md "XBD header contents (group U)".
 *
 * Which limits.h.html section a constant lives in decides whether its
 * absence is a gap at all, so the fences below are split that way and
 * two whole sections are deliberately NOT fenced.  "Runtime Invariant
 * Values (Possibly Indeterminate)" and "Pathname Variable Values" each
 * say a definition "shall be OMITTED from <limits.h> on specific
 * implementations where the corresponding value is equal to or greater
 * than the stated minimum, but is unspecified" / "can vary depending on
 * the file to which it is applied" -- so every name in those two
 * sections is legally absent here, and fencing one would be
 * manufacturing a finding.  test_limits_posix_floors() above already
 * makes that call for CHILD_MAX and ATEXIT_MAX and is right to.
 * The three sections that DO say "shall define ... with the values
 * shown" are the ones fenced below.
 * ================================================================== */

static void test_limits_minimum_values_unmarked(void)
{
	CHECK(_POSIX_THREAD_DESTRUCTOR_ITERATIONS == 4);
	CHECK(_POSIX_THREAD_KEYS_MAX == 128);
	CHECK(_POSIX_THREAD_THREADS_MAX == 64);
}

static void test_limits_minimum_values_xsi(void)
{
	CHECK(_XOPEN_IOV_MAX == 16);
	CHECK(_XOPEN_NAME_MAX == 255);
	CHECK(_XOPEN_PATH_MAX == 1024);

	/* The floors these three exist to be: a published limit may not
	 * be more restrictive than the value the standard prints. */
	CHECK(IOV_MAX >= _XOPEN_IOV_MAX);
	CHECK(NAME_MAX >= _XOPEN_NAME_MAX);
	CHECK(PATH_MAX >= _XOPEN_PATH_MAX);
}

static void test_limits_runtime_increasable(void)
{
	CHECK(BC_BASE_MAX >= _POSIX2_BC_BASE_MAX);
	CHECK(BC_DIM_MAX >= _POSIX2_BC_DIM_MAX);
	CHECK(BC_SCALE_MAX >= _POSIX2_BC_SCALE_MAX);
	CHECK(BC_STRING_MAX >= _POSIX2_BC_STRING_MAX);
	CHECK(CHARCLASS_NAME_MAX >= _POSIX2_CHARCLASS_NAME_MAX);
	CHECK(COLL_WEIGHTS_MAX >= _POSIX2_COLL_WEIGHTS_MAX);
	CHECK(EXPR_NEST_MAX >= _POSIX2_EXPR_NEST_MAX);
	CHECK(LINE_MAX >= _POSIX2_LINE_MAX);
	CHECK(RE_DUP_MAX >= _POSIX_RE_DUP_MAX);

	/* "shall define macros and symbolic constants ... All macros and
	 * symbolic constants defined in this header shall be suitable for
	 * use in #if preprocessing directives" (limits.h.html
	 * DESCRIPTION) -- LINE_MAX is the one a utility actually sizes a
	 * buffer with at compile time. */
#if defined(LINE_MAX) && LINE_MAX >= 2048
	CHECK(1);
#else
	CHECK(0);
#endif
}

static void test_limits_other_invariant(void)
{
	CHECK(NL_ARGMAX >= 9);
	CHECK(NL_LANGMAX >= 14);		/* [XSI] */
	CHECK(NL_MSGMAX >= 32767);
	CHECK(NL_SETMAX >= 255);
	CHECK(NL_TEXTMAX >= _POSIX2_LINE_MAX);
	CHECK(NZERO >= 20);			/* [XSI] */
}

int main(void)
{
	test_limits_numerical();
	test_limits_consistency();
	test_limits_pathname();
	test_limits_posix_floors();
	test_limits_minimum_values_unmarked();
	test_limits_minimum_values_xsi();
	test_limits_runtime_increasable();
	test_limits_other_invariant();

	test_float_radix_and_rounds();
	test_float_flt();
	test_float_dbl();
	test_float_ldbl();

	test_stdint_exact_width();
	test_stdint_least_fast();
	test_stdint_max();
	test_stdint_pointer_width();
	test_stdint_wchar();
	test_stdint_c_macros();

	test_inttypes_pri_fixed();
	test_inttypes_scn_fixed();
	test_inttypes_pri_scn_least_fast();
	test_inttypes_pri_scn_max_ptr();

	test_strtoimax_errors();
	test_imaxabs();
	test_imaxdiv();

	if (!fails) printf("posix-limits: all tests passed\n");
	return fails != 0;
}
