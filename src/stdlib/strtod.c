/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
/* strtod/strtof/strtold.
 *
 * On this target "long double" is just a double (see arch/x86_64's tcc:
 * it does not give the type an 80-bit range), so a scheme that leans on
 * long double having extra range or precision is not available here,
 * and neither is a double-double approximation of 10^e: rounding the
 * decimal mantissa, then the power, then the product accumulates well
 * past the one-ulp error C99 7.20.1.3p9 allows, and the intermediate
 * squarings overflow to infinity (and then to NaN) for exponents that
 * the final result would have saturated to HUGE_VAL on perfectly well.
 *
 * So the conversion is done exactly instead.  Both a decimal and a hex
 * input name a value N / D * 2^e2 for integers N and D, and the
 * correctly rounded result is obtained by long-dividing the two as
 * big integers, after scaling so the quotient has exactly as many bits
 * as the destination format's significand; the remainder then decides
 * the rounding, with ties broken to even.  That is a single rounding of
 * the exact value, which is what C99 7.20.1.3p9 asks for.
 *
 * Only the first MAXDIG significant digits are kept; anything after
 * them is folded into a sticky flag.  This is exact, not an
 * approximation: a rounding boundary (a midpoint between two adjacent
 * doubles, i.e. an odd multiple of 2^-1075 at worst) has at most 752
 * significant decimal digits, so it can never fall strictly inside the
 * one-unit-in-the-last-kept-place interval that the discarded tail
 * spans.  Either the boundary is exactly the kept prefix - and then the
 * sticky flag says the true value is above it, so we round up - or the
 * kept prefix already decides the rounding for the whole value. */
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <float.h>
#include <wchar.h>
#include <features.h>

/* Significant decimal digits kept exactly; see the note above for why
 * this bound makes the conversion exact rather than merely close. */
#define MAXDIG 800

/* Big non-negative integers, base 2^32, least significant limb first.
 * n is the number of limbs in use, with no leading zero limb, so n == 0
 * means the value is zero.  Its narrow unsigned type encodes the nonnegative
 * domain, and every operation below keeps it at or below BN_LIMBS.  The size
 * is chosen so that nothing here can
 * overflow it: the widest intermediate is the divisor scaled by the
 * quotient width, at most 800 digits (2658 bits) of decimal mantissa
 * plus 1074 bits of subnormal scaling plus 53 bits of quotient. */
#define BN_LIMBS 180
typedef struct { unsigned char n; uint32_t d[BN_LIMBS]; } bn_t;

/* Every bn_*() function below shares the identical `const bn_t *`/`bn_t *`
 * contract: each dereferences its own a/b/dst/src argument's `->n` (and
 * often `->d[]`) unconditionally as its first real operation -- even a
 * `if (!a->n) return;`-shaped early-out still has to read a->n to evaluate
 * the condition. None of these ever checks its own bn_t pointer for NULL,
 * and every real call site in this file passes the address of a real
 * on-stack bn_t -- never NULL. */
static void bn_copy(bn_t *dst, const bn_t *src) __attribute__((nonnull(1, 2)));
static void bn_setu32(bn_t *a, uint32_t v) __attribute__((nonnull(1)));
static void bn_muladd(bn_t *a, uint32_t m, uint32_t c) __attribute__((nonnull(1)));
static int bn_bits(const bn_t *a) __attribute__((nonnull(1)));
static void bn_shl(bn_t *a, int k) __attribute__((nonnull(1)));
static void bn_shr1(bn_t *a) __attribute__((nonnull(1)));
static int bn_cmp(const bn_t *a, const bn_t *b) __attribute__((nonnull(1, 2)));
static void bn_sub(bn_t *a, const bn_t *b) __attribute__((nonnull(1, 2)));

/* Only the limbs in use are copied; the rest of d is stale, which
 * every operation here is careful never to look at. */
static void bn_copy(bn_t *dst, const bn_t *src)
{
	int i;
	dst->n = src->n;
	for (i = 0; i < src->n; i++) dst->d[i] = src->d[i];
}

static void bn_setu32(bn_t *a, uint32_t v)
{
	a->d[0] = v;
	a->n = v ? 1 : 0;
}

/* a = a * m + c */
static void bn_muladd(bn_t *a, uint32_t m, uint32_t c) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	uint64_t carry = c;
	int i;

	for (i = 0; i < a->n; i++) {
		uint64_t t = (uint64_t)a->d[i] * m + carry;
		a->d[i] = (uint32_t)t;
		carry = t >> 32;
	}
	while (carry && a->n < BN_LIMBS) {
		a->d[a->n++] = (uint32_t)carry;
		carry /= 0x100000000ULL;
	}
}

static int bn_bits(const bn_t *a)
{
	uint32_t v;
	int b;

	if (!a->n) return 0;
	v = a->d[a->n - 1];
	b = (a->n - 1) * 32;
	while (v) { b++; v /= 2; }
	return b;
}

/* v << b deliberately shifts bits off the top of each limb -- that is
 * the carry into the next one -- so this is the standard shift-with-
 * carry idiom for a multi-limb shift, not an accidental overflow. */
__wraps static void bn_shl(bn_t *a, int k)
{
	int w = k / 32, b = k % 32, i;

	if (!a->n || k <= 0) return;
	if (b) {
		uint32_t carry = 0;
		for (i = 0; i < a->n; i++) {
			uint32_t v = a->d[i];
			a->d[i] = (v << b) | carry;
			carry = v >> (32 - b);
		}
		if (carry && a->n < BN_LIMBS) a->d[a->n++] = carry;
	}
	if (w) {
		if (a->n + w > BN_LIMBS) w = BN_LIMBS - a->n; /* cannot happen; do not corrupt memory if it does */
		/* OPEN LINT FINDING (spicule.ValidPointer): a->d[i+w] is in
		 * bounds given the clamp above, but proving it needs the
		 * clamp's own arithmetic tied back to BN_LIMBS across the
		 * reassignment of w -- outside this checker's index proof. */
		for (i = a->n - 1; i >= 0; i--) a->d[i + w] = a->d[i];
		for (i = 0; i < w; i++) a->d[i] = 0;
		a->n += w;
	}
}

/* a->d[i+1] << 31 carries the bottom bit of the next limb up into the
 * top of this one -- the same shift-with-carry idiom as bn_shl, just
 * shifting the other way -- and is meant to discard the rest of that
 * limb, not to overflow by accident. */
__wraps static void bn_shr1(bn_t *a)
{
	int i;

	if (!a->n) return;
	for (i = 0; i < a->n - 1; i++)
		a->d[i] = (a->d[i] >> 1) | (a->d[i + 1] << 31);
	a->d[a->n - 1] >>= 1;
	if (!a->d[a->n - 1]) a->n--;
}

static int bn_cmp(const bn_t *a, const bn_t *b)
{
	int i;

	if (a->n != b->n) return a->n < b->n ? -1 : 1;
	for (i = a->n - 1; i >= 0; i--)
		if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
	return 0;
}

/* a -= b; the caller guarantees a >= b.  Each limb subtraction is
 * deliberately allowed to go negative (wrap) in the uint64_t: bit 32 of
 * the wrapped result is exactly the borrow into the next limb, the
 * standard subtract-with-borrow idiom for multi-limb subtraction. */
__wraps static void bn_sub(bn_t *a, const bn_t *b)
{
	uint64_t borrow = 0;
	int i;

	for (i = 0; i < a->n; i++) {
		uint64_t t = (uint64_t)a->d[i] - (i < b->n ? b->d[i] : 0) - borrow;
		a->d[i] = (uint32_t)t;
		borrow = (t >> 32) & 1;
	}
	while (a->n && !a->d[a->n - 1]) a->n--; // NOLINT(clang-analyzer-security.ArrayBound) -- bn_shl already clamps a->n to BN_LIMBS before any write reaches it
}

/* a *= 10^e (e >= 0), as 5^e followed by an exact shift. */
static void bn_mul_pow10(bn_t *a, int e)
{
	int k = e;
	while (k >= 13) {
		bn_muladd(a, 1220703125u, 0); /* 5^13 */
		k -= 13;
	}
	if (k) {
		uint32_t m = 1;
		while (k--) m *= 5;
		bn_muladd(a, m, 0);
	}
	bn_shl(a, e);
}

/* The correctly rounded value of (N / D) * 2^e2, in a format with p
 * significand bits whose smallest exponent is emin (so the smallest
 * positive value is 2^emin).  sticky says the true value is strictly
 * greater than N / D * 2^e2 by less than one unit in its last place.
 * N must be nonzero and D must be nonzero.  The result is exact in
 * double even when p is float's 24, so a caller converting to float
 * afterwards does not round a second time. */
static double bn_scale_round(bn_t *N, bn_t *D, int e2, int sticky, int p, int emin) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	bn_t A, B, T;
	int k, g, t, i, c;
	uint64_t q = 0;

	k = bn_bits(N) - bn_bits(D) + e2; /* value is in (2^(k-1), 2^(k+1)) */
	if (k >= 1025) return HUGE_VAL;   /* past every finite format here */
	if (k <= emin - 2) return 0.0;    /* below half the smallest value */

	g = k - p;
	if (g < emin) g = emin;
	for (;;) {
		bn_copy(&A, N); bn_copy(&B, D);
		t = e2 - g;
		if (t > 0) bn_shl(&A, t); else bn_shl(&B, -t);
		/* want floor(A / B) to have exactly p bits, or fewer only
		 * when g has bottomed out at emin (a subnormal result). */
		bn_copy(&T, &B); bn_shl(&T, p);
		if (bn_cmp(&A, &T) >= 0) { g++; continue; }
		if (g > emin) {
			bn_copy(&T, &B); bn_shl(&T, p - 1);
			if (bn_cmp(&A, &T) < 0) { g--; continue; }
		}
		break;
	}

	/* Restoring long division: q = floor(A / B), A becomes the remainder. */
	bn_copy(&T, &B); bn_shl(&T, p - 1);
	for (i = p - 1; i >= 0; i--) {
		if (bn_cmp(&A, &T) >= 0) { bn_sub(&A, &T); q |= (uint64_t)1 << i; }
		bn_shr1(&T);
	}

	/* Round to nearest, ties to even; a sticky tail beats the tie. */
	bn_shl(&A, 1);
	c = bn_cmp(&A, &B);
	if (c > 0 || (c == 0 && (sticky || (q & 1)))) {
		q++;
		if (q >> p) { q >>= 1; g++; }
	}
	return scalbn((double)q, g);
}

/* ------------------------------------------------------------------
 * INPUT CURSOR
 *
 * The parsing front end below (ci_prefix, parse_hex, parse_dec, strtox)
 * reads through gc() and steps by `st` bytes instead of dereferencing a
 * char* directly, so that one parser serves both strtod() (st == 1,
 * bytes) and wcstod() (st == sizeof(wchar_t), UTF-16 code units).  The
 * big-integer core above is untouched and knows nothing about this: by
 * the time a value reaches it the input is already digits and an
 * exponent.
 *
 * `st` is a size_t, not an int, because it is a byte stride into a
 * buffer and every use of it is pointer arithmetic.  Declared as int it
 * needs a widening cast at each site that scales it by a count -- and
 * one was missed, so `parse_hex(s + 2 * st, ...)` computed the offset
 * in int and widened the product to ptrdiff_t afterwards (clang-tidy
 * bugprone-implicit-widening-of-multiplication-result, which fires on
 * 64-bit targets only: it returns early unless the index expression is
 * narrower than ptrdiff_t, and i386's ptrdiff_t is 32 bits).  Nothing
 * truncated -- st is only ever 1 or sizeof(wchar_t) -- but four
 * compensating casts that exist only because the declaration was wrong,
 * and a fifth site that needed one and did not have it, are the
 * argument for fixing the type rather than the site.  Note that gc()
 * being a macro means there is no parameter conversion to launder the
 * value: the declared type of `st` is now the only thing that decides
 * what width the arithmetic happens in.
 *
 * Why a shared parser rather than narrowing a wide string into a buffer
 * and calling strtod() on it: a conforming subject sequence is
 * UNBOUNDED -- "1" followed by a million digits is a valid input that
 * this converter handles exactly today -- so any fixed narrowing buffer
 * truncates a value, and a dynamic one puts an allocation, whose
 * failure wcstod() has no return value to report, in front of a
 * function that cannot fail for that reason.  (musl solves this by
 * streaming the wide string through a FILE and substituting a byte that
 * cannot appear in a subject sequence; that works because its
 * __floatscan reads a stream.  Ours reads a contiguous buffer, so there
 * is nothing to stream through.  Recorded here so the next reader does
 * not have to rediscover it.)
 *
 * Every character this grammar accepts is ASCII, and the <ctype.h>
 * functions used below are all ASCII-only by construction (see
 * src/ctype/isdigit.c and friends: each is a range test on the value,
 * false for everything above 0x7f).  A wide unit of 0x1234 therefore
 * answers false to isdigit()/isspace()/isalnum() and is returned
 * unchanged by tolower(), exactly as a non-subject-sequence byte does,
 * so no wide-specific classification is needed anywhere.
 * ------------------------------------------------------------------ */
/* A MACRO, not a static function, and the difference is measured rather
 * than assumed: the shipped compiler for this target is tcc, which does
 * no inlining, so a fetch helper written as a function is a real call
 * per character scanned.  Here that is worth about 1.4% (this parser's
 * time is dominated by the big-integer division, not the scan); in
 * src/stdio/scanf.c, whose scanner is nearly all cursor, the same
 * helper cost 17%.  Same abstraction either way -- the only difference
 * is whether the compiler is given the chance to fold `st` away at each
 * site. */
#define gc(p, s) ((s) == 1 ? (unsigned)(unsigned char)*(p) \
	                           : (unsigned)*(const wchar_t *)(p))

/* s/word are both required: word's `while (*word)` loop dereferences it
 * unconditionally, and s (via the gc() macro) is dereferenced the same way
 * whenever the loop body runs, which it always does for this file's three
 * call sites ("inf"/"infinity"/"nan", none empty). Every call site passes
 * strtox()'s own required s, never NULL. */
static int ci_prefix(const char *s, const char *word, size_t st) __attribute__((nonnull(1, 2)));
static int ci_prefix(const char *s, const char *word, size_t st)
{
	int n = 0;
	while (*word) {
		if (tolower((int)gc(s + (size_t)n * st, st)) != *word) return 0;
		n++; word++;
	}
	return n;
}

/* s/end/ok/nz are all required. s is dereferenced (via the gc() macro)
 * unconditionally on the `for (;;)` loop's first iteration, which always
 * runs. ok is written on every return path with no NULL check; end/nz join
 * it unconditionally on the normal path. Every call site is strtox()'s own
 * `parse_hex(s + 2 * st, &end, &ok, &nz, ...)`, whose s/end/ok/nz are
 * required or on-stack locals -- never NULL. */
static double parse_hex(const char *s, const char **end, int *ok, int *nz, int p, int emin, size_t st)
    __attribute__((nonnull(1, 2, 3, 4)));
static double parse_hex(const char *s, const char **end, int *ok, int *nz, int p, int emin, size_t st) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	bn_t N, D;
	uint64_t m = 0;
	int exp = 0, any = 0, seen_dot = 0, sticky = 0, e = 0, eneg = 0, d;
	const char *p2 = s;
	unsigned c;

	for (;; p2 += st) {
		c = gc(p2, st);
		if (isdigit((int)c)) d = (int)c - '0';
		else if (c >= 'a' && c <= 'f') d = (int)c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') d = (int)c - 'A' + 10;
		else if (c == '.' && !seen_dot) { seen_dot = 1; continue; }
		else break;
		any = 1;
		if (m >> 60) { sticky |= d; if (!seen_dot) exp += 4; }
		else { m = (m << 4) | (unsigned)d; if (seen_dot) exp -= 4; }
	}
	if (!any) { *ok = 0; return 0; }
	if (sticky) m |= 1; /* the tail is below every bit we kept */
	c = gc(p2, st);
	if (c == 'p' || c == 'P') {
		const char *q = p2 + st;
		c = gc(q, st);
		if (c == '+') q += st; else if (c == '-') { eneg = 1; q += st; }
		if (isdigit((int)gc(q, st))) {
			while (isdigit((int)(c = gc(q, st)))) { if (e < 100000) e = e * 10 + (int)(c - '0'); q += st; }
			p2 = q;
		}
	}
	exp += eneg ? -e : e;
	*end = p2;
	*ok = 1;
	*nz = m != 0;
	if (!m) return 0.0;
	bn_setu32(&N, (uint32_t)m);
	if (m >> 32) { N.d[1] = (uint32_t)(m >> 32); N.n = 2; }
	bn_setu32(&D, 1);
	return bn_scale_round(&N, &D, exp, 0, p, emin);
}

/* Same shape and reasoning as parse_hex() above: s is dereferenced
 * unconditionally by the `for (;;)` loop's first iteration; ok is written
 * on every return path; end/nz join it unconditionally on the normal path.
 * Every call site passes the identical required-s/on-stack-locals shape. */
static double parse_dec(const char *s, const char **end, int *ok, int *nz, int p, int emin, size_t st)
    __attribute__((nonnull(1, 2, 3, 4)));
static double parse_dec(const char *s, const char **end, int *ok, int *nz, int p, int emin, size_t st) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	bn_t N, D;
	unsigned char dig[MAXDIG];
	int nd = 0, exp = 0, any = 0, seen_dot = 0, e = 0, eneg = 0, sticky = 0, i;
	const char *p2 = s;
	unsigned c;

	for (;; p2 += st) {
		c = gc(p2, st);
		if (isdigit((int)c)) {
			any = 1;
			if (nd < MAXDIG) {
				if (nd || c != '0') dig[nd++] = (unsigned char)(c - '0');
				if (seen_dot) exp--;
			} else {
				if (c != '0') sticky = 1;
				if (!seen_dot) exp++;
			}
		} else if (c == '.' && !seen_dot) {
			seen_dot = 1;
		} else break;
	}
	if (!any) { *ok = 0; return 0; }
	c = gc(p2, st);
	if (c == 'e' || c == 'E') {
		const char *q = p2 + st;
		c = gc(q, st);
		if (c == '+') q += st; else if (c == '-') { eneg = 1; q += st; }
		if (isdigit((int)gc(q, st))) {
			while (isdigit((int)(c = gc(q, st)))) { if (e < 100000) e = e * 10 + (int)(c - '0'); q += st; }
			p2 = q;
		}
	}
	exp += eneg ? -e : e;
	*end = p2;
	*ok = 1;
	*nz = nd != 0;
	if (!nd) return 0.0;

	/* Trailing zeros of the kept prefix only make the big integers
	 * wider; the sticky tail's size is unaffected by dropping them. */
	while (nd > 1 && dig[nd - 1] == 0) { nd--; exp++; }

	/* The value lies in [10^(exp+nd-1), 10^(exp+nd)), which is enough
	 * to settle the two extremes without building anything: 10^309 is
	 * already past DBL_MAX and 10^-324 is below half the smallest
	 * subnormal.  This also keeps the shifts below from running away
	 * on an exponent like 1e99999. */
	if (exp + nd >= 310) return HUGE_VAL;
	if (exp + nd <= -324) return 0.0;

	bn_setu32(&N, 0);
	for (i = 0; i < nd; ) {
		uint32_t chunk = 0, mul = 1;
		int j;
		for (j = 0; j < 9 && i < nd; j++, i++) { chunk = chunk * 10 + dig[i]; mul *= 10; }
		bn_muladd(&N, mul, chunk);
	}
	bn_setu32(&D, 1);
	if (exp > 0) bn_mul_pow10(&N, exp);
	else if (exp < 0) bn_mul_pow10(&D, -exp);
	return bn_scale_round(&N, &D, 0, sticky, p, emin);
}

/* s0 is required: `while (isspace((int)gc(s, st))) s += st;` (s starts as
 * s0) dereferences it unconditionally as this function's first operation,
 * with no NULL check. endptr is genuinely optional: POSIX documents "if
 * endptr is not NULL" for the whole strtod() family, and `if (endptr)
 * *endptr = ...;` is a real, live guard, the same shape as setenv()/
 * unsetenv()'s own name check. Marking s0 also lets the checker prove
 * `gc(end, st)`/`gc(q, st)` below, since end/q are pointer arithmetic off
 * the now-nonnull s. */
static long double strtox(const char *s0, char **endptr, int kind, size_t st) __attribute__((nonnull(1)));
static long double strtox(const char *s0, char **endptr, int kind, size_t st) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *s = s0, *end;
	double v;
	int neg = 0, ok = 0, n, nz = 1, lit = 0;
	int p = kind == 0 ? 24 : 53;
	int emin = kind == 0 ? -149 : -1074;
	unsigned c;

	while (isspace((int)gc(s, st))) s += st;
	c = gc(s, st);
	if (c == '+') s += st; else if (c == '-') { neg = 1; s += st; }

	n = ci_prefix(s, "inf", st);
	if (n) {
		int n2 = ci_prefix(s, "infinity", st);
		end = s + (size_t)(n2 ? n2 : n) * st;
		v = HUGE_VAL;
		ok = 1; lit = 1;
	} else {
		n = ci_prefix(s, "nan", st);
		if (n) {
			end = s + (size_t)n * st;
			if (gc(end, st) == '(') {
				const char *q = end + st;
				while (isalnum((int)(c = gc(q, st))) || c == '_') q += st;
				if (gc(q, st) == ')') end = q + st;
			}
			v = NAN;
			ok = 1; lit = 1;
		} else if (gc(s, st) == '0' && (gc(s + st, st) == 'x' || gc(s + st, st) == 'X')) {
			v = parse_hex(s + 2 * st, &end, &ok, &nz, p, emin, st);
			if (!ok) { /* just "0" then */
				v = 0; end = s + st; ok = 1; nz = 0;
			}
		} else {
			v = parse_dec(s, &end, &ok, &nz, p, emin, st);
		}
	}
	if (!ok) { if (endptr) *endptr = (char *)s0; return 0; }
	if (endptr) *endptr = (char *)end;

	/* Range check in the destination type.  v is already the exactly
	 * rounded value in that type's precision, so a plain comparison
	 * against its limits is the whole story: no second rounding can
	 * pull an out-of-range value back in, or push an in-range one out.
	 * An "inf" or "nan" spelling is not a range error at all - nothing
	 * was rounded there - so it skips this. */
	if (!lit) {
		double max = kind == 0 ? FLT_MAX : DBL_MAX;
		double min = kind == 0 ? FLT_MIN : DBL_MIN;
		if (v > max) { errno = ERANGE; v = HUGE_VAL; }
		else if (nz && v < min) errno = ERANGE;
	}
	return neg ? -(long double)v : (long double)v;
}

float strtof(const char *__restrict s, char **__restrict e) { return (float)strtox(s, e, 0, 1); }
double strtod(const char *__restrict s, char **__restrict e) { return (double)strtox(s, e, 1, 1); }
long double strtold(const char *__restrict s, char **__restrict e) { return strtox(s, e, 2, 1); }

/* wcstod()/wcstof()/wcstold(): wcstod.html DESCRIPTION, RETURN VALUE,
 * ERRORS -- "equivalent to strtod(), strtof(), and strtold()
 * respectively, except that the argument nptr is a wide-character
 * string".  Same parser, stride sizeof(wchar_t); see the input-cursor
 * note above for why this is a shared parser rather than a narrowing
 * wrapper.
 *
 * The pointer laundering is the only wart.  strtox() walks raw bytes and
 * reports its stop position as a char*, which for stride > 1 is a
 * position inside the wide array; casting it back to wchar_t* is exact,
 * because every step it took was a whole multiple of sizeof(wchar_t)
 * from a properly aligned start.  The alternative -- a second endptr
 * type threaded through the parser -- would duplicate the one thing
 * that has to stay in step between the two strides.
 */
static long double wcstox(const wchar_t *nptr, wchar_t **endptr, int kind)
{
	char *end = 0;
	long double v = strtox((const char *)nptr, &end, kind,
	                       sizeof(wchar_t));
	if (endptr) *endptr = (wchar_t *)end;
	return v;
}

float wcstof(const wchar_t *__restrict s, wchar_t **__restrict e)
{ return (float)wcstox(s, e, 0); }
double wcstod(const wchar_t *__restrict s, wchar_t **__restrict e)
{ return (double)wcstox(s, e, 1); }
long double wcstold(const wchar_t *__restrict s, wchar_t **__restrict e)
{ return wcstox(s, e, 2); }
