/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __vfprintf: the one formatter every printf/fprintf/sprintf/snprintf
 * variant calls into.  sprintf/snprintf write into a throwaway
 * fixed-size memory-buffer FILE (like fmemopen's) built on the stack.
 *
 * Floating-point conversions (%f/%e/%g/%a and capitals) are exact: a
 * finite double's decimal expansion terminates, so dec_exact/dec_round
 * below compute and round every digit exactly (ties to even), and %a
 * reads its hex significand straight out of the bits.
 *
 * Positional (%n$) arguments are implemented at no cost to unnumbered
 * formats (see THE ARGUMENT LIST below).  No conversion sizes a buffer
 * from the caller's precision, which C99 7.19.6.1 leaves unbounded (see
 * PREC_MAX below).
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>
#include <math.h>
#include <wchar.h>
#include <errno.h>
#include "stdio_impl.h"

enum { LM_NONE, LM_hh, LM_h, LM_l, LM_ll, LM_j, LM_z, LM_t, LM_L };

/* A precision is an int with no upper bound (C99 7.19.6.1), so no buffer
 * may be sized from one.  PREC_MAX is the largest precision fmt_f/fmt_e
 * ever write in full: a double's exact expansion has at most 767
 * significant digits, the last at the 1074th fractional place (smallest
 * subnormal is 2^-1074), so every place past PREC_MAX is a zero.
 * emit_float clamps to PREC_MAX and streams the dropped zeros. */
#define PREC_MAX 1080
/* Worst case: 309 integer digits (DBL_MAX at %f) + point + PREC_MAX
 * fractional digits = 1390 bytes, rounded up; %e/%g bodies are smaller. */
#define BODYMAX 1536

/* ------------------------------------------------------------------
 * FORMAT CURSOR
 *
 * gf() reads through the cursor and steps by `st` bytes so one scanner
 * serves both fprintf() (byte format) and fwprintf() (wide format).
 *
 * A macro, not a function: tcc does no inlining, and a function-call
 * fetch measured 17% slower (same change in src/stdio/scanf.c).
 *
 * Named `fp`, not `p`: a stale dereference of the old name is then a
 * compile error instead of a silent one-byte misread of a wide unit,
 * which at st == 1 would behave perfectly and pass every test.
 * ------------------------------------------------------------------ */
#define gf(q, s) ((s) == 1 ? (unsigned)(unsigned char)*(q) \
	                           : (unsigned)*(const wchar_t *)(q))

/* ------------------------------------------------------------------
 * THE SINK
 *
 * Everything emitted goes through out() below, so one body of code
 * serves fprintf() (byte-counted return) and fwprintf() (wide-character-
 * counted return, per fwprintf.html RETURN VALUE).
 *
 * MEASURED: one formatter costs ~5.9% versus two specialized ones
 * (snprintf benchmark, x86_64-win32-tcc under Wine).  Two instantiations
 * were considered and declined: %ls/%lc are written once for all four
 * argument/sink combinations so they cannot drift, and a second parser
 * is a defect surface no differential test catches. This library's
 * consumers are compile- or I/O-bound, where the 5.9% is unmeasurable.
 *
 * `count`/`bad` live in the struct, not the parameter lists, so the
 * signature change forces every call site to be converted -- a refactor
 * whose misses still compile is a refactor whose misses ship.
 *
 * `ost` holds wcrtomb() state across the units of one %ls: a
 * supplementary character is two wchar_t on this target, and wcrtomb()
 * buffers the high surrogate until its partner arrives.
 * ------------------------------------------------------------------ */
struct sink {
	FILE *f;
	int wide;       /* emit wide characters, and count them */
	int widemem;    /* wide AND the buffer holds wchar_t: precomputed,
	                 * because out() is the hottest function here and
	                 * tcc will not hoist the two loads itself */
	long count;     /* logical (untruncated) total, in sink units */
	int bad;
	mbstate_t ost;
};

/* sk is nonnull: every function here dereferences it unconditionally,
 * always the caller's own struct sink on the stack. */
static int count_fits(struct sink *sk, size_t n) __attribute__((nonnull(1)));
static int count_fits(struct sink *sk, size_t n)
{
	if (n <= (size_t)(INT_MAX - sk->count)) return 1;
	errno = EOVERFLOW;
	sk->f->err = 1;
	sk->bad = 1;
	return 0;
}

/* Emit n bytes of ASCII text that this file GENERATED (digits, signs,
 * padding, "0x", "(nil)"/"(null)"), never a caller's string.  That
 * restriction is what makes a wide sink cheap: an ASCII byte encodes to
 * itself, so only a buffer holding wchar_t directly (f->wmem) needs
 * converting.  A short write is a real error unless f is a fixed memory
 * buffer (sprintf/snprintf), where it is just truncation. */
static void out(struct sink *sk, const char *s, size_t n) __attribute__((nonnull(1)));
static void out(struct sink *sk, const char *s, size_t n)
{
	if (sk->bad) return;
	if (!count_fits(sk, n)) return;
	if (sk->widemem) {
		while (n) {
			wchar_t stage[32];
			size_t k = n < 32 ? n : 32, i;
			for (i = 0; i < k; i++) stage[i] = (wchar_t)(unsigned char)s[i];
			if (__fwrite(stage, sizeof *stage, k, sk->f) != k) {
				if (!sk->f->is_mem || sk->f->mem_dynamic) { sk->f->err = 1; sk->bad = 1; return; }
			}
			sk->count += (long)k;
			s += k; n -= k;
		}
		return;
	}
	if (n && __fwrite(s, 1, n, sk->f) != n) {
		if (!sk->f->is_mem || sk->f->mem_dynamic) { sk->f->err = 1; sk->bad = 1; return; }
	}
	sk->count += (long)n;
}

static void pad(struct sink *sk, char c, size_t n) __attribute__((nonnull(1)));
static void pad(struct sink *sk, char c, size_t n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char buf[16];
	size_t emit = n;
	size_t skipped = 0;

	if (sk->bad || !count_fits(sk, n)) return;
	/* A fixed memory sink still counts everything that would have been
	 * written, but the discarded tail past its capacity is never
	 * visited 16 bytes at a time -- that would make a large width take
	 * linear time and the INT_MAX check practically unreachable. */
	if (sk->f->is_mem && !sk->f->mem_dynamic) {
		size_t avail = sk->f->mem_pos < sk->f->mem_size
		             ? sk->f->mem_size - sk->f->mem_pos : 0;
		if (sk->widemem) avail /= sizeof(wchar_t);
		if (emit > avail) { skipped = emit - avail; emit = avail; }
	}
	memset(buf, c, sizeof buf);
	{
		/* ceil(emit / sizeof buf), without an overflowing addition. */
		size_t chunks = emit / sizeof buf + (emit % sizeof buf != 0);
		while (chunks > 0 && !sk->bad) {
			size_t k = emit < sizeof buf ? emit : sizeof buf;
			out(sk, buf, k);
			emit -= k;
			chunks--;
		}
	}
	/* out() only counted the stored prefix; add back the discarded tail. */
	if (!sk->bad) sk->count += (long)skipped;
}

/* Integer/pointer conversions accumulate digits least-significant-first,
 * so what they hold is the reverse of what belongs on the stream.  n is
 * always small: the widest case is a 64-bit value in octal, 22 digits. */
static void out_reversed(struct sink *sk, const char *digits, int n) __attribute__((nonnull(1, 2)));
static void out_reversed(struct sink *sk, const char *digits, int n)
{
	char rev[32];
	int i;
	for (i = 0; i < n; i++) rev[i] = digits[n - 1 - i];
	out(sk, rev, (size_t)n);
}

/* Emit n wide characters from a CALLER (%ls, %lc, or %s widened).
 * Unlike out(), these can be anything, so no ASCII shortcut applies.  On
 * a byte-backed stream each unit is encoded via wcrtomb() through
 * sk->ost: a supplementary character is two wchar_t here, and wcrtomb()
 * answers 0 (nothing written) for the high surrogate until its partner
 * arrives, though the count still advances by wide characters. */
static void out_units(struct sink *sk, const wchar_t *w, size_t n) __attribute__((nonnull(1)));
static void out_units(struct sink *sk, const wchar_t *w, size_t n)
{
	if (sk->bad) return;
	if (!count_fits(sk, n)) return;
	if (sk->f->wmem) {
		if (n && __fwrite(w, sizeof *w, n, sk->f) != n) {
			if (!sk->f->is_mem || sk->f->mem_dynamic) { sk->f->err = 1; sk->bad = 1; return; }
		}
		sk->count += (long)n;
		return;
	}
	{
		size_t i;
		char buf[MB_LEN_MAX];
		for (i = 0; i < n; i++) {
			size_t r = wcrtomb(buf, w[i], &sk->ost);
			if (r == (size_t)-1) { sk->f->err = 1; sk->bad = 1; return; }
			if (r && __fwrite(buf, 1, r, sk->f) != r) {
				if (!sk->f->is_mem || sk->f->mem_dynamic) { sk->f->err = 1; sk->bad = 1; return; }
			}
			sk->count++;
		}
	}
}

/* ------------------------------------------------------------------
 * STRING AND CHARACTER ARGUMENTS
 *
 * The one place a caller's own data is emitted.  Both the argument type
 * and the sink unit vary independently, giving four cases, two copies
 * and two conversions:
 *
 *   char *   -> bytes     copy       fprintf  "%s"
 *   wchar_t* -> bytes     wcrtomb    fprintf  "%ls"
 *   wchar_t* -> wide      copy       fwprintf "%ls"
 *   char *   -> wide      mbrtowc    fwprintf "%s"
 *
 * A partial character is never written, and the precision/field width
 * are always measured in the SINK's unit, never the argument's
 * (fprintf.html/fwprintf.html, the s conversion).
 *
 * One function measures and emits, called twice: emit == 0 gets the
 * length the field width pads against, emit == 1 writes it.  Two passes
 * rather than a staging buffer, since a string argument has no bound
 * (see PREC_MAX).
 * ------------------------------------------------------------------ */
/* arg is nonnull: every branch below dereferences it. */
static long str_arg(struct sink *sk, const void *arg, int wide_arg, int prec, int emit)
    __attribute__((nonnull(1, 2)));
static long str_arg(struct sink *sk, const void *arg, int wide_arg, int prec, int emit) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	mbstate_t st;
	long units = 0;

	memset(&st, 0, sizeof st);

	if (!wide_arg && !sk->wide) {			/* char * -> bytes */
		const char *s = arg;
		size_t n = strlen(s);
		if (prec >= 0 && (size_t)prec < n) n = (size_t)prec;
		if (emit) out(sk, s, n);
		return (long)n;
	}
	if (wide_arg && sk->wide) {			/* wchar_t * -> wide */
		const wchar_t *w = arg;
		size_t n = 0;
		while (w[n] && (prec < 0 || n < (size_t)prec)) n++;
		if (emit) out_units(sk, w, n);
		return (long)n;
	}
	if (wide_arg) {					/* wchar_t * -> bytes */
		const wchar_t *w = arg;
		char buf[MB_LEN_MAX];
		for (; *w; w++) {
			size_t r = wcrtomb(buf, *w, &st);
			if (r == (size_t)-1) break;	/* [EILSEQ]: stop here */
			/* A character that does not fit inside the precision
			 * entirely is not written at all. */
			if (prec >= 0 && units + (long)r > prec) break;
			units += (long)r;
			if (emit && r) out(sk, buf, r);
		}
		return units;
	}
	{						/* char * -> wide */
		const char *s = arg;
		while (*s || !mbsinit(&st)) {
			wchar_t wc = 0;
			size_t r = mbrtowc(&wc, s, MB_LEN_MAX, &st);
			size_t used;
			if (r == (size_t)-1 || r == (size_t)-2) break;
			/* (size_t)-3: a low surrogate delivered from state alone,
			 * consuming nothing -- the second half of a supplementary
			 * character. */
			used = r == (size_t)-3 ? 0 : r;
			if (prec >= 0 && units >= prec) break;
			units++;
			if (emit) out_units(sk, &wc, 1);
			s += used;
			if (!used && !*s && mbsinit(&st)) break;
		}
		return units;
	}
}

/* %s and %ls: measure, pad, emit, pad. */
static void emit_str(struct sink *sk, const void *arg, int wide_arg, int prec, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                     int flags, int width)
{
	long n = str_arg(sk, arg, wide_arg, prec, 0);
	long padn = width - n;
	if (padn < 0) padn = 0;
	if (flags & 4) { str_arg(sk, arg, wide_arg, prec, 1); pad(sk, ' ', (size_t)padn); }
	else { pad(sk, ' ', (size_t)padn); str_arg(sk, arg, wide_arg, prec, 1); }
}

/* ---- exact decimal expansion of a double ---------------------------- */

/* Big non-negative integers in base 10^9, least significant limb first,
 * so reading decimal digits back out is splitting limbs rather than
 * dividing a binary big integer down.  Only mul_small is needed here.
 *
 * DEC_LIMBS bounds the widest value formed below, (2^53-1) * 5^1074 (the
 * smallest subnormal's numerator): 767 digits, 86 limbs.  EXACT_DIG is
 * the matching bound on the digits themselves. */
#define DEC_LIMBS 88
#define EXACT_DIG 768

/* a = a * m, for m small enough that limb * m + carry stays inside a
 * uint64 (every m used here is below 2^30). */
static int mul_small(uint32_t *a, int n, uint32_t m) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	uint64_t carry = 0;
	int i;

	for (i = 0; i < n; i++) {
		uint64_t t = (uint64_t)a[i] * m + carry;
		a[i] = (uint32_t)(t % 1000000000u);
		carry = t / 1000000000u;
	}
	/* cannot run past DEC_LIMBS; do not corrupt memory if it does */
	while (carry && n < DEC_LIMBS) {
		a[n++] = (uint32_t)(carry % 1000000000u);
		carry /= 1000000000u;
	}
	return n;
}

/* The exact decimal expansion of a finite v >= 0: d[0..nd) are its
 * significant digits, and d[0] is the 10^decexp place (value is
 * 0.d * 10^(decexp+1), every place past d[nd-1] a zero). */
struct dec {
	int nd;
	int decexp;
	char d[EXACT_DIG];
};

static void dec_exact(double v, struct dec *D)
{
	union { double f; uint64_t i; } u;
	uint32_t bn[DEC_LIMBS];
	uint64_t m;
	int e2, bl = 0, k, i, j, nfrac = 0, chunks;
	char *p;

	u.f = v;
	e2 = (int)(u.i >> 52 & 0x7ff);
	m = u.i & 0xfffffffffffffULL;
	if (e2) { m |= (uint64_t)1 << 52; e2 -= 1075; }
	else e2 = -1074;   /* subnormal: no implicit bit, the same scale */

	if (!m) { D->nd = 1; D->decexp = 0; D->d[0] = '0'; return; }
	while (m) { bn[bl++] = (uint32_t)(m % 1000000000u); m /= 1000000000u; }

	/* v = m * 2^e2: for e2 >= 0, the integer m << e2; for e2 < 0,
	 * m * 5^-e2 with the point -e2 places from the right (m / 2^k ==
	 * m * 5^k / 10^k), so one big integer carries every digit and no
	 * division is needed to produce them. */
	chunks = e2 > 0 ? e2 / 29 + (e2 % 29 != 0) : 0;
	while (chunks > 0) {
		k = e2 > 29 ? 29 : e2;
		bl = mul_small(bn, bl, 1u << k);
		e2 -= k;
		chunks--;
	}
	if (e2 < 0) {
		nfrac = -e2;
		chunks = nfrac / 12 + (nfrac % 12 != 0);
		for (k = nfrac; chunks > 0; chunks--) {
			if (k >= 12) { bl = mul_small(bn, bl, 244140625u); k -= 12; }  /* 5^12 */
			else {
				uint32_t f = 1;
				while (k--) f *= 5;
				bl = mul_small(bn, bl, f);
			}
		}
	}

	p = D->d;
	{
		uint32_t hi = bn[bl - 1];
		char t[10];
		i = 0;
		do { t[i++] = (char)('0' + (int)(hi % 10)); hi /= 10; } while (hi);
		while (i > 0) {
			i--;
			*p++ = t[i];
		}
	}
	for (i = bl - 2; i >= 0; i--) {
		uint32_t w = bn[i];
		for (j = 8; j >= 0; j--) { p[j] = (char)('0' + (int)(w % 10)); w /= 10; }
		p += 9;
	}
	D->nd = (int)(p - D->d);
	D->decexp = D->nd - 1 - nfrac;
	/* trailing zeros are implicit; dropping them keeps dec_round's own
	 * "is the discarded tail nonzero" test short */
	while (D->nd > 1 && D->d[D->nd - 1] == '0') D->nd--;
}

/* Round D to want >= 1 significant digits, to nearest with ties to
 * even.  Asking for more digits than the expansion has is a no-op.  A
 * carry out of the leading digit bumps decexp, leaving "1" and zeros. */
static void dec_round(struct dec *D, int want)
{
	int i, up;

	if (want >= D->nd) return;
	up = D->d[want] > '5';
	if (D->d[want] == '5') {
		for (i = want + 1; i < D->nd; i++) if (D->d[i] != '0') { up = 1; break; }
		if (!up) up = (D->d[want - 1] - '0') & 1;   /* a tie goes to even */
	}
	D->nd = want;
	if (!up) {
		while (D->nd > 1 && D->d[D->nd - 1] == '0') D->nd--;
		return;
	}
	for (i = want - 1; i >= 0; i--) {
		if (D->d[i] != '9') { D->d[i]++; D->nd = i + 1; return; }
		D->d[i] = '0';
	}
	D->d[0] = '1';
	D->nd = 1;
	D->decexp++;
}

/* %f-style body (no sign): pos digits before the point, then a point
 * and prec digits after it, from D rounded to decexp+1+prec significant
 * digits.  When that count is not positive, the value rounds to a zero
 * or a one at the last place shown. */
static int fmt_f(char *buf, struct dec *D, int prec, int alt)
{
	int want = D->decexp + 1 + prec, pos, i, n = 0;

	if (want >= 1) dec_round(D, want);
	else {
		/* want == 0: the leading digit is one place below the last
		 * shown, rounding up only past 5 or on an exact tie with
		 * something nonzero after (ties otherwise go to even zero).
		 * want < 0 is further down still and always rounds to zero. */
		D->d[0] = (want == 0 && (D->d[0] > '5' || (D->d[0] == '5' && D->nd > 1)))
		          ? '1' : '0';
		D->nd = 1;
		D->decexp = -prec;
	}
	pos = D->decexp + 1;
	if (pos <= 0) {
		buf[n++] = '0';
		if (prec > 0 || alt) buf[n++] = '.';
		for (i = 0; i < -pos && i < prec; i++) buf[n++] = '0';
		for (i = 0; i < prec + pos; i++) buf[n++] = (char)(i < D->nd ? D->d[i] : '0');
	} else {
		for (i = 0; i < pos; i++) buf[n++] = (char)(i < D->nd ? D->d[i] : '0');
		if (prec > 0 || alt) buf[n++] = '.';
		for (i = 0; i < prec; i++) buf[n++] = (char)(pos + i < D->nd ? D->d[pos + i] : '0');
	}
	return n;
}

/* %e-style body (no sign).  *epos receives the offset of the 'e', the
 * point at which emit_float splices in any zeros a clamped precision
 * left out of the mantissa. */
static int fmt_e(char *buf, struct dec *D, int prec, int alt, int upper, int *epos) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int i, n = 0;

	dec_round(D, prec + 1);
	buf[n++] = D->d[0];
	if (prec > 0 || alt) {
		buf[n++] = '.';
		for (i = 1; i < prec + 1; i++) buf[n++] = (char)(i < D->nd ? D->d[i] : '0');
	}
	*epos = n;
	buf[n++] = upper ? 'E' : 'e';
	buf[n++] = D->decexp < 0 ? '-' : '+';
	{
		unsigned ax = (unsigned)(D->decexp < 0 ? -D->decexp : D->decexp);
		char eb[8]; int ei = 0;
		if (ax == 0) eb[ei++] = '0';
		while (ax) { eb[ei++] = (char)('0' + ax % 10); ax /= 10; }
		while (ei < 2) eb[ei++] = '0';
		while (ei--) buf[n++] = eb[ei];
	}
	return n;
}

/* strip trailing fractional zeros (and a bare trailing point) from a
 * body already formatted by fmt_f/fmt_e, for %g without '#'. */
static int strip_g(char *buf, int n, int has_exp) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int mant_end = n, i;
	if (has_exp) { for (i = 0; i < n; i++) if (buf[i] == 'e' || buf[i] == 'E') { mant_end = i; break; } }
	i = mant_end;
	if (memchr(buf, '.', mant_end)) {
		while (i > 0 && buf[i - 1] == '0') i--;
		if (i > 0 && buf[i - 1] == '.') i--;
	}
	if (i != mant_end)
		for (int j = mant_end; j < n; j++) buf[i + j - mant_end] = buf[j];
	return n - (mant_end - i);
}

/* %a-style body: hex significand and decimal binary exponent, without
 * the sign or "0x" -- emit_float carries those in the prefix so a '0'
 * flag can pad between them (C99 7.19.6.1p6).  *epos receives the
 * offset of the 'p'.  The 52 mantissa bits are exactly 13 hex digits;
 * a precision below 13 rounds to nearest with ties to even. */
static int fmt_a(char *buf, double v, int prec, int alt, int upper, int *epos) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *hex = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	union { double f; uint64_t i; } u;
	uint64_t man;
	int e, nd, i, n = 0;
	char lead;

	u.f = v;
	e = (int)(u.i >> 52 & 0x7ff);
	man = u.i & 0xfffffffffffffULL;
	if (!e) { lead = '0'; e = man ? -1022 : 0; }   /* subnormal, or zero */
	else { lead = '1'; e -= 1023; }

	if (prec < 0) {
		/* no precision given: exactly the digits the value needs */
		nd = 13;
		while (nd > 0 && !(man >> (52 - 4 * nd) & 0xf)) nd--;
	} else if (prec < 13) {
		int shift = (13 - prec) * 4;
		uint64_t rem = man & (((uint64_t)1 << shift) - 1);
		uint64_t half = (uint64_t)1 << (shift - 1);
		man >>= shift;
		/* a tie goes to even; at precision 0 that digit is the leading one */
		if (rem > half || (rem == half && ((prec ? man : (uint64_t)(lead - '0')) & 1))) man++;
		if (man >> (4 * prec)) { man = 0; lead++; }   /* carried out of the digits */
		man <<= shift;
		nd = prec;
	} else nd = 13;   /* the caller's extra digits are zeros; see PREC_MAX */

	buf[n++] = lead;
	if (nd > 0 || alt) buf[n++] = '.';
	for (i = 0; i < nd; i++) buf[n++] = hex[man >> (48 - 4 * i) & 0xf];
	if (prec > 13) for (i = 13; i < prec; i++) buf[n++] = '0';
	*epos = n;
	buf[n++] = upper ? 'P' : 'p';
	buf[n++] = e < 0 ? '-' : '+';
	{
		unsigned ax = (unsigned)(e < 0 ? -e : e);
		char eb[8]; int ei = 0;
		if (ax == 0) eb[ei++] = '0';
		while (ax) { eb[ei++] = (char)('0' + ax % 10); ax /= 10; }
		while (ei--) buf[n++] = eb[ei];
	}
	return n;
}

/* Write a body of n bytes with `zeros` further '0' spliced in at offset
 * zpos, where a precision clamped to PREC_MAX left off. */
static void out_body(struct sink *sk, const char *body, int n, int zpos, long zeros) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	out(sk, body, (size_t)zpos);
	pad(sk, '0', (size_t)zeros);
	out(sk, body + zpos, (size_t)(n - zpos));
}

static void emit_float(struct sink *sk, double v, int conv, int prec, int alt, int flags, int width)
    __attribute__((nonnull(1)));
static void emit_float(struct sink *sk, double v, int conv, int prec, int alt, int flags, int width) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char body[BODYMAX];
	struct dec D;
	char pfx[3];
	int n, neg = signbit(v);
	int upper = conv == 'F' || conv == 'E' || conv == 'G' || conv == 'A';
	char sign = (char)(neg ? '-' : (flags & 1 ? '+' : (flags & 2 ? ' ' : 0)));
	char av = (char)(conv == 'F' ? 'f' : conv == 'E' ? 'e' : conv == 'G' ? 'g' :
	                 conv == 'A' ? 'a' : conv);
	int prefixlen = 0;
	long zeros = 0;   /* mantissa places past PREC_MAX, all of them zeros */
	int zpos = 0;     /* where in body they belong */
	int total, special = 0;

	v = fabs(v);
	/* A NaN keeps whatever sign the flags ask for (C99 7.19.6.1p6/p8);
	 * glibc and musl both print "+nan". body[] is length-tracked (n),
	 * never NUL-terminated -- out_body always writes exactly n bytes. */
	if (isnan(v)) { memcpy(body, upper ? "NAN" : "nan", 3); n = 3; special = 1; } // NOLINT(bugprone-not-null-terminated-result)
	else if (isinf(v)) { memcpy(body, upper ? "INF" : "inf", 3); n = 3; special = 1; } // NOLINT(bugprone-not-null-terminated-result)
	else if (av == 'a') {
		int pu = prec > PREC_MAX ? PREC_MAX : prec;
		zeros = prec > PREC_MAX ? (long)prec - pu : 0;
		n = fmt_a(body, v, pu, alt, upper, &zpos);
	}
	else if (av == 'f' || av == 'e') {
		int p = prec < 0 ? 6 : prec;
		int pu = p > PREC_MAX ? PREC_MAX : p;
		zeros = (long)p - pu;
		dec_exact(v, &D);
		if (av == 'f') { n = fmt_f(body, &D, pu, alt); zpos = n; }
		else n = fmt_e(body, &D, pu, alt, upper, &zpos);
	} else { /* g/G */
		int P = prec < 0 ? 6 : (prec == 0 ? 1 : prec);
		int PU = P > PREC_MAX ? PREC_MAX : P;
		dec_exact(v, &D);
		/* the form is chosen from the rounded value's exponent (C99
		 * 7.19.6.1p8), so round first; fmt_e/fmt_f round again as a no-op */
		dec_round(&D, PU);
		/* without '#' the zeros a clamped precision drops are exactly
		 * the ones strip_g would take off again, so they never go out */
		zeros = alt ? (long)P - PU : 0;
		if (D.decexp < -4 || D.decexp >= P) {
			n = fmt_e(body, &D, PU - 1, alt, upper, &zpos);
			if (!alt) n = strip_g(body, n, 1);
		} else {
			n = fmt_f(body, &D, PU - 1 - D.decexp, alt);
			zpos = n;
			if (!alt) n = strip_g(body, n, 0);
		}
	}
	if (zeros <= 0 || zpos > n) { zeros = 0; zpos = n; }

	if (sign) pfx[prefixlen++] = sign;
	if (av == 'a' && !special) { pfx[prefixlen++] = '0'; pfx[prefixlen++] = upper ? 'X' : 'x'; }

	/* printf's return is an int (C99 7.19.6.1p3): refuse a conversion
	 * whose zero run alone would not fit rather than spend an age
	 * emitting a result that cannot be reported. */
	if (zeros > (long)(INT_MAX - n - prefixlen)) {
		errno = EOVERFLOW;
		sk->f->err = 1;
		sk->bad = 1;
		return;
	}
	total = n + (int)zeros + prefixlen;

	{
		int pad_n = width - total;
		if (pad_n < 0) pad_n = 0;
		if (flags & 4) { /* left */
			out(sk, pfx, (size_t)prefixlen);
			out_body(sk, body, n, zpos, zeros);
			pad(sk, ' ', (size_t)pad_n);
		} else if ((flags & 8) && !special) { /* zero pad, never for inf/nan */
			out(sk, pfx, (size_t)prefixlen);
			pad(sk, '0', (size_t)pad_n);
			out_body(sk, body, n, zpos, zeros);
		} else {
			pad(sk, ' ', (size_t)pad_n);
			out(sk, pfx, (size_t)prefixlen);
			out_body(sk, body, n, zpos, zeros);
		}
	}
}

/* ------------------------------------------------------------------
 * THE ARGUMENT LIST: fprintf.html's numbered conversions
 *
 * "%n$"/"*m$" name a specific argument (n in [1,{NL_ARGMAX}]); a format
 * mixing numbered and unnumbered conversions is invalid.
 *
 * A numbered format reads arguments out of order and va_arg cannot be
 * rewound, so they must be collected into an indexable table first --
 * which needs each argument's TYPE, known only from the conversion
 * specification naming it.  Hence the format is scanned twice:
 * build_argtab() below fills the table by type, and the ordinary loop
 * then sources every argument from the table instead of the va_list.
 *
 * THE UNNUMBERED PATH DOES NOT PAY FOR THIS: no pre-scan, no table, no
 * allocation.  The format is classified at the first conversion
 * specification, and until a numbered one appears arguments come off
 * the va_list exactly as before -- one predictable branch per argument.
 * The table is NL_ARGMAX entries of frame rather than a malloc, since a
 * malloc here would be paid by every printf call in every program.
 *
 * MEASURED: the unnumbered path is ~5% slower than before this existed
 * (CPU time, x86_64-win32-tcc under Wine).  Not the table (shrinking it
 * to one entry didn't help) and not call overhead (folding arg_type()
 * into parse_spec() didn't help either) -- it's the specification being
 * parsed into a struct the conversion reads back, which is what buys
 * both passes ONE parser instead of two that must agree with each
 * other, the same trade declined once already at the sink above.
 * ------------------------------------------------------------------ */

/* The type an argument is fetched with -- what va_arg itself is handed
 * after default argument promotions, so there is no A_CHAR or A_SHORT:
 * %hhd's argument arrives as an int and is narrowed after fetching. */
enum { A_NONE, A_INT, A_UINT, A_LONG, A_ULONG, A_LLONG, A_ULLONG,
       A_SIZE, A_SSIZE, A_PTRDIFF, A_WINT, A_DOUBLE, A_PTR };

/* One fetched argument, normalised: every integer widens into i or u out
 * of va_arg, so conversions read one member per signedness rather than
 * per length modifier.  This keeps the C type a specification names in
 * one place (pop_arg() below, and TAKE's fast-path duplicates, each
 * under the same constant) instead of two mappings -- fetch and type
 * table -- that could silently disagree. */
union varg {
	long long i;
	unsigned long long u;
	double d;
	void *p;
};

/* a is written unconditionally on every path (including the A_NONE
 * default). ap is nonnull: every real call site passes the address of a
 * local va_list. */
static void pop_arg(union varg *a, int type, va_list *ap)
    __attribute__((nonnull(1, 3)));
static void pop_arg(union varg *a, int type, va_list *ap)
{
	switch (type) {
	case A_INT:     a->i = va_arg(*ap, int); break;
	case A_UINT:    a->u = va_arg(*ap, unsigned int); break;
	case A_LONG:    a->i = va_arg(*ap, long); break;
	case A_ULONG:   a->u = va_arg(*ap, unsigned long); break;
	case A_LLONG:   a->i = va_arg(*ap, long long); break;
	case A_ULLONG:  a->u = va_arg(*ap, unsigned long long); break; // NOLINT(bugprone-branch-clone) -- va_arg must name the exact unsigned long long source type; the following size_t case only canonicalizes identically on LLP64
	/* LLP64: long is 32 bits while size_t/ptrdiff_t are 64, so `long` is
	 * the wrong type to pull these with ("%zd" above 4G printed its low
	 * half).  Pull each as the type fprintf.html names for z/t. */
	case A_SIZE:    a->u = va_arg(*ap, size_t); break;
	case A_SSIZE:   a->i = va_arg(*ap, ssize_t); break; // NOLINT(bugprone-branch-clone) -- va_arg must name the exact ssize_t source type; the following ptrdiff_t case only canonicalizes identically on this ABI
	/* ptrdiff_t is signed whatever the conversion's signedness is -- t
	 * has no unsigned counterpart -- so %tu/%to/%tx fetch it as one and
	 * reinterpret afterwards. */
	case A_PTRDIFF: a->i = va_arg(*ap, ptrdiff_t); break;
	case A_WINT:    a->i = va_arg(*ap, wint_t); break;
	case A_DOUBLE:  a->d = va_arg(*ap, double); break;
	case A_PTR:     a->p = va_arg(*ap, void *); break;
	default:        a->i = 0; break;   /* A_NONE: nothing is fetched */
	}
}

/* The type a conversion fetches.  A_NONE for one that fetches nothing:
 * an unknown conversion (emitted literally) or a format that ended
 * before its conversion character. */
static int arg_type(int lm, int conv) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	switch (conv) {
	case 'd': case 'i':
		switch (lm) {
		case LM_l: return A_LONG;
		case LM_ll: case LM_j: return A_LLONG;
		/* widthmod-ok: A_SSIZE is fetched as ssize_t in pop_arg(). */
		case LM_z: return A_SSIZE;
		/* widthmod-ok: A_PTRDIFF is fetched as ptrdiff_t in pop_arg(). */
		case LM_t: return A_PTRDIFF;
		default: return A_INT;      /* hh and h promote to int */
		}
	case 'u': case 'o': case 'x': case 'X':
		switch (lm) {
		case LM_l: return A_ULONG;
		case LM_ll: case LM_j: return A_ULLONG;
		/* widthmod-ok: A_SIZE is fetched as size_t in pop_arg(). */
		case LM_z: return A_SIZE;
		/* widthmod-ok: A_PTRDIFF is fetched as ptrdiff_t in pop_arg(). */
		case LM_t: return A_PTRDIFF;
		default: return A_UINT;
		}
	case 'c': return lm == LM_l ? A_WINT : A_INT;
	case 's': case 'p': case 'n': return A_PTR;
	/* L is accepted and ignored: long double is a double on both of
	 * this library's targets (tcc gives an 8-byte long double), so %Lf
	 * fetches the same argument %f does. */
	case 'f': case 'F': case 'e': case 'E': case 'g': case 'G':
	case 'a': case 'A': return A_DOUBLE;
	default: return A_NONE;
	}
}

/* One parsed conversion specification.  width and prec hold a literal
 * one; wpos and ppos are -1 when there is no '*' at all, 0 for a '*'
 * that takes the next unused argument, and n for a "*n$" that names
 * one.  argpos is 0 when the specification is unnumbered. */
struct spec {
	int argpos;
	int flags;      /* 1=+ 2=space 4=- 8=0 16=# 32=' */
	int width, wpos;
	int prec, ppos;
	int lm;
	int conv;       /* the conversion character, 0 at end of format */
	int type;       /* arg_type(lm, conv) */
	int width_overflow;
};

/* "%n$"/"*n$": a digit run terminated by '$', not distinguishable from a
 * width until the '$' is seen ("%1$s" vs "%12s"), so read ahead and
 * rewind on a miss.  A leading '0' is never an index (n is in
 * [1,{NL_ARGMAX}]), so "%0$d" is a width of 0.  The accumulator stops
 * past NL_ARGMAX to avoid signed overflow on an unclamped digit run. */
static const char *scan_argno(const char *fp, int st, int *n) __attribute__((nonnull(1, 3)));
static const char *scan_argno(const char *fp, int st, int *n)
{
	const char *q = fp;
	int v = 0;

	*n = 0;
	if (gf(q, st) < '1' || gf(q, st) > '9') return fp;
	while (gf(q, st) >= '0' && gf(q, st) <= '9') {
		if (v <= NL_ARGMAX) {
			unsigned digit = (unsigned)(gf(q, st) - '0');
			v = (int)((unsigned)v * 10u + digit);
		}
		q += st;
	}
	if (gf(q, st) != '$') return fp;
	*n = v;
	return q + st;
}

/* Parse one conversion specification, cursor left on the conversion
 * character (or the terminating null of a format that ends
 * mid-specification, seen by the caller as sp->conv == 0).
 *
 * ONE parser, called by both passes: a second scanner for the
 * type-collecting pass would be a copy of this grammar that could
 * silently disagree, fetching the wrong argument for a conversion.  The
 * cost is one call per directive, not per format character (gf() above
 * already avoids that). */
static const char *parse_spec(const char *fp, int st, struct spec *sp) __attribute__((nonnull(1, 3)));
static const char *parse_spec(const char *fp, int st, struct spec *sp)
{
	int n;

	sp->flags = 0;
	sp->width = 0;
	sp->wpos = -1;
	sp->prec = -1;
	sp->ppos = -1;
	sp->lm = LM_NONE;
	sp->width_overflow = 0;

	/* The guard, rather than letting scan_argno() return early on its
	 * own: tcc does not inline, so on the overwhelmingly common
	 * specification -- one that does not begin with a digit at all --
	 * this comparison is the whole cost of looking for an index,
	 * instead of a call that finds nothing. */
	sp->argpos = 0;
	if (gf(fp, st) >= '1' && gf(fp, st) <= '9')
		fp = scan_argno(fp, st, &sp->argpos);

	for (;; fp += st) {
		if (gf(fp, st) == '-') sp->flags |= 4;
		else if (gf(fp, st) == '+') sp->flags |= 1;
		else if (gf(fp, st) == ' ') sp->flags |= 2;
		else if (gf(fp, st) == '0') sp->flags |= 8;
		else if (gf(fp, st) == '#') sp->flags |= 16;
		/* The [CX] apostrophe flag (thousands' grouping, %i/%d/%u/%f/
		 * %F/%g/%G) must be ACCEPTED regardless of locale.  Accepted
		 * and ignored is the complete implementation: LC_NUMERIC's
		 * grouping is "" in the only locale this library has, so
		 * ignoring it produces byte-for-byte the unflagged output.  The
		 * bit is recorded for a future locale with real grouping to
		 * hook on.  Omitting it from this loop entirely (rather than
		 * just not implementing grouping) was a real bug: the
		 * apostrophe then fell through to the literal-echo default arm,
		 * which consumes no argument, so every conversion after a %' in
		 * the same format silently read the previous one's argument. */
		else if (gf(fp, st) == '\'') sp->flags |= 32;
		else break;
	}

	if (gf(fp, st) == '*') {
		fp = scan_argno(fp + st, st, &n);
		sp->wpos = n;
	} else {
		while (gf(fp, st) >= '0' && gf(fp, st) <= '9') {
			int digit = (int)(gf(fp, st) - '0');
			if (sp->width > (INT_MAX - digit) / 10) {
				sp->width = INT_MAX;
				sp->width_overflow = 1;
			} else sp->width = (int)((unsigned)sp->width * 10u +
				(unsigned)digit);
			fp += st;
		}
	}
	if (gf(fp, st) == '.') {
		fp += st;
		if (gf(fp, st) == '*') { fp = scan_argno(fp + st, st, &n); sp->ppos = n; }
		else {
			sp->prec = 0;
			while (gf(fp, st) >= '0' && gf(fp, st) <= '9') {
				int digit = (int)(gf(fp, st) - '0');
				if (sp->prec > (INT_MAX - digit) / 10)
					sp->prec = INT_MAX;
				else sp->prec = (int)((unsigned)sp->prec * 10u +
					(unsigned)digit);
				fp += st;
			}
		}
	}
	for (;;) {
		if (gf(fp, st) == 'h') { sp->lm = sp->lm == LM_h ? LM_hh : LM_h; fp += st; }
		else if (gf(fp, st) == 'l') { sp->lm = sp->lm == LM_l ? LM_ll : LM_l; fp += st; }
		else if (gf(fp, st) == 'j') { sp->lm = LM_j; fp += st; }
		else if (gf(fp, st) == 'z') { sp->lm = LM_z; fp += st; }
		else if (gf(fp, st) == 't') { sp->lm = LM_t; fp += st; }
		else if (gf(fp, st) == 'L') { sp->lm = LM_L; fp += st; }
		else break;
	}
	sp->conv = (int)gf(fp, st);
	sp->type = arg_type(sp->lm, sp->conv);
	return fp;
}

/* Collect the arguments a numbered format names into tab[1..NL_ARGMAX],
 * in index order, and return the highest index used -- or -1 for a
 * format this cannot serve, reported as [EINVAL].  A diagnosed refusal
 * beats a guess: the alternative is arguments read at the wrong
 * offset, i.e. an int dereferenced as a char *.  Refused: mixing
 * numbered and unnumbered forms, and an index outside
 * [1,{NL_ARGMAX}].  Not refused: a gap in the numbering (see below). */
static int build_argtab(const char *fmt, int st, union varg *tab, va_list *ap)
    __attribute__((nonnull(1, 3, 4)));
static int build_argtab(const char *fmt, int st, union varg *tab, va_list *ap)
{
	unsigned char types[NL_ARGMAX + 1];
	const char *fp = fmt;
	struct spec sp;
	int i, max = 0;

	memset(types, A_NONE, sizeof types);
	while (gf(fp, st)) {
		if (gf(fp, st) != '%') { fp += st; continue; }
		fp += st;
		if (gf(fp, st) == '%') { fp += st; continue; }
		fp = parse_spec(fp, st, &sp);
		if (sp.conv) fp += st;
		if (sp.width_overflow) return -2;

		/* An unnumbered form in a format that already showed a
		 * numbered one: a '*' or conversion naming no argument. */
		if (sp.wpos == 0 || sp.ppos == 0) return -1;
		if (sp.type != A_NONE && !sp.argpos) return -1;

		/* "*m$" is always an int -- fprintf.html: "the argument ...
		 * shall be converted to an int". */
		if (sp.wpos > 0) {
			if (sp.wpos > NL_ARGMAX) return -1;
			types[sp.wpos] = A_INT;
			if (sp.wpos > max) max = sp.wpos;
		}
		if (sp.ppos > 0) {
			if (sp.ppos > NL_ARGMAX) return -1;
			types[sp.ppos] = A_INT;
			if (sp.ppos > max) max = sp.ppos;
		}
		if (sp.type != A_NONE) {
			if (sp.argpos > NL_ARGMAX) return -1;
			/* Naming an argument twice is fine (the point of the
			 * feature); two different types is undefined, and the
			 * last specification wins. */
			types[sp.argpos] = (unsigned char)sp.type;
			if (sp.argpos > max) max = sp.argpos;
		}
	}

	/* A GAP: an index below the highest one used that no specification
	 * names, as in "%9$d" with the first eight args unmentioned.  POSIX
	 * leaves this undefined; it must not read an unwritten slot, so the
	 * unnamed argument is fetched as an int (the default-promotion
	 * result for anything narrower, and unobservable on LLP64 where
	 * every slot is one register wide). */
	for (i = 1; i < max + 1; i++)
		if (types[i] == A_NONE) types[i] = A_INT;

	for (i = 1; i < max + 1; i++) pop_arg(&tab[i], types[i], ap);
	return max;
}

/* The argument a specification names: out of the table for a numbered
 * format, off the va_list for an unnumbered one.  A macro because the
 * `else` arm must expand va_arg in this function's own frame.
 *
 * A_INT and A_PTR are spelled out here rather than left to pop_arg:
 * together they cover nearly every conversion this library's consumers
 * write, and under tcc (no inlining) routing them through pop_arg
 * measured 2-3% slower.  Each arm here is guarded by the same constant
 * that selects the matching arm of pop_arg's switch, so the two cannot
 * disagree about a type without disagreeing about `ty`. */
#define TAKE(dst, pos, ty) do { \
	if (argtab) (dst) = argtab[pos]; \
	else if ((ty) == A_INT) (dst).i = va_arg(aq, int); \
	else if ((ty) == A_PTR) (dst).p = va_arg(aq, void *); \
	else pop_arg(&(dst), (ty), &aq); \
} while (0)

/* f and fmt are nonnull; ap is a va_list BY VALUE, not a pointer this
 * attribute can describe. */
static int vfprintf_st(FILE *f, const char *fmt, va_list ap, int st) __attribute__((nonnull(1, 2)));
static int vfprintf_st(FILE *f, const char *fmt, va_list ap, int st)
{
	struct sink sink, *sk = &sink;
	const char *fp = fmt;
	if (st != 1 && st != (int)sizeof(wchar_t)) {
		errno = EINVAL;
		return -1;
	}
	/* Only a numbered format ever touches these; the frame cost buys the
	 * common path freedom from a malloc. */
	union varg argv[NL_ARGMAX + 1];
	union varg *argtab = 0;
	/* A local COPY of ap, since everything below fetches through its
	 * ADDRESS: va_list is an array type on some ABIs (not this
	 * library's targets), where &ap would point to the wrong thing.
	 * Copying costs nothing -- vfprintf.html leaves ap's value after
	 * return unspecified. */
	va_list aq;
	va_copy(aq, ap);

	sink.f = f;
	sink.wide = st != 1;
	sink.widemem = sink.wide && f->wmem;
	sink.count = 0;
	sink.bad = 0;
	memset(&sink.ost, 0, sizeof sink.ost);

	while (gf(fp, st) && !sk->bad) {
		if (gf(fp, st) != '%') {
			/* A run of ordinary characters, from the CALLER's format:
			 * in a wide format these may be anything, so out()'s ASCII
			 * shortcut and byte-based length don't apply. */
			const char *start = fp;
			while (gf(fp, st) && gf(fp, st) != '%') fp += st;
			if (st == 1) out(sk, start, (size_t)(fp - start));
			else out_units(sk, (const wchar_t *)start,
			               (size_t)((fp - start) / st));
			continue;
		}
		fp += st;
		if (gf(fp, st) == '%') { out(sk, "%", 1); fp += st; continue; }

		{
			struct spec sp;
			union varg a;
			int flags, width, prec;

			fp = parse_spec(fp, st, &sp);
			if (sp.width_overflow) {
				errno = EOVERFLOW;
				sk->f->err = 1;
				sk->bad = 1;
				break;
			}

			/* The first specification that names an argument settles
			 * the whole format: every argument comes out of the table
			 * from here on, and build_argtab() has already refused the
			 * format if any other specification is unnumbered. */
			if (!argtab && (sp.argpos || sp.wpos > 0 || sp.ppos > 0)) {
				int argresult = build_argtab(fmt, st, argv, &aq);
				if (argresult < 0) {
					/* fprintf.html's nearest named failure is [EINVAL]
					 * "insufficient arguments". Unlike [EOVERFLOW]/
					 * [EILSEQ] above, the stream's error indicator is
					 * NOT set: nothing went wrong with the stream, only
					 * with the caller's format string. */
					errno = argresult == -2 ? EOVERFLOW : EINVAL;
					if (argresult == -2) sk->f->err = 1;
					sk->bad = 1;
					break;
				}
				argtab = argv;
			}

			flags = sp.flags;
			/* Width, then precision, then the conversion's own
			 * argument -- the only order the unnumbered form can
			 * consume them in. */
			width = sp.width;
			if (sp.wpos >= 0) {
				TAKE(a, sp.wpos, A_INT);
				width = (int)a.i;
				/* A negative width is a '-' flag plus a positive
				 * width; INT_MIN has no representable positive
				 * magnitude, and `-width` would itself be UB. */
				if (width == INT_MIN) {
					errno = EOVERFLOW;
					sk->f->err = 1;
					sk->bad = 1;
					break;
				}
				if (width < 0) { flags |= 4; width = -width; }
			}
			prec = sp.prec;
			if (sp.ppos >= 0) {
				TAKE(a, sp.ppos, A_INT);
				prec = (int)a.i;
				/* a negative precision is taken as omitted */
				if (prec < 0) prec = -1;
			}
			/* Zeroed unconditionally so every read of `a` below is
			 * defined outright, not by an sp.type/sp.conv correlation
			 * no local reader (or clang-analyzer) can check. */
			a.i = 0;
			if (sp.type != A_NONE) TAKE(a, sp.argpos, sp.type);

			switch (sp.conv) {
			case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
				int base = sp.conv == 'o' ? 8 : (sp.conv == 'x' || sp.conv == 'X') ? 16 : 10;
				int upper = sp.conv == 'X';
				int issigned = sp.conv == 'd' || sp.conv == 'i';
				int neg = 0;
				unsigned long long uv;
				char digbuf[32]; int dn = 0, zpad;
				char prefix[3]; int pn = 0;

				if (issigned) {
					long long sv;
					/* Already fetched at its length modifier's width
					 * and sign-extended (see pop_arg); only hh/h, which
					 * name a type narrower than the promoted int, need
					 * narrowing here. */
					switch (sp.lm) {
					case LM_hh: sv = (signed char)a.i; break; // NOLINT(bugprone-signed-char-misuse,cert-str34-c) -- deliberate sign extension of a %hhd argument, not a table index
					case LM_h: sv = (short)a.i; break;
					default: sv = a.i; break;
					}
					neg = sv < 0;
					/* Negate after widening: -sv is undefined for
					 * LLONG_MIN, while negating the unsigned value
					 * wraps modulo 2**64 (C99 6.3.1.3p2), which is
					 * exactly the magnitude wanted. */
					uv = neg ? __neg_mag((unsigned long long)sv) : (unsigned long long)sv;
				} else {
					switch (sp.lm) {
					case LM_hh: uv = (unsigned char)a.u; break;
					case LM_h: uv = (unsigned short)a.u; break;
					/* widthmod-ok: pop_arg() fetched ptrdiff_t; this reinterprets it unsigned. */
					case LM_t: uv = (unsigned long long)a.i; break;
					default: uv = a.u; break;
					}
				}

				if (uv == 0 && prec == 0) { /* "" for 0 with explicit precision 0 */ }
				else {
					unsigned long long t = uv;
					/* base 8/10/16 reaches zero well before this
					 * one-pass-per-bit guard does. */
					unsigned bits_left = (unsigned)(sizeof t * CHAR_BIT);
					do {
						digbuf[dn++] = "0123456789abcdef"[t % (unsigned)base];
						if (upper && digbuf[dn-1] > '9') digbuf[dn-1] -= 32;
						t /= (unsigned)base;
						bits_left--;
					} while (t && bits_left > 0);
				}
				/* A precision is an unbounded minimum digit count
				 * (C99 7.19.6.1p5), so leading zeros it calls for are
				 * padded to the stream rather than stored. */
				zpad = prec > dn ? prec - dn : 0;

				if (neg) prefix[pn++] = '-';
				else if (issigned && (flags & 1)) prefix[pn++] = '+';
				else if (issigned && (flags & 2)) prefix[pn++] = ' ';
				/* '#' octal needs a leading zero only if the precision
				 * has not already put one there */
				if ((flags & 16) && base == 8 && !zpad && (dn == 0 || digbuf[dn-1] != '0')) digbuf[dn++] = '0';
				if ((flags & 16) && base == 16 && uv != 0) { prefix[pn++] = '0'; prefix[pn++] = upper ? 'X' : 'x'; }

				if (zpad > INT_MAX - dn - pn) { errno = EOVERFLOW; sk->f->err = 1; sk->bad = 1; break; }
				{
					int total = dn + pn + zpad;
					int padn = width - total; if (padn < 0) padn = 0;
					int zero = (flags & 8) && !(flags & 4) && prec < 0;
					if (flags & 4) {
						out(sk, prefix, (size_t)pn);
						pad(sk, '0', (size_t)zpad);
						out_reversed(sk, digbuf, dn);
						pad(sk, ' ', (size_t)padn);
					} else if (zero) {
						out(sk, prefix, (size_t)pn);
						pad(sk, '0', (size_t)padn);
						out_reversed(sk, digbuf, dn);
					} else {
						pad(sk, ' ', (size_t)padn);
						out(sk, prefix, (size_t)pn);
						pad(sk, '0', (size_t)zpad);
						out_reversed(sk, digbuf, dn);
					}
				}
				break;
			}
			case 'c': {
				/* With an l qualifier, %lc is converted as if by %ls
				 * on a two-element {wc, 0} array (fprintf.html) --
				 * written literally so %lc and %ls cannot disagree.
				 * Plain %c in a wide format goes through btowc()
				 * (fwprintf.html). */
				if (sp.lm == LM_l) {
					wchar_t wc[2];
					wc[0] = (wchar_t)a.i;
					wc[1] = 0;
					emit_str(sk, wc, 1, -1, flags, width);
				} else if (sk->wide) {
					wchar_t wc[2];
					wint_t b = btowc((int)a.i);
					/* btowc() answers WEOF for any byte that is not a
					 * complete character alone (0x80+ under this
					 * library's UTF-8); the conversion fails rather
					 * than inventing one (fwprintf.html's [EILSEQ],
					 * via fputwc()). */
					if (b == WEOF) {
						errno = EILSEQ;
						sk->f->err = 1;
						sk->bad = 1;
						break;
					}
					wc[0] = (wchar_t)b;
					wc[1] = 0;
					emit_str(sk, wc, 1, -1, flags, width);
				} else {
					char c = (char)a.i;
					int padn = width - 1; if (padn < 0) padn = 0;
					if (flags & 4) { out(sk, &c, 1); pad(sk, ' ', (size_t)padn); }
					else { pad(sk, ' ', (size_t)padn); out(sk, &c, 1); }
				}
				break;
			}
			case 's': {
				const void *arg = a.p;
				int wide_arg = sp.lm == LM_l;
				/* A null argument is undefined; printing "(null)"
				 * instead of dereferencing it matches glibc. */
				if (!arg) {
					static const wchar_t wnull[7] = { '(', 'n', 'u', 'l', 'l', ')', 0 };
					arg = wide_arg ? (const void *)wnull : (const void *)"(null)";
				}
				emit_str(sk, arg, wide_arg, prec, flags, width);
				break;
			}
			case 'p': {
				void *ptr = a.p;
				uintptr_t uv = (uintptr_t)ptr;
				int dn = 2;   /* the "0x" prefix, emitted literally below */
				if (!ptr) { out(sk, "(nil)", 5); break; }
				{
					char rev[sizeof(uintptr_t) * 2]; int rn = 0;
					do { rev[rn++] = "0123456789abcdef"[uv % 16]; uv /= 16; } while (uv);
					{
						int padn = width - (dn + rn); if (padn < 0) padn = 0;
						if (flags & 4) {
							out(sk, "0x", 2);
							out_reversed(sk, rev, rn);
							pad(sk, ' ', (size_t)padn);
						} else {
							pad(sk, ' ', (size_t)padn);
							out(sk, "0x", 2);
							out_reversed(sk, rev, rn);
						}
					}
				}
				break;
			}
			case 'n': {
				void *ptr = a.p;
				switch (sp.lm) {
				case LM_hh: *(signed char *)ptr = (signed char)sk->count; break;
				case LM_h: *(short *)ptr = (short)sk->count; break;
				case LM_l: *(long *)ptr = (long)sk->count; break;
				case LM_ll: case LM_j: *(long long *)ptr = (long long)sk->count; break;
				case LM_z: *(size_t *)ptr = (size_t)sk->count; break;
				case LM_t: *(ptrdiff_t *)ptr = (ptrdiff_t)sk->count; break;
				default: *(int *)ptr = (int)sk->count; break;
				}
				break;
			}
			case 'f': case 'F': case 'e': case 'E': case 'g': case 'G':
			case 'a': case 'A': {
				emit_float(sk, a.d, sp.conv, prec, flags & 16, flags, width);
				break;
			}
			default:
				/* an unknown conversion: emit '%' and the conversion
				 * character literally (as glibc does), without any
				 * "n$" that came between them */
				if (sp.conv) {
					out(sk, "%", 1);
					if (st == 1) out(sk, fp, 1);
					else out_units(sk, (const wchar_t *)fp, 1);
				}
				break;
			}
			if (sp.conv) fp += st;
		}
	}
	va_end(aq);
	return sk->bad ? -1 : (int)sk->count;
}

int __vfprintf(FILE *f, const char *fmt, va_list ap)
{
	return vfprintf_st(f, fmt, ap, 1);
}

/* sprintf/snprintf/vsprintf/vsnprintf share this: a throwaway FILE that
 * is a fixed (or, for plain sprintf, unbounded) memory buffer. */
/* s is deliberately not marked nonnull: vasprintf() below calls this
 * with s == 0, cap == 0 to measure a format's length without writing,
 * per snprintf's own "s may be null when n is zero" convention
 * (fprintf.html). */
static int vxprintf_mem(char *s, size_t cap, const char *fmt, va_list ap) __attribute__((nonnull(3)));
static int vxprintf_mem(char *s, size_t cap, const char *fmt, va_list ap)
{
	FILE mf; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- implementation-owned transient memory-stream adapter is constructed from scratch, not copied
	int r;
	memset(&mf, 0, sizeof mf);
	mf.fd = -1;
	mf.pid = -1;
	mf.is_mem = 1;
	mf.writable = 1;
	mf.bufmode = _IONBF;   /* every write must land in mem_buf right away: nothing ever flushes this FILE */
	mf.mem_buf = (unsigned char *)s;
	mf.mem_size = cap;
	r = __vfprintf(&mf, fmt, ap);
	/* __fwrite staged a byte via __ensure_buf; this local FILE never
	 * sees fclose, so freeing it is ours to do (same rule as
	 * vsscanf_impl in scanf.c). */
	free(mf.buf);
	if (cap) {
		size_t pos = mf.mem_len;
		if (pos >= cap) pos = cap - 1;
		s[pos] = 0;
	}
	return r;
}

int vsprintf(char *__restrict s, const char *__restrict fmt, __isoc_va_list ap)
{
	return vxprintf_mem(s, (size_t)-1, fmt, ap);
}
/* fprintf.html: snprintf() shall fail with [EOVERFLOW] if n > {INT_MAX},
 * refused up front (s untouched) since the return type is int but the
 * value promised is the would-have-been length, which need not be
 * representable past {INT_MAX}.  Checked here (not in vxprintf_mem())
 * since only these two entry points take an n from the caller;
 * vsprintf()'s (size_t)-1 sentinel and vasprintf()'s computed length
 * are not caller-supplied.  swprintf() has a different [EOVERFLOW] (see
 * vswprintf_impl below): it returns what it actually wrote, never a
 * would-have-been length, so it needs no such ceiling. */
int vsnprintf(char *__restrict s, size_t n, const char *__restrict fmt, __isoc_va_list ap)
{
	if (n > (size_t)INT_MAX) { errno = EOVERFLOW; return -1; }
	return vxprintf_mem(s, n, fmt, ap);
}
int vfprintf(FILE *__restrict f, const char *__restrict fmt, __isoc_va_list ap)
{
	return __vfprintf(f, fmt, ap);
}
int vprintf(const char *__restrict fmt, __isoc_va_list ap)
{
	return __vfprintf(stdout, fmt, ap);
}

int sprintf(char *__restrict s, const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vsprintf(s, fmt, ap);
	va_end(ap);
	return r;
}
int snprintf(char *__restrict s, size_t n, const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return r;
}
int printf(const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfprintf(stdout, fmt, ap);
	va_end(ap);
	return r;
}
int fprintf(FILE *__restrict f, const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfprintf(f, fmt, ap);
	va_end(ap);
	return r;
}

int vdprintf(int fd, const char *__restrict fmt, __isoc_va_list ap)
{
	/* No FILE exists for fd; wrap it in one for the call without
	 * touching the descriptor table. */
	FILE f; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- implementation-owned transient descriptor-stream adapter is constructed from scratch, not copied
	int r;
	memset(&f, 0, sizeof f);
	f.fd = fd;
	f.pid = -1;
	f.writable = 1;
	f.bufmode = _IONBF;
	r = __vfprintf(&f, fmt, ap);
	if (fflush(&f) < 0) r = -1;
	/* fflush() only drains the buffer __ensure_buf() allocated; it never
	 * releases it, and this stack FILE never reaches fclose(), so
	 * freeing it here is ours to do (ASan-caught leak otherwise). */
	if (f.buf && !f.user_buf) free(f.buf);
	return r;
}
int dprintf(int fd, const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vdprintf(fd, fmt, ap);
	va_end(ap);
	return r;
}

int vasprintf(char **s, const char *fmt, __isoc_va_list ap)
{
	va_list ap2;
	int n;
	va_copy(ap2, ap);
	n = vxprintf_mem(0, 0, fmt, ap2);
	va_end(ap2);
	{
		size_t bytes;
		if (n < 0 || !__size_add_checked((size_t)n, 1, &bytes)) { *s = 0; return -1; }
		*s = malloc(bytes);
		if (!*s) return -1;
		return vxprintf_mem(*s, bytes, fmt, ap);
	}
}
int asprintf(char **s, const char *fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vasprintf(s, fmt, ap);
	va_end(ap);
	return r;
}

/* ------------------------------------------------------------------
 * THE WIDE FAMILY: fwprintf.html.  Same formatter, stride
 * sizeof(wchar_t), sink counting wide characters instead of bytes.
 * ------------------------------------------------------------------ */
int __vfwprintf(FILE *f, const wchar_t *fmt, va_list ap)
{
	if (!f->wide) f->wide = 1;
	return vfprintf_st(f, (const char *)fmt, ap, (int)sizeof(wchar_t));
}

/* swprintf() is NOT snprintf() with a different unit: unlike snprintf,
 * which reports truncation via a would-have-been length (return >= n),
 * swprintf() has no such length -- it returns -1/[EOVERFLOW] once n or
 * more wide characters were requested.  So this does not reuse
 * vxprintf_mem(): the buffer is a wmem memory FILE, and the logical
 * count is compared against n afterwards.  One wide character is
 * reserved for the terminating null, hence the `>= n` test. */
/* s has no "just measure" null convention here: n == 0 is a real error
 * (there is no would-have-been length for it to report). */
static int vswprintf_impl(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap)
    __attribute__((nonnull(1, 3)));
static int vswprintf_impl(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap)
{
	FILE mf; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- implementation-owned transient wide memory-stream adapter is constructed from scratch, not copied
	int r;

	if (!n) { errno = EOVERFLOW; return -1; }
	memset(&mf, 0, sizeof mf);
	mf.fd = -1;
	mf.pid = -1;
	mf.is_mem = 1;
	mf.wmem = 1;
	mf.wide = 1;
	mf.writable = 1;
	mf.bufmode = _IONBF;
	mf.mem_buf = (unsigned char *)s;
	/* One unit short of the caller's array: the hidden unit is where the
	 * terminating null goes, so an overrun is a detectable short write. */
	mf.mem_size = (n - 1) * sizeof(wchar_t);
	r = vfprintf_st(&mf, (const char *)fmt, ap, (int)sizeof(wchar_t));
	s[mf.mem_len / sizeof(wchar_t)] = 0;
	/* Same buffer ownership as vxprintf_mem(). */
	free(mf.buf);
	if (r < 0) return r;
	if ((size_t)r >= n) { errno = EOVERFLOW; return -1; }
	return r;
}

int vswprintf(wchar_t *__restrict s, size_t n, const wchar_t *__restrict fmt, __isoc_va_list ap)
{
	return vswprintf_impl(s, n, fmt, ap);
}
int vfwprintf(FILE *__restrict f, const wchar_t *__restrict fmt, __isoc_va_list ap)
{
	return __vfwprintf(f, fmt, ap);
}
int vwprintf(const wchar_t *__restrict fmt, __isoc_va_list ap)
{
	return __vfwprintf(stdout, fmt, ap);
}

int swprintf(wchar_t *__restrict s, size_t n, const wchar_t *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vswprintf_impl(s, n, fmt, ap);
	va_end(ap);
	return r;
}
int fwprintf(FILE *__restrict f, const wchar_t *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfwprintf(f, fmt, ap);
	va_end(ap);
	return r;
}
int wprintf(const wchar_t *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfwprintf(stdout, fmt, ap);
	va_end(ap);
	return r;
}

// NOLINTEND(misc-include-cleaner)
