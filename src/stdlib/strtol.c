/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* Integer conversions, C99 7.20.1.4.  One worker parses an unsigned
 * magnitude clamped to a limit; the typed wrappers apply the sign and
 * their own ranges.  long is 32 bits on both Windows arches. */
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <features.h>

/* Parse into *out.  Returns 1 on overflow (out = UINTMAX_MAX), 0 else.
 * *neg is set from the sign.  *end is the first unparsed character, or
 * nptr when nothing numeric was found. */
/* nptr/end/neg/out are all required. nptr is dereferenced unconditionally
 * (`while (isspace((unsigned char)*s)) s++;`, s == nptr at entry) as this
 * function's first real operation -- the checker's own report names this
 * one. neg is written (`*neg = 0;`) even before that, unconditionally.
 * end/out are both written on EVERY return path: the invalid-base early
 * return (`*end = nptr; *out = 0;`) and the normal completion (`*end =
 * any ? s : nptr; *out = ovf ? UINTMAX_MAX : v;`), with no NULL check on
 * either. This file's own single real caller (strtox()) always passes
 * `&end`/`&neg`/`&v`, on-stack locals, never NULL, and forwards its own
 * (required, see below) nptr unchanged. */
static int parse(const char *nptr, const char **end, int base, int *neg, uintmax_t *out)
    __attribute__((nonnull(1, 2, 4, 5)));
static int parse(const char *nptr, const char **end, int base, int *neg, uintmax_t *out)
{
	const char *s = nptr;
	uintmax_t v = 0, cutoff;
	int any = 0, ovf = 0, cutlim, d;
	unsigned char c;

	*neg = 0;
	while (isspace((unsigned char)*s)) s++;
	if (*s == '+') s++;
	else if (*s == '-') { *neg = 1; s++; }
	if (base == 0) {
		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && isxdigit((unsigned char)s[2])) { base = 16; s += 2; }
		else if (s[0] == '0') base = 8;
		else base = 10;
	} else if (base == 16) {
		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && isxdigit((unsigned char)s[2])) s += 2;
	}
	if (base < 2 || base > 36) { errno = EINVAL; *end = nptr; *out = 0; return 0; }
	cutoff = UINTMAX_MAX / (unsigned)base;
	cutlim = (int)(UINTMAX_MAX % (unsigned)base);
	for (; *s; s++) {
		c = (unsigned char)*s;
		if (c >= '0' && c <= '9') d = c - '0';
		else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
		else break;
		if (d >= base) break;
		any = 1;
		if (ovf) continue;
		if (v > cutoff || (v == cutoff && d > cutlim)) { ovf = 1; continue; }
		v = v * (unsigned)base + (unsigned)d;
	}
	*end = any ? s : nptr;
	*out = ovf ? UINTMAX_MAX : v;
	return ovf;
}

/* Every "0 - x" below is deliberate: C99 7.20.1.4p6 defines a negative
 * result as its two's-complement bit pattern in the unsigned return
 * type, which unary minus on an unsigned operand produces directly by
 * wrapping modulo 2**N (C99 6.2.5p9) -- including for x == 0 - (lim+1),
 * the one negative magnitude (e.g. LONG_MIN) a signed destination type
 * cannot represent positively. */
__wraps static uintmax_t strtox(const char *nptr, char **endptr, int base, uintmax_t lim) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *end;
	uintmax_t v;
	int neg, ovf;

	ovf = parse(nptr, &end, base, &neg, &v);
	if (endptr) *endptr = (char *)end;
	if (lim == UINTMAX_MAX || lim == (uintmax_t)ULONG_MAX) {
		/* unsigned: wrap negatives, clamp on overflow */
		if (ovf || v > lim) { errno = ERANGE; return lim; }
		return neg ? (0 - v) & lim : v;
	}
	/* signed: lim is the positive maximum */
	if (neg) {
		if (ovf || v > lim + 1) { errno = ERANGE; return 0 - (lim + 1); }
		return 0 - v;
	}
	if (ovf || v > lim) { errno = ERANGE; return lim; }
	return v;
}

long strtol(const char *__restrict s, char **__restrict e, int b)
{ return (long)(intmax_t)strtox(s, e, b, LONG_MAX); }
unsigned long strtoul(const char *__restrict s, char **__restrict e, int b)
{ return (unsigned long)strtox(s, e, b, ULONG_MAX); }
long long strtoll(const char *__restrict s, char **__restrict e, int b)
{ return (long long)strtox(s, e, b, LLONG_MAX); }
unsigned long long strtoull(const char *__restrict s, char **__restrict e, int b)
{ return (unsigned long long)strtox(s, e, b, ULLONG_MAX); }
intmax_t strtoimax(const char *__restrict s, char **__restrict e, int b)
{ return (intmax_t)strtox(s, e, b, INTMAX_MAX); }
uintmax_t strtoumax(const char *__restrict s, char **__restrict e, int b)
{ return strtox(s, e, b, UINTMAX_MAX); }

// NOLINTEND(misc-include-cleaner)
