/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The wide integer conversion family: wcstol()/wcstoll()/wcstoul()/
 * wcstoull() (https://pubs.opengroup.org/onlinepubs/9699919799/functions/wcstol.html
 * and wcstoul.html) and wcstoimax()/wcstoumax() (C99 7.24.4.1.2, and
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/wcstoimax.html),
 * all six over one shared parser -- the wchar_t mirror of
 * src/stdlib/strtol.c, whose parse()/strtox() split and whose typed
 * wrappers this file reproduces one for one.
 *
 * HISTORY, because the previous version of this comment now reads as a
 * decision that no longer holds: this file used to be wcstoimax.c and
 * defined only wcstoimax()/wcstoumax().  It justified keeping its own
 * parser rather than generalising strtol.c's with "there is no other
 * wide integer conversion function to share it with (no wcstol()/
 * wcstoul() is declared in wchar.h)".  That premise was removed the
 * moment wcstol() and friends were declared, so the file was renamed
 * after its primary POSIX page and the four wrappers added here rather
 * than in a second file with a second copy of the same parser.  The
 * conclusion the old comment reached -- a parallel wide parser instead
 * of templating the byte one over two character types -- is unchanged
 * and still deliberate: strtol.c and this file are each about ninety
 * lines, and a shared template would have to be macro-expanded or
 * indirected through a character-fetch callback to serve both, which
 * costs more clarity than the duplication does.
 *
 * wchar_t on this target is an unsigned short UTF-16 code unit (each
 * arch's bits/alltypes.h.gen).  Every character this parser cares about
 * -- digits, '+'/'-', the ASCII letters used as base-36 digits, and the
 * C locale's whitespace set -- lives below U+0080, so comparing wchar_t
 * values directly against L'0'..L'9' needs no wctype.h machinery any
 * more than strtol.c needs <ctype.h> to do more than ASCII.  A
 * surrogate half can never compare equal to any of them, so UTF-16
 * text terminates the subject sequence exactly where it should.
 *
 * LLP64 note: long is 32 bits here and long long is 64, so wcstol() and
 * wcstoll() are genuinely different functions with different ranges --
 * unlike on LP64, where a bug conflating them would go unnoticed.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <inttypes.h>
#include <wchar.h>
#include <limits.h>
#include <errno.h>
#include <features.h>

static int isws(wchar_t c)
{
	return c == L' ' || c == L'\t' || c == L'\n' || c == L'\v' || c == L'\f' || c == L'\r';
}

/* Same contract as strtol.c's parse(): returns 1 on overflow (out =
 * UINTMAX_MAX), *neg from the sign, *end the first unparsed wchar_t (or
 * nptr if nothing numeric was found). */
/* Same shape and reasoning as strtol.c's parse(): nptr/end/neg/out are
 * all required. nptr is dereferenced unconditionally (`while (isws(*s))
 * s++;`, s == nptr at entry) as this function's first real operation --
 * the checker's own report names this one. neg is written (`*neg = 0;`)
 * even before that, unconditionally. end/out are both written on every
 * return path (the invalid-base early return and the normal
 * completion), with no NULL check on either. This file's own single
 * real caller (wcstox()) always passes `&end`/`&neg`/`&v`, on-stack
 * locals, never NULL. */
static int wparse(const wchar_t *nptr, const wchar_t **end, int base, int *neg, uintmax_t *out)
    __attribute__((nonnull(1, 2, 4, 5)));
static int wparse(const wchar_t *nptr, const wchar_t **end, int base, int *neg, uintmax_t *out)
{
	const wchar_t *s = nptr;
	uintmax_t v = 0, cutoff;
	int any = 0, ovf = 0, cutlim, d;
	wchar_t c;

	*neg = 0;
	while (isws(*s)) s++;
	if (*s == L'+') s++;
	else if (*s == L'-') { *neg = 1; s++; }
	if (base == 0) {
		if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')
		 && ((s[2] >= L'0' && s[2] <= L'9') || (s[2] >= L'a' && s[2] <= L'f') || (s[2] >= L'A' && s[2] <= L'F')))
			{ base = 16; s += 2; }
		else if (s[0] == L'0') base = 8;
		else base = 10;
	} else if (base == 16) {
		if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')
		 && ((s[2] >= L'0' && s[2] <= L'9') || (s[2] >= L'a' && s[2] <= L'f') || (s[2] >= L'A' && s[2] <= L'F')))
			s += 2;
	}
	if (base < 2 || base > 36) { errno = EINVAL; *end = nptr; *out = 0; return 0; }
	cutoff = UINTMAX_MAX / (unsigned)base;
	cutlim = (int)(UINTMAX_MAX % (unsigned)base);
	for (;; s++) {
		c = *s;
		if (c >= L'0' && c <= L'9') d = (int)(c - L'0');
		else if (c >= L'a' && c <= L'z') d = (int)(c - L'a' + 10);
		else if (c >= L'A' && c <= L'Z') d = (int)(c - L'A' + 10);
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

/* Same "0 - x" two's-complement reasoning as strtol.c's strtox(): see
 * the comment there for why it is deliberate and not a stray sign bug. */
__wraps static uintmax_t wcstox(const wchar_t *nptr, wchar_t **endptr, int base, uintmax_t lim) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const wchar_t *end;
	uintmax_t v;
	int neg, ovf;

	ovf = wparse(nptr, &end, base, &neg, &v);
	if (endptr) *endptr = (wchar_t *)end;
	if (lim == UINTMAX_MAX || lim == (uintmax_t)ULONG_MAX) {
		/* unsigned destination: wrap negatives modulo 2**N, clamp on
		 * overflow.  Same two-value discriminator strtol.c's strtox()
		 * uses, and sound for the same reason: no signed limit
		 * (LONG_MAX, LLONG_MAX, INTMAX_MAX) can equal ULONG_MAX or
		 * UINTMAX_MAX, because a signed maximum always has its top bit
		 * clear.  ULLONG_MAX is UINTMAX_MAX here, so it is covered by
		 * the first arm. */
		if (ovf || v > lim) { errno = ERANGE; return lim; }
		return neg ? (0 - v) & lim : v;
	}
	if (neg) {
		if (ovf || v > lim + 1) { errno = ERANGE; return 0 - (lim + 1); }
		return 0 - v;
	}
	if (ovf || v > lim) { errno = ERANGE; return lim; }
	return v;
}

long wcstol(const wchar_t *__restrict s, wchar_t **__restrict e, int b)
{ return (long)(intmax_t)wcstox(s, e, b, LONG_MAX); }
unsigned long wcstoul(const wchar_t *__restrict s, wchar_t **__restrict e, int b)
{ return (unsigned long)wcstox(s, e, b, ULONG_MAX); }
long long wcstoll(const wchar_t *__restrict s, wchar_t **__restrict e, int b)
{ return (long long)wcstox(s, e, b, LLONG_MAX); }
unsigned long long wcstoull(const wchar_t *__restrict s, wchar_t **__restrict e, int b)
{ return (unsigned long long)wcstox(s, e, b, ULLONG_MAX); }

intmax_t wcstoimax(const wchar_t *__restrict s, wchar_t **__restrict e, int b)
{ return (intmax_t)wcstox(s, e, b, INTMAX_MAX); }
uintmax_t wcstoumax(const wchar_t *__restrict s, wchar_t **__restrict e, int b)
{ return wcstox(s, e, b, UINTMAX_MAX); }

// NOLINTEND(misc-include-cleaner)
