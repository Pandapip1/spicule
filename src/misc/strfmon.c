/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * strfmon(), strfmon_l() -- strfmon.html.
 *
 * "The strfmon() function shall place characters into the array pointed
 * to by s as controlled by the string pointed to by format. No more
 * than maxsize bytes are placed into the array."
 *
 * RETURN VALUE: "If the total number of resulting bytes including the
 * terminating null byte is not more than maxsize, these functions shall
 * return the number of bytes placed into the array pointed to by s, not
 * including the terminating NUL character. Otherwise, -1 shall be
 * returned, the contents of the array are unspecified, and errno shall
 * be set to indicate the error."  ERRORS, the only one defined and a
 * *shall fail*: "[E2BIG] Conversion stopped due to lack of space in the
 * buffer."
 *
 * WHERE THE LOCALE SAYS NOTHING.  "The LC_MONETARY category of the
 * current locale affects the behavior of this function including the
 * monetary radix character ..., the grouping separator, the currency
 * symbols, and formats."  ntlibc has one locale, and the POSIX locale's
 * LC_MONETARY block is "not available" throughout (src/misc/locale.c's
 * __posix_lconv: every string empty, every char field {CHAR_MAX}).  A
 * formatter cannot format with nothing, so each fallback is listed here
 * rather than buried, because each is a place where this file decides
 * something POSIX left to the locale:
 *
 *   radix character   mon_decimal_point is ""; the LC_NUMERIC
 *                     decimal_point (".") is used instead.  Falling
 *                     back to the numeric radix is what the page's own
 *                     parenthesis ("which may be different from the
 *                     numeric radix character") presumes is the normal
 *                     case when they are not different.
 *   default .p        frac_digits (int_frac_digits for %i) is
 *                     {CHAR_MAX}, i.e. "not available", so the
 *                     locale-supplied default the page refers to does
 *                     not exist.  2 is used.
 *   negative sign     negative_sign is "".  A '-' is used.  This is the
 *                     one fallback that would be actively dangerous to
 *                     get wrong: honouring the empty string literally
 *                     would print -42 as "42", which is a plausible
 *                     wrong answer with no way for the caller to tell.
 *                     positive_sign IS honoured as empty, because an
 *                     empty positive sign is the ordinary case and
 *                     loses no information.
 *   symbol placement  p_cs_precedes/n_cs_precedes/p_sep_by_space/
 *                     n_sep_by_space/sign_posn are all {CHAR_MAX}.  The
 *                     symbol precedes the quantity with no separating
 *                     space and the sign leads the whole field.  The
 *                     currency symbol is "" in this locale, so this
 *                     choice is unobservable today; it is written down
 *                     because it stops being unobservable the moment a
 *                     second locale exists.
 *   grouping          mon_grouping is "", so no separators are
 *                     inserted.  The grouping code below is still
 *                     written and still runs; it just always decides
 *                     there is nothing to insert.
 *
 * The '(' flag is implemented as parentheses around the whole
 * quantity-and-symbol, per "If '(' is specified, negative amounts are
 * enclosed within parentheses.", and suppresses the sign string.
 *
 * Left precision also equalises the positive and negative sign forms,
 * as required by the alignment paragraph under the #n option.  This is
 * deliberately not applied to conversions without #n: the paragraph is
 * scoped to left precision, and ordinary %.0n must remain the unpadded
 * representation.
 *
 * "The behavior is undefined if the locale argument to strfmon_l() is
 * the special locale object LC_GLOBAL_LOCALE or is not a valid locale
 * object handle."  As in src/misc/langinfo.c, undefined is not
 * diagnosed: the handle is ignored, never dereferenced, and not
 * validated, because every handle this library can produce denotes the
 * same immutable C locale and a caller must not come to depend on a
 * check the standard does not require.
 *
 * A conversion specifier character other than 'i', 'n' or '%' is not
 * described by the page at all, so its behaviour is undefined.  This
 * returns -1 with errno EINVAL rather than guessing, on the principle
 * that a caller who can tell something went wrong is better served than
 * one handed a plausible string.
 */
#include <monetary.h>
#include <locale.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

/* The assembled quantity -- sign, symbol, grouped digits, radix,
 * fraction -- before field-width padding.  A double's %f expansion is
 * at most ~310 integer digits; the caps on left and right precision
 * below keep everything else bounded, and field-width padding is
 * emitted straight to the output rather than through here, so a huge
 * width costs nothing. */
#define FIELD_MAX 1024
#define PREC_MAX  256

struct out {
	char *p;
	size_t left;       /* bytes still writable, NUL already reserved */
	size_t written;
};

/* o/t both required: o->left is dereferenced unconditionally at
 * entry with no guard, and t flows into memcpy() unconditionally --
 * this tree's own established mem/str doctrine (242ed40) treats that
 * as a genuine use regardless of length. Every real call site passes
 * &o (a stack local, never NULL) and either fmt (proven live by the
 * `while (*fmt)` loop that reached it) or field (a stack array). */
static int put(struct out *o, const char *t, size_t l) __attribute__((nonnull(1, 2)));
static int put(struct out *o, const char *t, size_t l)
{
	if (l > o->left) return -1;
	memmove(o->p, t, l);
	o->p += l;
	o->left -= l;
	o->written += l;
	return 0;
}

/* o required, same as put() above. */
static int putc_n(struct out *o, char c, size_t n) __attribute__((nonnull(1)));
static int putc_n(struct out *o, char c, size_t n)
{
	size_t i;
	if (n > o->left) return -1;
	for (i = 0; i < n; i++) o->p[i] = c;
	o->p += n;
	o->left -= n;
	o->written += n;
	return 0;
}

/* Append to the field buffer, refusing to overflow it. f/fl/t all
 * required: *fl is dereferenced unconditionally at entry with no
 * guard, and f/t both flow into memcpy() unconditionally, same
 * doctrine as put() above. Every real call site passes field (a
 * stack array) and &fl (a stack local). */
static int fappend(char *restrict f, size_t *fl, const char *restrict t, size_t l)
    __attribute__((nonnull(1, 2, 3)));
static int fappend(char *restrict f, size_t *fl, const char *restrict t, size_t l)
{
	size_t i;
	if (l > FIELD_MAX - *fl) return -1;
	for (i = 0; i < l; i++) f[*fl + i] = t[i];
	*fl += l;
	return 0;
}

/* fmt required: dereferenced unconditionally at `while (*fmt)`, no
 * guard, and every real caller (strfmon()/strfmon_l() below) forwards
 * its own fmt unchecked. s is deliberately NOT marked: with maxsize
 * == 0 this returns E2BIG before ever touching s (`if (maxsize == 0)
 * ...; o.p = s;`), so a NULL s genuinely does not crash on that one
 * path -- an artifact of the E2BIG check rather than a documented
 * "s is optional" contract, but not something `nonnull` may
 * overstate either way. */
static ssize_t vstrfmon(char *s, size_t maxsize, const char *fmt, va_list ap)
    __attribute__((nonnull(3)));
static ssize_t vstrfmon(char *s, size_t maxsize, const char *fmt, va_list ap)
{
	struct lconv *lc = localeconv();
	struct out o;

	if (maxsize == 0) { errno = E2BIG; return -1; }
	o.p = s;
	o.left = maxsize - 1;   /* the terminating NUL is always owed */
	o.written = 0;

	while (*fmt) {
		char fill = ' ';
		int nogrp = 0, negpar = 0, nosym = 0, left = 0, intl;
		unsigned long fw = 0, lp = 0, rp;
		const char *sym, *sign, *radix, *thousep, *grouping;
		char num[512], field[FIELD_MAX];
		size_t fl = 0, ndigits, numlen, nlen, align_pad = 0;
		char *dot;
		double x;
		int n;

		if (*fmt != '%') {
			if (put(&o, fmt, 1) < 0) goto e2big;
			fmt++;
			continue;
		}
		fmt++;
		/* "Convert to a '%'; no argument is converted. The entire
		 * conversion specification shall be %%." */
		if (*fmt == '%') {
			if (put(&o, fmt, 1) < 0) goto e2big;
			fmt++;
			continue;
		}

		/* Flags.  "One or more of the following optional flags can
		 * be specified"; order is not fixed, so this loops. */
		for (;; fmt++) {
			if (*fmt == '=') {
				if (!fmt[1]) { errno = EINVAL; return -1; }
				fill = *++fmt;
				continue;
			}
			if (*fmt == '^') { nogrp = 1; continue; }
			/* "Only one of '+' or '(' may be specified ... If
			 * neither flag is specified, the '+' style is used." */
			if (*fmt == '(') { negpar = 1; continue; }
			if (*fmt == '+') { continue; }
			if (*fmt == '!') { nosym = 1; continue; }
			if (*fmt == '-') { left = 1; continue; }
			break;
		}

		/* Field width: "A decimal digit string w specifying a
		 * minimum field width in bytes ... The default is 0." */
		for (; *fmt >= '0' && *fmt <= '9'; fmt++) {
			if (fw > (unsigned long)-1 / 16) { errno = E2BIG; return -1; }
			fw = fw * 10 + (unsigned long)(*fmt - '0');
		}

		/* Left precision "#n", right precision ".p". */
		if (*fmt == '#') {
			for (fmt++; *fmt >= '0' && *fmt <= '9'; fmt++)
				lp = lp * 10 + (unsigned long)(*fmt - '0');
			if (lp > PREC_MAX) { errno = E2BIG; return -1; }
		}
		intl = 0;
		rp = (unsigned long)-1;
		if (*fmt == '.') {
			for (rp = 0, fmt++; *fmt >= '0' && *fmt <= '9'; fmt++)
				rp = rp * 10 + (unsigned long)(*fmt - '0');
		}

		if (*fmt == 'i') intl = 1;
		else if (*fmt != 'n') { errno = EINVAL; return -1; }
		fmt++;

		if (rp == (unsigned long)-1) {
			/* "If a right precision is not included, a default
			 * specified by the current locale is used." */
			int fd = intl ? lc->int_frac_digits : lc->frac_digits;
			rp = fd >= 0 && fd < CHAR_MAX ? (unsigned long)fd : 2;
		}
		if (rp > PREC_MAX) { errno = E2BIG; return -1; }

		sym = nosym ? "" : (intl ? lc->int_curr_symbol : lc->currency_symbol);
		radix = lc->mon_decimal_point;
		if (!*radix) radix = lc->decimal_point;
		thousep = lc->mon_thousands_sep;
		grouping = lc->mon_grouping;

		x = va_arg(ap, double);

		/* "The amount being formatted is rounded to the specified
		 * number of digits prior to formatting." -- which is what
		 * "%.*f" does, so the rounding rule is not reimplemented. */
		n = snprintf(num, sizeof num, "%.*f", (int)rp,
		             x < 0 ? -x : x);
		if (n < 0 || (size_t)n >= sizeof num) { errno = E2BIG; return -1; }
		numlen = (size_t)n;

		dot = memchr(num, '.', numlen);
		ndigits = dot ? (size_t)(dot - num) : numlen;

		/* "#n ... This option causes an amount to be formatted as
		 * if it has the number of digits specified by n. If more
		 * than n digit positions are required, this conversion
		 * specification is ignored." */
		if (lp && ndigits > lp) continue;

		/* Sign and the opening parenthesis.  Every path below
		 * assigns sign, including the negative_sign fallback the
		 * banner describes, so there is no initialiser here to go
		 * stale if a branch is ever added: a new branch that
		 * forgets to assign is a compile-time warning rather than
		 * a silently empty sign. */
		if (x < 0) {
			if (negpar) sign = "(";
			else sign = *lc->negative_sign ? lc->negative_sign : "-";
		} else {
			sign = lc->positive_sign;
			if (lp && negpar) align_pad = 2;
			else if (lp) {
				const char *negative = *lc->negative_sign ? lc->negative_sign : "-";
				if (strlen(negative) > strlen(sign))
					align_pad = strlen(negative) - strlen(sign);
			}
		}
		if (lp && x < 0 && !negpar && strlen(lc->positive_sign) > strlen(sign))
			align_pad = strlen(lc->positive_sign) - strlen(sign);
		if (align_pad) {
			if (align_pad > FIELD_MAX - fl) goto e2big;
			memset(field + fl, ' ', align_pad);
			fl += align_pad;
		}
		if (fappend(field, &fl, sign, strlen(sign)) < 0) goto e2big;
		if (fappend(field, &fl, sym, strlen(sym)) < 0) goto e2big;

		/* Left-precision fill.  "Digit positions in excess of those
		 * actually required are filled with the numeric fill
		 * character", and "Grouping separators are not applied to
		 * fill characters even if the fill character is a digit" --
		 * so the fill goes in before the grouped digits and is not
		 * itself grouped. */
		if (lp > ndigits) {
			size_t k = lp - ndigits;
			if (k > FIELD_MAX - fl) goto e2big;
			memset(field + fl, fill, k);
			fl += k;
		}

		/* Grouping.  mon_grouping is "" in this locale, so this
		 * loop always concludes there is nothing to insert; it is
		 * written out anyway so that a locale which does define
		 * grouping does not need this function rewritten. */
		if (nogrp || !*grouping || !*thousep) {
			if (fappend(field, &fl, num, ndigits) < 0) goto e2big;
		} else {
			size_t i = 0;
			const char *g = grouping;
			size_t run = (size_t)*g;
			size_t head = ndigits;

			/* Walk the group sizes from the least significant
			 * end to find where the first (most significant)
			 * group starts. */
			while (run != CHAR_MAX && head > run) {
				if (!run) break;
				head -= run;
				if (g[1]) { g++; run = (size_t)*g; }
			}
			if (fappend(field, &fl, num, head) < 0) goto e2big;
			i = head;
			g = grouping;
			run = (size_t)*g;
			while (i < ndigits) {
				size_t take = ndigits - i < run ? ndigits - i : run;
				if (fappend(field, &fl, thousep, strlen(thousep)) < 0)
					goto e2big;
				if (fappend(field, &fl, num + i, take) < 0) goto e2big;
				i += take;
				if (g[1]) { g++; run = (size_t)*g; }
			}
		}

		/* "If the value of the right precision p is 0, no radix
		 * character appears." */
		if (dot) {
			if (fappend(field, &fl, radix, strlen(radix)) < 0) goto e2big;
			if (fappend(field, &fl, dot + 1, numlen - ndigits - 1) < 0)
				goto e2big;
		}

		if (x < 0 && negpar)
			if (fappend(field, &fl, ")", 1) < 0) goto e2big;

		/* Field width.  "-" is "ignored unless a field width ... is
		 * specified", which falls out of only being consulted here. */
		nlen = fl;
		if (fw > nlen) {
			if (left) {
				if (put(&o, field, nlen) < 0) goto e2big;
				if (putc_n(&o, ' ', fw - nlen) < 0) goto e2big;
			} else {
				if (putc_n(&o, ' ', fw - nlen) < 0) goto e2big;
				if (put(&o, field, nlen) < 0) goto e2big;
			}
		} else {
			if (put(&o, field, nlen) < 0) goto e2big;
		}
	}

	*o.p = 0;
	return (ssize_t)o.written;

e2big:
	errno = E2BIG;
	return -1;
}

ssize_t strfmon(char *restrict s, size_t maxsize, const char *restrict fmt, ...)
{
	va_list ap;
	ssize_t r;

	va_start(ap, fmt);
	r = vstrfmon(s, maxsize, fmt, ap);
	va_end(ap);
	return r;
}

ssize_t strfmon_l(char *restrict s, size_t maxsize, locale_t locale,
                  const char *restrict fmt, ...)
{
	va_list ap;
	ssize_t r;

	(void)locale;
	va_start(ap, fmt);
	r = vstrfmon(s, maxsize, fmt, ap);
	va_end(ap);
	return r;
}
