/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A strptime covering the same specifiers strftime writes (%Y %y %C %m
 * %d %H %M %S %e %j %U %W %a %A %b %B %p %z %% plus %n/%t as
 * whitespace), plus the composite conversions %c %D %F %r %R %T %x %X,
 * which are handled by expanding them to the equivalent simple format
 * (matching what strftime writes for them in the C locale) and
 * recursing.  Unrecognized conversions and the locale %E/%O modifiers
 * are not implemented.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "time_impl.h"

/* s is required: the while condition dereferences *s unconditionally
 * (even for a zero-length skip) as the very first thing this function
 * does, with no NULL check, and every real call site in this file
 * already holds a live cursor into the string being parsed. */
static const char *skip_ws(const char *s) __attribute__((nonnull(1)));
static const char *skip_ws(const char *s)
{
	while (isspace((unsigned char)*s)) s++;
	return s;
}

/* Parse up to maxdigits decimal digits (after optional leading blanks),
 * the way strptime's numeric conversions do.
 *
 * s is required: after skip_ws(s) returns, this function dereferences
 * *s directly (`if (*s == '+' ...)`) with no NULL check. out is required
 * too: `*out = neg ? -v : v;` is unconditional on the only path that
 * returns non-NULL, and every one of this file's own call sites passes
 * `&v`, a real on-stack local, never NULL.
 *
 * The same `*s` (the line right after `s = skip_ws(s);`) is now itself
 * flagged: the same "no returns_nonnull-shaped contract this checker
 * reads yet" gap parse()'s own comment documents -- skip_ws() never
 * returns NULL, verified by inspection of its own single-statement
 * body, not just assumed. */
static const char *read_num(const char *s, int maxdigits, long *out)
    __attribute__((nonnull(1, 3)));
static const char *read_num(const char *s, int maxdigits, long *out)
{
	int n = 0;
	long v = 0;
	int neg = 0;
	s = skip_ws(s);
	if (*s == '+' || *s == '-') { neg = (*s == '-'); s++; }
	if (!isdigit((unsigned char)*s)) return NULL;
	while (n < maxdigits) {
		if (!isdigit((unsigned char)*s)) break;
		v = v * 10 + (*s++ - '0');
		n++;
	}
	*out = neg ? -v : v;
	return s;
}

/* Match a name (case-insensitively) against one of the tables, longest
 * candidate first isn't necessary since none is a prefix of another
 * within the same table, but abbreviations ARE prefixes of the full
 * names, so try full names before abbreviations. */
/* full/abbr/full_len/idx are required; s is deliberately NOT marked. The
 * three tables are indexed as soon as their respective loops run (n is
 * always 7 or 12 at this file's two real call sites, never 0), and idx is
 * written (`*idx = i;`) on every match. None is ever NULL at either call
 * site (__ntlibc_day_name/_abbr, __ntlibc_month_name/_abbr, the matching
 * literal-derived length table, and parse()'s on-stack `idx`). s is only
 * forwarded into strncasecmp() -- never dereferenced directly by this
 * function's own body -- so it is left unmarked, the same "purely
 * forwarded, the real callee already owns the contract" reasoning as
 * time.h's own ctime_r()/clock_gettime() comments. */
static const char *match_name(const char *s, const char *const *full,
    const char *const *abbr, const unsigned char *full_len, int n, int *idx)
    __attribute__((nonnull(2, 3, 4, 6)));
static const char *match_name(const char *s, const char *const *full,
    const char *const *abbr, const unsigned char *full_len, int n,
    int *idx) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	for (int i = 0; i < n; i++) {
		size_t len = full_len[i];
		if (!strncasecmp(s, full[i], len)) { *idx = i; return s + len; }
	}
	for (int i = 0; i < n; i++) {
		size_t len = 3;
		if (!strncasecmp(s, abbr[i], len)) { *idx = i; return s + len; }
	}
	return NULL;
}

/* pm: -1: no %p seen; 0: AM; 1: PM.  century: -1: no %C seen, else the
 * century value %C parsed (e.g. 19 for the 1900s).  Both are shared
 * across recursive calls so that %r's %p applies to its %I and %C
 * combines correctly with a %y anywhere else in the same format. */
/* Every pointer parameter here is required, and every one of them is
 * genuinely dereferenced somewhere in this function's own body (the
 * checker's own report names only *f, the loop condition -- the same
 * one-finding-per-function masking prior sweeps have already documented
 * -- but each of the rest is exactly as real, verified by hand): f is
 * dereferenced unconditionally by the loop condition itself; s directly
 * (`if (*s != *f) return NULL;`) whenever the current format character
 * is a literal; tm on every recognized conversion (`tm->tm_year = ...`
 * and friends); pm/century/year2 on their own conversions (%p/%C/%y).
 * strptime() (this file's only real, non-recursive caller) always passes
 * `&pm`/`&century`/`&year2`, on-stack locals it owns; the recursive
 * self-call for %c/%D/%F/%r/%R/%T/%x/%X forwards the same pointers
 * unchanged, never re-deriving a possibly-null one.
 *
 * Marking s here lets the checker explore further into this loop than
 * before, surfacing several more `*s` sites (the literal-character
 * comparison, `%z`'s post-skip_ws()/read_num() checks, `%Z`'s scan, and
 * `%%`) that a fresh dataflow pass cannot re-derive as nonnull across a
 * reassignment from skip_ws()/read_num()/match_name()'s own return
 * value -- none of the three carries a `returns_nonnull`-shaped
 * contract this checker currently reads, even though all three are, by
 * inspection, incapable of returning NULL on any path this loop
 * actually takes (skip_ws() never returns NULL at all; read_num()/
 * match_name()'s NULL returns are always caught by this loop's own
 * `s = ...; if (!s) return NULL;` before `s` is used again). Sound by
 * hand at every one of these sites; closing the class properly would
 * mean teaching the checker to trust `returns_nonnull`-shaped
 * functions, a real but separate lemma this pass did not attempt. */
// NOLINTNEXTLINE(misc-no-recursion) -- composite directives recurse into fixed subformats with bounded expansion depth
static const char *parse(const char *s, const char *f, struct tm *tm,
	int *pm, int *century, int *year2) __attribute__((nonnull(1, 2, 3, 4, 5, 6)));
// NOLINTNEXTLINE(misc-no-recursion) -- composite directives recurse into fixed subformats with bounded expansion depth
static const char *parse(const char *s, const char *f, struct tm *tm,
	int *pm, int *century, int *year2)
{
	long v;
	int idx;
	const char *sub;

	for (; *f; f++) {
		if (*f != '%') {
			if (isspace((unsigned char)*f)) { s = skip_ws(s); continue; }
			if (*s != *f) return NULL;
			s++;
			continue;
		}
		f++;
		if (!*f) return NULL;
		switch (*f) {
		case 'c': sub = "%a %b %e %H:%M:%S %Y"; goto expand;
		case 'D': case 'x': sub = "%m/%d/%y"; goto expand;
		case 'F': sub = "%Y-%m-%d"; goto expand;
		case 'r': sub = "%I:%M:%S %p"; goto expand;
		case 'R': sub = "%H:%M"; goto expand;
		case 'T': case 'X': sub = "%H:%M:%S"; goto expand;
		expand:
			s = parse(s, sub, tm, pm, century, year2);
			if (!s) return NULL;
			break;
		/* Widths follow musl/glibc: %Y 4, %j 3, %u/%w 1, everything else 2,
		 * so an unseparated "%Y%m%d" doesn't let %Y swallow later fields. */
		case 'Y':
			s = read_num(s, 4, &v);
			if (!s) return NULL;
			tm->tm_year = (int)(v - 1900);
			break;
		case 'y':
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			*year2 = (int)v;
			if (*century >= 0) {
				/* %C already ran (in either order relative to %y): the
				 * century it set wins, %y only supplies the low two
				 * digits. */
				tm->tm_year = (int)((long)*century * 100 + v - 1900);
			} else {
				/* No %C in this format: fall back to the traditional
				 * "%y-alone" pivot -- 69..99 is 1969..1999, 00..68 is
				 * 2000..2068. */
				tm->tm_year = (int)(v < 69 ? v + 100 : v);
			}
			break;
		case 'C':
			/* "All but the last two digits of the year" -- combines with a
			 * %y elsewhere in the format to form the full year; on its own
			 * it sets the century with the low two digits defaulting to 0. */
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			*century = (int)v;
			tm->tm_year = (int)(v * 100 + (*year2 >= 0 ? *year2 : 0) - 1900);
			break;
		case 's': {
			char *end;
			time_t t = (time_t)strtoll(skip_ws(s), &end, 10);
			if (end == skip_ws(s) || !localtime_r(&t, tm)) return NULL;
			s = end;
			break;
		}
		case 'U': case 'W':
			/* Week number (00..53); consumed like any other numeric
			 * field but not fed back into tm -- struct tm has no
			 * week-number member, and mktime/gmtime never look at one,
			 * so (as in glibc/musl) it's parsed and discarded. */
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			break;
		case 'm':
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			tm->tm_mon = (int)v - 1;
			break;
		case 'd': case 'e':
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			tm->tm_mday = (int)v;
			break;
		case 'H': case 'I':
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			tm->tm_hour = (int)v;
			break;
		case 'M':
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			tm->tm_min = (int)v;
			break;
		case 'S':
			s = read_num(s, 2, &v);
			if (!s) return NULL;
			tm->tm_sec = (int)v;
			break;
		case 'j':
			s = read_num(s, 3, &v);
			if (!s) return NULL;
			tm->tm_yday = (int)v - 1;
			break;
		case 'u':
			s = read_num(s, 1, &v);
			if (!s) return NULL;
			tm->tm_wday = (int)(v == 7 ? 0 : v);
			break;
		case 'w':
			s = read_num(s, 1, &v);
			if (!s) return NULL;
			tm->tm_wday = (int)v;
			break;
		case 'a': case 'A': {
			static const unsigned char lengths[7] = {
				sizeof "Sunday" - 1, sizeof "Monday" - 1,
				sizeof "Tuesday" - 1, sizeof "Wednesday" - 1,
				sizeof "Thursday" - 1, sizeof "Friday" - 1,
				sizeof "Saturday" - 1
			};
			s = match_name(s, __ntlibc_day_name, __ntlibc_day_name_abbr,
			               lengths, 7, &idx);
			if (!s) return NULL;
			tm->tm_wday = idx;
			break;
		}
		case 'b': case 'B': case 'h': {
			static const unsigned char lengths[12] = {
				sizeof "January" - 1, sizeof "February" - 1,
				sizeof "March" - 1, sizeof "April" - 1,
				sizeof "May" - 1, sizeof "June" - 1,
				sizeof "July" - 1, sizeof "August" - 1,
				sizeof "September" - 1, sizeof "October" - 1,
				sizeof "November" - 1, sizeof "December" - 1
			};
			s = match_name(s, __ntlibc_month_name, __ntlibc_month_name_abbr,
			               lengths, 12, &idx);
			if (!s) return NULL;
			tm->tm_mon = idx;
			break;
		}
		case 'p':
			if (!strncasecmp(s, "AM", 2)) { *pm = 0; s += 2; }
			else if (!strncasecmp(s, "PM", 2)) { *pm = 1; s += 2; }
			else return NULL;
			break;
		case 'z':
			s = skip_ws(s);
			if (*s == 'Z') { tm->__tm_gmtoff = 0; s++; }
			else if (*s == '+' || *s == '-') {
				int sign = *s == '-' ? -1 : 1;
				long h, mn = 0;
				s++;
				s = read_num(s, 2, &h);
				if (!s) return NULL;
				if (*s == ':') s++;
				if (isdigit((unsigned char)*s)) {
					s = read_num(s, 2, &mn);
					if (!s) return NULL;
				}
				tm->__tm_gmtoff = sign * (h * 3600 + mn * 60);
			} else return NULL;
			break;
		case 'Z':
			while (isalpha((unsigned char)*s)) s++;
			break;
		case 'n': case 't':
			s = skip_ws(s);
			break;
		case '%':
			if (*s != '%') return NULL;
			s++;
			break;
		default:
			return NULL;
		}
	}
	return s;
}

char *strptime(const char *restrict s, const char *restrict f, struct tm *restrict tm)
{
	int pm = -1;
	int century = -1;
	int year2 = -1;

	s = parse(s, f, tm, &pm, &century, &year2);
	if (!s) return NULL;
	if (pm == 1 && tm->tm_hour < 12) tm->tm_hour += 12;
	else if (pm == 0 && tm->tm_hour == 12) tm->tm_hour = 0;
	return (char *)s;
}

// NOLINTEND(misc-include-cleaner)
