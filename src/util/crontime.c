/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See src/util/crontime.h for the grammar this implements and why.
 */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include "crontime.h"

/* Matches `text` (of length `len`) case-insensitively against one of
 * the three-letter `names`, returning lo+index on a match or -1. */
static int match_name(const char *text, size_t len, int lo, int hi, const char *const *names)
{
	int i;

	if (!names || len != 3) return -1;
	for (i = lo; i <= hi; i++) {
		const char *n = names[i - lo];
		if (tolower((unsigned char)text[0]) == n[0] &&
		    tolower((unsigned char)text[1]) == n[1] &&
		    tolower((unsigned char)text[2]) == n[2])
			return i;
	}
	return -1;
}

/* Parses one number-or-name at `*pp`, advancing `*pp` past it. `dow7`
 * is nonzero only for the day-of-week field, where a literal 7 is
 * allowed and later folded to 0. Returns the value or -1 on a
 * malformed token. */
static int parse_one(const char **pp, int lo, int hi, const char *const *names, int dow7)
{
	const char *p = *pp;
	const char *start = p;
	long v;
	char *end;

	if (isalpha((unsigned char)*p)) {
		while (isalpha((unsigned char)*p)) p++;
		v = match_name(start, (size_t)(p - start), lo, hi, names);
		if (v < 0) return -1;
		*pp = p;
		return (int)v;
	}
	if (!isdigit((unsigned char)*p)) return -1;
	v = strtol(p, &end, 10);
	if (end == p) return -1;
	*pp = end;
	/* 7 stays 7 here, not folded to 0 yet: the caller checks a-b is
	 * ascending on these raw values, and "5-7" must not look like "5-0"
	 * (which would reject Fri-Sun ranges as wrapping). Folded to 0 only
	 * once the range is set, in __crontime_parse_field(). */
	if (v < lo || v > (dow7 ? 7 : hi)) return -1;
	return (int)v;
}

int __crontime_parse_field(const char *text, int lo, int hi,
	const char *const *names, unsigned char *out)
{
	const char *p = text;
	int dow7 = (lo == 0 && hi == 6);

	/* Every caller-supplied `out` array is sized to cover index 0
	 * through hi inclusive (struct crontime's own minute[60]/hour[24]/
	 * dom[32]/month[13]/dow[7] -- dom/month simply leave index 0
	 * unused), so zeroing [0,hi] is always safe and always enough. */
	memset(out, 0, (size_t)(hi + 1) * sizeof out[0]);

	if (!*p) return -1;

	for (;;) {
		int a, b, step = 1;

		if (*p == '*') {
			a = lo;
			b = hi;
			p++;
		} else {
			a = parse_one(&p, lo, hi, names, dow7);
			if (a < 0) return -1;
			if (*p == '-') {
				p++;
				b = parse_one(&p, lo, hi, names, dow7);
				if (b < 0) return -1;
			} else {
				b = a;
			}
		}
		if (*p == '/') {
			long s;
			char *end;
			p++;
			if (!isdigit((unsigned char)*p)) return -1;
			errno = 0;
			s = strtol(p, &end, 10);
			/* s becomes the loop stride below (cast to int). An
			 * unchecked strtol() overflow (e.g.
			 * "0-59/99999999999999999999") truncates to a small or
			 * negative int on cast, walking out[] off the end of
			 * struct crontime until it segfaults. Rejecting anything
			 * past INT_MAX costs nothing real -- no field has more
			 * than 60 values. */
			if (end == p || errno == ERANGE || s <= 0 || s > INT_MAX) return -1;
			p = end;
			step = (int)s;
		}
		if (b < a) return -1; /* crontab(5) ranges never wrap */
		{
			/* step can be up to INT_MAX while b is at most 59, so
			 * `v += step` could overflow int. Check "does the next v
			 * pass b" before adding, rather than compute v+step and
			 * compare, so the overflow never happens. */
			int v = a;
			for (;;) {
				/* Fold a raw 7 to 0 only here, once the range itself
				 * (checked against the unfolded a/b above) is known
				 * good -- see parse_one()'s own comment. */
				out[dow7 && v == 7 ? 0 : v] = 1;
				if (v > b - step) break;
				v += step;
			}
		}
		if (*p == ',') { p++; continue; }
		break;
	}
	return *p ? -1 : 0;
}

static const char *const month_names[12] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec"
};
static const char *const dow_names[7] = {
	"sun", "mon", "tue", "wed", "thu", "fri", "sat"
};

int __crontime_parse(const char *min, const char *hour, const char *dom,
	const char *mon, const char *dow, struct crontime *out)
{
	if (__crontime_parse_field(min, 0, 59, 0, out->minute) < 0) return -1;
	if (__crontime_parse_field(hour, 0, 23, 0, out->hour) < 0) return -1;
	if (__crontime_parse_field(dom, 1, 31, 0, out->dom) < 0) return -1;
	if (__crontime_parse_field(mon, 1, 12, month_names, out->month) < 0) return -1;
	if (__crontime_parse_field(dow, 0, 6, dow_names, out->dow) < 0) return -1;
	out->dom_is_star = (dom[0] == '*' && dom[1] == 0);
	return 0;
}

int __crontime_matches(const struct crontime *e, const struct tm *t)
{
	int mon1 = t->tm_mon + 1;

	if (!e->minute[t->tm_min] || !e->hour[t->tm_hour] || !e->month[mon1])
		return 0;
	/* crontab(1p): day-of-month and day-of-week are AND'd normally,
	 * but OR'd when day-of-month was literally "*" and day-of-week
	 * is a real restriction -- see struct crontime's own comment. */
	if (e->dom_is_star) return e->dow[t->tm_wday];
	return e->dom[t->tm_mday] && e->dow[t->tm_wday];
}
