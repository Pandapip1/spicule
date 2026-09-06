/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See src/util/attime.h for the grammar this implements and why.
 */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>
#include "attime.h"

enum period { P_MINUTE, P_HOUR, P_DAY, P_WEEK, P_MONTH, P_YEAR };

static int word_is(const char *w, const char *lit)
{
	return strcasecmp(w, lit) == 0;
}

/* "minute"/"minutes"/"hour"/"hours"/.../"years" -- both singular and
 * plural spellings, per the period production quoted in attime.h. */
static int parse_period(const char *w, enum period *out)
{
	static const struct { const char *s; const char *p; enum period v; } tab[] = {
		{ "minute", "minutes", P_MINUTE },
		{ "hour",   "hours",   P_HOUR },
		{ "day",    "days",    P_DAY },
		{ "week",   "weeks",   P_WEEK },
		{ "month",  "months",  P_MONTH },
		{ "year",   "years",   P_YEAR },
	};
	size_t i;
	for (i = 0; i < sizeof tab / sizeof tab[0]; i++)
		if (word_is(w, tab[i].s) || word_is(w, tab[i].p)) { *out = tab[i].v; return 0; }
	return -1;
}

/* Applies `n` units of `p` to `base`, via calendar arithmetic for
 * month/year (so "next month" from Jan 31 lands on a real date, not
 * an overflowed one -- mktime()'s own documented normalization
 * handles a day-of-month past the target month's length by carrying
 * into the month after, which is the same rule every real `at`
 * agrees on) and plain seconds arithmetic for everything smaller
 * (which is exact and never needs normalization). */
static time_t apply_increment(time_t base, long n, enum period p)
{
	switch (p) {
	case P_MINUTE: return base + n * 60;
	case P_HOUR:   return base + n * 3600;
	case P_DAY:    return base + n * 86400;
	case P_WEEK:   return base + n * 7 * 86400;
	case P_MONTH:
	case P_YEAR: {
		struct tm tmv;
		if (!localtime_r(&base, &tmv)) return (time_t)-1;
		if (p == P_MONTH) tmv.tm_mon += (int)n;
		else tmv.tm_year += (int)n;
		tmv.tm_isdst = -1;
		return mktime(&tmv);
	}
	}
	return (time_t)-1;
}

/* The exact per-unit second count apply_increment() itself multiplies
 * `n` by for the four non-calendar periods; 0 for P_MONTH/P_YEAR,
 * which have no fixed seconds-per-unit at all (calendar arithmetic
 * instead). Shared with maybe_increment() below so the overflow bound
 * it checks is always the identical multiplier apply_increment() is
 * about to use, not a guess. */
static long period_seconds(enum period p)
{
	switch (p) {
	case P_MINUTE: return 60;
	case P_HOUR:   return 3600;
	case P_DAY:    return 86400;
	case P_WEEK:   return 7 * 86400;
	default:       return 0;
	}
}

/* Consumes an `increment` production at *ip if present ('+' number
 * period, or "next" period); a no-op (returns the base time
 * unchanged) if *ip does not start with one -- increment is always
 * optional in every grammar branch that allows it. */
static time_t maybe_increment(char *const *words, int n, int *ip, time_t base)
{
	int i = *ip;
	enum period p;

	if (i < n && word_is(words[i], "next")) {
		if (i + 1 >= n || parse_period(words[i + 1], &p) < 0) return base;
		*ip = i + 2;
		return apply_increment(base, 1, p);
	}
	if (i < n && words[i][0] == '+') {
		long v;
		char *end;
		const char *numword = words[i] + 1;
		int consumed_num_word = 1;

		if (!*numword) { /* "+" and the number are separate words */
			if (i + 1 >= n) return base;
			numword = words[i + 1];
			consumed_num_word = 2;
		}
		errno = 0;
		v = strtol(numword, &end, 10);
		if (end == numword || *end || errno == ERANGE) return base;
		if (i + consumed_num_word >= n || parse_period(words[i + consumed_num_word], &p) < 0)
			return base;
		/* strtol() succeeding (no ERANGE) only means v fits in a
		 * `long`, not that apply_increment()'s own n*mult multiply
		 * does too -- "at now +99999999999999999999 days" otherwise
		 * overflows that multiply and silently schedules the job
		 * *yesterday* instead of being rejected (this project also
		 * builds with a 32-bit `long` on NT/tcc, where the margin is
		 * far smaller still). Bounding v against the exact multiplier
		 * apply_increment() is about to use catches it here, before
		 * the overflow happens, the same as a malformed increment is
		 * already rejected: silently, leaving the words unconsumed so
		 * the caller's own "extra operands"/"invalid time" check
		 * reports it. P_MONTH/P_YEAR have no seconds multiplier, but
		 * still narrow to `int` below, so bound against that instead. */
		{
			long mult = period_seconds(p);
			if (mult ? (v > LONG_MAX / mult || v < LONG_MIN / mult)
			         : (v > INT_MAX / 2 || v < INT_MIN / 2))
				return base;
		}
		*ip = i + consumed_num_word + 1;
		return apply_increment(base, v, p);
	}
	return base;
}

/* am_pm suffix, either glued onto the digits ("10am") or its own word
 * ("10 am"). Returns 1 for am, 2 for pm, 0 for none; advances *ip
 * past a separate am/pm word if that is where it was found. */
static int match_ampm(const char *s)
{
	if (!strcasecmp(s, "am") || !strcasecmp(s, "a.m.")) return 1;
	if (!strcasecmp(s, "pm") || !strcasecmp(s, "p.m.")) return 2;
	return 0;
}

/* `time` production: hr24clock_hr_min | hr24clock_hour:minute |
 * wallclock_hr_min am_pm | wallclock_hour:minute am_pm | noon |
 * midnight. Fills tm_hour/tm_min/tm_sec (sec always 0 -- the grammar
 * has no seconds field). Returns 0 and advances *ip past what it
 * consumed, or -1 (leaving *ip unmoved) if words[*ip] is not a valid
 * `time` at all. */
static int parse_clocktime(char *const *words, int n, int *ip, struct tm *out)
{
	int i = *ip;
	const char *w, *colon;
	char digits[16];
	int hour, min, ampm = 0;
	size_t wlen;

	if (i >= n) return -1;
	w = words[i];

	if (word_is(w, "noon")) { out->tm_hour = 12; out->tm_min = 0; out->tm_sec = 0; *ip = i + 1; return 0; }
	if (word_is(w, "midnight")) { out->tm_hour = 0; out->tm_min = 0; out->tm_sec = 0; *ip = i + 1; return 0; }

	wlen = strlen(w);
	/* Peel a glued am/pm suffix off the end, if present, before
	 * looking at the digits/colon shape. */
	if (wlen >= 2) {
		int g = match_ampm(w + wlen - 2);
		if (g && wlen == 2) return -1; /* "am"/"pm" alone is not a time */
		if (g) { ampm = g; wlen -= 2; }
	}
	if (wlen == 0 || wlen >= sizeof digits) return -1;
	memcpy(digits, w, wlen);
	digits[wlen] = 0;

	colon = strchr(digits, ':');
	if (colon) {
		char hbuf[8], mbuf[8];
		size_t hl = (size_t)(colon - digits);
		if (hl == 0 || hl > 2 || strlen(colon + 1) != 2) return -1;
		memcpy(hbuf, digits, hl); hbuf[hl] = 0;
		memcpy(mbuf, colon + 1, 2); mbuf[2] = 0;
		if (!isdigit((unsigned char)hbuf[0]) || (hl == 2 && !isdigit((unsigned char)hbuf[1]))) return -1;
		if (!isdigit((unsigned char)mbuf[0]) || !isdigit((unsigned char)mbuf[1])) return -1;
		hour = atoi(hbuf);
		min = atoi(mbuf);
	} else {
		size_t dl = strlen(digits);
		size_t j;
		for (j = 0; j < dl; j++) if (!isdigit((unsigned char)digits[j])) return -1;
		switch (dl) {
		case 1: case 2: hour = atoi(digits); min = 0; break;
		case 3: { char hb[2]; hb[0] = digits[0]; hb[1] = 0; hour = atoi(hb); min = atoi(digits + 1); break; }
		case 4: { char hb[3]; hb[0] = digits[0]; hb[1] = digits[1]; hb[2] = 0; hour = atoi(hb); min = atoi(digits + 2); break; }
		default: return -1;
		}
	}
	if (min > 59) return -1;

	if (!ampm && i + 1 < n) {
		int g = match_ampm(words[i + 1]);
		if (g) { ampm = g; i++; }
	}

	if (ampm) {
		if (hour < 1 || hour > 12) return -1;
		hour %= 12;
		if (ampm == 2) hour += 12;
	} else {
		if (hour > 23) return -1;
	}

	out->tm_hour = hour;
	out->tm_min = min;
	out->tm_sec = 0;
	*ip = i + 1;
	return 0;
}

static const char *const month_abbrev[12] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec"
};
static const char *const dow_abbrev[7] = {
	"sun", "mon", "tue", "wed", "thu", "fri", "sat"
};

static int match_abbrev3(const char *w, const char *const *tab, int count)
{
	int i;
	if (strlen(w) < 3) return -1;
	for (i = 0; i < count; i++)
		if (strncasecmp(w, tab[i], 3) == 0) return i;
	return -1;
}

enum date_kind { DATE_NONE, DATE_TODAY, DATE_TOMORROW, DATE_WEEKDAY, DATE_MONTHDAY, DATE_MONTHDAY_YEAR, DATE_ISO };

/* `date` production, plus the ISO-date extension attime.h documents.
 * Leaves *tmv's date fields untouched (DATE_NONE) if words[*ip] is
 * not a recognized date at all -- date is always optional. */
static enum date_kind parse_date(char *const *words, int n, int *ip, struct tm *tmv)
{
	int i = *ip;
	const char *w;
	int mi, wd;

	if (i >= n) return DATE_NONE;
	w = words[i];

	if (word_is(w, "today")) { *ip = i + 1; return DATE_TODAY; }
	if (word_is(w, "tomorrow")) {
		/* +1 here is intentionally a raw, unnormalized tm_mday --
		 * __attime_parse()'s own mktime() call normalizes a 32nd of
		 * a 31-day month into the 1st of the next one, the same way
		 * every calendar-arithmetic mktime() caller in this tree
		 * already relies on. */
		tmv->tm_mday += 1;
		*ip = i + 1;
		return DATE_TOMORROW;
	}

	wd = match_abbrev3(w, dow_abbrev, 7);
	if (wd >= 0) {
		int delta = wd - tmv->tm_wday;
		if (delta < 0) delta += 7;
		tmv->tm_mday += delta;
		*ip = i + 1;
		return DATE_WEEKDAY;
	}

	mi = match_abbrev3(w, month_abbrev, 12);
	if (mi >= 0) {
		long day;
		char *end;
		int day_has_comma;
		if (i + 1 >= n) return DATE_NONE;
		day = strtol(words[i + 1], &end, 10);
		/* The day_number word may carry the grammar's own trailing
		 * comma glued on ("sep 5, 2026" tokenizes as "sep"/"5,"/
		 * "2026") -- tolerate exactly that one trailing character
		 * before requiring the rest of the token to be pure digits. */
		day_has_comma = (*end == ',' && end[1] == 0);
		if (end == words[i + 1] || (*end && !day_has_comma) || day < 1 || day > 31)
			return DATE_NONE;
		tmv->tm_mon = mi;
		tmv->tm_mday = (int)day;
		i += 2;
		if (i < n) {
			size_t l = strlen(words[i]);
			const char *yw = words[i];
			int has_comma = day_has_comma;
			if (!has_comma && l > 0 && yw[l - 1] == ',') { has_comma = 1; }
			/* Accept "sep 5, 2026" (comma glued to either the day or
			 * the year word) and "sep 5 2026" (no comma at all) --
			 * the comma is punctuation the grammar shows but nothing
			 * here depends on its exact placement to parse correctly. */
			if (has_comma) {
				const char *yword = words[i];
				size_t yl = strlen(yword);
				char ybuf[16];
				if (!day_has_comma) {
					/* comma was glued to the year word itself --
					 * strip it before parsing the number. */
					if (yl == 0 || yl - 1 >= sizeof ybuf) return DATE_NONE;
					memcpy(ybuf, yword, yl - 1);
					ybuf[yl - 1] = 0;
					yword = ybuf;
				}
				{
					long y = strtol(yword, &end, 10);
					if (end != yword && !*end && y > 0) {
						tmv->tm_year = (int)(y < 100 ? y + 100 : y - 1900);
						*ip = i + 1;
						return DATE_MONTHDAY_YEAR;
					}
				}
				return DATE_NONE;
			}
			{
				long y = strtol(words[i], &end, 10);
				if (end != words[i] && !*end && y > 0) {
					tmv->tm_year = (int)(y < 100 ? y + 100 : y - 1900);
					*ip = i + 1;
					return DATE_MONTHDAY_YEAR;
				}
			}
		}
		*ip = i;
		return DATE_MONTHDAY;
	}

	/* ISO extension: CCYY-MM-DD, exactly one word. */
	if (strlen(w) == 10 && w[4] == '-' && w[7] == '-') {
		int y, mo, dd, k;
		int ok = 1;
		for (k = 0; k < 10 && ok; k++)
			if (k != 4 && k != 7 && !isdigit((unsigned char)w[k])) ok = 0;
		if (ok) {
			y = (w[0] - '0') * 1000 + (w[1] - '0') * 100 + (w[2] - '0') * 10 + (w[3] - '0');
			mo = (w[5] - '0') * 10 + (w[6] - '0');
			dd = (w[8] - '0') * 10 + (w[9] - '0');
			if (mo >= 1 && mo <= 12 && dd >= 1 && dd <= 31) {
				tmv->tm_year = y - 1900;
				tmv->tm_mon = mo - 1;
				tmv->tm_mday = dd;
				*ip = i + 1;
				return DATE_ISO;
			}
		}
	}

	return DATE_NONE;
}

int __attime_parse(char *const *words, int n, time_t now, time_t *out)
{
	struct tm base;
	int i = 0;
	time_t result;

	if (n <= 0) return -1;
	if (!localtime_r(&now, &base)) return -1;
	base.tm_isdst = -1;

	if (word_is(words[0], "now")) {
		i = 1;
		result = maybe_increment(words, n, &i, now);
		if (result == (time_t)-1) return -1;
		*out = result;
		return i;
	}

	{
		struct tm tmv = base; /* seeds today's date; parse_clocktime overwrites h/m/s */
		int had_time = (parse_clocktime(words, n, &i, &tmv) == 0);
		enum date_kind dk = DATE_NONE;
		time_t t;

		if (!had_time) {
			/* No leading `time`: only the ISO-date extension is
			 * allowed to stand alone (attime.h's own documented
			 * shorthand), defaulting to midnight. */
			tmv.tm_hour = 0; tmv.tm_min = 0; tmv.tm_sec = 0;
			dk = parse_date(words, n, &i, &tmv);
			if (dk != DATE_ISO) return -1;
		} else {
			dk = parse_date(words, n, &i, &tmv);
		}

		tmv.tm_isdst = -1;
		t = mktime(&tmv);
		if (t == (time_t)-1) return -1;

		if (dk == DATE_NONE && t <= now) t = apply_increment(t, 1, P_DAY);
		else if (dk == DATE_WEEKDAY && t <= now) t = apply_increment(t, 1, P_WEEK);
		else if (dk == DATE_MONTHDAY && t <= now) t = apply_increment(t, 1, P_YEAR);
		/* This apply_increment() (unlike every other one in this file)
		 * feeds its result into a *second* time computation --
		 * maybe_increment()'s own `base` argument just below -- rather
		 * than going straight to the final check. Left unchecked, a
		 * failure here (apply_increment() returning the real
		 * (time_t)-1 sentinel rather than a valid time) would be
		 * silently treated as a legitimate base time by any further
		 * "+N period"/"next period" clause maybe_increment() parses
		 * from the remaining words, which would arithmetic its way
		 * into some *other*, bogus-but-valid-looking time_t that no
		 * longer equals -1 -- sailing straight past the check after
		 * the maybe_increment() call below undetected. Reject it here
		 * instead, immediately, the same as every other apply_increment()/
		 * mktime() result in this function already is. */
		if (t == (time_t)-1) return -1;

		t = maybe_increment(words, n, &i, t);
		if (t == (time_t)-1) return -1;
		*out = t;
		return i;
	}
}
