/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bits shared between the files in src/time/ but not meant for anyone
 * else: the proleptic-Gregorian civil calendar <-> day-count conversion
 * (there is no other libc around to borrow it from, so it is reproduced
 * here), the day/month name tables strftime/strptime/asctime need, and
 * a tiny zero-padded-decimal formatter used by both strftime and
 * asctime so the two agree on how numbers look.
 */
#ifndef _SPICULE_TIME_IMPL_H
#define _SPICULE_TIME_IMPL_H

#include <time.h>
#include <features.h>

/* Howard Hinnant's days_from_civil/civil_from_days
 * (http://howardhinnant.github.io/date_algorithms.html), which turn a
 * proleptic-Gregorian y/m/d (m in 1..12) into a day count relative to
 * 1970-01-01 and back, correctly and branchlessly for any year an int
 * can hold (including negative ones, via the usual "add 400 years"
 * trick to keep the truncating divisions well-behaved).
 *
 * Both functions add an unsigned constant like -3u/-9u to fold a
 * "subtract, then wrap the month index into 0..11" into one unsigned
 * addition (see the implicit-integer-sign-change note in
 * tools/asan-build.sh for the same expression's other half): the
 * addition itself wraps modulo 2**32, on purpose, to land back at
 * mp - 3 / mp - 9. */
static inline __wraps long long __days_from_civil(long long y, unsigned m, unsigned d) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	y -= m <= 2;
	long long era = (y >= 0 ? y : y - 399) / 400;
	unsigned yoe = (unsigned)(y - era * 400);                /* 0..399 */
	unsigned mp = m + (m > 2 ? -3u : 9u);                     /* Mar=0..Feb=11 */
	unsigned doy = (153 * mp + 2) / 5 + d - 1;                /* 0..365 */
	unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;     /* 0..146096 */
	return era * 146097 + (long long)doe - 719468;
}

static inline __wraps void __civil_from_days(long long z, long long *y, unsigned *m, unsigned *d) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	z += 719468;
	long long era = (z >= 0 ? z : z - 146096) / 146097;
	unsigned doe = (unsigned)(z - era * 146097);              /* 0..146096 */
	unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; /* 0..399 */
	long long yy = (long long)yoe + era * 400;
	unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);   /* 0..365 */
	unsigned mp = (5 * doy + 2) / 153;                        /* Mar=0..Feb=11 */
	*d = doy - (153 * mp + 2) / 5 + 1;
	*m = mp + (mp < 10 ? 3 : -9);
	*y = yy + (*m <= 2);
}

/* 1970-01-01 (day 0) was a Thursday (wday 4, Sunday=0); the +11 turns
 * C's truncating (possibly negative) % into the usual 0..6 result. */
static inline int __wday_from_days(long long z)
{
	return (int)((z % 7 + 11) % 7);
}

/* Floor (not truncating) division/modulus: C's / and % truncate toward
 * zero, which is wrong for the "always round toward negative infinity"
 * arithmetic the ISO week-number formulas below assume when they run on
 * a year before 1 CE.  Both __days_from_civil/__civil_from_days above
 * dodge the same problem a different way (the "+ 719468"/era trick);
 * these are kept separate and simple because the ISO week formulas are
 * the standard textbook ones (Wikipedia, "ISO week date", "Calculating
 * the week number from a month and day of the month or ordinal day of
 * the year") and are easiest to check against that source written the
 * way the source writes them. */
static inline long long __floordiv(long long a, long long b)
{
	long long q = a / b;
	if (a % b != 0 && ((a < 0) != (b < 0))) q--;
	return q;
}

static inline long long __floormod(long long a, long long b)
{
	long long r = a % b;
	if (r != 0 && ((r < 0) != (b < 0))) r += b;
	return r;
}

/* Long years (ISO 8601's term for a week-based year with 53 Monday-
 * Sunday weeks instead of 52): true iff 1 January of the year falls on
 * a Thursday, or the year is a leap year and 1 January falls on a
 * Wednesday.  Expressed the standard way, via P(y) = (y + floor(y/4) -
 * floor(y/100) + floor(y/400)) mod 7 -- P(y)==4 or P(y-1)==3. */
static inline int __iso_weeks_in_year(long long y)
{
	long long p = __floormod(y + __floordiv(y, 4) - __floordiv(y, 100) + __floordiv(y, 400), 7);
	long long pp = __floormod((y - 1) + __floordiv(y - 1, 4) - __floordiv(y - 1, 100) + __floordiv(y - 1, 400), 7);
	return (p == 4 || pp == 3) ? 53 : 52;
}

/* The ISO 8601 week-based year and week number (strftime's %G and %V)
 * for a given full calendar year, 0-based day-of-year and 0-based
 * Sunday=0 weekday -- exactly what struct tm's tm_year+1900/tm_yday/
 * tm_wday already carry, so callers pass those straight through.
 * "Both January 4th and the first Thursday of January are always in
 * week 1" (strftime.html's %V entry) is the defining property; the
 * `week` expression below is the standard ISO-week-from-ordinal-date
 * formula (same source as __iso_weeks_in_year's comment), and a result
 * outside [1, weeks in that year] means the date belongs to the last
 * week of the previous week-based year or week 1 of the next one. */
static inline void __iso_week(long long year, int yday, int wday, long long *out_year, int *out_week) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int isodow = wday == 0 ? 7 : wday;             /* Monday=1..Sunday=7 */
	long long week = ((long long)yday + 1 - isodow + 10) / 7;

	if (week < 1) {
		*out_year = year - 1;
		*out_week = __iso_weeks_in_year(year - 1);
	} else if (week > __iso_weeks_in_year(year)) {
		*out_year = year + 1;
		*out_week = 1;
	} else {
		*out_year = year;
		*out_week = (int)week;
	}
}

extern const char *const __spicule_day_name[7];
extern const char *const __spicule_day_name_abbr[7];
extern const char *const __spicule_month_name[12];
extern const char *const __spicule_month_name_abbr[12];

/* Write the decimal digits of v into tmp (capacity cap), zero-padded (or
 * pad-charred) to at least width digits -- more if v needs them, never
 * truncated.  Returns the digit count written, least-significant-digit
 * bookkeeping done internally; the caller gets the digits in the right
 * (most-significant-first) order in tmp[0..return). */
static inline int __num_digits(char *tmp, int cap, unsigned long v, int width, char pad) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char rev[24];
	int n = 0;
	do {
		if (n < (int)sizeof rev) rev[n] = (char)('0' + v % 10);
		n++;
		v /= 10;
	} while (v);
	while (n < width) {
		if (n < (int)sizeof rev) rev[n] = pad;
		n++;
	}
	if (n > cap) n = cap;
	for (int i = 0; i < n; i++) tmp[i] = rev[n - 1 - i];
	return n;
}

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
