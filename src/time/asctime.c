/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * "Www Mmm dd hh:mm:ss yyyy\n" -- built by hand rather than through
 * sprintf, since stdio's formatted output isn't necessarily around yet
 * (this module doesn't want a dependency on it either way).
 */
#include <time.h>
#include <string.h>
#include "time_impl.h"
#include "ownership_stubs.h" /* __ownership_pointer_nonnull(), __ownership_writable_span() */

/* Widened to hold up to 8 year digits (see the tm_year comment below),
 * one byte more than the classic 26-byte "Www Mmm dd hh:mm:ss yyyy\n\0". */
char *asctime_r(const struct tm *tm, char *buf withtok(writable_span(30)))
{
	char *p = buf;
	int n;
	__ownership_writable_span(p, 30);
	const char *wd = (unsigned)tm->tm_wday < 7 ? __spicule_day_name_abbr[tm->tm_wday] : "???";
	const char *mo = (unsigned)tm->tm_mon < 12 ? __spicule_month_name_abbr[tm->tm_mon] : "???";
	/* Both branches are always a real string literal (either "???" or one
	 * of names.c's fixed tables); the checker can't see into a global
	 * array's initializer. */
	__ownership_pointer_nonnull(wd);
	__ownership_pointer_nonnull(mo);

	*p++ = wd[0]; *p++ = wd[1]; *p++ = wd[2]; *p++ = ' ';
	*p++ = mo[0]; *p++ = mo[1]; *p++ = mo[2]; *p++ = ' ';
	/* Open finding, left as-is: every write below through '*p' is sound
	 * (__num_digits' own `if (n > cap) n = cap;` bounds each returned n
	 * by the cap literal actually passed here, so p never leaves the
	 * writable_span(30) asserted above), but the checker has no
	 * annotation in ownership.h for "this return value is bounded by
	 * this parameter", so it cannot carry that bound from __num_digits'
	 * return across the `p += n;` that follows. Not a real bug. */
	n = __num_digits(p, 2, (unsigned)tm->tm_mday, 2, ' '); p += n; *p++ = ' ';
	n = __num_digits(p, 2, (unsigned)tm->tm_hour, 2, '0'); p += n; *p++ = ':';
	n = __num_digits(p, 2, (unsigned)tm->tm_min, 2, '0'); p += n; *p++ = ':';
	n = __num_digits(p, 2, (unsigned)tm->tm_sec, 2, '0'); p += n; *p++ = ' ';
	/* tm_year is `int` and unbounded (callers may hand back an out-of-range
	 * value); widen to `long long` before the +1900 add so a caller-
	 * supplied extreme value overflows there rather than in `int` --
	 * plain `long` would not help here, since it is 32-bit on this
	 * (LLP64) target same as `int`. */
	n = __num_digits(p, 8, (unsigned long)((long long)tm->tm_year + 1900), 4, '0'); p += n;
	*p++ = '\n';
	*p = 0;
	return buf;
}

char *asctime(const struct tm *tm)
{
	static char buf[32];
	return asctime_r(tm, buf); // NOLINT(bugprone-unsafe-functions,cert-msc24-c,cert-msc33-c) -- asctime must expose the same fixed-format conversion; its implementation-owned buffer is sized for this implementation's bounded output
}
