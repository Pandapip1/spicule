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
#include "ownership_stubs.h" /* unsafe_assume_pointer_nonnull(), unsafe_assume_writable_span() */

/* Widened to hold up to 8 year digits (see the tm_year comment below),
 * one byte more than the classic 26-byte "Www Mmm dd hh:mm:ss yyyy\n\0". */
char *asctime_r(const struct tm *tm, char *buf withtok(writable_span(30)))
{
	char *p = buf;
	int n;
	unsafe_assume_writable_span(p, 30);
	const char *wd = (unsigned)tm->tm_wday < 7 ? __spicule_day_name_abbr[tm->tm_wday] : "???";
	const char *mo = (unsigned)tm->tm_mon < 12 ? __spicule_month_name_abbr[tm->tm_mon] : "???";
	/* Both branches are a real string literal; the checker can't see through
	 * a global array's initializer. */
	unsafe_assume_pointer_nonnull(wd);
	unsafe_assume_pointer_nonnull(mo);

	*p++ = wd[0]; *p++ = wd[1]; *p++ = wd[2]; *p++ = ' ';
	*p++ = mo[0]; *p++ = mo[1]; *p++ = mo[2]; *p++ = ' ';
	/* Open finding: __num_digits' own `if (n > cap) n = cap;` bounds each n
	 * by the cap passed here, so p stays within writable_span(30), but the
	 * checker can't carry that bound across the `p += n;` below. Not a bug. */
	n = __num_digits(p, 2, (unsigned)tm->tm_mday, 2, ' '); p += n; *p++ = ' ';
	n = __num_digits(p, 2, (unsigned)tm->tm_hour, 2, '0'); p += n; *p++ = ':';
	n = __num_digits(p, 2, (unsigned)tm->tm_min, 2, '0'); p += n; *p++ = ':';
	n = __num_digits(p, 2, (unsigned)tm->tm_sec, 2, '0'); p += n; *p++ = ' ';
	/* long is also 32-bit here (LLP64), so widen to long long before +1900
	 * to make an out-of-range tm_year overflow there instead of in int. */
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
