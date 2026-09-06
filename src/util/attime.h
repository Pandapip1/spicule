/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * at(1p)'s TIME clause grammar (the `timespec` operand form -- the
 * other SYNOPSIS form, `-t time_arg`, reuses touch(1p)'s own
 * `[[CC]YY]MMDDhhmm[.SS]` grammar directly via src/util/touch.c's
 * parse_touch_t()-shaped logic re-implemented in src/util/atbatch.c,
 * since that grammar is already fully specified and tested there and
 * has nothing in common with this one worth sharing).
 *
 * GRAMMAR IMPLEMENTED, fetched from the real at(1p) page
 * (https://pubs.opengroup.org/onlinepubs/9699919799/utilities/at.html)
 * and checked directly rather than reconstructed from familiarity
 * with any one `at` implementation's manual page:
 *
 *   timespec  := nowspec | time [date] [increment]
 *   nowspec   := "now" [increment]
 *   time      := hr24clock_hr_min [timezone_name]
 *              | hr24clock_hour ':' minute [timezone_name]
 *              | wallclock_hr_min am_pm [timezone_name]
 *              | wallclock_hour ':' minute am_pm [timezone_name]
 *              | "noon" | "midnight"
 *   date      := month_name day_number [',' year_number]
 *              | day_of_week
 *              | "today" | "tomorrow"
 *   increment := '+' number period | "next" period
 *   period    := "minute(s)" | "hour(s)" | "day(s)" | "week(s)"
 *              | "month(s)" | "year(s)"
 *
 * DEVIATIONS, each a deliberate, documented scope line rather than a
 * silent gap:
 *
 *   - timezone_name is NOT implemented (parsed as far as `time`, then
 *     a trailing word that isn't a valid date/increment/end-of-input
 *     is a clean parse failure). This library has no timezone-name
 *     database anywhere else either (see include/time.h's own TZ
 *     handling, which is offset-based, not name-based) -- accepting
 *     the syntax and silently ignoring it would misreport what was
 *     actually scheduled, which this project's house style refuses.
 *   - month_name and day_of_week are matched as the first three
 *     letters, case-insensitively (e.g. "sep", "SEP", "September" all
 *     match) -- the same real-world convention src/util/crontime.c
 *     documents for crontab(5)'s own month/day-of-week names, kept
 *     identical here for a consistent user-facing rule across both
 *     utilities rather than two different name grammars.
 *   - One extension beyond the page above, spelled out because this
 *     project's own task brief for this pass names it explicitly as
 *     an example to support: an ISO 8601 calendar date, "CCYY-MM-DD",
 *     accepted anywhere the `date` production is, functioning like
 *     "month_name day_number, year_number" but unambiguous and
 *     locale-independent. A bare ISO date with no leading `time` word
 *     (e.g. "at 2026-09-05" with nothing before it) is accepted too,
 *     defaulting the time-of-day to midnight -- documented here as
 *     this implementation's own convention for that shorthand, since
 *     the standard grammar always requires `time` first and does not
 *     define what a bare date alone would mean.
 *
 * ROLLING A TIME THAT HAS ALREADY PASSED FORWARD
 * --------------------------------------------------
 * "It is unspecified whether a time in the past ... is acceptable"
 * (at.html's own ordinary-form wording), which leaves this
 * implementation free to pick the one real behaviour every `at`
 * implementation actually agrees on for a *bare* time: `time` with no
 * `date` rolls to tomorrow if that time-of-day has already passed
 * today (`at 9am` run at 5pm today means tomorrow 9am, not an error --
 * without this, "no date" would be indistinguishable from "reject
 * anything before midnight tonight", which nothing calling `at` this
 * way actually wants). The same reasoning extends to two of the named
 * `date` forms, and only those two, because only those two have an
 * inherent "next occurrence" reading:
 *
 *   - day_of_week rolls forward a week at a time until the resulting
 *     date+time is in the future (so "at 3pm tue", issued at 4pm on a
 *     Tuesday, means next Tuesday, not today).
 *   - month_name day_number with no year_number rolls the year
 *     forward by one if that date+time has already passed this year
 *     (so "at noon jan 1" issued in December means next January).
 *
 * "today", "tomorrow" and the ISO-date extension never roll: what the
 * caller named is what gets scheduled, even if that lands in the
 * past. Whether a resulting time is in the past at all is not this
 * file's decision -- __attime_parse() always returns whatever it
 * computed; src/util/atbatch.c's own submission logic checks the
 * result against "now" once, in one place, rather than scattering
 * that judgment call across every grammar branch here.
 *
 * This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard and its own declarations
 * so they cannot collide with user code.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_UTIL_ATTIME_H
#define _NTLIBC_UTIL_ATTIME_H

#include <time.h>

/* Parses the timespec grammar above out of `words[0..n-1]` (already
 * split on whitespace by the caller -- exactly at(1p)'s own argv
 * words once its "-m"/"-f"/"-q" options have been stripped). `now` is
 * "the current time", used for every relative computation (today's
 * date, "now"/"today"/"tomorrow", and the two rolling rules above).
 *
 * On success, returns the number of words consumed (always >= 1,
 * never > n) and fills *out with the resulting absolute time; on a
 * malformed or empty timespec, returns -1 and leaves *out untouched.
 * A successful parse that does not consume all of `n` words is itself
 * a caller-visible error (extra trailing garbage) -- at.c checks
 * that, this function does not, so a partial match against a longer,
 * unrelated argument list is never silently accepted as a prefix. */
int __attime_parse(char *const *words, int n, time_t now, time_t *out);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
