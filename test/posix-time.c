/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <time.h> not already exercised
 * by test/time.c (broad known-epoch/round-trip sanity pass) or
 * test/posix-parse.c (mktime normalization / strftime short-buffer
 * boundary). Each block cites the page it was checked against under
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 *
 * Timezone-dependent checks set TZ explicitly rather than relying on
 * the runner's zone (see test/time.c for the same pattern).
 */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* difftime.html RETURN VALUE: "the difference ... expressed in seconds
 * as a type double." Check the type, not just the numeric value (which
 * test/time.c already covers extensively). */
static void test_difftime_return_type(void)
{
	CHECK(sizeof(difftime(0, 0)) == sizeof(double));
	/* fractional-looking magnitude only possible if truly double: this
	 * value doesn't fit exactly in a 32-bit float's mantissa but does in
	 * a double, so a double-returning difftime reproduces it exactly. */
	{
		time_t a = (time_t)9007199254740993LL; /* 2^53+1 */
		double d = difftime(a, 0);
		CHECK(d == 9007199254740993.0);
	}
}

/* gmtime.html ERRORS: "[EOVERFLOW] The result cannot be represented."
 * RETURN VALUE: null pointer returned on error. localtime()/localtime_r()
 * are specified via the same page and inherit the same EOVERFLOW
 * behaviour (localtime_r calls gmtime_r after applying the fixed TZ
 * offset -- src/time/localtime.c). Use a time_t so far in the future
 * that the resulting year does not fit in `int` (tm_year is `int`). */
static void test_gmtime_overflow(void)
{
	struct tm sentinel, tm;
	time_t huge = LLONG_MAX;

	memset(&sentinel, 0x5a, sizeof sentinel);
	tm = sentinel;
	errno = 0;
	CHECK(gmtime_r(&huge, &tm) == NULL);
	CHECK(errno == EOVERFLOW);
	/* gmtime_r bails out before writing any field on overflow (checked
	 * by inspection of src/time/gmtime.c: the EOVERFLOW check runs
	 * before any assignment to *result), so the caller's struct is left
	 * untouched. */
	CHECK(memcmp(&tm, &sentinel, sizeof tm) == 0);

	errno = 0;
	CHECK(gmtime(&huge) == NULL);
	CHECK(errno == EOVERFLOW);

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
	errno = 0;
	CHECK(localtime_r(&huge, &tm) == NULL);
	CHECK(errno == EOVERFLOW);
}

/* mktime.html DESCRIPTION: "the original values of the tm_wday and
 * tm_yday components of the structure are ignored" -- garbage input
 * values in those fields must not influence the computed result. */
static void test_mktime_ignores_wday_yday_input(void)
{
	struct tm a, b;

	memset(&a, 0, sizeof a);
	a.tm_year = 100; a.tm_mon = 1; a.tm_mday = 29; /* 2000-02-29, a Tuesday */
	a.tm_wday = 99; a.tm_yday = -12345; /* garbage, must be ignored */
	b = a;
	b.tm_wday = 0; b.tm_yday = 0;

	CHECK(mktime(&a) == mktime(&b));
	CHECK(a.tm_wday == 2); /* actual Tuesday, not the garbage 99 */
	CHECK(a.tm_yday == 59);
}

/* mktime.html RETURN VALUE: "Upon successful completion, the values of
 * the tm_wday and tm_yday components ... shall be set appropriately,
 * and the other components are set to represent the specified time
 * since the Epoch, but with their values forced to the ranges
 * indicated in the <time.h> entry"; ERRORS: "[EOVERFLOW] The result
 * cannot be represented." RETURN VALUE: "the value (time_t)-1 shall be
 * returned and errno set to indicate the error."
 *
 * BUG: src/time/mktime.c calls localtime_r(&t, tm) and discards its
 * return value. When the computed y-1900 doesn't fit in `int` (tm_year
 * is `int`, and tm_mon/12 can push the effective year further out),
 * localtime_r -> gmtime_r correctly detects this and returns NULL with
 * errno set to EOVERFLOW (per gmtime.html), but mktime() still returns
 * the raw (garbage, unrepresentable) computed time_t instead of
 * (time_t)-1, and *tm is left with its original (also garbage) fields
 * rather than being either normalized or left alone consistently.
 * Confirmed live: tm_year=INT_MAX, tm_mon=100 makes
 * mktime() return 67768036422969600 with errno left at EOVERFLOW
 * (75) instead of returning (time_t)-1. */
static void test_mktime_overflow_returns_minus_one(void)
{
	struct tm tm;

	memset(&tm, 0, sizeof tm);
	tm.tm_year = INT_MAX;
	tm.tm_mon = 100; /* mon/12 pushes the effective year past INT_MAX-1900 */
	tm.tm_mday = 1;
	errno = 0;
	CHECK(mktime(&tm) == (time_t)-1);
	CHECK(errno == EOVERFLOW);
}

/* clock.html DESCRIPTION: "the implementation's best approximation to
 * the processor time used by the process" -- CPU time, not wall-clock
 * time. Sleeping (wall-clock elapsed) should barely move clock()'s CPU
 * time, unlike a busy loop of comparable wall duration. */
#if SPICULE_TEST(PASS, posix_time_clocks_per_sec_type) /* CLOCKS_PER_SEC has type clock_t.
	 * basedefs/time.h.html, "The <time.h> header shall define the
	 * following macros": "CLOCKS_PER_SEC -- A number used to convert
	 * the value returned by the clock() function into seconds.  The
	 * value shall be an integer constant expression with type clock_t
	 * and value 1000000."  (ISO C says the same: the macro "expands to
	 * an expression ... with type clock_t".)
	 *
	 * Mechanism: include/time.h has
	 *
	 *     #define CLOCKS_PER_SEC 1000000
	 *
	 * an unsuffixed decimal constant, so its type is int -- 32 bits on
	 * this LLP64 target -- while clock_t is `_Int64`, i.e. long long
	 * (obj/include/bits/alltypes.h).  The type half of the clause is
	 * simply not met; the value half is, and is already pinned in
	 * test/time.c.
	 *
	 * It is not academic.  The type is what governs the arithmetic the
	 * macro takes part in: any expression that scales it is evaluated
	 * in int and overflows there, before the result is ever widened to
	 * the clock_t it is being assigned to.  One hour of CPU time,
	 * CLOCKS_PER_SEC * 3600, is 3600000000 -- past INT_MAX, so it wraps
	 * to a negative number.  The far commoner clock()/CLOCKS_PER_SEC
	 * happens to be fine, because there the clock_t operand promotes
	 * the macro, which is why nothing has caught this.
	 *
	 * The fix is a suffix: 1000000LL, or ((clock_t)1000000).
	 *
	 * Re-enable when the macro carries clock_t's width. */
static void test_clocks_per_sec_type(void)
{
	CHECK(sizeof(CLOCKS_PER_SEC) == sizeof(clock_t));

	/* the observable consequence of the type, not just its size */
	CHECK((clock_t)(CLOCKS_PER_SEC * 3600) == (clock_t)3600000000LL);

	/* the value half of the same clause, kept alongside it */
	CHECK(CLOCKS_PER_SEC == 1000000);
}
#endif

static void test_clock_is_cpu_time_not_wall_time(void)
{
	struct timespec req, before_wall, after_wall;
	clock_t c1, c2;

	req.tv_sec = 0; req.tv_nsec = 150000000L; /* 150ms */
	clock_gettime(CLOCK_MONOTONIC, &before_wall);
	c1 = clock();
	CHECK(clock_nanosleep(CLOCK_REALTIME, 0, &req, NULL) == 0);
	c2 = clock();
	clock_gettime(CLOCK_MONOTONIC, &after_wall);

	CHECK(c1 != (clock_t)-1 && c2 != (clock_t)-1 && c2 >= c1);
	/* wall time definitely advanced by roughly 150ms */
	CHECK(after_wall.tv_sec > before_wall.tv_sec ||
	      (after_wall.tv_nsec - before_wall.tv_nsec) > 100000000L ||
	      after_wall.tv_sec - before_wall.tv_sec >= 1);
	/* but CPU time used while merely blocked in a sleep should be a
	 * small fraction of that -- well under 100ms of CLOCKS_PER_SEC
	 * (1000000) units, i.e. under 100000 clock() ticks. */
	CHECK((c2 - c1) < CLOCKS_PER_SEC / 10);
}

/* clock_gettime.html / clock_getres.html ERRORS: "[EINVAL] The clock_id
 * argument does not specify a known clock." Exercise the CPU-time
 * clocks' resolution too (test/time.c only checks REALTIME/MONOTONIC). */
static void test_clock_getres_cputime(void)
{
	struct timespec res;

	CHECK(clock_getres(CLOCK_PROCESS_CPUTIME_ID, &res) == 0);
	CHECK(res.tv_sec == 0 && res.tv_nsec > 0);
	CHECK(clock_getres(CLOCK_THREAD_CPUTIME_ID, &res) == 0);
	CHECK(res.tv_sec == 0 && res.tv_nsec > 0);
}

/* clock_getres.html DESCRIPTION: "If res is NULL, the clock resolution
 * is not returned." i.e. a NULL res is a legal no-op query, not an
 * error.
 *
 * BUG: src/time/clock_gettime.c's clock_getres() writes res->tv_sec /
 * res->tv_nsec unconditionally, with no NULL check, for every clock
 * id branch. Confirmed live: calling clock_getres(CLOCK_REALTIME, NULL)
 * crashes the process with SIGSEGV (wine exit code 11) rather than
 * returning 0. Not exercised live here since it would take down this
 * whole test binary (and the "N tests passed/failed" accounting with
 * it) rather than failing a single CHECK. */
static void test_clock_getres_null(void)
{
	CHECK(clock_getres(CLOCK_REALTIME, NULL) == 0);
}

/* clock_settime.html ERRORS: "[EINVAL] The tp argument to
 * clock_settime() is outside the range for the clock ID, or the
 * nanosecond field is negative or greater than or equal to 1000
 * million."
 *
 * BUG: src/time/clock_gettime.c's clock_settime() never checks
 * ts->tv_nsec's range before handing it to NtSetSystemTime -- only the
 * clock-id check (id != CLOCK_REALTIME) can produce EINVAL. Not
 * exercised live: on this target the only way to observe the
 * CLOCK_REALTIME path succeed or fail is to actually call
 * NtSetSystemTime, which depends on unpredictable process privilege
 * (see test/time.c's stime()/clock_settime() tests, which already
 * accept either outcome) and would either silently corrupt the host's
 * clock by a fraction of a second or mask the missing-EINVAL bug behind
 * a privilege-driven EPERM either way. */
static void test_clock_settime_bad_nsec(void)
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = -1;
	errno = 0;
	CHECK(clock_settime(CLOCK_REALTIME, &ts) == -1);
	CHECK(errno == EINVAL);

	/* Reject an epoch outside NT's signed 100ns range before attempting
	 * the privileged syscall, making the result account-independent. */
	ts.tv_sec = LLONG_MAX;
	ts.tv_nsec = 0;
	errno = 0;
	CHECK(clock_settime(CLOCK_REALTIME, &ts) == -1);
	CHECK(errno == EINVAL);
	ts.tv_sec = LLONG_MIN;
	errno = 0;
	CHECK(clock_settime(CLOCK_REALTIME, &ts) == -1);
	CHECK(errno == EINVAL);
}

/* clock_nanosleep.html ERRORS: "[EINVAL] The rqtp argument specified a
 * nanosecond value less than zero or greater than or equal to 1000
 * million, or specified a clock ID that is not supported."
 *
 * RETURN VALUE: "If the call is interrupted by a signal, ... or if the
 * function is unable to be executed for any other reason, ...
 * clock_nanosleep() function shall return the corresponding value of
 * errno. ... These functions shall not set errno." -- clock_nanosleep(),
 * like the other pthread_*-shaped functions, returns the error number
 * DIRECTLY, not -1 with errno set. This used to assert the -1/errno
 * contract, which matched src/time/clock_nanosleep.c's old (wrong)
 * implementation rather than the spec; both are fixed together. */
static void test_clock_nanosleep_einval(void)
{
	struct timespec req;

	req.tv_sec = 0; req.tv_nsec = 0;
	CHECK(clock_nanosleep((clockid_t)999, 0, &req, NULL) == EINVAL);

	req.tv_sec = 0; req.tv_nsec = 1000000000L; /* == 1e9, out of range */
	CHECK(clock_nanosleep(CLOCK_REALTIME, 0, &req, NULL) == EINVAL);

	req.tv_sec = 0; req.tv_nsec = -1;
	CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL) == EINVAL);
}

/* clock_nanosleep.html DESCRIPTION: relative-mode (flags==0) suspends
 * the calling thread for at least the requested interval. Sanity-check
 * actual elapsed wall time against CLOCK_MONOTONIC, independent of the
 * CPU-time check above. */
static void test_clock_nanosleep_relative(void)
{
	struct timespec req, before, after;
	long long ns;

	req.tv_sec = 0; req.tv_nsec = 100000000L; /* 100ms */
	CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
	CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL) == 0);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);

	ns = (after.tv_sec - before.tv_sec) * 1000000000LL + (after.tv_nsec - before.tv_nsec);
	CHECK(ns >= 90000000LL); /* allow a little scheduling slack under */
}

/* clock_nanosleep.html DESCRIPTION: "If the flag TIMER_ABSTIME is set
 * ... the thread ... shall be suspended until ... the time value of
 * the clock specified by clock_id reaches the absolute time specified
 * by rqtp". For CLOCK_MONOTONIC, that means "reaches" as measured by
 * CLOCK_MONOTONIC's own (arbitrary-epoch) reading -- i.e. an absolute
 * request should be built from a prior clock_gettime(CLOCK_MONOTONIC)
 * reading plus a delta, and clock_nanosleep should sleep until that
 * monotonic instant.
 *
 * BUG: src/time/clock_nanosleep.c's TIMER_ABSTIME branch always builds
 * the absolute LARGE_INTEGER via __unix_to_ticks(req->tv_sec,
 * req->tv_nsec), which assumes req is seconds-since-1970 (an NT
 * FILETIME conversion) regardless of clock_id. For CLOCK_MONOTONIC,
 * req is actually seconds-since-an-arbitrary-epoch (the performance
 * counter's start, typically near boot -- see monotonic_get() in
 * src/time/clock_gettime.c), a far smaller number: fed through
 * __unix_to_ticks it produces an absolute NT time in the distant past
 * (near 1601), so NtDelayExecution returns immediately. Confirmed
 * live: requesting CLOCK_MONOTONIC/TIMER_ABSTIME for "now + 2s"
 * returned in about 3 microseconds instead of sleeping ~2 seconds. */
static void test_clock_nanosleep_monotonic_abstime(void)
{
	struct timespec now, req, before, after;
	long long ns;

	CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	req = now;
	req.tv_sec += 1; /* absolute monotonic instant ~1s from now */

	CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
	CHECK(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL) == 0);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);

	ns = (after.tv_sec - before.tv_sec) * 1000000000LL + (after.tv_nsec - before.tv_nsec);
	CHECK(ns >= 900000000LL); /* should have waited ~1s; actually returns in microseconds */
}

/* clock_nanosleep.html DESCRIPTION: "if, at the time of the call, the
 * time value specified by rqtp is less than or equal to the current
 * value of the clock ... then clock_nanosleep() shall return
 * immediately". CLOCK_REALTIME's TIMER_ABSTIME path does go through
 * __unix_to_ticks correctly (REALTIME's own readings *are* unix-epoch
 * seconds), so this should behave correctly -- sanity-check it, since
 * the CLOCK_MONOTONIC case above is fenced as broken. */
static void test_clock_nanosleep_realtime_abstime_past(void)
{
	struct timespec past;

	CHECK(clock_gettime(CLOCK_REALTIME, &past) == 0);
	/* already in the past by the time NtDelayExecution sees it */
	CHECK(clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &past, NULL) == 0);
}

/* ctime.html DESCRIPTION: "It shall be equivalent to:
 *     asctime(localtime(clock))"
 * test/time.c checks ctime() against literal expected strings under
 * TZ=UTC0; check the equivalence itself, and under a non-UTC TZ so the
 * localtime() half of the equivalence actually does something. */
static void test_ctime_equals_asctime_localtime(void)
{
	time_t t = 951782400 + 3661; /* 2000-02-29-ish */
	struct tm tm;
	char abuf[32];

	CHECK(setenv("TZ", "EST5", 1) == 0);
	tzset();
	CHECK(!strcmp(ctime(&t), asctime(localtime(&t))));
	localtime_r(&t, &tm);
	CHECK(!strcmp(ctime(&t), asctime_r(&tm, abuf)));

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
}

/* ctime.html ERRORS: "No errors are defined." -- ctime_r's failure
 * mode (NULL) is only reachable through localtime_r()'s own EOVERFLOW,
 * which test_gmtime_overflow already exercises for localtime_r
 * directly; confirm ctime_r propagates it rather than crashing. */
static void test_ctime_r_overflow_propagates(void)
{
	time_t huge = LLONG_MAX;
	char buf[32];

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
	CHECK(ctime_r(&huge, buf) == NULL);
	CHECK(ctime(&huge) == NULL);
}

/* asctime.html: the example format is exactly 26 bytes including the
 * terminating NUL ("Sun Sep 16 01:03:52 1973\n\0"); asctime_r()
 * requires "at least 26 bytes". Confirm an exactly-26-byte buffer is
 * sufficient (test/time.c already checks strlen()==25 into a 32-byte
 * buffer; this pins the exact-fit boundary). */
static void test_asctime_r_exact_buffer(void)
{
	struct tm tm;
	time_t t = 0;
	char buf[26];

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
	gmtime_r(&t, &tm);
	CHECK(asctime_r(&tm, buf) == buf);
	CHECK(!strcmp(buf, "Thu Jan  1 00:00:00 1970\n"));
	CHECK(strlen(buf) + 1 == 26);
}

/* strptime.html: the conversion table includes "%C - All but the last
 * two digits of the year {2}" as a base (non-locale-alternate)
 * conversion, alongside %y for the low two digits.
 *
 * BUG: src/time/strptime.c has no case for '%C' (confirmed by
 * inspection: its switch handles c/D/x/F/r/R/T/X/Y/y/m/d/e/H/I/M/S/j/
 * u/w/a/A/b/B/h/p/z/Z/n/t/%, and falls through to `default: return
 * NULL` for anything else) -- any format using %C is rejected outright.
 * Confirmed live: strptime("19", "%C", &tm) returns NULL. */
static void test_strptime_century(void)
{
	struct tm tm;
	char *end;

	memset(&tm, 0, sizeof tm);
	end = strptime("1970", "%C%y", &tm);
	CHECK(end != NULL && *end == 0);
	CHECK(tm.tm_year == 70);
}

/* strptime.html RETURN VALUE: "Upon successful completion, strptime()
 * shall return a pointer to the character following the last character
 * parsed." -- already exercised extensively in test/time.c via
 * strftime/strptime round-trips; add the DESCRIPTION clause that a
 * literal '%' in the format must match a literal '%' in the input
 * (%% conversion) even embedded mid-format, and that ordinary
 * whitespace characters in the format consume runs of input whitespace
 * of any length including zero (already covered for one case in
 * test/time.c; this covers a run of several).
 */
static void test_strptime_literal_percent_and_ws_run(void)
{
	struct tm tm;
	char *end;

	memset(&tm, 0, sizeof tm);
	end = strptime("31%done", "%d%%done", &tm);
	CHECK(end && *end == 0 && tm.tm_mday == 31);

	memset(&tm, 0, sizeof tm);
	end = strptime("2000\t\t  \n02", "%Y %m", &tm);
	CHECK(end && *end == 0 && tm.tm_year == 100 && tm.tm_mon == 1);
}

#if SPICULE_TEST(PASS, posix_time_tzname_dst_designation) /* BUG: tzname[1] is always tzname[0]; TZ's DST designation is
	 * never parsed.  tzset.html DESCRIPTION: "The tzset() function
	 * shall set the external variable tzname as follows:
	 *
	 *     tzname[0] = "std";
	 *     tzname[1] = "dst";
	 *
	 * where std and dst are as described in XBD Chapter 8."  XBD Ch. 8
	 * gives TZ the form `std offset dst[offset][,start[/time],
	 * end[/time]]` and describes dst as "no less than three, nor more
	 * than {TZNAME_MAX}, bytes that are the designation for the
	 * corresponding Daylight Saving Time (DST) timezone".
	 *
	 * Mechanism: src/time/tzset.c reads one name into one buffer and
	 * then does
	 *
	 *     tzname[0] = tzname[1] = __tzname_buf;
	 *
	 * The parse moves on to the offset and never comes back for the
	 * dst field, so the two entries are the same pointer for every TZ
	 * value.
	 *
	 * This is separable from the DST deviation the file's banner does
	 * document.  That one is about *rules*: no transition dates are
	 * parsed, so `daylight` is always 0 and localtime() never shifts --
	 * and neither of those is disputed here.  tzname[1] is not a rule.
	 * It is a literal string sitting in the TZ value the caller
	 * supplied, requiring no zone database, no transition arithmetic
	 * and no change to timezone, daylight or localtime().  An
	 * application that reports its zone as tzname[daylight], or logs
	 * both names, gets the standard-time name where the DST name is
	 * required.
	 *
	 * The ledger's tzset row claims tzname[0]/[1] is covered; no test
	 * in the tree asserts tzname[1] at all.
	 *
	 * Re-enable when tzset() parses the dst designation. */
static void test_tzname_dst_designation(void)
{
	CHECK(setenv("TZ", "EST5EDT", 1) == 0);
	tzset();
	CHECK(!strcmp(tzname[0], "EST"));
	CHECK(!strcmp(tzname[1], "EDT"));

	CHECK(setenv("TZ", "CET-1CEST", 1) == 0);
	tzset();
	CHECK(!strcmp(tzname[0], "CET"));
	CHECK(!strcmp(tzname[1], "CEST"));

	/* with a rule suffix, which changes nothing about the designations */
	CHECK(setenv("TZ", "PST8PDT,M3.2.0,M11.1.0", 1) == 0);
	tzset();
	CHECK(!strcmp(tzname[0], "PST"));
	CHECK(!strcmp(tzname[1], "PDT"));

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
}
#endif

/* tzset.html DESCRIPTION: "The daylight variable shall be set to 0 if
 * Daylight Savings Time conversions should never be applied ...
 * otherwise it shall be set to a non-zero value." spicule's tzset() has
 * no DST ruleset at all (src/time/tzset.c), so daylight is always 0,
 * for every TZ value including ones with a DST suffix -- already
 * covered for one such TZ in test/time.c (PST8PDT,M3.2.0,M11.1.0);
 * add the plain "name+DST-name" form without a rule suffix. */
static void test_tzset_daylight_always_zero(void)
{
	CHECK(setenv("TZ", "CET-1CEST", 1) == 0);
	tzset();
	CHECK(daylight == 0);
	CHECK(timezone == -1 * 3600);
	CHECK(!strcmp(tzname[0], "CET"));

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
}

/* timespec_get: C11 (and POSIX.1-2024, not POSIX.1-2017 base -- see
 * https://man7.org/linux/man-pages/man3/timespec_get.3.html); spicule
 * still declares it in <time.h>. "returns the nonzero base if it is a
 * supported time base ... or 0 otherwise." test/time.c already checks
 * TIME_UTC success and an unsupported-base failure; add that ts is left
 * alone on failure (unspecified by the standard, but worth pinning
 * spicule's actual behaviour) and that repeated calls are monotonic
 * non-decreasing along with CLOCK_REALTIME. */
static void test_timespec_get_matches_realtime(void)
{
	struct timespec ts, rt;

	CHECK(timespec_get(&ts, TIME_UTC) == TIME_UTC);
	CHECK(clock_gettime(CLOCK_REALTIME, &rt) == 0);
	CHECK(rt.tv_sec >= ts.tv_sec && rt.tv_sec - ts.tv_sec <= 5);
}

/* ---- strftime.html conversion-specifier table: %U, %W, %V, %G, %g
 * (the ISO-8601 week-number family), now implemented in
 * src/time/strftime.c using the ISO-week arithmetic in
 * src/time/time_impl.h (__iso_week()/__iso_weeks_in_year()).
 *
 * Definitions (quoted from strftime.html's conversion table):
 *   %U: "week number of the year as a decimal number [00,53]. The
 *       first Sunday of January is the first day of week 1; days in
 *       the new year before this are in week 0."
 *   %W: same, but "The first Monday of January is the first day of
 *       week 1."
 *   %V: "week number of the year (Monday as the first day of the
 *       week) ... [01,53]. If the week containing 1 January has four
 *       or more days in the new year, then it is considered week 1.
 *       Otherwise, it is the last week of the previous year, and the
 *       next week is week 1. Both January 4th and the first Thursday
 *       of January are always in week 1."
 *   %G: "the week-based year ... as a decimal number".
 *   %g: "the last 2 digits of the week-based year ... [00,99]."
 *
 * Every expected value below was independently computed with GNU
 * coreutils `date -u -d @<epoch> +%U/%W/%V/%G/%g` (glibc's strftime),
 * not derived from spicule or from memory. */
#if SPICULE_TEST(PASS, posix_time_strftime_iso_week_thursday_years) /* BUG: %V/%G/%g lose a week in every year that begins on a
	 * Thursday.  strftime.html's %V entry: "Replaced by the week number
	 * of the year (Monday as the first day of the week) as a decimal
	 * number [01,53].  If the week containing 1 January has four or
	 * more days in the new year, then it is considered week 1.
	 * Otherwise, it is the last week of the previous year, and the next
	 * week is week 1.  Both January 4th and the first Thursday of
	 * January are always in week 1."  %G and %g carry the same
	 * week-based year.
	 *
	 * Mechanism: src/time/time_impl.h's __iso_week() computes
	 *
	 *     week = (yday - isodow + 10) / 7;
	 *
	 * The standard ISO-week-from-ordinal-date formula its comment cites
	 * takes a *1-based* ordinal day of year.  tm_yday is 0-based, so
	 * this evaluates floor((ordinal - isodow + 9) / 7) -- one less
	 * whenever (ordinal - isodow + 10) is a multiple of 7.  Within one
	 * year (ordinal - isodow) is constant across a week and steps by 7,
	 * so that congruence holds for every date in a year or for none of
	 * them: precisely the years whose 1 January is a Thursday.  The
	 * trailing comment "always > 0" is wrong for the same reason --
	 * yday = 0 with isodow = 7 gives 0 -- and the `week < 1` arm below
	 * it then absorbs the error into "last week of the previous year",
	 * which is why it produces a plausible answer instead of an obvious
	 * one.
	 *
	 * 1970, 1976, 1981, 1987, 1998, 2004, 2009, 2015, 2026, 2032 and
	 * 2037 all start on a Thursday.  The existing reference instants in
	 * test_strftime_week_number_family() are in 2000 (Saturday) and
	 * 2001 (Monday), which is why they pass.
	 *
	 * Re-enable when __iso_week() is given the 1-based ordinal its
	 * formula expects. */
static void test_strftime_iso_week_thursday_years(void)
{
	struct tm tm;
	time_t t;
	char buf[16];

	/* 1970-01-01 is a Thursday, so it is the first Thursday of January
	 * and therefore in week 1 by the clause's own defining property. */
	t = 0;
	CHECK(gmtime_r(&t, &tm) != 0);
	CHECK(strftime(buf, sizeof buf, "%V", &tm) == 2 && !strcmp(buf, "01"));
	CHECK(strftime(buf, sizeof buf, "%G", &tm) == 4 && !strcmp(buf, "1970"));
	CHECK(strftime(buf, sizeof buf, "%g", &tm) == 2 && !strcmp(buf, "70"));

	/* 2015-12-31, also a Thursday: 2015 began on a Thursday, so it is a
	 * 53-week ISO year and this is week 53 of it -- the upper end of
	 * the [01,53] range the clause names. */
	t = 1451520000;
	CHECK(gmtime_r(&t, &tm) != 0);
	CHECK(strftime(buf, sizeof buf, "%V", &tm) == 2 && !strcmp(buf, "53"));
	CHECK(strftime(buf, sizeof buf, "%G", &tm) == 4 && !strcmp(buf, "2015"));

	/* 2026-01-01, a Thursday: week 1 of 2026, not week 52 of 2025. */
	t = 1767225600;
	CHECK(gmtime_r(&t, &tm) != 0);
	CHECK(strftime(buf, sizeof buf, "%V", &tm) == 2 && !strcmp(buf, "01"));
	CHECK(strftime(buf, sizeof buf, "%G", &tm) == 4 && !strcmp(buf, "2026"));
}
#endif

static void test_strftime_week_number_family(void)
{
	struct tm tm;
	time_t t;
	char buf[16];

	/* 2000-02-29 (Tuesday), tm_yday=59: also the instant test/time.c
	 * already pins the pass-through behaviour for, so the two files'
	 * reference values are directly comparable. */
	t = 951782400;
	CHECK(gmtime_r(&t, &tm) != 0);
	CHECK(strftime(buf, sizeof buf, "%U", &tm) == 2 && !strcmp(buf, "09"));
	CHECK(strftime(buf, sizeof buf, "%W", &tm) == 2 && !strcmp(buf, "09"));
	CHECK(strftime(buf, sizeof buf, "%V", &tm) == 2 && !strcmp(buf, "09"));
	CHECK(strftime(buf, sizeof buf, "%G", &tm) == 4 && !strcmp(buf, "2000"));
	CHECK(strftime(buf, sizeof buf, "%g", &tm) == 2 && !strcmp(buf, "00"));

	/* 2000-01-01 (Saturday): before the year's first Sunday/Monday, so
	 * %U and %W both fall in week 0; 1 January's Monday-Sunday week
	 * has fewer than four days in the new year, so the ISO week-based
	 * year (%G/%g) is 1999, not 2000, and %V is that year's week 52. */
	t = 946684800;
	CHECK(gmtime_r(&t, &tm) != 0);
	CHECK(strftime(buf, sizeof buf, "%U", &tm) == 2 && !strcmp(buf, "00"));
	CHECK(strftime(buf, sizeof buf, "%W", &tm) == 2 && !strcmp(buf, "00"));
	CHECK(strftime(buf, sizeof buf, "%V", &tm) == 2 && !strcmp(buf, "52"));
	CHECK(strftime(buf, sizeof buf, "%G", &tm) == 4 && !strcmp(buf, "1999"));
	CHECK(strftime(buf, sizeof buf, "%g", &tm) == 2 && !strcmp(buf, "99"));

	/* 2001-01-08 (Monday): the one reference instant where %U and %W
	 * actually diverge (the year's first Sunday, week 1 under %U,
	 * hasn't happened yet; the first Monday, week 1 under %W, has, so
	 * this is already %W's week 2) -- pins that they are genuinely two
	 * different algorithms, not aliases of each other. */
	t = 978912000;
	CHECK(gmtime_r(&t, &tm) != 0);
	CHECK(strftime(buf, sizeof buf, "%U", &tm) == 2 && !strcmp(buf, "01"));
	CHECK(strftime(buf, sizeof buf, "%W", &tm) == 2 && !strcmp(buf, "02"));
	CHECK(strftime(buf, sizeof buf, "%V", &tm) == 2 && !strcmp(buf, "02"));
}

/* ---- getdate.html: real getdate() reads the file named by $DATEMSK, a
 * newline-separated list of strptime templates, tries each against the
 * argument, and defaults any field a matched template didn't set to
 * "today"'s corresponding value.  src/time/getdate.c now implements
 * $DATEMSK (when set, ERRORS code 2 when it can't be opened), ERRORS
 * code 1 when it is unset/empty, today-defaulting, and ERRORS code 8;
 * see that file's header comment for the one remaining imprecision
 * (code 1 reused for a null/empty s too) and why it is out of this
 * fence's scope. */
/* One shared $DATEMSK template file for most of test_getdate() below --
 * every format its calls need, one per line, per getdate.html
 * DESCRIPTION's "newline-separated list of templates, tried in order".
 * Two sub-blocks below need $DATEMSK pointed elsewhere for a moment
 * (a nonexistent path for ERRORS code 2, a second real file to prove
 * that ONLY its own templates apply once $DATEMSK is set) and restore
 * this one afterward. */
#define POSIX_DATEMSK_PATH "t-posix-datemsk.tmpl"
static void write_posix_datemsk(void)
{
	FILE *tf = fopen(POSIX_DATEMSK_PATH, "w");
	CHECK(tf != 0);
	if (tf) {
		fputs("%Y-%m-%d %H:%M:%S\n"
		      "%Y-%m-%d\n"
		      "%H:%M\n", tf);
		CHECK(fclose(tf) == 0);
	}
	CHECK(setenv("DATEMSK", POSIX_DATEMSK_PATH, 1) == 0);
}

#if SPICULE_TEST(PASS, posix_time_getdate_no_datemsk_must_fail) /* getdate.html ERRORS code 1 -- "The DATEMSK environment variable
	is null or undefined" -- is now implemented for real:
	src/time/getdate.c no longer falls back to a built-in template
	list when $DATEMSK is unset (see that file's header comment for
	what changed and why test/time.c's own getdate coverage, the
	thing that used to depend on the fallback, no longer does).  At
	file scope rather than nested in test_getdate() (a NESTED
	function definition is not valid C -- tcc rejects it outright,
	"function without file scope cannot be static", which is what
	the old UNIMPL disposition's own required compile failure was
	actually testing rather than the clause's absence, discovered
	while turning this into a PASS): test-policy.py's pedantic probe
	finds this definition by name and appends a call to it at the
	very end of main() (see that tool's own transformed_source()),
	after test_getdate() has already returned, so unsetting $DATEMSK
	here does not disturb anything there. */
static void test_getdate_no_datemsk_must_fail(void)
{
	unsetenv("DATEMSK");
	getdate_err = 0;
	CHECK(getdate("2000-01-02 03:04:05") == 0);
	CHECK(getdate_err == 1);
}
#endif

static void test_getdate(void)
{
	struct tm *tm;

	/* getdate.html DESCRIPTION: "getdate() shall use the value of the
	 * DATEMSK environment variable to locate a template file", tried
	 * in order against the input. */
	write_posix_datemsk();

	tm = getdate("2000-01-02 03:04:05");
	CHECK(tm != 0);
	if (tm) {
		CHECK(tm->tm_year == 100 && tm->tm_mon == 0 && tm->tm_mday == 2);
		CHECK(tm->tm_hour == 3 && tm->tm_min == 4 && tm->tm_sec == 5);
		CHECK(tm->tm_wday == 0); /* 2000-01-02 was a Sunday */
	}

	/* getdate.html error table, code 7: "No line in the template file
	 * matches the input date/time specification" -- none of
	 * POSIX_DATEMSK_PATH's three lines matches this input. */
	tm = getdate("not a date at all, definitely no template matches this");
	CHECK(tm == 0 && getdate_err == 7);

	/* getdate.html ERRORS code 2, "The template file ... cannot be
	 * opened for reading". */
	CHECK(setenv("DATEMSK", "/nonexistent/path/that/does/not/exist", 1) == 0);
	tm = getdate("2000-01-02 03:04:05");
	CHECK(tm == 0 && getdate_err == 2);

	/* $DATEMSK naming a DIFFERENT real template file: only ITS
	 * templates apply -- POSIX_DATEMSK_PATH's are not consulted at all
	 * once $DATEMSK points elsewhere, matching DESCRIPTION's "the
	 * template file" (singular, the one $DATEMSK currently names). */
	{
		char t[] = "datemsk-XXXXXX";
		int fd = mkstemp(t);
		CHECK(fd >= 0);
		if (fd >= 0) {
			static const char tpl[] = "%Y/%m/%d %H:%M\n";
			CHECK(write(fd, tpl, sizeof tpl - 1) == (ssize_t)(sizeof tpl - 1));
			CHECK(close(fd) == 0);
			CHECK(setenv("DATEMSK", t, 1) == 0);

			tm = getdate("2000/01/02 03:04");
			CHECK(tm != 0);
			if (tm) {
				CHECK(tm->tm_year == 100 && tm->tm_mon == 0 && tm->tm_mday == 2);
				CHECK(tm->tm_hour == 3 && tm->tm_min == 4);
			}

			/* POSIX_DATEMSK_PATH's own "%Y-%m-%d %H:%M:%S" no longer
			 * matches while $DATEMSK points at this file instead. */
			tm = getdate("2000-01-02 03:04:05");
			CHECK(tm == 0 && getdate_err == 7);

			unlink(t);
		}
	}

	/* Back to the shared template file for the rest of this function. */
	CHECK(setenv("DATEMSK", POSIX_DATEMSK_PATH, 1) == 0);

	/* getdate.html DESCRIPTION: "elements of the [struct tm] that are
	 * not specified by the [matched] template ... shall be set the
	 * same as their equivalents in the current time and date." --
	 * src/time/getdate.c seeds the working struct tm from
	 * localtime_r()'s "now" before running strptime(), so the
	 * "%H:%M"-only line in POSIX_DATEMSK_PATH leaves the date fields
	 * at today's values. */
	{
		time_t now = time(0);
		struct tm today;
		CHECK(gmtime_r(&now, &today) != 0);
		tm = getdate("13:45");
		CHECK(tm != 0);
		if (tm) {
			CHECK(tm->tm_hour == 13 && tm->tm_min == 45);
			CHECK(tm->tm_year == today.tm_year && tm->tm_mon == today.tm_mon && tm->tm_mday == today.tm_mday);
		}
	}

	/* getdate.html ERRORS code 8: "The input date is not valid, but
	 * ... syntactically correct" (the page's own example is exactly
	 * this: February 31).  src/time/getdate.c range-checks tm_mday
	 * against the actual days in tm_mon (time_impl.h's civil-calendar
	 * arithmetic) before mktime() gets a chance to normalize it
	 * forward -- POSIX_DATEMSK_PATH's "%Y-%m-%d" line matches this
	 * input's syntax, which is exactly what code 8 requires. */
	tm = getdate("2000-02-31");
	CHECK(tm == 0 && getdate_err == 8);

	CHECK(unsetenv("DATEMSK") == 0);
	unlink(POSIX_DATEMSK_PATH);
}

/* ---- nanosleep.html: audited under unistd.h, not here.  Confirmed by
 * inspection: nanosleep() lives in src/unistd/sleep.c (grouped there,
 * not under src/time/), and test/unistd.c exercises it (sanity-checked
 * against CLOCK_MONOTONIC elapsed time, same file as the rest of
 * <unistd.h>'s sleep family); test/POSIX-COVERAGE.md's time.h section
 * cross-references the same split ("nanosleep -- src/unistd/sleep.c --
 * see unistd.h section below").  Nothing to add here: duplicating the
 * same clause-by-clause pass under time.h as well would just be two
 * copies of the same test, not two different ones. */

int main(void)
{
	test_difftime_return_type();
	test_gmtime_overflow();
	test_mktime_ignores_wday_yday_input();
	test_mktime_overflow_returns_minus_one();
	test_clock_is_cpu_time_not_wall_time();
	test_clock_getres_cputime();
	test_clock_getres_null();
	test_clock_settime_bad_nsec();
	test_clock_nanosleep_einval();
	test_clock_nanosleep_relative();
	test_clock_nanosleep_monotonic_abstime();
	test_clock_nanosleep_realtime_abstime_past();
	test_ctime_equals_asctime_localtime();
	test_ctime_r_overflow_propagates();
	test_asctime_r_exact_buffer();
	test_strptime_century();
	test_strptime_literal_percent_and_ws_run();
	test_tzset_daylight_always_zero();
	test_timespec_get_matches_realtime();
	test_strftime_week_number_family();
	test_getdate();

	if (!fails) printf("posix-time: all tests passed\n");
	return fails != 0;
}
