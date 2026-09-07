/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#if defined(__linux__)
#include <sched.h>
#include <sys/mman.h>
#endif
#include "../src/internal/libc.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
/* setitimer()/ualarm() real-repeat-delivery tests' own SIGALRM handler:
 * a signal handler must be a real, file-scope function, so the counter
 * it bumps lives here too rather than as a local in main(). */
static volatile sig_atomic_t alarm_hit_count;
static void alarm_hit(int sig) { (void)sig; alarm_hit_count++; }
#endif

struct known {
	long long t;
	int year, mon, mday, hour, min, sec, wday, yday;
};

/* Fixed epochs with independently known broken-down values. */
static const struct known known[] = {
	{ 0LL,            1970,  0,  1,  0,  0,  0, 4,   0 },  /* Thu 1970-01-01 */
	{ 951782400LL,    2000,  1, 29,  0,  0,  0, 2,  59 },  /* Tue 2000-02-29 (leap) */
	{ 1078012800LL,   2004,  1, 29,  0,  0,  0, 0,  59 },  /* Sun 2004-02-29 */
	{ 2147483647LL,   2038,  0, 19,  3, 14,  7, 2,  18 },  /* Tue 2038-01-19 */
	{ -1LL,           1969, 11, 31, 23, 59, 59, 3, 364 },  /* Wed 1969-12-31 */
	{ -86400LL,       1969, 11, 31,  0,  0,  0, 3, 364 },
	{ -2208988800LL,  1900,  0,  1,  0,  0,  0, 1,   0 },  /* Mon 1900-01-01 */
	{ 946684799LL,    1999, 11, 31, 23, 59, 59, 5, 364 },  /* Fri */
	{ 946684800LL,    2000,  0,  1,  0,  0,  0, 6,   0 },  /* Sat */
	{ 978307199LL,    2000, 11, 31, 23, 59, 59, 0, 365 },  /* Sun, leap year has 366 days */
	{ 978307200LL,    2001,  0,  1,  0,  0,  0, 1,   0 },  /* Mon */
	{ 1709164800LL,   2024,  1, 29,  0,  0,  0, 4,  59 },  /* Thu 2024-02-29 */
	{ 4102444800LL,   2100,  0,  1,  0,  0,  0, 5,   0 },  /* Fri 2100-01-01 */
	{ 4107456000LL,   2100,  1, 28,  0,  0,  0, 0,  58 },  /* 2100 not a leap year */
	{ 4107542400LL,   2100,  2,  1,  0,  0,  0, 1,  59 },
};

static void check_tm(const struct tm *tm, const struct known *k)
{
	CHECK(tm != NULL);
	if (!tm) return;
	CHECK(tm->tm_year + 1900 == k->year);
	CHECK(tm->tm_mon == k->mon);
	CHECK(tm->tm_mday == k->mday);
	CHECK(tm->tm_hour == k->hour);
	CHECK(tm->tm_min == k->min);
	CHECK(tm->tm_sec == k->sec);
	CHECK(tm->tm_wday == k->wday);
	CHECK(tm->tm_yday == k->yday);
	CHECK(tm->tm_isdst == 0);
}

static void test_nt_tick_extremes(void)
{
	long long ticks, sec;
	long nsec;

	/* Kernel timestamps normally describe real dates, but these helpers
	 * are the trust boundary for raw signed LARGE_INTEGER values.  Both
	 * endpoints used to overflow while subtracting the NT epoch before
	 * division made the result small again. */
	CHECK(__ticks_to_unix_sec(LLONG_MIN) == -933981677285LL);
	CHECK(__ticks_to_unix_nsec(LLONG_MIN) == -477580800L);
	CHECK(__ticks_to_unix_sec(LLONG_MAX) == 910692730085LL);
	CHECK(__ticks_to_unix_nsec(LLONG_MAX) == 477580700L);
	CHECK(__ticks_to_unix_sec(__TICKS_1601_TO_1970 - 1) == 0);
	CHECK(__ticks_to_unix_nsec(__TICKS_1601_TO_1970 - 1) == -100L);
	CHECK(__ticks_to_unix_sec(__TICKS_1601_TO_1970 + 1) == 0);
	CHECK(__ticks_to_unix_nsec(__TICKS_1601_TO_1970 + 1) == 100L);

	/* Process times and performance counters are signed NT fields.  A
	 * successful but malformed kernel response must be rejected without
	 * overflowing, dividing by zero, or constructing an invalid timespec. */
	CHECK(__clock_combine_cpu_ticks(0, 0, &ticks) && ticks == 0);
	CHECK(__clock_combine_cpu_ticks(LLONG_MAX, 0, &ticks) &&
	      ticks == LLONG_MAX);
	CHECK(!__clock_combine_cpu_ticks(-1, 0, &ticks));
	CHECK(!__clock_combine_cpu_ticks(0, -1, &ticks));
	CHECK(!__clock_combine_cpu_ticks(LLONG_MAX, 1, &ticks));

	CHECK(__clock_qpc_to_timespec(10000001, 10000000, &sec, &nsec) &&
	      sec == 1 && nsec == 100);
	CHECK(__clock_qpc_to_timespec(LLONG_MAX - 1, LLONG_MAX, &sec, &nsec) &&
	      sec == 0 && nsec == 999999999L);
	CHECK(!__clock_qpc_to_timespec(-1, 1, &sec, &nsec));
	CHECK(!__clock_qpc_to_timespec(0, 0, &sec, &nsec));
	CHECK(!__clock_qpc_to_timespec(0, -1, &sec, &nsec));

	CHECK(__clock_qpc_resolution(1, &sec, &nsec) &&
	      sec == 1 && nsec == 0);
	CHECK(__clock_qpc_resolution(2, &sec, &nsec) &&
	      sec == 0 && nsec == 500000000L);
	CHECK(__clock_qpc_resolution(LLONG_MAX, &sec, &nsec) &&
	      sec == 0 && nsec == 1);
	CHECK(!__clock_qpc_resolution(0, &sec, &nsec));
	CHECK(!__clock_qpc_resolution(-1, &sec, &nsec));
}

static void fill(struct tm *tm, int y, int mo, int d, int h, int mi, int s)
{
	memset(tm, 0, sizeof *tm);
	tm->tm_year = y - 1900;
	tm->tm_mon = mo;
	tm->tm_mday = d;
	tm->tm_hour = h;
	tm->tm_min = mi;
	tm->tm_sec = s;
}

int main(void)
{
	size_t i;
	char buf[128];
	test_nt_tick_extremes();

	/* Per-process timers: cover all five entry points without depending
	 * on scheduler timing or asynchronous signal delivery. */
	{
		struct sigevent ev;
		struct itimerspec set, old, current;
		timer_t timer;

		memset(&ev, 0, sizeof ev);
		ev.sigev_notify = SIGEV_NONE;
		CHECK(timer_create(CLOCK_MONOTONIC, &ev, &timer) == 0);
		CHECK(timer_gettime(timer, &current) == 0);
		CHECK(current.it_value.tv_sec == 0 && current.it_value.tv_nsec == 0);
		CHECK(current.it_interval.tv_sec == 0 && current.it_interval.tv_nsec == 0);
		memset(&set, 0, sizeof set);
		set.it_value.tv_sec = 10;
		set.it_interval.tv_sec = 2;
		CHECK(timer_settime(timer, 0, &set, &old) == 0);
		CHECK(old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
		CHECK(timer_gettime(timer, &current) == 0);
		CHECK(current.it_value.tv_sec >= 9 && current.it_value.tv_sec <= 10);
		CHECK(current.it_interval.tv_sec == 2 && current.it_interval.tv_nsec == 0);
		CHECK(timer_getoverrun(timer) == 0);
		CHECK(timer_delete(timer) == 0);
		errno = 0;
		CHECK(timer_delete(timer) == -1 && errno == EINVAL);
	}

	CHECK(setenv("TZ", "UTC0", 1) == 0);
	tzset();
	CHECK(timezone == 0);
	CHECK(daylight == 0);
	CHECK(!strcmp(tzname[0], "UTC"));

	/* gmtime / localtime (TZ=UTC0) against known epochs */
	for (i = 0; i < sizeof known / sizeof *known; i++) {
		time_t t = (time_t)known[i].t;
		struct tm tm, *p;
		p = gmtime(&t);
		check_tm(p, &known[i]);
		CHECK(gmtime_r(&t, &tm) == &tm);
		check_tm(&tm, &known[i]);
		p = localtime(&t);
		check_tm(p, &known[i]);
		CHECK(localtime_r(&t, &tm) == &tm);
		check_tm(&tm, &known[i]);
		/* round-trips */
		gmtime_r(&t, &tm);
		CHECK(timegm(&tm) == t);
		check_tm(&tm, &known[i]);
		localtime_r(&t, &tm);
		CHECK(mktime(&tm) == t);
		check_tm(&tm, &known[i]);
	}

	/* yday over a whole leap year and non-leap year is consecutive */
	{
		time_t t;
		struct tm tm;
		int expect = 0;
		for (t = 946684800; t < 978307200; t += 86400) {   /* 2000 */
			gmtime_r(&t, &tm);
			CHECK(tm.tm_yday == expect++);
		}
		CHECK(expect == 366);
		expect = 0;
		for (t = 978307200; t < 1009843200; t += 86400) {  /* 2001 */
			gmtime_r(&t, &tm);
			CHECK(tm.tm_yday == expect++);
		}
		CHECK(expect == 365);
	}

	/* mktime / timegm normalisation */
	{
		struct tm tm;

		fill(&tm, 2000, 13, 1, 0, 0, 0);        /* month 13 -> Feb 2001 */
		CHECK(timegm(&tm) == 980985600);
		CHECK(tm.tm_year == 101 && tm.tm_mon == 1 && tm.tm_mday == 1);

		fill(&tm, 2000, 2, 0, 0, 0, 0);         /* day 0 of March -> Feb 29 */
		CHECK(timegm(&tm) == 951782400);
		CHECK(tm.tm_mon == 1 && tm.tm_mday == 29 && tm.tm_wday == 2 && tm.tm_yday == 59);

		fill(&tm, 1999, 11, 31, 25, 0, 0);      /* hour 25 -> Jan 1 01:00 */
		CHECK(timegm(&tm) == 946688400);
		CHECK(tm.tm_year == 100 && tm.tm_mon == 0 && tm.tm_mday == 1 && tm.tm_hour == 1);

		fill(&tm, 1970, 0, 1, 0, 0, -1);        /* sec -1 -> 1969-12-31 23:59:59 */
		CHECK(timegm(&tm) == -1);
		CHECK(tm.tm_year == 69 && tm.tm_mon == 11 && tm.tm_mday == 31 && tm.tm_hour == 23 && tm.tm_min == 59 && tm.tm_sec == 59);

		fill(&tm, 1970, -1, 1, 0, 0, 0);        /* month -1 -> Dec 1969 */
		CHECK(timegm(&tm) == -2678400);
		CHECK(tm.tm_year == 69 && tm.tm_mon == 11);

		fill(&tm, 1970, 0, 1, 0, 0, 0);
		tm.tm_mon = 24; tm.tm_mday = 32; tm.tm_min = 61;
		CHECK(timegm(&tm) == timegm(&tm));
		CHECK(tm.tm_year == 72 && tm.tm_mon == 1 && tm.tm_mday == 1 && tm.tm_hour == 1 && tm.tm_min == 1);

		/* same through mktime under UTC */
		fill(&tm, 2000, 13, 1, 0, 0, 0);
		CHECK(mktime(&tm) == 980985600);
		fill(&tm, 2000, 2, 0, 0, 0, 0);
		CHECK(mktime(&tm) == 951782400);
		fill(&tm, 1999, 11, 31, 25, 0, 0);
		CHECK(mktime(&tm) == 946688400);
		fill(&tm, 1970, 0, 1, 0, 0, -1);
		CHECK(mktime(&tm) == -1);
		CHECK(tm.tm_wday == 3 && tm.tm_yday == 364);
	}

	/* strftime */
	{
		struct tm tm;
		time_t t = 951782400 + 13 * 3600 + 5 * 60 + 9;   /* 2000-02-29 13:05:09 Tue */
		size_t n;

		gmtime_r(&t, &tm);
#define FMT(f, expect) do { \
		memset(buf, 'x', sizeof buf); \
		n = strftime(buf, sizeof buf, f, &tm); \
		CHECK(n == strlen(expect)); \
		CHECK(!strcmp(buf, expect)); \
		if (strcmp(buf, expect)) printf("  %s -> \"%s\" (want \"%s\")\n", f, buf, expect); \
	} while (0)
		FMT("%Y", "2000");
		FMT("%m", "02");
		FMT("%d", "29");
		FMT("%H", "13");
		FMT("%M", "05");
		FMT("%S", "09");
		FMT("%j", "060");
		FMT("%a", "Tue");
		FMT("%A", "Tuesday");
		FMT("%b", "Feb");
		FMT("%h", "Feb");
		FMT("%B", "February");
		FMT("%y", "00");
		FMT("%C", "20");
		FMT("%e", "29");
		FMT("%p", "PM");
		FMT("%I", "01");
		FMT("%Z", "UTC");
		FMT("%z", "+0000");
		FMT("%%", "%");
		FMT("%F", "2000-02-29");
		FMT("%012F", "002000-02-29");
		FMT("%03C", "020");
		FMT("%+5Y", "+2000");
		FMT("%s", "951829509");
		FMT("%T", "13:05:09");
		FMT("%D", "02/29/00");
		FMT("%R", "13:05");
		FMT("%r", "01:05:09 PM");
		FMT("%x", "02/29/00");
		FMT("%X", "13:05:09");
		FMT("%c", "Tue Feb 29 13:05:09 2000");
		FMT("%u", "2");
		FMT("%w", "2");
		FMT("%n%t", "\n\t");
		FMT("", "");
		FMT("plain text", "plain text");
		FMT("%Y-%m-%dT%H:%M:%SZ", "2000-02-29T13:05:09Z");

		/* Fuzz run 33133459536, crash-b07ca7a157a73b30dad93f4ce2ad4f086357a7ee
		 * (Base64 ACVyJyVjsa5BJyVz): %s formats the negative epoch from
		 * this deliberately unnormalised struct tm.  Computing its magnitude
		 * must not rely on unsigned wraparound, which UBSan diagnoses. */
		memset(&tm, 0, sizeof tm);
		tm.tm_sec = -8; tm.tm_min = -16; tm.tm_hour = -8;
		tm.tm_mday = -8; tm.tm_mon = -64; tm.tm_year = -384;
		tm.tm_wday = -64; tm.tm_yday = -64;
		n = strftime(buf, sizeof buf, "%s", &tm);
		CHECK(n > 1 && buf[0] == '-');

		/* Fuzz run 33134051092, crash-6a40031ce286bfd536c454bfe579a43d8a634350:
		 * parsing an unbounded field width must not overflow int, and applying
		 * one must fail through the caller's buffer bound rather than overflow
		 * a fixed-size intermediate buffer. */
		n = strftime(buf, sizeof buf, "%3333333333g", &tm);
		CHECK(n == 2);
		n = strftime(buf, sizeof buf, "%3333333333Y", &tm);
		CHECK(n == 0);

		/* Fuzz run 33134496955, crash-222e7b9f782287564a38cfa4871a9b1dd2075cff:
		 * the same unbounded-field-width overflow as the pair above, but
		 * found again through a conversion (%X) that never even looks at
		 * the parsed width -- the int overflow happens while *parsing* the
		 * 102-digit run, in the width accumulator itself, before the
		 * switch on the conversion letter ever runs, so a specifier that
		 * discards its width is no protection against it. */
		n = strftime(buf, sizeof buf,
			"%X%111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111X%r",
			&tm);
		CHECK(n == 36 && !strcmp(buf, "-08:-16:-08-08:-16:-08-08:-16:-08 AM"));

		/* Fuzz run 33134256900, crash-0960a3fcb3369734eb77a4b2fe91551c9b963a70:
		 * same width-accumulator overflow, found through %r instead of %X. */
		memset(&tm, 0, sizeof tm);
		tm.tm_sec = 35; tm.tm_min = 5; tm.tm_hour = -7;
		n = strftime(buf, sizeof buf,
			"%r+%222222222222222222222222222222222222222r", &tm);
		CHECK(n == 25 && !strcmp(buf, "-07:05:35 AM+-07:05:35 AM"));

		/* Sunday: %u is 7, %w is 0; single-digit %e is space padded */
		t = 1078012800;   /* Sun 2004-02-29 */
		gmtime_r(&t, &tm);
		FMT("%u", "7");
		FMT("%w", "0");
		FMT("%a %A", "Sun Sunday");
		t = 0;
		gmtime_r(&t, &tm);
		FMT("%e", " 1");
		FMT("%c", "Thu Jan  1 00:00:00 1970");
		FMT("%I %p", "12 AM");
		FMT("%r", "12:00:00 AM");
		FMT("%j", "001");
		tm.tm_hour = 12;
		FMT("%I %p", "12 PM");
		tm.tm_hour = 23;
		FMT("%I %p", "11 PM");
		t = -2208988800LL;   /* 1900 */
		gmtime_r(&t, &tm);
		FMT("%Y %y %C", "1900 00 19");

		/* Week-number family. */
		t = 951782400;
		gmtime_r(&t, &tm);
		memset(buf, 0, sizeof buf);
		n = strftime(buf, sizeof buf, "%U", &tm);
		CHECK(n == 2);
		CHECK(!strcmp(buf, "%U") || !strcmp(buf, "09"));
		n = strftime(buf, sizeof buf, "%W", &tm);
		CHECK(!strcmp(buf, "%W") || !strcmp(buf, "09"));
		n = strftime(buf, sizeof buf, "%V", &tm);
		CHECK(!strcmp(buf, "%V") || !strcmp(buf, "09"));
		n = strftime(buf, sizeof buf, "%G", &tm);
		CHECK(!strcmp(buf, "%G") || !strcmp(buf, "2000"));
		n = strftime(buf, sizeof buf, "%s", &tm);
		CHECK(!strcmp(buf, "951782400"));

		/* width-limited buffers: too small returns 0, exact fit works */
		n = strftime(buf, 4, "%Y", &tm);
		CHECK(n == 0);
		n = strftime(buf, 5, "%Y", &tm);
		CHECK(n == 4 && !strcmp(buf, "2000"));
		n = strftime(buf, 1, "%Y", &tm);
		CHECK(n == 0);
		n = strftime(buf, 0, "%Y", &tm);
		CHECK(n == 0);
		n = strftime(buf, 1, "", &tm);
		CHECK(n == 0 && buf[0] == 0);
		n = strftime(buf, 10, "%F", &tm);
		CHECK(n == 0);
		n = strftime(buf, 11, "%F", &tm);
		CHECK(n == 10);
		n = strftime(buf, 3, "abcdef", &tm);
		CHECK(n == 0);

		/* strftime_l with a null locale behaves like strftime */
		n = strftime_l(buf, sizeof buf, "%F", &tm, (locale_t)0);
		CHECK(n == 10 && !strcmp(buf, "2000-02-29"));

		/* %z with a non-zero gmtoff */
		tm.__tm_gmtoff = -5 * 3600;
		FMT("%z", "-0500");
		tm.__tm_gmtoff = 5 * 3600 + 30 * 60;
		FMT("%z", "+0530");
		tm.__tm_zone = "EST";
		FMT("%Z", "EST");

		/* Every struct tm arithmetic input is caller-controlled.  Exercise
		 * both ends of each distinct expression so UBSan also runs these
		 * paths: signed magnitude, +1/+1900, week arithmetic, and %z's
		 * absolute offset. */
		memset(&tm, 0, sizeof tm);
		tm.tm_mday = INT_MIN;
		FMT("%d", "-2147483648");
		tm.tm_mon = INT_MAX;
		FMT("%m", "2147483648");
		tm.tm_mday = 0;
		tm.tm_year = INT_MAX;
		FMT("%D", "2147483648/00/47");
		tm.tm_yday = INT_MAX;
		tm.tm_wday = 0;
		FMT("%j", "2147483648");
		FMT("%U", "306783379");
		FMT("%W", "306783378");
		FMT("%V", "01");
		tm.__tm_gmtoff = LONG_MIN;
		FMT("%z", "-59652314");
#undef FMT
	}

	/* strptime parses back what strftime wrote */
	{
		struct tm tm, out;
		time_t t = 2147483647;   /* 2038-01-19 03:14:07 Tue */
		char *end;
		static const char *const fmts[] = {
			"%Y-%m-%d %H:%M:%S",
			"%a %b %e %H:%M:%S %Y",
			"%A, %B %d, %Y %I:%M:%S %p",
			"%d/%m/%y %H:%M",
			"%j %Y %H:%M:%S",
			"%H%M%S %d%m%Y",
			"%F %T",
			"%j %Y %T",
			"%c",
			"%D %R",
			"%Y%m%d%H%M%S",
		};

		gmtime_r(&t, &tm);
		for (i = 0; i < sizeof fmts / sizeof *fmts; i++) {
			size_t n = strftime(buf, sizeof buf, fmts[i], &tm);
			CHECK(n > 0);
			memset(&out, 0, sizeof out);
			out.tm_mday = 1;
			end = strptime(buf, fmts[i], &out);
			CHECK(end != NULL);
			if (!end) { printf("  strptime(\"%s\", \"%s\") failed\n", buf, fmts[i]); continue; }
			CHECK(*end == 0);
			CHECK(out.tm_year == tm.tm_year);
			if (strstr(fmts[i], "%j") == NULL) {
				CHECK(out.tm_mon == tm.tm_mon);
				CHECK(out.tm_mday == tm.tm_mday);
			} else {
				CHECK(out.tm_yday == tm.tm_yday);
			}
			CHECK(out.tm_hour == tm.tm_hour);
			CHECK(out.tm_min == tm.tm_min);
			if (strstr(fmts[i], "%S") || strstr(fmts[i], "%T") || strstr(fmts[i], "%c"))
				CHECK(out.tm_sec == tm.tm_sec);
			if (strstr(fmts[i], "%a") || strstr(fmts[i], "%A") || strstr(fmts[i], "%c"))
				CHECK(out.tm_wday == tm.tm_wday);
		}

		/* explicit values */
		memset(&out, 0, sizeof out);
		end = strptime("1970-01-01 00:00:00", "%Y-%m-%d %H:%M:%S", &out);
		CHECK(end && *end == 0);
		CHECK(out.tm_year == 70 && out.tm_mon == 0 && out.tm_mday == 1 && out.tm_hour == 0);
		CHECK(timegm(&out) == 0);

		memset(&out, 0, sizeof out);
		end = strptime("10.7.56 in 18th", "%d.%m.%y in %C th", &out);
		CHECK(end && *end == 0);
		CHECK(out.tm_year == 1856 - 1900 && out.tm_mon == 6 && out.tm_mday == 10);

		memset(&out, 0, sizeof out);
		end = strptime("683078400", "%s", &out);
		CHECK(end && *end == 0);
		CHECK(out.tm_year == 1991 - 1900 && out.tm_mon == 7 && out.tm_mday == 25);

		memset(&out, 0, sizeof out);
		end = strptime("Thursday January 1 1970", "%A %B %d %Y", &out);
		CHECK(end && *end == 0 && out.tm_wday == 4 && out.tm_mon == 0);

		/* case-insensitive names, abbreviation vs full */
		memset(&out, 0, sizeof out);
		end = strptime("tue FEB 29", "%a %b %d", &out);
		CHECK(end && *end == 0 && out.tm_wday == 2 && out.tm_mon == 1 && out.tm_mday == 29);

		/* %p handling */
		memset(&out, 0, sizeof out);
		end = strptime("12:30 AM", "%I:%M %p", &out);
		CHECK(end && out.tm_hour == 0 && out.tm_min == 30);
		memset(&out, 0, sizeof out);
		end = strptime("12:30 PM", "%I:%M %p", &out);
		CHECK(end && out.tm_hour == 12);
		memset(&out, 0, sizeof out);
		end = strptime("1:30 PM", "%I:%M %p", &out);
		CHECK(end && out.tm_hour == 13);

		/* %y pivot: 69..99 -> 19xx, 00..68 -> 20xx */
		memset(&out, 0, sizeof out);
		CHECK(strptime("69", "%y", &out) && out.tm_year == 69);
		CHECK(strptime("68", "%y", &out) && out.tm_year == 168);
		CHECK(strptime("99", "%y", &out) && out.tm_year == 99);
		CHECK(strptime("00", "%y", &out) && out.tm_year == 100);

		/* %z */
		memset(&out, 0, sizeof out);
		CHECK(strptime("-0500", "%z", &out) && out.__tm_gmtoff == -18000);
		CHECK(strptime("+05:30", "%z", &out) && out.__tm_gmtoff == 19800);
		CHECK(strptime("Z", "%z", &out) && out.__tm_gmtoff == 0);

		/* leftover input is returned, not an error */
		memset(&out, 0, sizeof out);
		end = strptime("2000-02-29 trailing", "%Y-%m-%d", &out);
		CHECK(end && !strcmp(end, " trailing"));

		/* whitespace in the format matches any amount (incl. none) of input space */
		memset(&out, 0, sizeof out);
		end = strptime("2000   02", "%Y %m", &out);
		CHECK(end && *end == 0 && out.tm_mon == 1);

		/* %% */
		memset(&out, 0, sizeof out);
		end = strptime("50%", "%S%%", &out);
		CHECK(end && *end == 0 && out.tm_sec == 50);

		/* garbage is rejected */
		memset(&out, 0, sizeof out);
		CHECK(strptime("garbage", "%Y-%m-%d", &out) == NULL);
		CHECK(strptime("2000-xx-29", "%Y-%m-%d", &out) == NULL);
		CHECK(strptime("2000/02/29", "%Y-%m-%d", &out) == NULL);
		CHECK(strptime("Xyzday", "%A", &out) == NULL);
		CHECK(strptime("Foo", "%b", &out) == NULL);
		CHECK(strptime("13:00 XM", "%H:%M %p", &out) == NULL);
		CHECK(strptime("", "%Y", &out) == NULL);
		CHECK(strptime("abc", "%Q", &out) == NULL);
		CHECK(strptime("2000", "%Y%", &out) == NULL);
		CHECK(strptime("5", "%%", &out) == NULL);
		CHECK(strptime("x", "%z", &out) == NULL);
	}

	/* asctime / ctime */
	{
		struct tm tm;
		time_t t = 0;
		char abuf[32];

		gmtime_r(&t, &tm);
		CHECK(!strcmp(asctime(&tm), "Thu Jan  1 00:00:00 1970\n"));
		CHECK(asctime_r(&tm, abuf) == abuf);
		CHECK(!strcmp(abuf, "Thu Jan  1 00:00:00 1970\n"));
		CHECK(strlen(abuf) == 25);
		CHECK(!strcmp(ctime(&t), "Thu Jan  1 00:00:00 1970\n"));
		CHECK(ctime_r(&t, abuf) == abuf);
		CHECK(!strcmp(abuf, "Thu Jan  1 00:00:00 1970\n"));

		t = 951782400 + 13 * 3600 + 5 * 60 + 9;
		CHECK(!strcmp(ctime(&t), "Tue Feb 29 13:05:09 2000\n"));
		t = 2147483647;
		CHECK(!strcmp(ctime(&t), "Tue Jan 19 03:14:07 2038\n"));
		t = -1;
		CHECK(!strcmp(ctime(&t), "Wed Dec 31 23:59:59 1969\n"));
		t = 1078012800;
		CHECK(!strcmp(ctime(&t), "Sun Feb 29 00:00:00 2004\n"));

		/* asctime and strftime %c agree */
		gmtime_r(&t, &tm);
		strftime(buf, sizeof buf, "%c\n", &tm);
		CHECK(!strcmp(buf, asctime(&tm)));
	}

	/* difftime */
	{
		CHECK(difftime(10, 3) == 7.0);
		CHECK(difftime(3, 10) == -7.0);
		CHECK(difftime(0, 0) == 0.0);
		CHECK(difftime(2147483647, -1) == 2147483648.0);
		CHECK(difftime(-5, -10) == 5.0);
		CHECK(difftime((time_t)1LL << 40, 0) == 1099511627776.0);
	}

	/* fixed-offset timezones */
	{
		struct tm tm;
		time_t t = 0, r;

		CHECK(setenv("TZ", "EST5", 1) == 0);
		tzset();
		CHECK(timezone == 5 * 3600);
		CHECK(daylight == 0);
		CHECK(!strcmp(tzname[0], "EST"));

		CHECK(localtime_r(&t, &tm) == &tm);
		CHECK(tm.tm_year == 69 && tm.tm_mon == 11 && tm.tm_mday == 31);
		CHECK(tm.tm_hour == 19 && tm.tm_min == 0 && tm.tm_sec == 0);
		CHECK(tm.tm_wday == 3 && tm.tm_yday == 364);
		CHECK(tm.tm_isdst == 0);
		CHECK(tm.__tm_gmtoff == -5 * 3600);
		CHECK(tm.__tm_zone && !strcmp(tm.__tm_zone, "EST"));
		strftime(buf, sizeof buf, "%Z %z", &tm);
		CHECK(!strcmp(buf, "EST -0500"));
		CHECK(!strcmp(ctime(&t), "Wed Dec 31 19:00:00 1969\n"));

		/* mktime interprets fields as local -> UTC epoch */
		r = mktime(&tm);
		CHECK(r == 0);
		CHECK(tm.tm_hour == 19);
		fill(&tm, 1970, 0, 1, 0, 0, 0);
		CHECK(mktime(&tm) == 5 * 3600);
		/* gmtime is unaffected by TZ; timegm too */
		CHECK(gmtime_r(&t, &tm)->tm_hour == 0);
		fill(&tm, 1970, 0, 1, 0, 0, 0);
		CHECK(timegm(&tm) == 0);

		/* positive (east) offset, with minutes */
		CHECK(setenv("TZ", "IST-5:30", 1) == 0);
		tzset();
		CHECK(timezone == -(5 * 3600 + 30 * 60));
		CHECK(!strcmp(tzname[0], "IST"));
		localtime_r(&t, &tm);
		CHECK(tm.tm_mday == 1 && tm.tm_hour == 5 && tm.tm_min == 30);
		CHECK(tm.__tm_gmtoff == 5 * 3600 + 30 * 60);
		strftime(buf, sizeof buf, "%z", &tm);
		CHECK(!strcmp(buf, "+0530"));
		CHECK(mktime(&tm) == 0);

		/* localtime's fixed-offset subtraction is checked before it can
		 * overflow either time_t endpoint. */
		CHECK(setenv("TZ", "X1", 1) == 0);
		t = LLONG_MIN;
		errno = 0;
		CHECK(localtime_r(&t, &tm) == NULL && errno == EOVERFLOW);
		CHECK(setenv("TZ", "X-1", 1) == 0);
		t = LLONG_MAX;
		errno = 0;
		CHECK(localtime_r(&t, &tm) == NULL && errno == EOVERFLOW);

		/* timezone is negated into tm_gmtoff, so its saturated range must
		 * be symmetric rather than including the unnegatable LONG_MIN. */
		CHECK(setenv("TZ", "X-9999999999999999", 1) == 0);
		t = 0;
		CHECK(localtime_r(&t, &tm) == &tm);
		CHECK(timezone == -LONG_MAX && tm.__tm_gmtoff == LONG_MAX);
		t = 0;

		/* angle-bracket-quoted name */
		CHECK(setenv("TZ", "<+03>-3", 1) == 0);
		tzset();
		CHECK(timezone == -3 * 3600);
		CHECK(!strcmp(tzname[0], "+03"));

		/* DST rule suffix is ignored, but the base offset still parsed */
		CHECK(setenv("TZ", "PST8PDT,M3.2.0,M11.1.0", 1) == 0);
		tzset();
		CHECK(timezone == 8 * 3600);
		CHECK(!strcmp(tzname[0], "PST"));
		CHECK(daylight == 0);

		/* unset / empty -> UTC */
		CHECK(setenv("TZ", "", 1) == 0);
		tzset();
		CHECK(timezone == 0 && !strcmp(tzname[0], "UTC"));
		CHECK(unsetenv("TZ") == 0);
		tzset();
		CHECK(timezone == 0 && !strcmp(tzname[0], "UTC"));
		localtime_r(&t, &tm);
		CHECK(tm.tm_hour == 0 && tm.tm_mday == 1);

		CHECK(setenv("TZ", "UTC0", 1) == 0);
		tzset();
	}

	/* getdate.html DESCRIPTION: getdate() reads $DATEMSK's newline-
	 * separated strptime templates and tries each in turn -- ERRORS
	 * code 1 ("The DATEMSK environment variable is null or undefined")
	 * means every one of the calls below needs a real template file
	 * and $DATEMSK pointing at it first; src/time/getdate.c no longer
	 * falls back to a built-in list (see that file's own banner for
	 * why the fallback existed and why it is gone -- this block is the
	 * "one thing keeping the deviation in place" its removal note
	 * refers to). One line per form this block's calls below exercise. */
	{
		struct tm *p;
		FILE *tf = fopen("t-datemsk.tmpl", "w");

		CHECK(tf != NULL);
		if (tf) {
			fputs("%Y-%m-%d %H:%M:%S\n"
			      "%m/%d/%Y\n"
			      "%d %B %Y\n"
			      "%B %d, %Y\n"
			      "%H:%M\n", tf);
			CHECK(fclose(tf) == 0);
		}
		CHECK(setenv("DATEMSK", "t-datemsk.tmpl", 1) == 0);

		p = getdate("2000-02-29 13:05:09");
		CHECK(p != NULL);
		if (p) {
			CHECK(p->tm_year == 100 && p->tm_mon == 1 && p->tm_mday == 29);
			CHECK(p->tm_hour == 13 && p->tm_min == 5 && p->tm_sec == 9);
			CHECK(p->tm_wday == 2 && p->tm_yday == 59);
		}
		p = getdate("02/29/2000");
		CHECK(p && p->tm_year == 100 && p->tm_mon == 1 && p->tm_mday == 29 && p->tm_wday == 2);
		p = getdate("29 February 2000");
		CHECK(p && p->tm_mon == 1 && p->tm_mday == 29 && p->tm_year == 100);
		p = getdate("February 29, 2000");
		CHECK(p && p->tm_mon == 1 && p->tm_mday == 29 && p->tm_year == 100);
		p = getdate("13:05");
		CHECK(p && p->tm_hour == 13 && p->tm_min == 5);

		getdate_err = 0;
		CHECK(getdate("not a date at all") == NULL);
		CHECK(getdate_err == 7);

		/* These two are unrelated to $DATEMSK -- s itself is null/empty,
		 * checked before getdate() ever reads the environment -- so they
		 * hold with $DATEMSK still set, same as before this block existed. */
		getdate_err = 0;
		CHECK(getdate("") == NULL);
		CHECK(getdate_err == 1);
		getdate_err = 0;
		CHECK(getdate(NULL) == NULL);
		CHECK(getdate_err == 1);

		CHECK(unsetenv("DATEMSK") == 0);
		unlink("t-datemsk.tmpl");
	}

	/* time / clock_gettime / timespec_get / clock */
	{
		time_t t1, t2, t3;
		struct timespec ts, ts2, tg, mono1, mono2, cpu;
		int k;

		t1 = time(NULL);
		CHECK(time(&t2) == t2);
		CHECK(t1 >= 1600000000);
		CHECK(t2 >= t1 && t2 - t1 <= 5);

		CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0);
		CHECK(ts.tv_sec >= 1600000000);
		CHECK(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000);
		CHECK(ts.tv_sec >= t1 && ts.tv_sec - t1 <= 5);
		CHECK(clock_gettime(CLOCK_REALTIME_COARSE, &ts2) == 0);
		CHECK(ts2.tv_sec >= ts.tv_sec && ts2.tv_sec - ts.tv_sec <= 5);

		CHECK(timespec_get(&tg, TIME_UTC) == TIME_UTC);
		CHECK(tg.tv_sec >= ts.tv_sec && tg.tv_sec - ts.tv_sec <= 5);
		CHECK(tg.tv_nsec >= 0 && tg.tv_nsec < 1000000000);
		CHECK(timespec_get(&tg, 12345) == 0);

		t3 = time(NULL);
		CHECK(t3 >= t1);

		/* monotonic: non-decreasing across many calls */
		CHECK(clock_gettime(CLOCK_MONOTONIC, &mono1) == 0);
		CHECK(mono1.tv_nsec >= 0 && mono1.tv_nsec < 1000000000);
		for (k = 0; k < 1000; k++) {
			CHECK(clock_gettime(CLOCK_MONOTONIC, &mono2) == 0);
			CHECK(mono2.tv_sec > mono1.tv_sec || (mono2.tv_sec == mono1.tv_sec && mono2.tv_nsec >= mono1.tv_nsec));
			mono1 = mono2;
		}
		CHECK(clock_gettime(CLOCK_MONOTONIC_RAW, &mono2) == 0);
		CHECK(clock_gettime(CLOCK_BOOTTIME, &mono2) == 0);
		CHECK(mono2.tv_sec > mono1.tv_sec || (mono2.tv_sec == mono1.tv_sec && mono2.tv_nsec >= mono1.tv_nsec));

		CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu) == 0);
		CHECK(cpu.tv_sec >= 0 && cpu.tv_nsec >= 0 && cpu.tv_nsec < 1000000000);
		CHECK(cpu.tv_sec < 60);
		CHECK(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu) == 0);

		errno = 0;
		CHECK(clock_gettime(999, &ts) == -1);
		CHECK(errno == EINVAL);

		CHECK(clock_getres(CLOCK_REALTIME, &ts) == 0);
		CHECK(ts.tv_sec == 0 && ts.tv_nsec > 0);
		CHECK(clock_getres(CLOCK_MONOTONIC, &ts) == 0);
		CHECK(ts.tv_sec == 0 && ts.tv_nsec > 0);
		errno = 0;
		CHECK(clock_getres(999, &ts) == -1 && errno == EINVAL);

		{
			clockid_t id = -1;
			CHECK(clock_getcpuclockid(0, &id) == 0);
			CHECK(id == CLOCK_PROCESS_CPUTIME_ID);
			CHECK(clock_getcpuclockid(1234567, &id) == ESRCH);
		}

		/* clock(): CPU time, non-decreasing, and in CLOCKS_PER_SEC units */
		{
			clock_t c1 = clock(), c2;
			volatile unsigned long sink = 0;
			unsigned long j;
			CHECK(c1 != (clock_t)-1);
			CHECK(c1 >= 0);
			for (j = 0; j < 5000000; j++) sink += j ^ (j >> 3);
			c2 = clock();
			CHECK(c2 >= c1);
			CHECK((c2 - c1) < 60 * CLOCKS_PER_SEC);
			CHECK(CLOCKS_PER_SEC == 1000000);
		}

		/* stime/clock_settime: an unprivileged process normally gets
		 * EPERM; set the clock to "now" so that even if it succeeds the
		 * host clock is left where it was */
		{
			time_t before = time(NULL), after, target = before;
			int r;
			errno = 0;
			r = stime(&target);
			after = time(NULL);
			CHECK(r == 0 || (r == -1 && errno != 0));
			CHECK(after >= before - 1 && after - before <= 5);
			errno = 0;
			CHECK(clock_settime(CLOCK_MONOTONIC, &ts) == -1 && errno == EINVAL);
			target = LLONG_MAX;
			errno = 0;
			CHECK(stime(&target) == -1 && errno == EOVERFLOW);
			target = LLONG_MIN;
			errno = 0;
			CHECK(stime(&target) == -1 && errno == EOVERFLOW);
		}

		/* gettimeofday: agrees with time()/clock_gettime(CLOCK_REALTIME) */
		{
			struct timeval tv;
			time_t t1 = time(NULL), t2;
			CHECK(gettimeofday(&tv, NULL) == 0);
			t2 = time(NULL);
			CHECK(tv.tv_sec >= t1 && tv.tv_sec <= t2 + 1);
			CHECK(tv.tv_usec >= 0 && tv.tv_usec < 1000000);
		}

		/* settimeofday: same "set to now, unprivileged EPERM is fine"
		 * shape as the stime test above */
		{
			struct timeval before, tv, after;
			int r;
			CHECK(gettimeofday(&before, NULL) == 0);
			tv = before;
			errno = 0;
			r = settimeofday(&tv, NULL);
			CHECK(r == 0 || (r == -1 && errno != 0));
			CHECK(gettimeofday(&after, NULL) == 0);
			CHECK(after.tv_sec >= before.tv_sec && after.tv_sec - before.tv_sec <= 5);
			tv.tv_usec = -1;
			errno = 0;
			CHECK(settimeofday(&tv, NULL) == -1 && errno == EINVAL);
			tv.tv_usec = 1000000;
			errno = 0;
			CHECK(settimeofday(&tv, NULL) == -1 && errno == EINVAL);
			tv.tv_usec = LONG_MIN;
			errno = 0;
			CHECK(settimeofday(&tv, NULL) == -1 && errno == EINVAL);
			tv.tv_usec = LONG_MAX;
			errno = 0;
			CHECK(settimeofday(&tv, NULL) == -1 && errno == EINVAL);
		}

		/* getrlimit: real, enforced numbers -- not just any value */
		{
			struct rlimit rl;
			CHECK(getrlimit(RLIMIT_NOFILE, &rl) == 0);
			CHECK(rl.rlim_cur == 1024 && rl.rlim_max == 1024);
			CHECK(getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
			errno = 0;
			CHECK(getrlimit(999, &rl) == -1 && errno == EINVAL);
		}

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
		/* setrlimit()/getrlimit(): on Linux (unlike the NT build just
		 * proved above, which stays fixed at RLIM_INFINITY), RLIMIT_
		 * STACK/CORE/RSS/MEMLOCK are genuinely enforced by the kernel
		 * via prlimit64(2) -- src/misc/resource.c's own banner and
		 * src/misc/linux/plat_misc.c's __plat_rlimit_apply_extra().
		 * Each check below proves a REAL kernel-side effect, not just
		 * this library's own bookkeeping echoing itself back. */
		{
			struct rlimit rl, rl2;
			FILE *f;
			char line[256];

			/* RLIMIT_STACK: lower it, generously (this test's own
			 * stack usage is nowhere near 4 MiB, and the default is
			 * commonly 8 MiB -- see this file's own earlier check),
			 * then read the KERNEL's own record directly via /proc/
			 * self/limits (populated from task_rlimit(), entirely
			 * independent of anything this library stores) rather than
			 * just asking getrlimit() again -- that would only prove
			 * this library's own local variable round-trips, not that
			 * prlimit64(2) actually reached the kernel. No thread is
			 * ever made to run on the lowered limit, so there is no
			 * risk of overflowing it. */
			CHECK(getrlimit(RLIMIT_STACK, &rl) == 0);
			if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > 4 * 1024 * 1024) {
				rl.rlim_cur = 4 * 1024 * 1024;
				CHECK(setrlimit(RLIMIT_STACK, &rl) == 0);
				CHECK(getrlimit(RLIMIT_STACK, &rl2) == 0);
				CHECK(rl2.rlim_cur == rl.rlim_cur);

				f = fopen("/proc/self/limits", "r");
				CHECK(f != NULL);
				if (f) {
					int found = 0;
					unsigned long long soft = 0;
					while (fgets(line, sizeof line, f)) {
						if (strncmp(line, "Max stack size", sizeof("Max stack size") - 1) == 0 &&
						    sscanf(line + sizeof("Max stack size") - 1, "%llu", &soft) == 1) {
							found = 1;
							break;
						}
					}
					fclose(f);
					CHECK(found);
					CHECK(soft == (unsigned long long)rl.rlim_cur);
				}
			}

			/* RLIMIT_CORE: 0 is always a safe value to request (this
			 * process is not expected to dump core during this test
			 * either way), and the readback must report exactly what
			 * was set, not the old fixed RLIM_INFINITY. */
			CHECK(getrlimit(RLIMIT_CORE, &rl) == 0);
			rl.rlim_cur = 0;
			CHECK(setrlimit(RLIMIT_CORE, &rl) == 0);
			CHECK(getrlimit(RLIMIT_CORE, &rl2) == 0);
			CHECK(rl2.rlim_cur == 0);

			/* RLIMIT_MEMLOCK: prove a real downstream effect, not just
			 * a readback -- mlock() one page while the limit is still
			 * generous (proving this sandbox permits locking at all;
			 * skip the rest if it does not, the same "key the skip on
			 * the limit actually measured" idiom test/posix-mman.c's
			 * own test_mlock_munlock() already uses), then lower the
			 * limit to 0 and prove the SAME mlock() call now fails for
			 * real. mlock(2)'s own ERRORS section gives two distinct
			 * answers depending on the exact limit, measured here
			 * rather than assumed: ENOMEM is "a nonzero RLIMIT_MEMLOCK
			 * ... but tried to lock more than the limit permitted",
			 * while EPERM is specifically "not privileged ... and its
			 * RLIMIT_MEMLOCK ... is 0" -- the case this test actually
			 * creates, confirmed against a real mlock(2) call on this
			 * host before being relied on here. */
			{
				long pg = sysconf(_SC_PAGESIZE);
				void *p = pg > 0 ? malloc((size_t)pg) : 0;
				if (p && mlock(p, (size_t)pg) == 0) {
					CHECK(munlock(p, (size_t)pg) == 0);
					CHECK(getrlimit(RLIMIT_MEMLOCK, &rl) == 0);
					{
						rlim_t saved = rl.rlim_cur;
						rl.rlim_cur = 0;
						CHECK(setrlimit(RLIMIT_MEMLOCK, &rl) == 0);
						CHECK(getrlimit(RLIMIT_MEMLOCK, &rl2) == 0);
						CHECK(rl2.rlim_cur == 0);
						errno = 0;
						CHECK(mlock(p, (size_t)pg) == -1 && errno == EPERM);
						/* Restore, so nothing later in this process
						 * (or a child it forks) is surprised by a
						 * zeroed mlock budget. */
						rl.rlim_cur = saved;
						CHECK(setrlimit(RLIMIT_MEMLOCK, &rl) == 0);
					}
				}
				free(p);
			}

			/* RLIMIT_RSS: real syscall, honestly not enforced by the
			 * kernel itself since 2.4.30/2.6.9 (see include/sys/
			 * resource.h's own setrlimit() comment) -- only the round
			 * trip is checked here, which is exactly what is true. */
			CHECK(getrlimit(RLIMIT_RSS, &rl) == 0);
			rl.rlim_cur = 1024 * 1024;
			CHECK(setrlimit(RLIMIT_RSS, &rl) == 0);
			CHECK(getrlimit(RLIMIT_RSS, &rl2) == 0);
			CHECK(rl2.rlim_cur == 1024 * 1024);
		}
#endif

		/* getrusage: RUSAGE_SELF reports nonzero-capable, monotonic
		 * CPU time; RUSAGE_CHILDREN starts zeroed (waitpid() tests for
		 * accumulation live in process-win.c, which actually spawns) */
		{
			struct rusage ru;
			volatile unsigned long sink = 0, j;
			CHECK(getrusage(RUSAGE_SELF, &ru) == 0);
			for (j = 0; j < 20000000; j++) sink += j ^ (j >> 3);
			CHECK(getrusage(RUSAGE_SELF, &ru) == 0);
			CHECK(ru.ru_utime.tv_sec >= 0 && ru.ru_stime.tv_sec >= 0);
			CHECK(getrusage(RUSAGE_CHILDREN, &ru) == 0);
			errno = 0;
			CHECK(getrusage(999, &ru) == -1 && errno == EINVAL);
		}

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
		/* sched_setscheduler()/sched_getscheduler()/sched_setparam()/
		 * sched_getparam()/sched_rr_get_interval(): real Linux syscalls
		 * (src/misc/sched.c, src/misc/linux/plat_misc.c) giving genuine
		 * SCHED_FIFO/SCHED_RR enforcement, unlike the NT build's own
		 * always-succeeds local bookkeeping. Realtime scheduling
		 * changes normally need CAP_SYS_NICE, but an unprivileged
		 * process may still set SCHED_FIFO/SCHED_RR on ITSELF up to its
		 * own RLIMIT_RTPRIO (setrlimit.html's own rlimit -- nonzero by
		 * default in many environments, this test's own sandbox
		 * included), so BOTH outcomes are real and both are accepted:
		 * either a genuine, kernel-confirmed policy switch, or a real,
		 * specific EPERM -- never a silent always-succeeds no-op. */
		{
			struct sched_param param, param2;
			struct timespec interval;
			int prev_policy = sched_getscheduler(0);
			int r;

			CHECK(prev_policy >= 0);
			CHECK(sched_getparam(0, &param) == 0);

			param2.sched_priority = 1;
			errno = 0;
			r = sched_setscheduler(0, SCHED_FIFO, &param2);
			if (r == 0) {
				/* A real, kernel-confirmed switch: prove it with a
				 * fresh sched_getscheduler()/sched_getparam() round
				 * trip, which only a genuine kernel-side policy
				 * change -- not local bookkeeping -- could produce. */
				CHECK(sched_getscheduler(0) == SCHED_FIFO);
				CHECK(sched_getparam(0, &param2) == 0);
				CHECK(param2.sched_priority == 1);
				/* Put this process back the way it was found, before
				 * anything below (or any other test running on this
				 * host) can be surprised by a realtime-scheduled
				 * process. sched_setscheduler() returns 0 on success
				 * in this library (src/misc/sched.c's set_state()),
				 * not POSIX's own "former policy" -- an existing,
				 * out-of-scope design choice this test matches rather
				 * than second-guesses (test/posix-realtime.c's own
				 * test_posix_realtime_sched_policy_priorities() checks
				 * `== policy` instead, which only happens to agree
				 * with 0 because it reuses SCHED_OTHER==0 there). */
				CHECK(sched_setscheduler(0, prev_policy, &param) == 0);
				CHECK(sched_getscheduler(0) == prev_policy);
			} else {
				CHECK(r == -1 && errno == EPERM);
			}

			/* SCHED_SPORADIC has no Linux kernel equivalent (real
			 * policy 3 there is SCHED_BATCH, an unrelated real policy
			 * -- see src/misc/sched.c's own banner), so it keeps this
			 * library's own bookkeeping-only behaviour even here:
			 * always succeeds, and reads back exactly what was set,
			 * regardless of privilege. */
			param2.sched_priority = 1;
			CHECK(sched_setscheduler(0, SCHED_SPORADIC, &param2) == 0);
			CHECK(sched_getscheduler(0) == SCHED_SPORADIC);
			CHECK(sched_getparam(0, &param2) == 0);
			CHECK(param2.sched_priority == 1);
			CHECK(sched_setscheduler(0, prev_policy, &param) == 0);
			CHECK(sched_getscheduler(0) == prev_policy);

			/* sched_rr_get_interval(): real syscall regardless of the
			 * pid's own policy (Linux answers this for SCHED_OTHER
			 * too, its own per-policy default quantum). */
			CHECK(sched_rr_get_interval(0, &interval) == 0);
			CHECK(interval.tv_nsec >= 0 && interval.tv_nsec < 1000000000L);
			errno = 0;
			CHECK(sched_rr_get_interval(-12345, &interval) == -1);
			CHECK(errno == ESRCH || errno == EINVAL);
		}

		/* setitimer()/getitimer(): real, and genuinely repeating on
		 * Linux (src/time/linux/plat_itimer.c) -- the exact thing the
		 * NT build's own APC-based SIGALRM delivery cannot do (see
		 * that file's own banner: a computing thread's missed expiries
		 * there coalesce into one delivery instead of a series). A
		 * real SIGALRM handler that fires more than once is the whole
		 * point, so this proves exactly that, not just a round trip. */
		{
			struct itimerval iv, old;
			struct sigaction sa, old_sa;
			struct timespec nap;
			int i;

			memset(&sa, 0, sizeof sa);
			sa.sa_handler = alarm_hit;
			CHECK(sigemptyset(&sa.sa_mask) == 0);
			CHECK(sigaction(SIGALRM, &sa, &old_sa) == 0);

			/* getitimer() before any setitimer(): "no timer armed" is
			 * defined to read back as all-zero. */
			memset(&old, 0xFF, sizeof old);
			CHECK(getitimer(ITIMER_REAL, &old) == 0);
			CHECK(old.it_value.tv_sec == 0 && old.it_value.tv_usec == 0);
			CHECK(old.it_interval.tv_sec == 0 && old.it_interval.tv_usec == 0);

			alarm_hit_count = 0;
			iv.it_value.tv_sec = 0;    iv.it_value.tv_usec = 30000;   /* 30ms */
			iv.it_interval.tv_sec = 0; iv.it_interval.tv_usec = 30000; /* every 30ms */
			errno = 0;
			if (setitimer(ITIMER_REAL, &iv, 0) == 0) {
				/* Mid-flight getitimer(): it_interval must read back
				 * exactly, it_value must be a real, shrinking countdown. */
				CHECK(getitimer(ITIMER_REAL, &old) == 0);
				CHECK(old.it_interval.tv_sec == 0 && old.it_interval.tv_usec == 30000);
				CHECK(old.it_value.tv_sec == 0 && old.it_value.tv_usec <= 30000);

				/* nanosleep() is one of this library's own signal-aware
				 * wait points (__sig_drain_pending(), src/unistd/
				 * sleep.c), exactly where a queued SIGALRM notification
				 * actually gets delivered -- repeated short naps, not
				 * one long sleep, are what let MULTIPLE expiries
				 * actually run this handler rather than just the
				 * first. Bounded at 2 real seconds so a genuine
				 * delivery failure fails this CHECK instead of hanging
				 * the whole suite. */
				nap.tv_sec = 0; nap.tv_nsec = 10000000L; /* 10ms */
				for (i = 0; i < 200 && alarm_hit_count < 3; i++)
					nanosleep(&nap, 0);

				/* Disarm before anything else runs. */
				memset(&iv, 0, sizeof iv);
				CHECK(setitimer(ITIMER_REAL, &iv, &old) == 0);

				/* The actual point: real, REPEATED delivery. */
				CHECK(alarm_hit_count >= 3);
			} else {
				/* This setitimer(ITIMER_REAL, ...) is built on this
				 * library's own portable timer-manager machinery
				 * (src/time/timer.c), which spawns one real background
				 * thread the first time any timer is armed (src/time/
				 * linux/plat_itimer.c's own banner). Some sandboxes --
				 * this one included, confirmed independently by a bare
				 * pthread_create() failing the identical way -- refuse
				 * real thread creation outright (EAGAIN), which is an
				 * environment limitation this test cannot work around,
				 * not a bug in setitimer() itself: skip the delivery
				 * proof rather than fail it, the same "key the skip on
				 * what was actually measured" idiom test/posix-mman.c's
				 * own test_mlock_munlock() already uses. */
				CHECK(errno == EAGAIN);
				printf("SKIP time: setitimer(ITIMER_REAL) real-repeat-delivery "
				       "check: this environment does not permit real thread "
				       "creation (errno %d arming the timer manager thread)\n",
				       errno);
			}
			CHECK(sigaction(SIGALRM, &old_sa, 0) == 0);

			errno = 0;
			CHECK(setitimer(999, &iv, 0) == -1 && errno == EINVAL);
			errno = 0;
			CHECK(getitimer(999, &old) == -1 && errno == EINVAL);
		}

		/* ualarm(): built directly on setitimer(ITIMER_REAL, ...) --
		 * src/unistd/linux/plat_ualarm.c -- so this proves both its own
		 * microsecond unit conversion and, again, real repeating
		 * delivery through the very same mechanism. */
		{
			struct sigaction sa, old_sa;
			struct timespec nap;
			unsigned prev;
			int i;

			memset(&sa, 0, sizeof sa);
			sa.sa_handler = alarm_hit;
			CHECK(sigemptyset(&sa.sa_mask) == 0);
			CHECK(sigaction(SIGALRM, &sa, &old_sa) == 0);

			alarm_hit_count = 0;
			errno = 0;
			prev = ualarm(30000, 30000); /* 30ms, repeating every 30ms */
			CHECK(prev == 0); /* nothing scheduled before this call */

			if (errno != EAGAIN) {
				nap.tv_sec = 0; nap.tv_nsec = 10000000L;
				for (i = 0; i < 200 && alarm_hit_count < 2; i++)
					nanosleep(&nap, 0);

				(void)ualarm(0, 0); /* cancel */
				CHECK(alarm_hit_count >= 2);
			} else {
				/* Same environment limitation as setitimer(ITIMER_REAL)
				 * just above -- see that block's own comment. ualarm()
				 * itself has no [ERRORS] section to report this
				 * through (ualarm.html), and this library's own
				 * ualarm() deliberately folds a setitimer() failure
				 * into "0 scheduled" rather than inventing one
				 * (src/unistd/linux/plat_ualarm.c's own comment), so
				 * errno -- left exactly as setitimer() set it -- is
				 * the only way to tell this case apart from a genuine
				 * "nothing was scheduled before" here. */
				printf("SKIP time: ualarm() real-repeat-delivery check: "
				       "this environment does not permit real thread "
				       "creation (errno %d)\n", errno);
			}
			CHECK(sigaction(SIGALRM, &old_sa, 0) == 0);
		}

		/* adjtime(): real adjtimex(2)/ADJ_OFFSET_SINGLESHOT slewing
		 * (src/time/linux/plat_adjtime.c), unlike the NT build's own
		 * undefined-ok stub. The query form (delta == NULL) needs no
		 * privilege and must always succeed; a genuine slew request
		 * proves the syscall is REAL -- a specific, correct errno
		 * (EPERM, CAP_SYS_TIME) when refused, exactly the "prove it is
		 * real, not that privileged behavior works" shape
		 * test_acct_linux() (test/posix-unistd.c) already uses -- never
		 * a silent always-succeeds stub. */
		{
			struct timeval delta, old;
			int r;

			memset(&old, 0xFF, sizeof old);
			CHECK(adjtime(0, &old) == 0);

			delta.tv_sec = 0; delta.tv_usec = 1;
			errno = 0;
			r = adjtime(&delta, &old);
			CHECK(r == 0 || (r == -1 && errno == EPERM));
			if (r == 0) {
				/* A real slew was genuinely armed -- withdraw it
				 * immediately rather than let it run loose on this
				 * host after this test exits. */
				struct timeval undo;
				undo.tv_sec = 0; undo.tv_usec = -1;
				adjtime(&undo, 0);
			}
		}
#endif
	}

	if (!fails) printf("time: all tests passed\n");
	return fails != 0;
}
