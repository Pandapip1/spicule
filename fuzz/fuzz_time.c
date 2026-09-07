/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fuzzes the calendar half of src/time/: tzset.c, mktime.c, timegm.c,
 * gmtime.c, localtime.c, asctime.c, ctime.c (strftime/strptime already
 * have their own harnesses). $TZ is untrusted input in the ordinary
 * case, not the exotic one -- localtime()/ctime()/mktime() all call
 * tzset() implicitly, so any program reaches this parser regardless of
 * whether it mentions timezones. mktime()/timegm() are also REQUIRED to
 * accept and normalize out-of-range struct tm fields (tm_mon==13,
 * negative tm_sec), which is exactly the shape of code that overflows.
 *
 * Input layout: byte 0 flags; bytes 1-24 six little-endian int32
 * struct-tm fields; bytes 25-32 a little-endian time_t; the rest is the
 * $TZ string. Short input is zero-padded rather than rejected.
 *
 * timegm() and gmtime_r() are oracled against glibc's (see
 * host_timegm() in fuzz/host_oracle.c): both are pure proleptic-
 * Gregorian UTC arithmetic with no zone database or "now" involved, so
 * a disagreement is a real calendar bug. mktime()/localtime() are NOT
 * oracled -- glibc reads /usr/share/zoneinfo and applies POSIX DST
 * rules, while src/time/tzset.c documents this target has neither, so a
 * differential check there would just report that difference forever.
 * The oracle compares on fields folded into wide-but-not-overflowing
 * ranges; the true extremes are still driven, by the unrestricted pass
 * below, but through ASan/UBSan rather than comparison, since at the
 * extremes POSIX only guarantees (time_t)-1/EOVERFLOW and the two
 * libraries make different, both-defensible choices.
 *
 * mktime() is checked for idempotence instead (a POSIX contract
 * property, not implementation-specific): normalizing *tm and feeding
 * it back in must give the same instant. Checked only when `timezone`
 * is small enough that the shift itself can't overflow -- that overflow
 * is UBSan's to report directly, not this harness's to call a failed
 * idempotence. asctime_r()'s 26-byte buffer is used only for a struct
 * tm that is actually a valid four-digit-year time (the case the
 * 26-byte POSIX guarantee covers); every other tm gets 64 bytes so an
 * overrun beyond that is still caught. tzname[]'s pair is checked
 * non-NULL and NUL-terminated within its 32-byte buffer after any $TZ.
 *
 * getdate() is deliberately not covered: it calls time(0) and seeds
 * from localtime_r()'s idea of "now", so the same input doesn't
 * reproduce the same behavior twice -- it needs a fixed-"now" seam in
 * fuzz/ntstubs.c's clock first.
 */
/* timegm() is a BSD/GNU extension; include/time.h gates it behind
 * _BSD_SOURCE/_GNU_SOURCE, and the Makefile's -D_XOPEN_SOURCE=700 alone
 * doesn't include it. */
#define _BSD_SOURCE
#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);
extern long long host_timegm(const int in[6], int *ok);
extern int host_gmtime(long long t, int out[8]);

#define BIN 32

static int rd32(const unsigned char *p)
{
	unsigned u = (unsigned)p[0] | ((unsigned)p[1] << 8) |
	             ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
	return (int)u;
}

static long long rd64(const unsigned char *p)
{
	unsigned long long u = 0;
	int i;
	for (i = 7; i >= 0; i--) u = (u << 8) | p[i];
	return (long long)u;
}

/* Width computed in `unsigned`, not `int`: the +-2e9 time_t range folded
 * here has hi - lo == 4e9, which overflows `int`. */
static int fold(int v, int lo, int hi)
{
	unsigned span = ((unsigned)hi - (unsigned)lo) + 1u;
	return (int)((unsigned)lo + (unsigned)v % span);
}

/* Not spicule's snprintf (itself under test) or the host's (unreachable
 * from a file not compiled against host headers). */
static char *put_i(char *p, char *end, long long v)
{
	char tmp[24];
	int n = 0;
	unsigned long long u = v < 0 ? 0ULL - (unsigned long long)v : (unsigned long long)v;
	if (v < 0 && p < end) *p++ = '-';
	do { tmp[n++] = (char)('0' + (int)(u % 10)); u /= 10; } while (u);
	while (n-- > 0 && p < end) *p++ = tmp[n];
	return p;
}

static void describe(char *buf, size_t cap, const int f[6], const char *tz)
{
	char *p = buf, *end = buf + cap - 1;
	static const char *const names[6] = { "y=", " mon=", " mday=", " hour=", " min=", " sec=" };
	int i;
	for (i = 0; i < 6; i++) {
		const char *n = names[i];
		while (*n && p < end) *p++ = *n++;
		p = put_i(p, end, f[i]);
	}
	if (p < end) *p++ = ' ';
	if (p < end) *p++ = 'T';
	if (p < end) *p++ = 'Z';
	if (p < end) *p++ = '=';
	while (*tz && p < end) *p++ = *tz++;
	*p = 0;
}

static void load(struct tm *tm, const int f[6])
{
	memset(tm, 0, sizeof *tm);
	tm->tm_year = f[0];
	tm->tm_mon  = f[1];
	tm->tm_mday = f[2];
	tm->tm_hour = f[3];
	tm->tm_min  = f[4];
	tm->tm_sec  = f[5];
	tm->tm_isdst = 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	unsigned char bin[BIN];
	char tz[192], desc[320];
	int raw[6], f[6], i;
	unsigned flags;
	long long tval;
	size_t n;
	struct tm tm, g;
	time_t t;

	memset(bin, 0, sizeof bin);
	n = size < BIN ? size : BIN;
	memcpy(bin, data, n);
	if (size > BIN) { data += BIN; size -= BIN; } else size = 0;

	flags = bin[0];
	for (i = 0; i < 6; i++) raw[i] = rd32(bin + 1 + 4 * i);
	tval = rd64(bin + 24);

	/* Embedded NULs become '_' rather than truncating $TZ, so every
	 * fuzzer byte reaches the parser. */
	n = size < sizeof tz - 1 ? size : sizeof tz - 1;
	memcpy(tz, data, n);
	tz[n] = 0;
	for (i = 0; i < (int)n; i++) if (!tz[i]) tz[i] = '_';

	/* ------------------------------------------------ tzset / $TZ */
	if (flags & 1) unsetenv("TZ");
	else setenv("TZ", tz, 1);
	tzset();
	if (!tzname[0] || !tzname[1])
		oracle_mismatch_i("tzset left a NULL in tzname", tz, 0, 1);
	else if (strlen(tzname[0]) > 31 || strlen(tzname[1]) > 31)
		oracle_mismatch_i("tzset produced an over-long tzname", tz,
		                  (long long)strlen(tzname[0]), 31);
	/* `timezone` is a 32-bit long on the target (LLP64, per
	 * include/limits.h's LONG_MAX) but a 64-bit one in this native
	 * build, so an overflow of the target's `long` in tzset()'s
	 * `h*3600+mn*60+s` is invisible to UBSan here. What's still checkable
	 * natively is the value: it must fit the target's LONG_MIN/LONG_MAX,
	 * since that's the type it's stored in there. */
	if (timezone > (long long)LONG_MAX || timezone < (long long)LONG_MIN)
		oracle_mismatch_i("tzset computed a timezone the target's long cannot hold",
		                  tz, (long long)timezone, (long long)LONG_MAX);

	/* ------------------------------------- timegm/gmtime, oracled */
	f[0] = fold(raw[0], -5900, 4100);
	f[1] = fold(raw[1], -24, 35);
	f[2] = fold(raw[2], -60, 90);
	f[3] = fold(raw[3], -48, 71);
	f[4] = fold(raw[4], -120, 180);
	f[5] = fold(raw[5], -120, 180);
	describe(desc, sizeof desc, f, tz);

	{
		int ok = 0;
		long long want = host_timegm(f, &ok);
		load(&tm, f);
		t = timegm(&tm);
		if (ok && (long long)t != want)
			oracle_mismatch_i("timegm", desc, (long long)t, want);

		/* timegm() normalizes *tm on the way out, so the fields it
		 * left behind must describe the very instant it returned:
		 * feeding them back in is the round trip. */
		{
			int back[6];
			struct tm again;
			back[0] = tm.tm_year; back[1] = tm.tm_mon; back[2] = tm.tm_mday;
			back[3] = tm.tm_hour; back[4] = tm.tm_min; back[5] = tm.tm_sec;
			long long re;
			load(&again, back);
			re = (long long)timegm(&again);
			if (re != (long long)t)
				oracle_mismatch_i("timegm is not idempotent", desc, re, (long long)t);
		}

		/* gmtime_r on the instant timegm just produced. */
		{
			int hg[8];
			if (host_gmtime((long long)t, hg) && gmtime_r(&t, &g)) {
				if (g.tm_year != hg[0]) oracle_mismatch_i("gmtime tm_year", desc, g.tm_year, hg[0]);
				if (g.tm_mon  != hg[1]) oracle_mismatch_i("gmtime tm_mon",  desc, g.tm_mon,  hg[1]);
				if (g.tm_mday != hg[2]) oracle_mismatch_i("gmtime tm_mday", desc, g.tm_mday, hg[2]);
				if (g.tm_hour != hg[3]) oracle_mismatch_i("gmtime tm_hour", desc, g.tm_hour, hg[3]);
				if (g.tm_min  != hg[4]) oracle_mismatch_i("gmtime tm_min",  desc, g.tm_min,  hg[4]);
				if (g.tm_sec  != hg[5]) oracle_mismatch_i("gmtime tm_sec",  desc, g.tm_sec,  hg[5]);
				if (g.tm_wday != hg[6]) oracle_mismatch_i("gmtime tm_wday", desc, g.tm_wday, hg[6]);
				if (g.tm_yday != hg[7]) oracle_mismatch_i("gmtime tm_yday", desc, g.tm_yday, hg[7]);
			}
		}
	}

	/* gmtime_r on the input's own time_t, folded to the range glibc
	 * will also answer for, so the two can be compared there too. */
	{
		long long tt = (long long)fold((int)tval, -2000000000, 2000000000);
		time_t t2 = (time_t)tt;
		int hg[8];
		if (host_gmtime(tt, hg) && gmtime_r(&t2, &g)) {
			if (g.tm_year != hg[0] || g.tm_mon != hg[1] || g.tm_mday != hg[2] ||
			    g.tm_hour != hg[3] || g.tm_min != hg[4] || g.tm_sec != hg[5] ||
			    g.tm_wday != hg[6] || g.tm_yday != hg[7])
				oracle_mismatch_i("gmtime_r of a raw time_t", desc,
				                  (long long)g.tm_year, (long long)hg[0]);
			/* And back: gmtime_r's fields describe that instant. */
			{
				struct tm r = g;
				if ((long long)timegm(&r) != tt)
					oracle_mismatch_i("gmtime_r -> timegm round trip", desc,
					                  (long long)timegm(&r), tt);
			}
		}
	}

	/* -------------------------------- mktime, localtime, idempotence */
	if (timezone > -1000000L && timezone < 1000000L) {
		struct tm m1, m2;
		time_t a, b;
		load(&m1, f);
		a = mktime(&m1);
		if (a != (time_t)-1) {
			m2 = m1;
			b = mktime(&m2);
			if (b != a)
				oracle_mismatch_i("mktime is not idempotent", desc,
				                  (long long)b, (long long)a);
			/* localtime_r of the instant mktime returned must be the
			 * struct mktime left behind: they are defined to be the
			 * same operation (mktime.c ends by calling it). */
			if (localtime_r(&a, &m2)) {
				if (m2.tm_year != m1.tm_year || m2.tm_mon != m1.tm_mon ||
				    m2.tm_mday != m1.tm_mday || m2.tm_hour != m1.tm_hour ||
				    m2.tm_min != m1.tm_min || m2.tm_sec != m1.tm_sec)
					oracle_mismatch_i("mktime's tm disagrees with localtime_r", desc,
					                  m2.tm_year, m1.tm_year);
			}
		}
	}

	/* -------------------------------------------- asctime_r / ctime_r */
	{
		struct tm v;
		load(&v, f);
		timegm(&v);         /* normalize, so tm_wday/tm_yday are set */
		{
			int y = v.tm_year + 1900;
			int fits = y >= 1000 && y <= 9999 &&
			           (unsigned)v.tm_wday < 7 && (unsigned)v.tm_mon < 12 &&
			           v.tm_mday >= 1 && v.tm_mday <= 31 &&
			           (unsigned)v.tm_hour < 24 && (unsigned)v.tm_min < 60 &&
			           (unsigned)v.tm_sec < 61;
			size_t cap = fits ? 26 : 64;
			char *buf = malloc(cap);
			if (buf) {
				asctime_r(&v, buf);
				if (strlen(buf) >= cap)
					oracle_mismatch_i("asctime_r overran its buffer", desc,
					                  (long long)strlen(buf), (long long)cap);
				free(buf);
			}
		}
	}
	{
		time_t ct = (time_t)fold((int)tval, -2000000000, 2000000000);
		struct tm lt;
		if (localtime_r(&ct, &lt)) {
			int y = lt.tm_year + 1900;
			size_t cap = (y >= 1000 && y <= 9999) ? 26 : 64;
			char *buf = malloc(cap);
			if (buf) {
				if (ctime_r(&ct, buf) && strlen(buf) >= cap)
					oracle_mismatch_i("ctime_r overran its buffer", desc,
					                  (long long)strlen(buf), (long long)cap);
				free(buf);
			}
		}
	}

	/* ------------------------------- the unrestricted pass, no oracle */
	if (flags & 2) {
		struct tm w;
		load(&w, raw);
		timegm(&w);
		load(&w, raw);
		mktime(&w);
	}
	return 0;
}
