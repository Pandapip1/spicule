/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getdate() -- src/time/getdate.c. The most parser-shaped function in
 * src/time/, and both of its inputs are untrusted in the ordinary case:
 * the date string is whatever the user typed, and $DATEMSK names a FILE
 * whose contents become strptime format strings.
 *
 * getdate() calls time(0) and seeds its working struct tm from
 * localtime_r() so that fields the matched template does not mention
 * default to today. The same input therefore takes different branches on
 * different days, and a crash artefact might not reproduce from the
 * bytes that produced it. __ntfuzz_freeze_clock() in fuzz/ntstubs.c is
 * the seam that fixes it, called from LLVMFuzzerInitialize, which
 * libFuzzer runs before any input.
 *
 * Byte 0 is flags. The rest is split on '\n' into records: record 0 is
 * the date string handed to getdate(); the remaining records, when
 * flags bit 0 is set, are written to a file in the simulated volume
 * that $DATEMSK then names -- so the fuzzer writes the template file as
 * well as the input, and read_templates() and every strptime format
 * those templates spell are under test. With bit 0 clear, $DATEMSK is
 * unset and getdate() takes its built-in template list instead; both
 * paths matter and both are reached.
 *
 * Asserted:
 *
 *   - The contract between the return and getdate_err. getdate.html: on
 *     failure getdate() returns NULL and sets getdate_err to a value in
 *     1..8; on success it returns a pointer and getdate_err is not
 *     meaningful. A NULL with getdate_err left at 0, or set outside
 *     1..8, is a caller that cannot tell what went wrong -- and
 *     getdate_err is the only channel there is, since getdate() does
 *     not set errno.
 *
 *   - A successful parse is a real date: tm_mon 0..11, tm_mday 1..31,
 *     tm_hour 0..23, tm_min/tm_sec 0..60, tm_wday 0..6, tm_yday 0..365.
 *     getdate.c range-checks the day against the actual length of the
 *     month before accepting and then runs mktime() to normalize, so
 *     anything out of range here means one of those two did not happen.
 *
 *   - The returned tm round-trips: timegm() of the returned fields,
 *     back through gmtime_r(), must give the same fields. A struct tm
 *     that does not describe any instant is not a parse result.
 *
 * Not asserted: which template matched, or what the defaulted fields
 * came out as. Those depend on the frozen instant, and pinning them
 * would be pinning this harness's arbitrary choice of "now" rather than
 * anything about getdate().
 */
#define _BSD_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);
extern void __ntfuzz_freeze_clock(long long unix_seconds);

/* 2021-03-04T05:06:07Z.  Arbitrary, and deliberately not "round": a
 * frozen clock at midnight, or on the 1st, would quietly satisfy
 * defaulting bugs that any other instant would expose.  Nothing about
 * this number is derived from src/time/. */
#define FROZEN_NOW 1614834367LL

#define CAP  1024
#define TPLPATH "/tmp/datemsk"

static char storage[CAP + 1];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	__ntfuzz_freeze_clock(FROZEN_NOW);
	/* Checked, not assumed: if the freeze seam ever silently stops
	 * taking effect, every assertion below still passes and the
	 * harness quietly goes back to being nondeterministic, which
	 * nothing else in the run would notice. */
	if ((long long)time(0) != FROZEN_NOW)
		oracle_mismatch_i("the frozen-clock seam did not take effect", "",
		                  (long long)time(0), FROZEN_NOW);
	return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	const char *date;
	unsigned flags;
	size_t n, start, end;
	int use_datemsk;

	if (!size) return 0;
	flags = data[0];
	data++; size--;
	use_datemsk = (flags & 1) != 0;

	n = size < CAP ? size : CAP;
	memcpy(storage, data, n);
	storage[n] = 0;

	/* Record 0 is the date string.  It ends at the first '\n' (or at
	 * the end); the rest, if any, is the template file. */
	end = 0;
	while (end < n && storage[end] != '\n') end++;
	date = storage;
	start = end < n ? end + 1 : n;
	storage[end] = 0;

	if (use_datemsk) {
		/* The template file is written through spicule's own stdio
		 * into fuzz/ntstubs.c's simulated volume -- so fopen, fwrite
		 * and fclose are on the path too, and getdate.c's
		 * read_templates() reads back exactly what was written. */
		FILE *f = fopen(TPLPATH, "w");
		if (f) {
			if (start < n) fwrite(storage + start, 1, n - start, f);
			fclose(f);
			setenv("DATEMSK", TPLPATH, 1);
		} else {
			unsetenv("DATEMSK");
		}
	} else {
		unsetenv("DATEMSK");
	}

	getdate_err = 0;
	{
		struct tm *r = getdate(date);

		if (!r) {
			/* getdate.html: "the getdate_err variable shall be set
			 * to indicate the error", values 1 through 8.  It is
			 * the only channel -- getdate() does not set errno. */
			if (getdate_err < 1 || getdate_err > 8)
				oracle_mismatch_i("getdate returned NULL with no usable getdate_err",
				                  date, (long long)getdate_err, 0);
			return 0;
		}

		if (r->tm_mon < 0 || r->tm_mon > 11)
			oracle_mismatch_i("getdate accepted an out-of-range tm_mon", date, r->tm_mon, 11);
		if (r->tm_mday < 1 || r->tm_mday > 31)
			oracle_mismatch_i("getdate accepted an out-of-range tm_mday", date, r->tm_mday, 31);
		if (r->tm_hour < 0 || r->tm_hour > 23)
			oracle_mismatch_i("getdate accepted an out-of-range tm_hour", date, r->tm_hour, 23);
		if (r->tm_min < 0 || r->tm_min > 59)
			oracle_mismatch_i("getdate accepted an out-of-range tm_min", date, r->tm_min, 59);
		if (r->tm_sec < 0 || r->tm_sec > 60)
			oracle_mismatch_i("getdate accepted an out-of-range tm_sec", date, r->tm_sec, 60);
		if (r->tm_wday < 0 || r->tm_wday > 6)
			oracle_mismatch_i("getdate produced an out-of-range tm_wday", date, r->tm_wday, 6);
		if (r->tm_yday < 0 || r->tm_yday > 365)
			oracle_mismatch_i("getdate produced an out-of-range tm_yday", date, r->tm_yday, 365);

		/* The fields must describe an instant: convert and convert
		 * back.  getdate.c ends by calling mktime() to normalize, so
		 * a struct that does not survive this never was normalized. */
		{
			struct tm a = *r, b;
			time_t t = timegm(&a);
			if (gmtime_r(&t, &b)) {
				if (b.tm_year != r->tm_year || b.tm_mon != r->tm_mon ||
				    b.tm_mday != r->tm_mday || b.tm_hour != r->tm_hour ||
				    b.tm_min != r->tm_min || b.tm_sec != r->tm_sec)
					oracle_mismatch_i("getdate's tm does not survive a timegm/gmtime round trip",
					                  date, b.tm_mday, r->tm_mday);
			}
		}
	}
	return 0;
}
