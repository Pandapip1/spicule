/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This target has no timezone database (no /usr/share/zoneinfo, no
 * Windows registry lookup implemented here), so "local time" can't mean
 * anything richer than a fixed UTC offset.  tzset() understands just
 * the numeric-offset prefix of a POSIX TZ string -- "EST5EDT" or
 * "PST8PDT7" style DST rules are read only insofar as parsing the
 * leading "name offset" stops harmlessly at the first character it
 * doesn't understand.  With no TZ set (or TZ=UTC/empty) local time is
 * UTC, which is the safe default for a system that can't otherwise
 * know better.  daylight is always 0: without rules there is no DST to
 * apply, ever.
 */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include "ownership_stubs.h" /* unsafe_assume_pointer_nonnull() */

int daylight;
long timezone;
char *tzname[2] = { (char *)"UTC", (char *)"UTC" };

static char __tzname_std[32] = "UTC"; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
static char __tzname_dst[32] = "UTC"; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

/* v*factor, saturated to +-bound instead of wrapping.  v can be as
 * large as this build's own `long` (h/mn/s all come from strtol()), and
 * on an LP64 target `long` and `long long` are the same width, so
 * `bound` itself (the target's LONG_MAX, passed in by the caller) can
 * equal LLONG_MAX -- comparing against bound/factor first, rather than
 * forming v*factor and checking afterward, means the multiplication
 * itself never runs unless it is already known to fit. */
static long long mul_sat(long long v, long long factor, long long bound)
{
	if (v > bound / factor) return bound;
	if (v < -(bound / factor)) return -bound;
	return v * factor;
}

/* a+b, saturated to +-bound.  Both a and b are already within
 * [-bound, bound] at every call site below, which is what keeps
 * `bound - b` and `-bound - b` themselves from overflowing even when
 * bound is LLONG_MAX: b in [0, bound] puts bound-b in [0, bound], and b
 * in [-bound, 0) puts -bound-b in (-bound, 0]. */
static long long add_sat(long long a, long long b, long long bound)
{
	if (b >= 0) return a > bound - b ? bound : a + b;
	return a < -bound - b ? -bound : a + b;
}

static void read_name(const char **input, char *out, size_t cap)
{
	const char *p = *input;
	size_t n = 0;

	if (*p == '<') {
		p++;
		while (*p && *p != '>') {
			if (n + 1 < cap) out[n++] = *p;
			p++;
		}
		if (*p == '>') p++;
	} else {
		while (isalpha((unsigned char)*p)) {
			if (n + 1 < cap) out[n++] = *p;
			p++;
		}
	}
	out[n] = 0;
	*input = p;
}

void tzset(void)
{
	const char *tz = getenv("TZ");
	long h = 0, mn = 0, s = 0;
	int sign = 1;

	daylight = 0;
	if (!tz || !*tz) {
		memcpy(__tzname_std, "UTC", sizeof "UTC");
		memcpy(__tzname_dst, "UTC", sizeof "UTC");
		timezone = 0;
		tzname[0] = __tzname_std;
		tzname[1] = __tzname_dst;
		return;
	}

	/* Name: a run of letters, or a "quoted" run of anything but '>'. */
	read_name(&tz, __tzname_std, sizeof __tzname_std);
	/* read_name() only ever advances *input from its own live starting
	 * position; it never stores NULL back through input. */
	unsafe_assume_pointer_nonnull(tz);
	if (!__tzname_std[0]) memcpy(__tzname_std, "UTC", sizeof "UTC");
	tzname[0] = __tzname_std;

	/* Offset: [+-]?H[:MM[:SS]], POSIX sense (added to local time to get
	 * UTC), same sign convention as the `timezone` global. */
	if (*tz == '+') tz++;
	else if (*tz == '-') { sign = -1; tz++; }
	if (isdigit((unsigned char)*tz)) {
		h = strtol(tz, (char **)&tz, 10);
		if (*tz == ':') { tz++; mn = strtol(tz, (char **)&tz, 10); }
		if (*tz == ':') { tz++; s = strtol(tz, (char **)&tz, 10); }
	}
	read_name(&tz, __tzname_dst, sizeof __tzname_dst);
	if (!__tzname_dst[0])
		(void)strlcpy(__tzname_dst, __tzname_std, sizeof __tzname_dst);
	tzname[1] = __tzname_dst;
	/* h/mn/s come from strtol(), which saturates at LONG_MAX. On the LP64
	 * aarch64-linux target, long and long long are the same 64-bit width,
	 * so that saturated LONG_MAX IS LLONG_MAX: naively combining in
	 * `long long` then clamping overflows the multiplication itself before
	 * the clamp can see it (TZ=X9223372036854775807 used to wrap h*3600 to
	 * -3600, which the old clamp let through as a bogus UTC-1 offset
	 * instead of saturating). x86_64-win32's LLP64 long never had this
	 * problem: strtol() there saturates at 2147483647, which times 3600
	 * fits long long with room to spare.
	 *
	 * mul_sat()/add_sat() saturate at LONG_MAX one term at a time, so no
	 * intermediate result needs more range than the final answer,
	 * regardless of long's width on the target. */
	{
		long long total = mul_sat(h, 3600, LONG_MAX);
		total = add_sat(total, mul_sat(mn, 60, LONG_MAX), LONG_MAX);
		total = add_sat(total, s, LONG_MAX);
		/* localtime_r publishes -timezone in the same signed-long
		 * representation.  Keep the negative endpoint symmetric so that
		 * inverse is representable too; LONG_MIN has no positive mate.
		 * Safe to negate directly: total is already within
		 * [-LONG_MAX, LONG_MAX] by construction. */
		if (sign < 0) total = -total;
		timezone = (long)total;
	}
}
