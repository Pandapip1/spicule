/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * gettimeofday()/settimeofday() in terms of clock_gettime()/
 * clock_settime()(CLOCK_REALTIME) (src/time/clock_gettime.c), which are
 * themselves NtQuerySystemTime/NtSetSystemTime -- the same NT-epoch
 * clock time()/stime() are built on.  The tz argument is accepted (POSIX
 * says implementations "obsolete" it, but does not forbid it) and
 * ignored, the way glibc's own gettimeofday()/settimeofday() do: this
 * target has no notion of a system-wide timezone offset separate from
 * TZ (src/time/tzset.c).
 *
 * settimeofday()'s second parameter is only a real `struct timezone *`
 * under _GNU_SOURCE/_BSD_SOURCE (sys/time.h); _GNU_SOURCE is defined
 * here unconditionally, the way src/string/strlcpy.c and friends do for
 * their own non-default-visibility declarations, so this file always
 * sees the real prototype and stays a single definition regardless of
 * which feature-test macros whatever *else* is being built alongside it
 * happens to define -- library object files are never compiled with a
 * per-caller feature-test macro (see the Makefile's CFLAGS_ALL), so
 * this is the only way this translation unit can reliably match the
 * header's declaration when _GNU_SOURCE/_BSD_SOURCE isn't otherwise on.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <sys/time.h>
#include <time.h>
#include <errno.h>

int gettimeofday(struct timeval *__restrict tv, void *__restrict tz)
{
	struct timespec ts;
	(void)tz;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) return -1;
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
	return 0;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz)
{
	struct timespec ts;
	(void)tz;
	if (tv->tv_usec < 0 || tv->tv_usec >= 1000000L) {
		errno = EINVAL;
		return -1;
	}
	ts.tv_sec = tv->tv_sec;
	/* tv_usec validation bounds the product to [0, 999999000]. */
	ts.tv_nsec = (long)(tv->tv_usec * 1000);
	return clock_settime(CLOCK_REALTIME, &ts);
}

// NOLINTEND(misc-include-cleaner)
