/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ualarm(): "undefined-ok" on NT for the same reason getitimer()/
 * setitimer() are. ualarm.html's DESCRIPTION is ITIMER_REAL in different
 * units, so this is built directly on setitimer(ITIMER_REAL, ...)
 * (src/time/linux/plat_itimer.c) rather than a second raw mechanism.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <sys/time.h>

unsigned ualarm(unsigned useconds, unsigned interval)
{
	struct itimerval new, old;

	/* ualarm.html's own units are whole microseconds; struct timeval's
	 * tv_usec must stay within [0, 999999], so seconds and microseconds
	 * are split out explicitly rather than handing 10^6+ straight to
	 * tv_usec -- setitimer() itself would reject that (itimerval_valid(),
	 * src/time/linux/plat_itimer.c) and silently truncating here would
	 * misreport what was actually armed. */
	new.it_value.tv_sec = (time_t)(useconds / 1000000U);
	new.it_value.tv_usec = (suseconds_t)(useconds % 1000000U);
	new.it_interval.tv_sec = (time_t)(interval / 1000000U);
	new.it_interval.tv_usec = (suseconds_t)(interval % 1000000U);

	/* ualarm.html RETURN VALUE: "the number of microseconds until any
	 * previously scheduled alarm was due to be delivered, or 0 if there
	 * was no previously scheduled alarm." ualarm() itself defines no
	 * failure return at all (unlike alarm(), it has no [ERRORS] section
	 * either) -- a setitimer() failure has nothing meaningful to fold
	 * into an unsigned microsecond count, so it is treated the same way
	 * this library's own alarm() already treats a failed arm (src/
	 * unistd/sleep.c's own comment): silently, as "no alarm scheduled". */
	if (setitimer(ITIMER_REAL, &new, &old) < 0) return 0;
	if (old.it_value.tv_sec < 0) return 0;
	/* Clamped rather than allowed to wrap: a previous it_value beyond
	 * UINT_MAX microseconds (~71.5 minutes) cannot be represented in
	 * ualarm()'s own unsigned-microseconds return at all, and reporting
	 * the wrapped low bits would be a wrong answer, not an honest one. */
	if (old.it_value.tv_sec > (time_t)(0xFFFFFFFFU / 1000000U)) return 0xFFFFFFFFU;
	return (unsigned)old.it_value.tv_sec * 1000000U + (unsigned)old.it_value.tv_usec;
}

// NOLINTEND(misc-include-cleaner)
