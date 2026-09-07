/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * times(): every field of struct tms has a real source already wired
 * up elsewhere in this library, reused rather than re-derived:
 *
 *   tms_utime/tms_stime   -- NtQueryInformationProcess(ProcessTimes),
 *                            the exact call src/misc/resource.c's
 *                            getrusage(RUSAGE_SELF) already makes.
 *   tms_cutime/tms_cstime -- the running total src/process/wait.c
 *                            accumulates at every waitpid()/wait3()/
 *                            wait4() reap, read out via the same
 *                            __rusage_children() getrusage(RUSAGE_
 *                            CHILDREN) calls.
 *
 * Units: times.html's RETURN VALUE says the result (and every tms_*
 * field) is in "clock ticks" and directs the caller to
 * sysconf(_SC_CLK_TCK) to find out what a tick is.  src/unistd/
 * sysconf.c answers _SC_CLK_TCK with 100, so one tick is 1/100 second
 * -- and NT's own KERNEL_USER_TIMES fields are 100ns units, i.e.
 * __TICKS_PER_SEC (10,000,000) per second, so the conversion factor is
 * __TICKS_PER_SEC / 100 = 100,000 100ns-units per clock tick.  Kept as
 * that same __TICKS_PER_SEC-derived division src/time/clock.c already
 * uses for CLOCKS_PER_SEC, rather than a second hardcoded constant, so
 * a future change to _SC_CLK_TCK's answer cannot silently desync from
 * this file.
 *
 * Return value: times.html DESCRIPTION -- "elapsed real time, in clock
 * ticks, since an arbitrary point in the past" (traditionally system
 * start-up, but POSIX only requires it be fixed within one process's
 * lifetime).  CLOCK_MONOTONIC (src/time/clock_gettime.c, itself
 * NtQueryPerformanceCounter-backed) is exactly that: a free-running
 * counter from an arbitrary, never-jumping epoch, already used
 * elsewhere in this library for the same "some fixed point, don't
 * care which" contract.  ERRORS: "(clock_t)-1 shall be returned and
 * errno set" -- reachable if either underlying NT query fails.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/times.h>
#include <time.h>
#include <sys/resource.h>
#include <errno.h>
#include "libc.h"
#include "plat_misc.h"

static clock_t nt100ns_to_ticks(unsigned long long t100ns)
{
	return (clock_t)(t100ns / (__TICKS_PER_SEC / 100));
}

static clock_t timeval_to_ticks(const struct timeval *tv)
{
	unsigned long long t100ns = (unsigned long long)tv->tv_sec * __TICKS_PER_SEC
	    + (unsigned long long)tv->tv_usec * 10;
	return nt100ns_to_ticks(t100ns);
}

clock_t times(struct tms *buf)
{
	unsigned long long user100ns, kernel100ns;
	struct rusage cru;
	struct timespec mono;

	if (buf) {
		if (__plat_process_times_self(&user100ns, &kernel100ns) < 0) return (clock_t)-1;
		buf->tms_utime = nt100ns_to_ticks(user100ns);
		buf->tms_stime = nt100ns_to_ticks(kernel100ns);

		__rusage_children(&cru);
		buf->tms_cutime = timeval_to_ticks(&cru.ru_utime);
		buf->tms_cstime = timeval_to_ticks(&cru.ru_stime);
	}

	if (clock_gettime(CLOCK_MONOTONIC, &mono) < 0) return (clock_t)-1;
	return nt100ns_to_ticks((unsigned long long)mono.tv_sec * __TICKS_PER_SEC
	    + (unsigned long long)mono.tv_nsec / 100);
}

// NOLINTEND(misc-include-cleaner)
