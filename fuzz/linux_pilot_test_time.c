/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux platform pilot smoke test -- time subsystem -- NOT part of
 * spicule, same standing as fuzz/linux_pilot_test.c (the mman/unistd
 * pilot this extends) and fuzz/ntstubs.c before it.
 *
 * Exercises the REAL spicule public entry points (time(), clock(),
 * clock_gettime(), clock_settime(), clock_getres(), timespec_get(),
 * stime(), from the real src/time/{time,clock,clock_gettime,stime,
 * timespec_get}.c, statically linked here) against the new
 * src/time/linux/plat_time.c backend, running as a real, native
 * aarch64 Linux process on this host -- no Wine, no emulation.
 *
 * A raw clock_gettime(2) syscall, issued directly in this file with the
 * same aarch64 syscall number src/time/linux/plat_time.c itself uses
 * (confirmed independently against this host's glibc <sys/syscall.h>),
 * stands in for "the known-correct answer" throughout: every spicule
 * front-door result below is cross-checked against it, not just
 * checked for "didn't crash".
 */
#include <time.h>
#include <errno.h>

extern long syscall(long number, ...);
extern int printf(const char *, ...);

#define SYS_clock_gettime 113
#define SYS_nanosleep     101

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

/* Absolute difference between two (sec,nsec) timespec-shaped instants,
 * in nanoseconds, as a plain long long -- used only to bound how far two
 * independently taken "now" readings may drift apart during a test,
 * never to interpret an actual duration. */
static long long ns_diff(long long sec_a, long nsec_a, long long sec_b, long nsec_b)
{
	long long a = sec_a * 1000000000LL + nsec_a;
	long long b = sec_b * 1000000000LL + nsec_b;
	return a > b ? a - b : b - a;
}

int main(void)
{
	struct timespec raw, ts, ts2;
	time_t t;
	clock_t c1, c2;
	int i;

	/* --- time/linux/plat_time.c: raw oracle --- */
	{
		long ret = syscall(SYS_clock_gettime, CLOCK_REALTIME, &raw);
		CHECK(ret == 0, "raw clock_gettime(CLOCK_REALTIME) syscall succeeded (oracle)");
		printf("     (oracle) raw CLOCK_REALTIME = %lld.%09ld\n",
		       (long long)raw.tv_sec, raw.tv_nsec);
	}

	/* --- time/time.c: time() --- */
	{
		t = time(0);
		CHECK(t > 0, "time() returned a plausible positive epoch value");
		CHECK(t >= raw.tv_sec - 5 && t <= raw.tv_sec + 5,
		      "time()'s result matches the raw syscall oracle within 5s");
	}

	/* --- time/clock_gettime.c: clock_gettime(CLOCK_REALTIME) --- */
	{
		int ret = clock_gettime(CLOCK_REALTIME, &ts);
		CHECK(ret == 0, "clock_gettime(CLOCK_REALTIME) succeeded");
		CHECK(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L,
		      "clock_gettime(CLOCK_REALTIME) tv_nsec is in range");
		CHECK(ns_diff(ts.tv_sec, ts.tv_nsec, raw.tv_sec, raw.tv_nsec) < 5000000000LL,
		      "clock_gettime(CLOCK_REALTIME) matches the raw syscall oracle within 5s");
	}

	/* --- time/timespec_get.c: timespec_get(TIME_UTC) --- */
	{
		int base = timespec_get(&ts2, TIME_UTC);
		CHECK(base == TIME_UTC, "timespec_get(TIME_UTC) reports TIME_UTC");
		CHECK(ns_diff(ts2.tv_sec, ts2.tv_nsec, raw.tv_sec, raw.tv_nsec) < 5000000000LL,
		      "timespec_get(TIME_UTC) matches the raw syscall oracle within 5s");
	}

	/* --- time/clock_gettime.c: clock_gettime(CLOCK_MONOTONIC), advancing --- */
	{
		struct timespec m1, m2, sleep_req;
		int ret1, ret2;
		long rc;

		ret1 = clock_gettime(CLOCK_MONOTONIC, &m1);
		CHECK(ret1 == 0, "clock_gettime(CLOCK_MONOTONIC) first read succeeded");

		/* A real sleep, via the same raw-syscall discipline as the rest
		 * of this pilot -- nanosleep(2) is not itself in scope here
		 * (that is src/time/timespec's sibling clock_nanosleep.c, not
		 * converted here), so this is scaffolding exactly like fuzz/
		 * linux_pilot_test.c's raw openat() stand-in for open(), not a
		 * claim that spicule's own sleep is under test. */
		sleep_req.tv_sec = 0;
		sleep_req.tv_nsec = 20000000L; /* 20ms */
		rc = syscall(SYS_nanosleep, &sleep_req, (void *)0);
		CHECK(rc == 0, "raw nanosleep(2) scaffolding succeeded");

		ret2 = clock_gettime(CLOCK_MONOTONIC, &m2);
		CHECK(ret2 == 0, "clock_gettime(CLOCK_MONOTONIC) second read succeeded");

		CHECK((m2.tv_sec > m1.tv_sec) ||
		      (m2.tv_sec == m1.tv_sec && m2.tv_nsec > m1.tv_nsec),
		      "clock_gettime(CLOCK_MONOTONIC) strictly advanced across the sleep");

		CHECK(ns_diff(m1.tv_sec, m1.tv_nsec, m2.tv_sec, m2.tv_nsec) >= 15000000LL,
		      "clock_gettime(CLOCK_MONOTONIC) advanced by at least ~15ms (slept ~20ms)");
	}

	/* --- time/clock_gettime.c: clock_getres() --- */
	{
		struct timespec res;
		int ret = clock_getres(CLOCK_MONOTONIC, &res);
		CHECK(ret == 0, "clock_getres(CLOCK_MONOTONIC) succeeded");
		CHECK(res.tv_sec > 0 || res.tv_nsec > 0,
		      "clock_getres(CLOCK_MONOTONIC) reports a nonzero resolution");
	}

	/* --- time/clock_gettime.c: clock_gettime(CLOCK_PROCESS_CPUTIME_ID) --- */
	{
		struct timespec cpu1, cpu2;
		volatile long long busy = 0;
		int ret1 = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu1);
		CHECK(ret1 == 0, "clock_gettime(CLOCK_PROCESS_CPUTIME_ID) first read succeeded");
		CHECK(cpu1.tv_sec >= 0, "clock_gettime(CLOCK_PROCESS_CPUTIME_ID) is non-negative");

		/* Spend some real CPU time so the second reading has a chance to
		 * differ from the first -- getrusage()'s microsecond resolution
		 * means a too-short loop could plausibly read back identical
		 * values without that being a bug, so this only checks
		 * non-decrease, not strict advancement. */
		for (i = 0; i < 50000000; i++) busy += i;

		{
			int ret2 = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu2);
			CHECK(ret2 == 0, "clock_gettime(CLOCK_PROCESS_CPUTIME_ID) second read succeeded");
			CHECK((cpu2.tv_sec > cpu1.tv_sec) ||
			      (cpu2.tv_sec == cpu1.tv_sec && cpu2.tv_nsec >= cpu1.tv_nsec),
			      "clock_gettime(CLOCK_PROCESS_CPUTIME_ID) is monotonic non-decreasing");
		}
		(void)busy;
	}

	/* --- time/clock.c: clock() --- */
	{
		volatile long long busy = 0;
		c1 = clock();
		CHECK(c1 != (clock_t)-1, "clock() first read succeeded");
		for (i = 0; i < 50000000; i++) busy += i;
		c2 = clock();
		CHECK(c2 != (clock_t)-1, "clock() second read succeeded");
		CHECK(c2 >= c1, "clock() is monotonic non-decreasing across CPU-bound work");
		(void)busy;
	}

	/* --- time/stime.c + time/clock_gettime.c: clock_settime(CLOCK_REALTIME) ---
	 * Setting the system clock needs CAP_SYS_TIME; this pilot runs
	 * unprivileged, so the expected, correct outcome is
	 * EPERM from the kernel by way of this backend's raw clock_settime(2)
	 * -- proving errno actually propagates end to end from the syscall
	 * through __plat_realtime_set() to the caller, the same shape of
	 * proof fuzz/linux_pilot_test.c's msync()-through-a-real-fd check
	 * makes for a *successful* raw round trip. Tolerate an unexpected
	 * success too (root, or a container with CAP_SYS_TIME), since this
	 * is a statement about privilege, not about this backend's
	 * correctness either way. */
	{
		struct timespec now;
		int ret;
		clock_gettime(CLOCK_REALTIME, &now);
		ret = clock_settime(CLOCK_REALTIME, &now);
		CHECK(ret == 0 || (ret == -1 && errno == EPERM),
		      "clock_settime(CLOCK_REALTIME) either succeeds (privileged) or fails EPERM (unprivileged)");
		if (ret == -1) printf("     (errno=%d, EPERM=%d -- expected unprivileged outcome)\n", errno, EPERM);
		else printf("     (succeeded -- running privileged)\n");
	}

	/* --- time/stime.c: stime() --- same privilege story as clock_settime() above. */
	{
		int ret = stime(&t);
		CHECK(ret == 0 || (ret == -1 && errno == EPERM),
		      "stime() either succeeds (privileged) or fails EPERM (unprivileged)");
	}

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
