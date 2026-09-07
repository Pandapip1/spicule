/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Sleeping, and the one alarm clock.
 *
 * alarm() is a real NT waitable timer (NtCreateTimer/NtSetTimer/
 * NtCancelTimer); expiry queues a user APC that calls
 * __raise_internal(SIGALRM), the same in-process delivery path raise()
 * and abort() use.
 *
 * NT only runs a queued APC when the target thread is in an *alertable*
 * wait -- there's no way to interrupt a running thread. sleep(),
 * nanosleep(), usleep() and pause() all wait alertably, so they get
 * SIGALRM at the right instant; a thread that's computing gets nothing
 * until its next alertable wait, where a pending APC fires immediately.
 * A program that never sleeps never sees its SIGALRM. That gap is
 * recorded in test/POSIX-GAP-ACCOUNTING.md.
 *
 * POSIX timers use a dedicated manager thread (src/time/timer.c) that
 * signals a delivery event when it queues or catches a signal, waking
 * __alertable_delay() below and turning a caught handler into EINTR.
 *
 * The deadline is kept as an absolute NT system time -- the same clock
 * time()/clock_gettime(CLOCK_REALTIME) read and NtSetTimer's absolute
 * mode fires on -- so the alarm() answer and the actual signal moment
 * cannot drift apart, including across a clock_settime().
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_unistd.h"

/* Absolute time (see __plat_time_now()) the pending SIGALRM is due; 0
 * means no request. */
static long long alarm_due;
/* Which request the pending APC belongs to.  Bumped by every alarm(),
 * so a queued APC can name the request that queued it; see
 * alarm_apc_fire. */
static unsigned long alarm_seq;

/* Called on the arming thread when its alarm timer expires, only while
 * that thread is in an alertable wait (see the header comment). The APC
 * may belong to a request already superseded by a later alarm() or
 * alarm(0): __plat_alarm_cancel() can't recall an APC already handed to
 * the thread, only run at the next alertable wait.
 *
 * Matching is done by generation counter (seq == alarm_seq), not by
 * re-checking the clock: an NT timer can fire its APC a hair before
 * __plat_time_now() agrees the deadline passed (measured under Wine,
 * ~1ms early on roughly one run in three), and a clock check would drop
 * that notification permanently since it's never retried. The counter
 * matches an early expiry correctly with no clock read; alarm_due == 0
 * covers the cancelled case. */
static void alarm_apc_fire(unsigned long seq)
{
	if (!alarm_due || seq != alarm_seq) return;

	/* Cleared before delivery, not after: SIGALRM's default action
	 * terminates (so __raise_internal() may not return), and a handler
	 * that calls alarm() must see "no request pending". */
	alarm_due = 0;
	__sig_lock();
	__raise_internal(SIGALRM);
	__sig_unlock();
}

/* alarm.html: seconds until the previous request would fire, rounded
 * *up* -- 0 is reserved for "no such request", so truncating a part-second
 * remainder would wrongly report a live alarm as absent. */
static unsigned alarm_remaining(long long now)
{
	long long left;
	if (!alarm_due) return 0;
	left = alarm_due - now;
	/* Due, or overdue and not yet delivered (thread not alertable since;
	 * see header). No time remains either way. */
	if (left <= 0) return 0;
	return (unsigned)((left + __TICKS_PER_SEC - 1) / __TICKS_PER_SEC);
}

unsigned alarm(unsigned s)
{
	long long now = __plat_time_now();
	long long due;
	unsigned prev = alarm_remaining(now);

	/* A new request replaces the old one; both paths start by
	 * withdrawing what's there ("seconds == 0" cancels). */
	__plat_alarm_cancel();
	alarm_due = 0;
	/* Retire the old request's identity first, so a notification already
	 * handed over for it can no longer match (alarm_apc_fire). */
	alarm_seq++;

	if (s) {
		due = now + (long long)s * __TICKS_PER_SEC;
		/* alarm() is always successful (no error return), so a silent
		 * arming failure just leaves alarm_due at 0. */
		if (__plat_alarm_arm(due, alarm_seq, alarm_apc_fire) == 0)
			alarm_due = due;
	}
	return prev;
}

/* fork()'s child side only. RtlCloneUserProcess copies the address space,
 * so alarm_due arrives holding the parent's value; fork.html requires it
 * reset to zero and any alarm canceled. Deliberately not a
 * cancel-and-close: the timer handle was created without OBJ_INHERIT, so
 * it was never duplicated into the child and NT may have reused that
 * handle number for something else -- closing it would close that. */
void __alarm_reset_after_fork(void)
{
	alarm_due = 0;
	__plat_alarm_reset_after_fork();
	alarm_seq++;
}

/* Wait out `ticks` 100ns units, alertable, so an alarm APC can be
 * delivered mid-wait (see header comment).
 *
 * Returns 0 if the whole interval elapsed. Returns -1/EINTR with *left
 * set to the ticks still owed if a signal-catching function ran first --
 * an *ignored* SIGALRM must leave the interval running, which is what
 * the __sig_caught_count() comparison distinguishes (it only changes for
 * caught signals, not ignored ones).
 *
 * Elapsed time is measured on __plat_time_now(), not the performance
 * counter, so it agrees with alarm()'s system-clock deadlines even
 * across a clock step. */
int __alertable_delay(long long ticks, long long *left, const char *operation)
{
	unsigned long caught = __sig_caught_count();
	long long start, now, t;

	/* No unsafe/defer region needed: the only shared state here is reached
	 * through __sig_drain_pending()/__sig_wait_delivery(), which take
	 * __sig_lock() internally (itself a defer region); everything else is
	 * a local an abandoned thread can safely leave half-updated. So
	 * cancellation landing anywhere here, including mid-wait, is safe --
	 * exactly what pthread_cancel/2-1,3-1,4-1 exercise. */
	(void)operation;
	start = __plat_time_now();
	__pthread_testcancel();
	__sig_drain_pending();
	if (__sig_caught_count() != caught) {
		if (left) *left = ticks;
		errno = EINTR;
		return -1;
	}
	while (ticks > 0) {
		/* The signal-delivery event closes the check/wait race and wakes this
		 * thread as soon as a background source queues or catches a signal. */
		t = -ticks;
		if (!t) t = -1;   /* a 0 timeout means "yield", not "no wait" */
		__sig_wait_delivery(&t);
		__pthread_testcancel();
		__sig_drain_pending();

		now = __plat_time_now();
		ticks -= now - start;
		start = now;
		if (__sig_caught_count() != caught) {
			if (left) *left = ticks > 0 ? ticks : 0;
			errno = EINTR;
			return -1;
		}
	}
	return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
	long long ticks, owed = 0;

	if (!req || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L || req->tv_sec < 0) { errno = EINVAL; return -1; }
	ticks = __duration_ticks(req->tv_sec, req->tv_nsec);
	if (__alertable_delay(ticks, &owed, "nanosleep()") < 0) {
		/* nanosleep.html: "If the rmtp argument is non-NULL, the
		 * timespec structure referenced by it is updated to contain
		 * the amount of time remaining in the interval (the requested
		 * time minus the time actually slept)." */
		if (rem) {
			rem->tv_sec = (time_t)(owed / __TICKS_PER_SEC);
			rem->tv_nsec = (long)(owed % __TICKS_PER_SEC) * 100;
		}
		return -1;
	}
	if (rem) rem->tv_sec = rem->tv_nsec = 0;
	return 0;
}

unsigned sleep(unsigned s)
{
	long long owed = 0;
	if (__alertable_delay((long long)s * __TICKS_PER_SEC, &owed,
	    "sleep()") < 0)
		/* sleep.html: returns the "unslept" amount in seconds, rounded
		 * up for the same reason as alarm() -- 0 must mean the full
		 * interval elapsed. */
		return (unsigned)((owed + __TICKS_PER_SEC - 1) / __TICKS_PER_SEC);
	return 0;
}

int usleep(unsigned us)
{
	long long ticks = ((long long)us * __TICKS_PER_SEC + 999999) / 1000000;
	return __alertable_delay(ticks, 0, "usleep()");
}

int pause(void)
{
	unsigned long caught = __sig_caught_count();
	/* pause.html: waits for a signal that is caught or terminates,
	 * then EINTR. Alertable, so an alarm() APC ends it; an ignored
	 * signal changes no counter and leaves pause() waiting, as POSIX
	 * requires. No unsafe/defer region: see __alertable_delay() above. */
	while (__sig_caught_count() == caught) {
		__pthread_testcancel();
		__sig_drain_pending();
		if (__sig_caught_count() != caught) break;
		__sig_wait_delivery(0);
	}
	errno = EINTR;
	return -1;
}

// NOLINTEND(misc-include-cleaner)
