/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * POSIX per-process timers. One detached manager thread waits until the
 * nearest absolute deadline or until a timer operation signals its wake
 * event. That is deliberately one thread for the process, not one thread per
 * timer: timer_create() has a fixed, honest TIMER_MAX resource bound, and
 * fork() has only one background thread to forget and restart. Signal
 * delivery uses signal.c's process-pending queue, so the application
 * thread's mask -- not the manager thread's empty TLS mask -- decides when a
 * notification is consumed. A blocked timer signal therefore coalesces and
 * its missed interval expirations become timer_getoverrun()'s count.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_time.h"
#include "unsafe_pointer.h"

struct posix_timer {
	int active;
	clockid_t clock;
	struct sigevent event;
	long long due;
	long long interval;
	int overrun;
	int notification_pending;
};

static struct posix_timer timers[TIMER_MAX];
static int manager_started;
static __plat_handle_t manager_wake;

static int clock_supported(clockid_t clock)
{
	return clock == CLOCK_REALTIME || clock == CLOCK_MONOTONIC ||
	       clock == CLOCK_PROCESS_CPUTIME_ID;
}

/* ts is required in both: timespec_valid() dereferences ts->tv_sec
 * unconditionally as its first operand, and timespec_ticks() the same
 * way via ts->tv_nsec, with no NULL check in either. Both of this file's
 * two call sites (timer_settime()'s `&value->it_value`/
 * `&value->it_interval`) are addresses of fields of value, itself
 * required below -- never NULL. ticks (timespec_ticks()'s own 2nd
 * parameter) is written (`*ticks = ...`) only on the success path, but
 * every real call site passes `&first`/`&interval`, on-stack locals,
 * never NULL. */
static int timespec_valid(const struct timespec *ts) __attribute__((nonnull(1)));
static int timespec_ticks(const struct timespec *ts, long long *ticks) __attribute__((nonnull(1, 2)));

static int timespec_valid(const struct timespec *ts)
{
	return ts->tv_sec >= 0 && ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L;
}

static int timespec_ticks(const struct timespec *ts, long long *ticks)
{
	long long subsecond = (ts->tv_nsec + 99L) / 100L;
	if (ts->tv_sec > (INT64_MAX - subsecond) / __TICKS_PER_SEC)
		return 0;
	*ticks = ts->tv_sec * __TICKS_PER_SEC + subsecond;
	return 1;
}

/* ts is required: ticks_timespec() writes ts->tv_sec/tv_nsec
 * unconditionally regardless of the `ticks < 0` clamp above it, with no
 * NULL check, and its only two call sites (timer_value()'s
 * `&value->it_value`/`&value->it_interval`) are field addresses of
 * value, itself required below -- never NULL. */
static void ticks_timespec(long long ticks, struct timespec *ts) __attribute__((nonnull(2)));
static void ticks_timespec(long long ticks, struct timespec *ts)
{
	if (ticks < 0) ticks = 0;
	ts->tv_sec = (time_t)(ticks / __TICKS_PER_SEC);
	ts->tv_nsec = (long)(ticks % __TICKS_PER_SEC) * 100L;
}

static long long clock_ticks(clockid_t clock)
{
	struct timespec now;
	if (clock_gettime(clock, &now) < 0) return 0;
	return __duration_ticks(now.tv_sec, now.tv_nsec);
}

static struct posix_timer *timer_lookup(timer_t id)
{
	int i;
	for (i = 0; i < TIMER_MAX; i++)
		if (id == (timer_t)&timers[i] && timers[i].active) return &timers[i];
	return 0;
}

static void timer_signal(struct posix_timer *timer, long long expirations)
{
	siginfo_t si;
	long long overrun;

	if (timer->event.sigev_notify != SIGEV_SIGNAL) return;
	if (__sig_pending_member(timer->event.sigev_signo)) {
		overrun = expirations > INT_MAX - timer->overrun ?
			INT_MAX : timer->overrun + expirations;
		timer->overrun = (int)overrun;
		timer->notification_pending = 1;
		return;
	}
	/* A notification which was pending on the preceding poll has just
	 * been consumed.  Fold expirations from this narrow hand-off window
	 * into that notification rather than racing a second signal past the
	 * handler before it can call timer_getoverrun(). */
	if (timer->notification_pending) {
		overrun = expirations > INT_MAX - timer->overrun ?
			INT_MAX : timer->overrun + expirations;
		timer->overrun = (int)overrun;
		timer->notification_pending = 0;
		return;
	}
	timer->overrun = expirations > INT_MAX ? INT_MAX : (int)(expirations - 1);
	memset(&si, 0, sizeof si);
	si.si_signo = timer->event.sigev_signo;
	si.si_code = SI_TIMER;
	/* timer is checked into the fixed `timers` table by a DIFFERENT
	 * function (timer_create(), via timer_lookup()) earlier in the
	 * program -- an invariant this function's own body cannot see. */
	si.si_timerid = (int)unsafe_assume_shared_provenance(timer - timers);
	si.si_overrun = timer->overrun;
	si.si_value = timer->event.sigev_value;
	/* A timer expiration is process-directed. The manager is an internal
	 * service thread, so delivering against its TLS mask would make a signal
	 * blocked by the application look unblocked and would run the handler on
	 * the wrong thread. Queue it for an application signal-aware point. */
	__sig_queue_process_info(si.si_signo, &si);
	timer->notification_pending = __sig_pending_member(si.si_signo);
}

static void timer_expire(struct posix_timer *timer, long long now)
{
	long long expirations, elapsed, base;
	if (!timer->due || now < timer->due) return;
	expirations = 1;
	if (timer->interval) {
		elapsed = now - timer->due;
		expirations += elapsed / timer->interval;
		/* Compute the first deadline after now without multiplying the
		 * possibly enormous expiration count by the interval. */
		base = now - elapsed % timer->interval;
		timer->due = timer->interval > INT64_MAX - base ?
			INT64_MAX : base + timer->interval;
	} else {
		timer->due = 0;
	}
	timer_signal(timer, expirations);
}

static void timer_manager(void)
{
	for (;;) {
		long long nearest = 0;
		int i;

		__sig_lock();
		for (i = 0; i < TIMER_MAX; i++) {
			struct posix_timer *timer = &timers[i];
			long long now, left;
			if (!timer->active || !timer->due) continue;
			now = clock_ticks(timer->clock);
			timer_expire(timer, now);
			if (!timer->due) continue;
			left = timer->due - now;
			if (left < 0) left = 0;
			/* A process-CPU clock has no wall-clock deadline to wait on: its
			 * time advances only while a process thread runs. Keep that one
			 * optional clock on a bounded probe while all wall clocks use their
			 * exact next deadline. */
			if (timer->clock == CLOCK_PROCESS_CPUTIME_ID && left > 1000000)
				left = 1000000; /* 1 ms of wall time */
			if (!nearest || left < nearest) nearest = left;
		}
		__sig_unlock();

		__plat_timer_manager_wait(manager_wake, nearest, nearest != 0);
	}
}

static int start_manager(void)
{
	__plat_handle_t wake;
	if (manager_started) return 0;
	if (__plat_timer_manager_start(timer_manager, &wake) < 0) return -1;
	manager_wake = wake;
	manager_started = 1;
	return 0;
}

int timer_create(clockid_t clock, struct sigevent *event, timer_t *id)
{
	struct posix_timer *timer = 0;
	int i;

	if (!clock_supported(clock)) { errno = EINVAL; return -1; }
	if (event && event->sigev_notify != SIGEV_SIGNAL &&
	    event->sigev_notify != SIGEV_NONE) { errno = EINVAL; return -1; }
	if (event && event->sigev_notify == SIGEV_SIGNAL &&
	    (event->sigev_signo <= 0 || event->sigev_signo >= _NSIG)) {
		errno = EINVAL;
		return -1;
	}
	__sig_lock();
	for (i = 0; i < TIMER_MAX; i++)
		if (!timers[i].active) { timer = &timers[i]; break; }
	if (!timer) { __sig_unlock(); errno = EAGAIN; return -1; }
	if ((!event || event->sigev_notify == SIGEV_SIGNAL) &&
	    start_manager() < 0) { __sig_unlock(); return -1; }
	memset(timer, 0, sizeof *timer);
	timer->active = 1;
	timer->clock = clock;
	if (event) timer->event = *event;
	else {
		timer->event.sigev_notify = SIGEV_SIGNAL;
		timer->event.sigev_signo = SIGALRM;
		timer->event.sigev_value.sival_ptr = timer;
	}
	*id = (timer_t)timer;
	__sig_unlock();
	return 0;
}

/* Both required: timer->due is dereferenced unconditionally to compute
 * `left`, and value->it_value/it_interval (via ticks_timespec(), which
 * requires its own ts nonnull -- see above) unconditionally too, with no
 * NULL check on either. Both real call sites -- timer_settime()'s `if
 * (old) timer_value(timer, old);` (old already proven truthy by the
 * guard) and timer_gettime()'s own `value` (itself forwarded from a
 * caller that never passes NULL, see below) -- always supply a real
 * object. */
static void timer_value(struct posix_timer *timer, struct itimerspec *value)
    __attribute__((nonnull(1, 2)));
static void timer_value(struct posix_timer *timer, struct itimerspec *value)
{
	long long left = timer->due ? timer->due - clock_ticks(timer->clock) : 0;
	ticks_timespec(left, &value->it_value);
	ticks_timespec(timer->interval, &value->it_interval);
}

int timer_settime(timer_t id, int flags, const struct itimerspec *value,
                  struct itimerspec *old)
{
	struct posix_timer *timer;
	long long first, interval, now;

	if ((flags & ~TIMER_ABSTIME) || !timespec_valid(&value->it_value) ||
	    !timespec_valid(&value->it_interval)) { errno = EINVAL; return -1; }
	if (!timespec_ticks(&value->it_value, &first) ||
	    !timespec_ticks(&value->it_interval, &interval)) {
		errno = EOVERFLOW;
		return -1;
	}
	__sig_lock();
	timer = timer_lookup(id);
	if (!timer) { __sig_unlock(); errno = EINVAL; return -1; }
	if (old) timer_value(timer, old);
	if (first && !(flags & TIMER_ABSTIME)) {
		now = clock_ticks(timer->clock);
		if (first > INT64_MAX - now) {
			__sig_unlock();
			errno = EOVERFLOW;
			return -1;
		}
	}
	timer->interval = interval;
	timer->overrun = 0;
	if (!first) timer->due = 0;
	else if (flags & TIMER_ABSTIME) timer->due = first;
	else timer->due = now + first;
	if (manager_wake) __plat_timer_wake(manager_wake);
	__sig_unlock();
	return 0;
}

int timer_gettime(timer_t id, struct itimerspec *value)
{
	struct posix_timer *timer;
	__sig_lock();
	timer = timer_lookup(id);
	if (!timer) { __sig_unlock(); errno = EINVAL; return -1; }
	timer_value(timer, value);
	__sig_unlock();
	return 0;
}

int timer_getoverrun(timer_t id)
{
	struct posix_timer *timer;
	int result;
	__sig_lock();
	timer = timer_lookup(id);
	if (!timer) { __sig_unlock(); errno = EINVAL; return -1; }
	/* Account for sub-millisecond intervals even when the manager thread
	 * has not yet received a scheduling slice.  Expirations are a clock
	 * property, not a count of manager wakeups. */
	timer_expire(timer, clock_ticks(timer->clock));
	result = timer->overrun;
	timer->notification_pending = 0;
	__sig_unlock();
	return result;
}

int timer_delete(timer_t id)
{
	struct posix_timer *timer;
	__sig_lock();
	timer = timer_lookup(id);
	if (!timer) { __sig_unlock(); errno = EINVAL; return -1; }
	memset(timer, 0, sizeof *timer);
	if (manager_wake) __plat_timer_wake(manager_wake);
	__sig_unlock();
	return 0;
}

void __timer_reinit_after_fork(void)
{
	memset(timers, 0, sizeof timers);
	manager_started = 0;
	manager_wake = __PLAT_HANDLE_NULL;
}

// NOLINTEND(misc-include-cleaner)
