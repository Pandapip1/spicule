/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getitimer()/setitimer(): include/sys/time.h's own declarations carry an
 * "undefined-ok" marker whose reasoning is entirely NT-specific -- NT's
 * SIGALRM delivery (src/unistd/sleep.c's alarm()) is an APC that only
 * runs while the arming thread sits in an alertable wait, so an interval
 * timer's repeat expiries, generated while that thread is off doing
 * something else, would coalesce into a single delivery instead of
 * queueing. That marker stays true of, and only checked against, the NT
 * build. It has no bearing here.
 *
 * WHY THIS IS BUILT ON src/time/timer.c RATHER THAN A RAW setitimer(2)/
 * getitimer(2) SYSCALL, even though both are real Linux syscalls (SYS_
 * setitimer 103, SYS_getitimer 102 on this ABI): a raw kernel itimer
 * delivers its SIGALRM/SIGVTALRM/SIGPROF the way every other
 * asynchronously-generated signal does on Linux -- through a real
 * kernel-installed handler (rt_sigaction(2), with a real sigreturn
 * trampoline). This library does not have one of those yet on Linux:
 * src/signal/linux/sigdelivery.c's own banner says so outright
 * ("What this does NOT do yet is install any real kernel-level signal
 * handler ... genuinely assembly-level work ... not yet built") and
 * scopes that out as a separate, not-yet-landed migration effort.
 * Driving a raw kernel itimer through that gap would arm a real timer
 * whose expiry this process could never actually observe (or worse,
 * whose default action -- terminate -- would fire instead, since no real
 * handler would be registered with the kernel to catch it).
 *
 * src/time/timer.c already has a real, working, and genuinely repeating
 * mechanism for exactly this problem: one manager thread that computes
 * each timer's absolute deadline for itself (clock_gettime(), not a
 * kernel alarm), advances it correctly across missed periods
 * (timer_expire()'s own due/interval bookkeeping), and hands expiries to
 * signal.c's process-pending queue for delivery the next time an
 * application thread checks in (__sig_drain_pending(), called from
 * sleep()/nanosleep()/pause() and the other signal-aware waits). That
 * mechanism is UNCONDITIONALLY REAL repeating delivery, not NT's
 * coalescing failure mode: the manager thread's own bookkeeping keeps
 * advancing the due time and counting overruns regardless of what the
 * caller's thread is doing in the meantime, which is the entire
 * difference between "repeating" and "one-shot that happens to be
 * rearmed." So this file does not reinvent that timer machinery, or
 * touch the kernel's own itimer at all -- it lazily creates one ordinary
 * POSIX per-process timer (timer_create()) per ITIMER_* kind the first
 * time it is used, and forwards every setitimer()/getitimer() call
 * straight through timer_settime()/timer_gettime() on it. ualarm()
 * (src/unistd/linux/plat_ualarm.c) is built on this setitimer(), per the
 * same reasoning, rather than on a second raw mechanism.
 *
 * ITIMER_REAL maps onto CLOCK_REALTIME + SIGALRM, an exact match for its
 * own definition (setitimer.html: "real time ... generates SIGALRM").
 *
 * ITIMER_PROF maps onto CLOCK_PROCESS_CPUTIME_ID + SIGPROF, also an
 * exact match: ITIMER_PROF decrements "both in process virtual time and
 * when the system is running on behalf of the process", i.e. user+system
 * CPU time combined, which is exactly what CLOCK_PROCESS_CPUTIME_ID
 * already measures (src/misc/resource.c's getrusage() reads the very
 * same NtQueryInformationProcess(ProcessTimes)/getrusage(2) split this
 * clock is built from).
 *
 * ITIMER_VIRTUAL is the one honest approximation: its own definition is
 * user CPU time ONLY ("decrements only when the process is executing"),
 * and this library tracks no clock that excludes system time the way a
 * true virtual-time clock would -- CLOCK_PROCESS_CPUTIME_ID is the
 * closest available (user+system), and src/time/timer.c's manager
 * thread already uses it, bounded-probe style, for POSIX per-process-CPU
 * timers. Using it here too means ITIMER_VIRTUAL fires somewhat earlier
 * than strict POSIX would (system time counts toward it that should
 * not), a disclosed, honest simplification rather than a silent one --
 * and still a real, working, repeating timer, which no NT build has at
 * all.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

/* Indexed by ITIMER_REAL/ITIMER_VIRTUAL/ITIMER_PROF (0/1/2, <sys/
 * time.h>) directly -- three slots is a fixed, honest, tiny bound, well
 * within src/time/timer.c's own TIMER_MAX (32), and every real caller
 * only ever wants one or two of the three kinds in practice. */
static timer_t itimer_id[3];
static int itimer_created[3];

static int which_valid(int which)
{
	return which == ITIMER_REAL || which == ITIMER_VIRTUAL || which == ITIMER_PROF;
}

/* Lazily creates the one underlying POSIX timer this ITIMER_* kind
 * forwards to, the first time it is actually needed -- not at process
 * start, so a program that never calls setitimer()/getitimer() never
 * pays timer_create()'s TIMER_MAX-slot cost at all. 0/-1(errno) via
 * return, matching every other seam in this file. */
static int ensure_timer(int which)
{
	struct sigevent ev;
	clockid_t clock;

	if (itimer_created[which]) return 0;
	memset(&ev, 0, sizeof ev);
	ev.sigev_notify = SIGEV_SIGNAL;
	switch (which) {
	case ITIMER_REAL:
		clock = CLOCK_REALTIME;
		ev.sigev_signo = SIGALRM;
		break;
	case ITIMER_VIRTUAL:
		/* See this file's own banner: an honest approximation, not an
		 * exact virtual-time clock. */
		clock = CLOCK_PROCESS_CPUTIME_ID;
		ev.sigev_signo = SIGVTALRM;
		break;
	default: /* ITIMER_PROF: which_valid() has already ruled out anything else */
		clock = CLOCK_PROCESS_CPUTIME_ID;
		ev.sigev_signo = SIGPROF;
		break;
	}
	if (timer_create(clock, &ev, &itimer_id[which]) < 0) return -1;
	itimer_created[which] = 1;
	return 0;
}

/* usec is checked, not just trusted, the same way src/time/timer.c's own
 * timespec_valid() checks its own nsec field -- setitimer.html leaves an
 * out-of-range tv_usec undefined, and EINVAL is this library's own
 * chosen, honest answer for it rather than passing a bad value on into
 * timer_settime()'s own tv_nsec conversion below. */
static int itimerval_valid(const struct itimerval *v)
{
	return v->it_value.tv_usec >= 0 && v->it_value.tv_usec < 1000000 &&
	       v->it_interval.tv_usec >= 0 && v->it_interval.tv_usec < 1000000 &&
	       v->it_value.tv_sec >= 0 && v->it_interval.tv_sec >= 0;
}

int setitimer(int which, const struct itimerval *__restrict new, struct itimerval *__restrict old)
{
	struct itimerspec spec, ospec;

	if (!which_valid(which)) { errno = EINVAL; return -1; }
	/* setitimer.html documents no NULL-`new` case; this library's own
	 * choice, consistent with its general "a required pointer this
	 * function's own body would otherwise dereference unconditionally
	 * gets a real check, not a crash" discipline, rather than the real
	 * kernel's behind-the-syscall EFAULT. */
	if (!new) { errno = EFAULT; return -1; }
	if (!itimerval_valid(new)) { errno = EINVAL; return -1; }
	if (ensure_timer(which) < 0) return -1;

	spec.it_value.tv_sec = new->it_value.tv_sec;
	spec.it_value.tv_nsec = (long)new->it_value.tv_usec * 1000L;
	spec.it_interval.tv_sec = new->it_interval.tv_sec;
	spec.it_interval.tv_nsec = (long)new->it_interval.tv_usec * 1000L;

	/* Relative, not TIMER_ABSTIME: setitimer.html's it_value is always a
	 * duration from now, unlike timer_settime()'s own flags argument,
	 * which can go either way. */
	if (timer_settime(itimer_id[which], 0, &spec, old ? &ospec : 0) < 0) return -1;
	if (old) {
		old->it_value.tv_sec = ospec.it_value.tv_sec;
		old->it_value.tv_usec = (suseconds_t)(ospec.it_value.tv_nsec / 1000L);
		old->it_interval.tv_sec = ospec.it_interval.tv_sec;
		old->it_interval.tv_usec = (suseconds_t)(ospec.it_interval.tv_nsec / 1000L);
	}
	return 0;
}

int getitimer(int which, struct itimerval *value)
{
	struct itimerspec spec;

	if (!which_valid(which)) { errno = EINVAL; return -1; }
	if (!value) { errno = EFAULT; return -1; }
	if (!itimer_created[which]) {
		/* getitimer.html: no prior setitimer() means "no timer armed",
		 * reported as all-zero, exactly like a POSIX timer that was
		 * created but never armed (src/time/timer.c's timer_value()
		 * for a `due == 0` timer) -- there is no need to actually
		 * create the underlying timer just to read a value that is
		 * defined to be zero either way. */
		memset(value, 0, sizeof *value);
		return 0;
	}
	if (timer_gettime(itimer_id[which], &spec) < 0) return -1;
	value->it_value.tv_sec = spec.it_value.tv_sec;
	value->it_value.tv_usec = (suseconds_t)(spec.it_value.tv_nsec / 1000L);
	value->it_interval.tv_sec = spec.it_interval.tv_sec;
	value->it_interval.tv_usec = (suseconds_t)(spec.it_interval.tv_nsec / 1000L);
	return 0;
}

// NOLINTEND(misc-include-cleaner)
