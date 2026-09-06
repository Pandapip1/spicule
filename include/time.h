/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_TIME_H
#define _TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define __NEED_size_t
#define __NEED_time_t
#define __NEED_clock_t
#define __NEED_struct_timespec
#define __NEED_struct_tm

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define __NEED_clockid_t
#define __NEED_timer_t
#define __NEED_pid_t
#define __NEED_locale_t
#endif

#include <bits/alltypes.h>


clock_t clock (void);
async_signal_safe
time_t time (time_t *);
double difftime (time_t, time_t);
time_t mktime (struct tm *) __attribute__((nonnull(1)));
size_t strftime (char *__restrict, size_t, const char *__restrict, const struct tm *__restrict);
struct tm *gmtime (const time_t *);
struct tm *localtime (const time_t *);
char *asctime (const struct tm *);
char *ctime (const time_t *);
int timespec_get(struct timespec *, int) __attribute__((nonnull(1)));

#define CLOCKS_PER_SEC ((clock_t)1000000)

#define TIME_UTC 1

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)

size_t strftime_l (char *  __restrict, size_t, const char *  __restrict, const struct tm *  __restrict, locale_t);

struct tm *gmtime_r (const time_t *__restrict, struct tm *__restrict)
    __attribute__((nonnull(1, 2)));
struct tm *localtime_r (const time_t *__restrict, struct tm *__restrict)
    __attribute__((nonnull(1, 2)));
char *asctime_r (const struct tm *__restrict, char *__restrict)
    __attribute__((nonnull(1, 2)));
char *ctime_r (const time_t *, char *);

void tzset (void);

struct itimerspec {
	struct timespec it_interval;
	struct timespec it_value;
};

#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7

#define TIMER_ABSTIME 1

int nanosleep (const struct timespec *, struct timespec *);
int clock_getres (clockid_t, struct timespec *);
/* clock_gettime()'s ts is left unmarked: it's only forwarded onward,
 * never dereferenced directly. clock_settime()'s ts, by contrast, is
 * dereferenced directly, so it is marked. */
int clock_gettime (clockid_t, struct timespec *);
int clock_settime (clockid_t, const struct timespec *) __attribute__((nonnull(2)));
/* rem is genuinely optional (POSIX: "if the rmtp argument is
 * non-NULL"), same shape as nanosleep()'s own rem. */
int clock_nanosleep (clockid_t, int, const struct timespec *, struct timespec *)
    __attribute__((nonnull(3)));
int clock_getcpuclockid (pid_t, clockid_t *) __attribute__((nonnull(2)));
struct sigevent;
/* event is genuinely optional: POSIX documents "if evp is NULL" as a
 * real, defined case (SIGALRM is used instead). */
int timer_create(clockid_t, struct sigevent *__restrict, timer_t *__restrict)
    __attribute__((nonnull(3)));
int timer_delete(timer_t);
async_signal_safe
int timer_getoverrun(timer_t);
async_signal_safe
int timer_gettime(timer_t, struct itimerspec *);
/* old is genuinely optional: POSIX documents "if ovalue is not NULL" as
 * a real, defined case. */
async_signal_safe
int timer_settime(timer_t, int, const struct itimerspec *__restrict, struct itimerspec *__restrict)
    __attribute__((nonnull(3)));

extern int daylight;
extern long timezone;
extern char *tzname[2];

#endif


#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
/* s/f are deliberately NOT marked: strptime() only forwards them into
 * parse(), never dereferencing either itself. */
char *strptime (const char *__restrict, const char *__restrict, struct tm *__restrict)
    __attribute__((nonnull(3)));
extern int getdate_err;
struct tm *getdate (const char *);
#endif


#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int stime(const time_t *) __attribute__((nonnull(1)));
time_t timegm(struct tm *) __attribute__((nonnull(1)));
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
