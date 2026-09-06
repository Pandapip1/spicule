/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _PTHREAD_H
#define _PTHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>
/* Real implementations make CLOCK_* transitively visible from pthread.h
 * alone (used by pthread_condattr_setclock() etc. and assumed by test
 * sources that include only pthread.h); time.h's own guards match this
 * library's -D_GNU_SOURCE build convention, so a plain include is enough. */
#include <time.h>
#define __NEED_size_t
#define __NEED_time_t
#define __NEED_clockid_t
#define __NEED_struct_timespec
#define __NEED_struct_sched_param
#define __NEED_pthread_t
#define __NEED_pthread_attr_t
#include <bits/alltypes.h>
#include <sched.h>

typedef unsigned pthread_key_t;
typedef int pthread_once_t;

/* Synchronization objects are opaque but are stored in the caller's memory,
 * as POSIX requires.  The implementation uses these slots for NT dispatcher
 * handles and small counters; zero is the valid static initializer. */
typedef struct { void *__opaque[8]; } pthread_mutex_t;
typedef struct { void *__opaque[4]; } pthread_mutexattr_t;
typedef struct { void *__opaque[8]; } pthread_cond_t;
typedef struct { void *__opaque[4]; } pthread_condattr_t;
typedef struct { void *__opaque[12]; } pthread_rwlock_t;
typedef struct { void *__opaque[4]; } pthread_rwlockattr_t;
typedef struct { void *__opaque[8]; } pthread_barrier_t;
typedef struct { void *__opaque[4]; } pthread_barrierattr_t;
typedef struct { volatile int __value; } pthread_spinlock_t;


tokdef pthread_mutex_unlocked;
tokdef pthread_mutex_locked l_unlimited;
tokdef pthread_rwlock_unlocked;
tokdef pthread_rwlock_shared l_unlimited;
tokdef pthread_rwlock_exclusive;
tokdef pthread_spin_unlocked;
tokdef pthread_spin_locked l_unlimited;

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1
#define PTHREAD_SCOPE_SYSTEM 0
#define PTHREAD_SCOPE_PROCESS 1
#define PTHREAD_INHERIT_SCHED 0
#define PTHREAD_EXPLICIT_SCHED 1

#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED 1

#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_ERRORCHECK 1
#define PTHREAD_MUTEX_RECURSIVE 2
#define PTHREAD_MUTEX_DEFAULT PTHREAD_MUTEX_NORMAL
#define PTHREAD_MUTEX_STALLED 0
#define PTHREAD_MUTEX_ROBUST 1
#define PTHREAD_PRIO_NONE 0
#define PTHREAD_PRIO_INHERIT 1
#define PTHREAD_PRIO_PROTECT 2

#define PTHREAD_CANCEL_ENABLE 0
#define PTHREAD_CANCEL_DISABLE 1
#define PTHREAD_CANCEL_DEFERRED 0
#define PTHREAD_CANCEL_ASYNCHRONOUS 1
#define PTHREAD_CANCELED ((void *)-1)

#define PTHREAD_STACK_MIN 16384
#define PTHREAD_DESTRUCTOR_ITERATIONS 4
#define PTHREAD_KEYS_MAX 128
#define PTHREAD_THREADS_MAX 64
#define PTHREAD_BARRIER_SERIAL_THREAD (-1)

#define PTHREAD_MUTEX_INITIALIZER {{0}}
#define PTHREAD_COND_INITIALIZER {{0}}
#define PTHREAD_RWLOCK_INITIALIZER {{0}}
#define PTHREAD_ONCE_INIT 0

struct __pthread_cleanup {
	void (*__routine)(void *);
	void *__argument;
	struct __pthread_cleanup *__previous;
};

void __pthread_cleanup_push(struct __pthread_cleanup *);
void __pthread_cleanup_pop(struct __pthread_cleanup *, int);

/* These are paired lexical macros in POSIX, not ordinary functions. */
#define pthread_cleanup_push(routine, argument) do { \
	struct __pthread_cleanup __pthread_cleanup_frame = { \
		(routine), (argument), (struct __pthread_cleanup *)0 }; \
	__pthread_cleanup_push(&__pthread_cleanup_frame);
#define pthread_cleanup_pop(execute) \
	__pthread_cleanup_pop(&__pthread_cleanup_frame, (execute)); \
} while (0)

int pthread_create(pthread_t *__restrict, const pthread_attr_t *__restrict handle(pthread_attr),
	void *(*)(void *), void *__restrict);
fallible
int pthread_join(pthread_t, void **);
fallible
int pthread_detach(pthread_t);
pthread_t pthread_self(void);
int pthread_equal(pthread_t, pthread_t);
_Noreturn void pthread_exit(void *);

int pthread_attr_init(pthread_attr_t * construct(pthread_attr));
int pthread_attr_destroy(pthread_attr_t * destroy(pthread_attr));
int pthread_attr_getdetachstate(const pthread_attr_t *__restrict handle(pthread_attr), int *__restrict);
int pthread_attr_setdetachstate(pthread_attr_t * handle(pthread_attr), int);
int pthread_attr_getguardsize(const pthread_attr_t *__restrict handle(pthread_attr), size_t *__restrict);
int pthread_attr_setguardsize(pthread_attr_t * handle(pthread_attr), size_t);
int pthread_attr_getinheritsched(const pthread_attr_t *__restrict handle(pthread_attr), int *__restrict);
int pthread_attr_setinheritsched(pthread_attr_t * handle(pthread_attr), int);
int pthread_attr_getschedparam(const pthread_attr_t *__restrict handle(pthread_attr), struct sched_param *__restrict);
int pthread_attr_setschedparam(pthread_attr_t *__restrict handle(pthread_attr), const struct sched_param *__restrict);
int pthread_attr_getschedpolicy(const pthread_attr_t *__restrict handle(pthread_attr), int *__restrict);
int pthread_attr_setschedpolicy(pthread_attr_t * handle(pthread_attr), int);
int pthread_attr_getscope(const pthread_attr_t *__restrict handle(pthread_attr), int *__restrict);
int pthread_attr_setscope(pthread_attr_t * handle(pthread_attr), int);
int pthread_attr_getstack(const pthread_attr_t *__restrict handle(pthread_attr), void **__restrict, size_t *__restrict);
int pthread_attr_setstack(pthread_attr_t * handle(pthread_attr), void *, size_t);
int pthread_attr_getstacksize(const pthread_attr_t *__restrict handle(pthread_attr), size_t *__restrict);
int pthread_attr_setstacksize(pthread_attr_t * handle(pthread_attr), size_t);
int pthread_attr_getstackaddr(const pthread_attr_t *__restrict handle(pthread_attr), void **__restrict);
int pthread_attr_setstackaddr(pthread_attr_t * handle(pthread_attr), void *);
int pthread_getattr_np(pthread_t, pthread_attr_t *);

int pthread_once(pthread_once_t *, void (*)(void)) __attribute__((nonnull(1)));
int pthread_key_create(pthread_key_t *, void (*)(void *));
int pthread_key_delete(pthread_key_t);
void *pthread_getspecific(pthread_key_t);
int pthread_setspecific(pthread_key_t, const void *);

fallible
int pthread_cancel(pthread_t);
int pthread_setcancelstate(int, int *);
int pthread_setcanceltype(int, int *);
void pthread_testcancel(void);

fallible
int pthread_mutex_init(pthread_mutex_t *__restrict construct(pthread_mutex) static_handle(pthread_mutex) grant(pthread_mutex_unlocked), const pthread_mutexattr_t *__restrict handle(pthread_mutexattr));
fallible
int pthread_mutex_destroy(pthread_mutex_t * destroy(pthread_mutex) static_handle(pthread_mutex) consume(pthread_mutex_unlocked));
fallible
int pthread_mutex_lock(pthread_mutex_t * handle(pthread_mutex) static_handle(pthread_mutex) consume(pthread_mutex_unlocked) grant(pthread_mutex_locked));
fallible
int pthread_mutex_trylock(pthread_mutex_t * handle(pthread_mutex) static_handle(pthread_mutex) consume(pthread_mutex_unlocked) grant(pthread_mutex_locked));
fallible
int pthread_mutex_timedlock(pthread_mutex_t *__restrict handle(pthread_mutex) static_handle(pthread_mutex) consume(pthread_mutex_unlocked) grant(pthread_mutex_locked), const struct timespec *__restrict);
fallible
int pthread_mutex_unlock(pthread_mutex_t * handle(pthread_mutex) static_handle(pthread_mutex) consume(pthread_mutex_locked) grant(pthread_mutex_unlocked));
int pthread_mutex_getprioceiling(const pthread_mutex_t *__restrict handle(pthread_mutex) static_handle(pthread_mutex), int *__restrict);
int pthread_mutex_setprioceiling(pthread_mutex_t *__restrict handle(pthread_mutex) static_handle(pthread_mutex) withtok(pthread_mutex_unlocked), int, int *__restrict);
int pthread_mutex_consistent(pthread_mutex_t * handle(pthread_mutex) static_handle(pthread_mutex) withtok(pthread_mutex_locked));
int pthread_mutexattr_init(pthread_mutexattr_t * construct(pthread_mutexattr));
int pthread_mutexattr_destroy(pthread_mutexattr_t * destroy(pthread_mutexattr));
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *__restrict handle(pthread_mutexattr), int *__restrict);
int pthread_mutexattr_setpshared(pthread_mutexattr_t * handle(pthread_mutexattr), int);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *__restrict handle(pthread_mutexattr), int *__restrict);
int pthread_mutexattr_settype(pthread_mutexattr_t * handle(pthread_mutexattr), int);
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *__restrict handle(pthread_mutexattr), int *__restrict);
int pthread_mutexattr_setprotocol(pthread_mutexattr_t * handle(pthread_mutexattr), int);
int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *__restrict handle(pthread_mutexattr), int *__restrict);
int pthread_mutexattr_setprioceiling(pthread_mutexattr_t * handle(pthread_mutexattr), int);
int pthread_mutexattr_getrobust(const pthread_mutexattr_t *__restrict handle(pthread_mutexattr), int *__restrict);
int pthread_mutexattr_setrobust(pthread_mutexattr_t * handle(pthread_mutexattr), int);

fallible
int pthread_cond_init(pthread_cond_t *__restrict construct(pthread_cond) static_handle(pthread_cond), const pthread_condattr_t *__restrict handle(pthread_condattr));
fallible
int pthread_cond_destroy(pthread_cond_t * destroy(pthread_cond) static_handle(pthread_cond));
fallible
int pthread_cond_wait(pthread_cond_t *__restrict handle(pthread_cond) static_handle(pthread_cond), pthread_mutex_t *__restrict handle(pthread_mutex) static_handle(pthread_mutex) withtok(pthread_mutex_locked));
fallible
int pthread_cond_timedwait(pthread_cond_t *__restrict handle(pthread_cond) static_handle(pthread_cond), pthread_mutex_t *__restrict handle(pthread_mutex) static_handle(pthread_mutex) withtok(pthread_mutex_locked),
	const struct timespec *__restrict);
fallible
int pthread_cond_signal(pthread_cond_t * handle(pthread_cond) static_handle(pthread_cond));
fallible
int pthread_cond_broadcast(pthread_cond_t * handle(pthread_cond) static_handle(pthread_cond));
int pthread_condattr_init(pthread_condattr_t * construct(pthread_condattr));
int pthread_condattr_destroy(pthread_condattr_t * destroy(pthread_condattr));
int pthread_condattr_getclock(const pthread_condattr_t *__restrict handle(pthread_condattr), clockid_t *__restrict);
int pthread_condattr_setclock(pthread_condattr_t * handle(pthread_condattr), clockid_t);
int pthread_condattr_getpshared(const pthread_condattr_t *__restrict handle(pthread_condattr), int *__restrict);
int pthread_condattr_setpshared(pthread_condattr_t * handle(pthread_condattr), int);

fallible
int pthread_rwlock_init(pthread_rwlock_t *__restrict construct(pthread_rwlock) static_handle(pthread_rwlock) grant(pthread_rwlock_unlocked), const pthread_rwlockattr_t *__restrict handle(pthread_rwlockattr));
fallible
int pthread_rwlock_destroy(pthread_rwlock_t * destroy(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked));
fallible
int pthread_rwlock_rdlock(pthread_rwlock_t * handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared) grant(pthread_rwlock_shared));
fallible
int pthread_rwlock_tryrdlock(pthread_rwlock_t * handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared) grant(pthread_rwlock_shared));
int pthread_rwlock_timedrdlock(pthread_rwlock_t *__restrict handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared) grant(pthread_rwlock_shared), const struct timespec *__restrict);
fallible
int pthread_rwlock_wrlock(pthread_rwlock_t * handle(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive));
fallible
int pthread_rwlock_trywrlock(pthread_rwlock_t * handle(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive));
int pthread_rwlock_timedwrlock(pthread_rwlock_t *__restrict handle(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive), const struct timespec *__restrict);
fallible
int pthread_rwlock_unlock(pthread_rwlock_t * handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_shared) consume_any(pthread_rwlock_exclusive) grant(pthread_rwlock_unlocked));
int pthread_rwlockattr_init(pthread_rwlockattr_t * construct(pthread_rwlockattr));
int pthread_rwlockattr_destroy(pthread_rwlockattr_t * destroy(pthread_rwlockattr));
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *__restrict handle(pthread_rwlockattr), int *__restrict);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t * handle(pthread_rwlockattr), int);

fallible
int pthread_barrier_init(pthread_barrier_t *__restrict construct(pthread_barrier),
	const pthread_barrierattr_t *__restrict handle(pthread_barrierattr), unsigned);
fallible
int pthread_barrier_destroy(pthread_barrier_t * destroy(pthread_barrier));
fallible
int pthread_barrier_wait(pthread_barrier_t * handle(pthread_barrier));
int pthread_barrierattr_init(pthread_barrierattr_t * construct(pthread_barrierattr));
int pthread_barrierattr_destroy(pthread_barrierattr_t * destroy(pthread_barrierattr));
int pthread_barrierattr_getpshared(const pthread_barrierattr_t *__restrict handle(pthread_barrierattr), int *__restrict);
int pthread_barrierattr_setpshared(pthread_barrierattr_t * handle(pthread_barrierattr), int);

fallible
int pthread_spin_init(pthread_spinlock_t * construct(pthread_spin) grant(pthread_spin_unlocked), int);
fallible
int pthread_spin_destroy(pthread_spinlock_t * destroy(pthread_spin) consume(pthread_spin_unlocked));
fallible
int pthread_spin_lock(pthread_spinlock_t * handle(pthread_spin) consume(pthread_spin_unlocked) grant(pthread_spin_locked));
fallible
int pthread_spin_trylock(pthread_spinlock_t * handle(pthread_spin) consume(pthread_spin_unlocked) grant(pthread_spin_locked));
fallible
int pthread_spin_unlock(pthread_spinlock_t * handle(pthread_spin) consume(pthread_spin_locked) grant(pthread_spin_unlocked));

int pthread_atfork(void (*)(void), void (*)(void), void (*)(void));
int pthread_kill(pthread_t, int);

int pthread_getschedparam(pthread_t, int *__restrict, struct sched_param *__restrict);
int pthread_setschedparam(pthread_t, int, const struct sched_param *);
int pthread_setschedprio(pthread_t, int);
int pthread_getcpuclockid(pthread_t, clockid_t *);
int pthread_getconcurrency(void);
int pthread_setconcurrency(int);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
