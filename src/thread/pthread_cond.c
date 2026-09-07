/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pthread_impl.h"
#include "plat_thread.h"

#define COND_MAGIC ((ULONG_PTR)0x434f4e44u)
#define COND_DEAD ((ULONG_PTR)0x434f4e58u)
#define CONDATTR_MAGIC ((ULONG_PTR)0x43415454u)

struct cond_waiter;

struct cond_data {
	ULONG_PTR magic;
	struct cond_waiter *waiters;
	int pshared;
	clockid_t clock;
};

struct cond_waiter {
	struct cond_waiter *previous;
	struct cond_waiter *next;
	__plat_handle_t semaphore;
	int linked;
};

struct condattr_data {
	ULONG_PTR magic;
	int pshared;
	clockid_t clock;
};

struct cond_cleanup {
	struct cond_data *cond;
	struct cond_waiter *waiter;
	pthread_mutex_t *mutex withhandle(pthread_mutex)
		withtok(pthread_mutex_unlocked);
	int mutex_held;
};

static struct cond_data *cond_data(pthread_cond_t *cond)
{
	return (struct cond_data *)(void *)cond; // NOLINT(bugprone-casting-through-void) -- public pthread_cond_t is opaque storage for this ABI-defined internal layout
}

static const struct cond_data *const_cond_data(const pthread_cond_t *cond)
{
	return (const struct cond_data *)(const void *)cond; // NOLINT(bugprone-casting-through-void) -- public pthread_cond_t is opaque storage for this ABI-defined internal layout
}

static struct condattr_data *condattr_data(pthread_condattr_t *attr)
{
	return (struct condattr_data *)(void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_condattr_t is opaque storage for this ABI-defined internal layout
}

static const struct condattr_data *const_condattr_data(
	const pthread_condattr_t *attr)
{
	return (const struct condattr_data *)(const void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_condattr_t is opaque storage for this ABI-defined internal layout
}

static int cond_ready(pthread_cond_t *cond)
{
	struct cond_data *data;
	if (!cond) return EINVAL;
	data = cond_data(cond);
	__plat_fast_lock();
	if (data->magic == COND_MAGIC) {
		__plat_fast_unlock();
		return 0;
	}
	if (data->magic == COND_DEAD || data->magic != 0) {
		__plat_fast_unlock();
		return EINVAL;
	}
	if (data->magic == 0) {
		memset(data, 0, sizeof *data);
		data->magic = COND_MAGIC;
		data->pshared = PTHREAD_PROCESS_PRIVATE;
		data->clock = CLOCK_REALTIME;
	}
	__plat_fast_unlock();
	return data->magic == COND_MAGIC ? 0 : EINVAL;
}


int pthread_cond_init(pthread_cond_t *__restrict cond construct(pthread_cond) static_handle(pthread_cond),
	const pthread_condattr_t *__restrict attr handle(pthread_condattr))
{
	struct cond_data *data;
	const struct condattr_data *attributes = 0;
	if (!cond) return EINVAL;
	if (attr) {
		attributes = const_condattr_data(attr);
		if (attributes->magic != CONDATTR_MAGIC) return EINVAL;
	}
	memset(cond, 0, sizeof *cond); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- initializes caller-supplied opaque storage before constructing the condition variable; no live object is copied
	data = cond_data(cond);
	data->magic = COND_MAGIC;
	data->pshared = attributes ? attributes->pshared : PTHREAD_PROCESS_PRIVATE;
	data->clock = attributes ? attributes->clock : CLOCK_REALTIME;
	return 0;
}


int pthread_cond_destroy(pthread_cond_t *cond destroy(pthread_cond) static_handle(pthread_cond))
{
	struct cond_data *data;
	int error = cond_ready(cond);
	if (error) return error;
	data = cond_data(cond);
	__plat_fast_lock();
	if (data->waiters) {
		__plat_fast_unlock();
		return EBUSY;
	}
	data->magic = COND_DEAD;
	__plat_fast_unlock();
	return 0;
}

static void unlink_waiter(struct cond_data *cond, struct cond_waiter *waiter)
    __attribute__((nonnull(2)));
static void unlink_waiter(struct cond_data *cond, struct cond_waiter *waiter)
{
	if (!waiter->linked) return;
	if (waiter->previous) waiter->previous->next = waiter->next;
	else cond->waiters = waiter->next;
	if (waiter->next) waiter->next->previous = waiter->previous;
	waiter->linked = 0;
}

/* Real, source-visible tokens for LockDisciplineChecker.cpp's
 * spicule.LockDiscipline stage (tools/clang/LockHandoffContracts.h). A
 * function attaches one to its own declaration to assert a real lock
 * hand-off contract the checker cannot derive from the generic
 * pthread_*lock()/pthread_*unlock() protocol table alone, because the
 * function itself is not one of those calls. Both expand to nothing
 * outside the analyzer, so ordinary builds (including tcc, which never
 * sees past the #ifdef) are unaffected. */
#ifdef __clang_analyzer__
#define lock_requires_held_on_entry(argument) \
	__attribute__((annotate("spicule_lock_requires_held_on_entry:" #argument)))
#define lock_acquires_for_caller \
	__attribute__((annotate("spicule_lock_acquires_for_caller")))
#else
#define lock_requires_held_on_entry(argument)
#define lock_acquires_for_caller
#endif

/* cond_wait_cleanup is the pthread_cleanup_push() handler cond_wait
 * registers for its wait: if cancelled, the cancellation machinery
 * invokes this handler to restore the "mutex locked" postcondition on
 * the cancellation path, for the code that resumes after, not for
 * itself to release. Its mutex is cleanup->mutex, a struct field
 * reached through its lone void* argument, so it cannot be named by
 * parameter index the way cond_wait's lock_requires_held_on_entry()
 * below can -- lock_acquires_for_caller instead tells the checker that
 * whichever region this function's own pthread_mutex_lock() call
 * resolves to and successfully acquires is exempt, once acquired. */
static void cond_wait_cleanup(void *argument)
    __attribute__((nonnull(1))) lock_acquires_for_caller;
static void cond_wait_cleanup(void *argument)
{
	struct cond_cleanup *cleanup = argument;
	__plat_fast_lock();
	if (cleanup->waiter->linked)
		unlink_waiter(cleanup->cond, cleanup->waiter);
	__plat_fast_unlock();
	if (cleanup->waiter->semaphore) {
		__plat_sync_close(cleanup->waiter->semaphore);
		cleanup->waiter->semaphore = 0;
	}
	if (!cleanup->mutex_held) {
		(void)pthread_mutex_lock(cleanup->mutex);
		cleanup->mutex_held = 1;
	}
	free(cleanup->waiter);
	cleanup->waiter = 0;
}


/* cond_wait() is pthread_cond_wait()/pthread_cond_timedwait()'s shared
 * implementation: POSIX requires the mutex argument to those two public
 * functions to already be locked on entry and locked again on every
 * return. The generic protocol table in LockDisciplineChecker.cpp
 * enforces the first half at pthread_cond_wait()/pthread_cond_timedwait()'s
 * own call sites, but cond_wait is a separate function that table never
 * sees a call to -- without lock_requires_held_on_entry() below,
 * cond_wait's own first pthread_mutex_unlock(mutex) call would look
 * indistinguishable from releasing a lock nobody acquired. The checker
 * seeds the designated argument (index 1, mutex) as held on entry and
 * exempts it from the end-of-function "exits while held" check; the
 * exemption survives the region's own later release/reacquire cycle
 * below, covering both early returns that never touch the mutex and the
 * ordinary full wait-and-reacquire path. */
static int cond_wait(pthread_cond_t *__restrict cond,
	pthread_mutex_t *__restrict mutex withtok(pthread_mutex_locked), const struct timespec *absolute)
	lock_requires_held_on_entry(1)
{
	struct cond_data *data;
	struct cond_waiter *waiter;
	struct cond_cleanup cleanup;
	int result = 0, lock_error = 0, old_state = PTHREAD_CANCEL_ENABLE;
	int error;
	__sig_drain_pending();
	error = cond_ready(cond);
	if (error) return error;
	if (!mutex) return EINVAL;
	if (absolute && (absolute->tv_sec < 0 || absolute->tv_nsec < 0 ||
	    absolute->tv_nsec >= 1000000000L)) return EINVAL;
	data = cond_data(cond);
	waiter = calloc(1, sizeof *waiter);
	if (!waiter) return EAGAIN;
	if (__plat_semaphore_create(0, 1, 0, &waiter->semaphore) < 0) {
		free(waiter);
		return EAGAIN;
	}
	cleanup.cond = data;
	cleanup.waiter = waiter;
	cleanup.mutex_held = 0;
	pthread_cleanup_push(cond_wait_cleanup, &cleanup);
	__plat_fast_lock();
	waiter->next = data->waiters;
	if (waiter->next) waiter->next->previous = waiter;
	data->waiters = waiter;
	waiter->linked = 1;
	__plat_fast_unlock();
	/* pthread_mutex_unlock() below acquires __plat_fast_lock() itself, so
	 * it cannot be called while this thread still holds it -- that is a
	 * guaranteed self-deadlock against a non-recursive lock. Releasing the
	 * fast lock first does not reopen the lost-wakeup race the atomic
	 * "release mutex and wait" requirement guards against: the waiter is
	 * already linked into data->waiters, under the fast lock, before the
	 * mutex is actually released. Any other thread must acquire the fast
	 * lock to touch data->waiters (cond_signal()/cond_broadcast()) or to
	 * take mutex ownership (mutex_acquire()), and mutex ownership cannot
	 * change hands until pthread_mutex_unlock() below clears data->owner
	 * under its own fast-lock acquisition -- which, in this same thread's
	 * program order, only happens after the waiter is already published.
	 * So no thread can become the new mutex owner and signal the
	 * condition without already seeing this waiter linked. */
	error = pthread_mutex_unlock(mutex);
	if (error) {
		__plat_fast_lock();
		unlink_waiter(data, waiter);
		__plat_fast_unlock();
		cleanup.mutex_held = 1;
	} else cleanup.mutex = mutex;
	while (!error) {
		int status;
		if (absolute) {
			struct timespec now;
			long long ticks;
			clock_gettime(data->clock, &now);
			ticks = __timespec_diff_ticks(absolute->tv_sec,
				absolute->tv_nsec, now.tv_sec, now.tv_nsec);
			if (ticks <= 0) {
				status = __PLAT_WAIT_TIMEOUT;
			} else {
				status = __plat_wait_one(waiter->semaphore, 1, 1, -ticks);
			}
		} else {
			status = __plat_wait_one(waiter->semaphore, 1, 0, 0);
		}
		if (status == __PLAT_WAIT_TIMEOUT) {
			__plat_fast_lock();
			if (waiter->linked) unlink_waiter(data, waiter);
			else status = __PLAT_WAIT_OK;
			__plat_fast_unlock();
			result = status == __PLAT_WAIT_TIMEOUT ? ETIMEDOUT : 0;
			break;
		}
		if (status == __PLAT_WAIT_INTR) {
			__pthread_testcancel();
			continue;
		}
		if (status == __PLAT_WAIT_OK) {
			break;
		}
		__plat_fast_lock();
		if (waiter->linked) unlink_waiter(data, waiter);
		__plat_fast_unlock();
		result = EINVAL;
		break;
	}
	if (!error) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
		lock_error = pthread_mutex_lock(cleanup.mutex);
		cleanup.mutex_held = lock_error == 0;
		pthread_setcancelstate(old_state, 0);
	}
	pthread_cleanup_pop(0);
	if (waiter->semaphore) __plat_sync_close(waiter->semaphore);
	free(waiter);
	if (error) return error;
	return lock_error ? lock_error : result;
}


int pthread_cond_wait(pthread_cond_t *__restrict cond handle(pthread_cond) static_handle(pthread_cond),
	pthread_mutex_t *__restrict mutex handle(pthread_mutex) static_handle(pthread_mutex) withtok(pthread_mutex_locked))
{
	return cond_wait(cond, mutex, 0);
}


int pthread_cond_timedwait(pthread_cond_t *__restrict cond handle(pthread_cond) static_handle(pthread_cond),
	pthread_mutex_t *__restrict mutex handle(pthread_mutex) static_handle(pthread_mutex) withtok(pthread_mutex_locked), const struct timespec *__restrict absolute)
{
	if (!absolute) return EINVAL;
	return cond_wait(cond, mutex, absolute);
}


int pthread_cond_signal(pthread_cond_t *cond handle(pthread_cond) static_handle(pthread_cond))
{
	struct cond_data *data;
	struct cond_waiter *waiter;
	int error;
	__sig_drain_pending();
	error = cond_ready(cond);
	if (error) return error;
	data = cond_data(cond);
	__plat_fast_lock();
	waiter = data->waiters;
	if (waiter) {
		unlink_waiter(data, waiter);
		__plat_semaphore_post(waiter->semaphore);
	}
	__plat_fast_unlock();
	return 0;
}


int pthread_cond_broadcast(pthread_cond_t *cond handle(pthread_cond) static_handle(pthread_cond))
{
	struct cond_data *data;
	struct cond_waiter *waiter;
	int error;
	__sig_drain_pending();
	error = cond_ready(cond);
	if (error) return error;
	data = cond_data(cond);
	__plat_fast_lock();
	while ((waiter = data->waiters)) {
		unlink_waiter(data, waiter);
		__plat_semaphore_post(waiter->semaphore);
	}
	__plat_fast_unlock();
	return 0;
}


int pthread_condattr_init(pthread_condattr_t *attr construct(pthread_condattr))
{
	struct condattr_data *data;
	if (!attr) return EINVAL;
	memset(attr, 0, sizeof *attr);
	data = condattr_data(attr);
	data->magic = CONDATTR_MAGIC;
	data->pshared = PTHREAD_PROCESS_PRIVATE;
	data->clock = CLOCK_REALTIME;
	return 0;
}


int pthread_condattr_destroy(pthread_condattr_t *attr destroy(pthread_condattr))
{
	if (!attr || condattr_data(attr)->magic != CONDATTR_MAGIC) return EINVAL;
	memset(attr, 0, sizeof *attr);
	return 0;
}


int pthread_condattr_getclock(const pthread_condattr_t *__restrict attr handle(pthread_condattr),
	clockid_t *__restrict clock)
{
	if (!attr || !clock || const_condattr_data(attr)->magic != CONDATTR_MAGIC)
		return EINVAL;
	*clock = const_condattr_data(attr)->clock;
	return 0;
}


int pthread_condattr_setclock(pthread_condattr_t *attr handle(pthread_condattr), clockid_t clock)
{
	if (!attr || condattr_data(attr)->magic != CONDATTR_MAGIC ||
	    (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC)) return EINVAL;
	condattr_data(attr)->clock = clock;
	return 0;
}


int pthread_condattr_getpshared(const pthread_condattr_t *__restrict attr handle(pthread_condattr),
	int *__restrict pshared)
{
	if (!attr || !pshared || const_condattr_data(attr)->magic != CONDATTR_MAGIC)
		return EINVAL;
	*pshared = const_condattr_data(attr)->pshared;
	return 0;
}


int pthread_condattr_setpshared(pthread_condattr_t *attr handle(pthread_condattr), int pshared)
{
	if (!attr || condattr_data(attr)->magic != CONDATTR_MAGIC ||
	    (pshared != PTHREAD_PROCESS_PRIVATE &&
	     pshared != PTHREAD_PROCESS_SHARED)) return EINVAL;
	condattr_data(attr)->pshared = pshared;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
