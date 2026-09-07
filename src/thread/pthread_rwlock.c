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
#include "ownership_stubs.h"
#include "plat_thread.h"

#define RWLOCK_MAGIC ((ULONG_PTR)0x52574c4bu)
#define RWLOCK_DEAD ((ULONG_PTR)0x52574c58u)
#define RWATTR_MAGIC ((ULONG_PTR)0x52574154u)

struct rw_waiter;

struct rwlock_data {
	ULONG_PTR magic;
	struct rw_waiter *head;
	struct rw_waiter *tail;
	pthread_t writer;
	unsigned readers;
	unsigned waiting_writers;
	int pshared;
	volatile int shared_state;
};

struct rw_waiter {
	struct rw_waiter *previous;
	struct rw_waiter *next;
	struct rwlock_data *lock;
	__plat_handle_t semaphore;
	pthread_t owner;
	int write;
	int linked;
};

struct rwattr_data {
	ULONG_PTR magic;
	int pshared;
};

static struct rwlock_data *rwlock_data(pthread_rwlock_t *lock)
{
	return (struct rwlock_data *)(void *)lock; // NOLINT(bugprone-casting-through-void) -- public pthread_rwlock_t is opaque storage for this ABI-defined internal layout
}

static const struct rwattr_data *const_rwattr_data(
	const pthread_rwlockattr_t *attr)
{
	return (const struct rwattr_data *)(const void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_rwlockattr_t is opaque storage for this ABI-defined internal layout
}

static struct rwattr_data *rwattr_data(pthread_rwlockattr_t *attr)
{
	return (struct rwattr_data *)(void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_rwlockattr_t is opaque storage for this ABI-defined internal layout
}

static int rwlock_ready(pthread_rwlock_t *lock)
{
	struct rwlock_data *data;
	if (!lock) return EINVAL;
	data = rwlock_data(lock);
	__plat_fast_lock();
	if (data->magic == RWLOCK_MAGIC) {
		__plat_fast_unlock();
		return 0;
	}
	if (data->magic == RWLOCK_DEAD || data->magic != 0) {
		__plat_fast_unlock();
		return EINVAL;
	}
	memset(data, 0, sizeof *data);
	data->magic = RWLOCK_MAGIC;
	data->pshared = PTHREAD_PROCESS_PRIVATE;
	__plat_fast_unlock();
	return 0;
}

/* x86 branch stays literal asm because tcc needs it (see
 * pthread_cancel.c's copy of this function, duplicated rather than shared). */
static int compare_exchange(volatile int *address, int old_value, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	int new_value)
{
#if defined(__i386__) || defined(__x86_64__)
	int previous;
	__asm__ __volatile__("lock; cmpxchgl %2, %1"
		: "=a"(previous), "+m"(*address)
		: "r"(new_value), "0"(old_value) : "memory");
	return previous;
#elif defined(__aarch64__) && defined(_WIN32)
	extern int __spicule_aarch64_cas32(volatile int *address,
		int old_value, int new_value);
	return __spicule_aarch64_cas32(address, old_value, new_value);
#else
	__atomic_compare_exchange_n(address, &old_value, new_value, 0,
	                            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return old_value;
#endif
}

static int shared_acquire(struct rwlock_data *data,
	const struct timespec *absolute, int try_only, int write) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	for (;;) {
		int state = data->shared_state;
		if (write ? state == 0 : state >= 0) {
			int next = write ? -1 : state + 1;
			if (compare_exchange(&data->shared_state, state, next) == state)
				return 0;
			continue;
		}
		if (try_only) return EBUSY;
		if (!absolute || absolute->tv_nsec < 0 ||
		    absolute->tv_nsec >= 1000000000L) return EINVAL;
		{
			struct timespec now;
			clock_gettime(CLOCK_REALTIME, &now);
			if (now.tv_sec > absolute->tv_sec ||
			    (now.tv_sec == absolute->tv_sec &&
			     now.tv_nsec >= absolute->tv_nsec)) return ETIMEDOUT;
		}
		sched_yield();
	}
}

static void unlink_waiter(struct rw_waiter *waiter) __attribute__((nonnull(1)));
static void unlink_waiter(struct rw_waiter *waiter)
{
	struct rwlock_data *data = waiter->lock;
	if (!waiter->linked) return;
	if (waiter->previous) waiter->previous->next = waiter->next;
	else data->head = waiter->next;
	if (waiter->next) waiter->next->previous = waiter->previous;
	else data->tail = waiter->previous;
	if (waiter->write) data->waiting_writers--;
	waiter->linked = 0;
}

/* pthread_rwlock_rdlock.html, "Thread Execution Scheduling" clause: a
 * reader is blocked by a still-queued writer only if that writer's
 * priority is >= the reader's own -- not by mere presence in the
 * queue -- so the wake/admission paths need the highest priority
 * among currently-queued writers, not just whether any are queued. -1
 * is below every real sched_priority (SCHED_OTHER's minimum is 0), so
 * it is the correct "no writer queued" sentinel. */
static int max_waiting_writer_priority(const struct rwlock_data *data)
{
	struct rw_waiter *waiter;
	int max = -1;
	for (waiter = data->head; waiter; waiter = waiter->next)
		if (waiter->write && waiter->owner->sched_priority > max)
			max = waiter->owner->sched_priority;
	return max;
}

/* Records the acquisition too, on success, so both call sites can't drift
 * out of step on the "mark self as new owner" step. */
static int rwlock_try_immediate(struct rwlock_data *data, pthread_t self, int write)
{
	int available = write ? (!data->writer && !data->readers)
	                      : (!data->writer &&
	                         self->sched_priority > max_waiting_writer_priority(data));
	if (!available) return 0;
	if (write) data->writer = self;
	else data->readers++;
	return 1;
}

/* pthread_rwlock_unlock.html: waiters "acquire the lock in priority
 * order"; "for equal priority threads, write locks take precedence
 * over read locks". Readers whose priority beats every still-queued
 * writer can all be admitted together (they only ever contend with
 * that writer, not with each other); a writer is admitted only once
 * no reader was admitted this round, and ties among queued writers
 * break in FIFO (arrival) order via the strict '>' comparison below. */
static void wake_waiters(struct rwlock_data *data)
{
	struct rw_waiter *waiter, *next, *best;
	int max_writer;
	if (data->writer) return;
	max_writer = max_waiting_writer_priority(data);
	for (waiter = data->head; waiter; waiter = next) {
		next = waiter->next;
		if (waiter->write || waiter->owner->sched_priority <= max_writer) continue;
		data->readers++;
		unlink_waiter(waiter);
		__plat_semaphore_post(waiter->semaphore);
	}
	if (data->readers || !data->waiting_writers) return;
	best = 0;
	for (waiter = data->head; waiter; waiter = waiter->next) {
		if (!waiter->write) continue;
		if (!best || waiter->owner->sched_priority > best->owner->sched_priority)
			best = waiter;
	}
	data->writer = best->owner;
	unlink_waiter(best);
	__plat_semaphore_post(best->semaphore);
}

static void wait_cleanup(void *argument) __attribute__((nonnull(1)));
static void wait_cleanup(void *argument)
{
	struct rw_waiter *waiter = argument;
	__plat_fast_lock();
	if (waiter->linked) {
		unlink_waiter(waiter);
		wake_waiters(waiter->lock);
	}
	__plat_fast_unlock();
	if (waiter->semaphore) {
		__plat_sync_close(waiter->semaphore);
		waiter->semaphore = 0;
	}
	free(waiter);
}

static int rwlock_acquire(pthread_rwlock_t *lock,
	const struct timespec *absolute, int try_only, int write)
{
	struct rwlock_data *data;
	struct rw_waiter *waiter;
	pthread_t self;
	int result = 0, old_state = PTHREAD_CANCEL_ENABLE;
	int error = rwlock_ready(lock);
	if (error) return error;
	self = pthread_self();
	if (!self) return EAGAIN;
	data = rwlock_data(lock);
	if (data->pshared == PTHREAD_PROCESS_SHARED)
		return shared_acquire(data, absolute, try_only, write);
	__plat_fast_lock();
	if (rwlock_try_immediate(data, self, write)) {
		__plat_fast_unlock();
		return 0;
	}
	if (data->writer == self) {
		__plat_fast_unlock();
		return try_only ? EBUSY : EDEADLK;
	}
	if (try_only) {
		__plat_fast_unlock();
		return EBUSY;
	}
	if (!absolute || absolute->tv_sec < 0 || absolute->tv_nsec < 0 ||
	    absolute->tv_nsec >= 1000000000L) {
		__plat_fast_unlock();
		return EINVAL;
	}
	__plat_fast_unlock();
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
	waiter = calloc(1, sizeof *waiter);
	if (!waiter) {
		pthread_setcancelstate(old_state, 0);
		return EAGAIN;
	}
	waiter->lock = data;
	waiter->write = write;
	waiter->owner = self;
	if (__plat_semaphore_create(0, 1, 0, &waiter->semaphore) < 0) {
		free(waiter);
		pthread_setcancelstate(old_state, 0);
		return EAGAIN;
	}
	pthread_cleanup_push(wait_cleanup, waiter);
	__plat_fast_lock();
	if (rwlock_try_immediate(data, self, write)) {
		__plat_fast_unlock();
		pthread_setcancelstate(old_state, 0);
		goto done;
	}
	if (data->writer == self) {
		result = EDEADLK;
		__plat_fast_unlock();
		pthread_setcancelstate(old_state, 0);
		goto done;
	}
	waiter->previous = data->tail;
	if (data->tail) data->tail->next = waiter;
	else data->head = waiter;
	data->tail = waiter;
	waiter->linked = 1;
	if (write) data->waiting_writers++;
	__plat_fast_unlock();
	pthread_setcancelstate(old_state, 0);
	for (;;) {
		struct timespec now;
		long long ticks;
		int status;
		clock_gettime(CLOCK_REALTIME, &now);
		ticks = __timespec_diff_ticks(absolute->tv_sec,
			absolute->tv_nsec, now.tv_sec, now.tv_nsec);
		if (ticks <= 0) status = __PLAT_WAIT_TIMEOUT;
		else {
			if (ticks <= INT64_MAX - 10000) ticks += 10000;
			status = __plat_wait_one(waiter->semaphore, 1, 1, -ticks);
		}
		if (status == __PLAT_WAIT_INTR) continue;
		if (status == __PLAT_WAIT_TIMEOUT) {
			__plat_fast_lock();
			if (waiter->linked) {
				unlink_waiter(waiter);
				wake_waiters(data);
				result = ETIMEDOUT;
			}
			__plat_fast_unlock();
			break;
		}
		if (status == __PLAT_WAIT_ERROR) result = EINVAL;
		break;
	}
	done:
	pthread_cleanup_pop(1);
	return result;
}


int pthread_rwlock_init(pthread_rwlock_t *__restrict lock construct(pthread_rwlock) static_handle(pthread_rwlock) grant(pthread_rwlock_unlocked),
	const pthread_rwlockattr_t *__restrict attr handle(pthread_rwlockattr))
{
	struct rwlock_data *data;
	const struct rwattr_data *attributes = 0;
	if (!lock) return EINVAL;
	if (attr) {
		attributes = const_rwattr_data(attr);
		if (attributes->magic != RWATTR_MAGIC) return EINVAL;
	}
	memset(lock, 0, sizeof *lock);
	data = rwlock_data(lock);
	data->magic = RWLOCK_MAGIC;
	data->pshared = attributes ? attributes->pshared : PTHREAD_PROCESS_PRIVATE;
	__ownership_pthread_rwlock_initialized(lock);
	return 0;
}


int pthread_rwlock_destroy(pthread_rwlock_t *lock destroy(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked))
{
	struct rwlock_data *data;
	int error = rwlock_ready(lock);
	if (error) return error;
	data = rwlock_data(lock);
	if (data->pshared == PTHREAD_PROCESS_SHARED) {
		if (data->shared_state) return EBUSY;
		data->magic = RWLOCK_DEAD;
		__ownership_pthread_rwlock_destroyed(lock);
		return 0;
	}
	__plat_fast_lock();
	if (data->writer || data->readers || data->head) error = EBUSY;
	else data->magic = RWLOCK_DEAD;
	__plat_fast_unlock();
	if (!error) __ownership_pthread_rwlock_destroyed(lock);
	return error;
}


int pthread_rwlock_rdlock(pthread_rwlock_t *lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared) grant(pthread_rwlock_shared))
{
	struct timespec forever = {(time_t)0x7fffffff, 0};
	int error = rwlock_acquire(lock, &forever, 0, 0);
	if (!error) __ownership_pthread_rwlock_read_locked(lock);
	return error;
}


int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared) grant(pthread_rwlock_shared))
{
	int error = rwlock_acquire(lock, 0, 1, 0);
	if (!error) __ownership_pthread_rwlock_read_locked(lock);
	return error;
}


int pthread_rwlock_timedrdlock(pthread_rwlock_t *__restrict lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared) grant(pthread_rwlock_shared),
	const struct timespec *__restrict absolute)
{
	int error = rwlock_acquire(lock, absolute, 0, 0);
	if (!error) __ownership_pthread_rwlock_read_locked(lock);
	return error;
}


int pthread_rwlock_wrlock(pthread_rwlock_t *lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive))
{
	struct timespec forever = {(time_t)0x7fffffff, 0};
	int error = rwlock_acquire(lock, &forever, 0, 1);
	if (!error) __ownership_pthread_rwlock_write_locked(lock);
	return error;
}


int pthread_rwlock_trywrlock(pthread_rwlock_t *lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive))
{
	int error = rwlock_acquire(lock, 0, 1, 1);
	if (!error) __ownership_pthread_rwlock_write_locked(lock);
	return error;
}


int pthread_rwlock_timedwrlock(pthread_rwlock_t *__restrict lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive),
	const struct timespec *__restrict absolute)
{
	int error = rwlock_acquire(lock, absolute, 0, 1);
	if (!error) __ownership_pthread_rwlock_write_locked(lock);
	return error;
}


int pthread_rwlock_unlock(pthread_rwlock_t *lock handle(pthread_rwlock) static_handle(pthread_rwlock) consume_any(pthread_rwlock_shared) consume_any(pthread_rwlock_exclusive) grant(pthread_rwlock_unlocked))
{
	struct rwlock_data *data;
	pthread_t self = pthread_self();
	int error = rwlock_ready(lock);
	if (error) return error;
	data = rwlock_data(lock);
	if (data->pshared == PTHREAD_PROCESS_SHARED) {
		for (;;) {
			int state = data->shared_state;
			if (!state) return EINVAL;
			if (compare_exchange(&data->shared_state, state,
				state < 0 ? 0 : state - 1) == state) {
				__ownership_pthread_rwlock_unlocked(lock);
				return 0;
			}
		}
	}
	__plat_fast_lock();
	if (data->writer == self) data->writer = 0;
	else if (data->readers) data->readers--;
	else error = EINVAL;
	if (!error) wake_waiters(data);
	__plat_fast_unlock();
	if (!error) __ownership_pthread_rwlock_unlocked(lock);
	return error;
}


int pthread_rwlockattr_init(pthread_rwlockattr_t *attr construct(pthread_rwlockattr))
{
	struct rwattr_data *data;
	if (!attr) return EINVAL;
	memset(attr, 0, sizeof *attr);
	data = rwattr_data(attr);
	data->magic = RWATTR_MAGIC;
	data->pshared = PTHREAD_PROCESS_PRIVATE;
	return 0;
}


int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr destroy(pthread_rwlockattr))
{
	if (!attr || rwattr_data(attr)->magic != RWATTR_MAGIC) return EINVAL;
	memset(attr, 0, sizeof *attr);
	return 0;
}


int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *__restrict attr handle(pthread_rwlockattr),
	int *__restrict pshared)
{
	if (!attr || !pshared || const_rwattr_data(attr)->magic != RWATTR_MAGIC)
		return EINVAL;
	*pshared = const_rwattr_data(attr)->pshared;
	return 0;
}


int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr handle(pthread_rwlockattr), int pshared)
{
	if (!attr || rwattr_data(attr)->magic != RWATTR_MAGIC ||
	    (pshared != PTHREAD_PROCESS_PRIVATE &&
	     pshared != PTHREAD_PROCESS_SHARED)) return EINVAL;
	rwattr_data(attr)->pshared = pshared;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
