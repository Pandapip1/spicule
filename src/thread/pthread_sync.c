/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <errno.h>
#include <sched.h>
#include <string.h>
#include "pthread_impl.h"
#include "ownership_stubs.h"
#include "plat_thread.h"

#define SPIN_UNLOCKED 1
#define SPIN_LOCKED 2
#define BARRIER_MAGIC ((ULONG_PTR)0x42415252u)
#define BARRIER_DEAD ((ULONG_PTR)0x42415258u)
#define BARATTR_MAGIC ((ULONG_PTR)0x42415454u)

struct barrier_waiter;

struct barrier_data {
	ULONG_PTR magic;
	volatile int guard;
	volatile unsigned generation;
	unsigned count;
	unsigned waiting;
	int pshared;
	struct barrier_waiter *waiters;
};

struct barrier_waiter {
	struct barrier_data *barrier;
	struct barrier_waiter *next;
	__plat_handle_t event;
	unsigned generation;
};

struct barrierattr_data {
	ULONG_PTR magic;
	int pshared;
};

/* x86 branch stays the literal asm tcc needs; see
 * src/thread/pthread_cancel.c's own copy of this function for why
 * (duplicated in three files, not shared, but the reasoning is
 * identical) and for the aarch64/tcc (PLATFORM=nt ARCH=aarch64) branch
 * below's own story -- src/thread/nt/aarch64/atomic32.S's banner. */
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

static void acquire_guard(volatile int *guard)
{
	while (compare_exchange(guard, 0, 1) != 0) sched_yield();
}

static void release_guard(volatile int *guard)
{
	__asm__ __volatile__("" : : : "memory");
	*guard = 0;
}

static void alertable_yield(void)
{
	__plat_thread_alertable_yield();
	sched_yield();
}

int pthread_spin_init(pthread_spinlock_t *lock construct(pthread_spin) grant(pthread_spin_unlocked), int pshared)
{
	if (!lock || (pshared != PTHREAD_PROCESS_PRIVATE &&
	    pshared != PTHREAD_PROCESS_SHARED)) return EINVAL;
	lock->__value = SPIN_UNLOCKED;
	__ownership_pthread_spin_initialized(lock);
	return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock destroy(pthread_spin) consume(pthread_spin_unlocked))
{
	if (!lock || lock->__value != SPIN_UNLOCKED) return EBUSY;
	lock->__value = 0;
	__ownership_pthread_spin_destroyed(lock);
	return 0;
}

int pthread_spin_lock(pthread_spinlock_t *lock handle(pthread_spin) consume(pthread_spin_unlocked) grant(pthread_spin_locked))
{
	if (!lock) return EINVAL;
	for (;;) {
		int state = lock->__value;
		if (!state) return EINVAL;
		if (state == SPIN_UNLOCKED &&
		    compare_exchange(&lock->__value, SPIN_UNLOCKED,
			SPIN_LOCKED) == SPIN_UNLOCKED) {
			__ownership_pthread_spin_locked(lock);
			return 0;
		}
		alertable_yield();
	}
}

int pthread_spin_trylock(pthread_spinlock_t *lock handle(pthread_spin) consume(pthread_spin_unlocked) grant(pthread_spin_locked))
{
	int state;
	if (!lock) return EINVAL;
	state = lock->__value;
	if (!state) return EINVAL;
	if (state == SPIN_UNLOCKED &&
	    compare_exchange(&lock->__value, SPIN_UNLOCKED,
		SPIN_LOCKED) == SPIN_UNLOCKED) {
		__ownership_pthread_spin_locked(lock);
		return 0;
	}
	return EBUSY;
}

int pthread_spin_unlock(pthread_spinlock_t *lock handle(pthread_spin) consume(pthread_spin_locked) grant(pthread_spin_unlocked))
{
	if (!lock || lock->__value != SPIN_LOCKED) return EINVAL;
	__asm__ __volatile__("" : : : "memory");
	lock->__value = SPIN_UNLOCKED;
	__ownership_pthread_spin_unlocked(lock);
	return 0;
}

static struct barrier_data *barrier_data(pthread_barrier_t *barrier)
{
	return (struct barrier_data *)(void *)barrier; // NOLINT(bugprone-casting-through-void) -- public pthread_barrier_t is opaque storage for this ABI-defined internal layout
}

static struct barrierattr_data *barrierattr_data(pthread_barrierattr_t *attr)
{
	return (struct barrierattr_data *)(void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_barrierattr_t is opaque storage for this ABI-defined internal layout
}

static const struct barrierattr_data *const_barrierattr_data(
	const pthread_barrierattr_t *attr)
{
	return (const struct barrierattr_data *)(const void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_barrierattr_t is opaque storage for this ABI-defined internal layout
}

/* Each caller waits on its own event so releasing a generation broadcasts,
 * rather than an auto-reset wake one peer could steal. */
static void wake_barrier_waiters_locked(struct barrier_data *data,
	unsigned generation)
{
	struct barrier_waiter *waiter;
	for (waiter = data->waiters; waiter; waiter = waiter->next) {
		if (waiter->generation == generation && waiter->event)
			__plat_event_set(waiter->event);
	}
}

static void unlink_barrier_waiter_locked(struct barrier_waiter *waiter)
{
	struct barrier_waiter **link = &waiter->barrier->waiters;
	while (*link && *link != waiter) link = &(*link)->next;
	if (*link) *link = waiter->next;
}


int pthread_barrier_init(pthread_barrier_t *__restrict barrier construct(pthread_barrier),
	const pthread_barrierattr_t *__restrict attr handle(pthread_barrierattr), unsigned count)
{
	struct barrier_data *data;
	const struct barrierattr_data *attributes = 0;
	if (!barrier || !count) return EINVAL;
	if (attr) {
		attributes = const_barrierattr_data(attr);
		if (attributes->magic != BARATTR_MAGIC) return EINVAL;
	}
	memset(barrier, 0, sizeof *barrier);
	data = barrier_data(barrier);
	data->magic = BARRIER_MAGIC;
	data->count = count;
	data->pshared = attributes ? attributes->pshared :
		PTHREAD_PROCESS_PRIVATE;
	return 0;
}


int pthread_barrier_destroy(pthread_barrier_t *barrier destroy(pthread_barrier))
{
	struct barrier_data *data;
	int result = 0;
	if (!barrier) return EINVAL;
	data = barrier_data(barrier);
	if (data->magic != BARRIER_MAGIC) return EINVAL;
	if (data->pshared == PTHREAD_PROCESS_SHARED) {
		acquire_guard(&data->guard);
		if (data->waiting) result = EBUSY;
		else data->magic = BARRIER_DEAD;
		release_guard(&data->guard);
	} else {
		__plat_fast_lock();
		if (data->waiting) result = EBUSY;
		else data->magic = BARRIER_DEAD;
		__plat_fast_unlock();
	}
	return result;
}


int pthread_barrier_wait(pthread_barrier_t *barrier handle(pthread_barrier))
{
	struct barrier_data *data;
	struct barrier_waiter waiter;
	unsigned generation;
	if (!barrier) return EINVAL;
	data = barrier_data(barrier);
	if (data->magic != BARRIER_MAGIC) return EINVAL;
	if (data->pshared == PTHREAD_PROCESS_PRIVATE) {
		if (__plat_event_create(&waiter.event) < 0) waiter.event = 0;
		waiter.barrier = data;
		__plat_fast_lock();
		generation = data->generation;
		if (++data->waiting == data->count) {
			data->waiting = 0;
			data->generation++;
			wake_barrier_waiters_locked(data, generation);
			__plat_fast_unlock();
			if (waiter.event) __plat_sync_close(waiter.event);
			return PTHREAD_BARRIER_SERIAL_THREAD;
		}
		if (waiter.event) {
			waiter.generation = generation;
			waiter.next = data->waiters;
			data->waiters = &waiter;
		}
		__plat_fast_unlock();
		if (waiter.event) {
			int wait_result;
			do {
				wait_result = __plat_wait_one(waiter.event, 1, 0, 0);
			} while (wait_result == __PLAT_WAIT_INTR);
			__plat_fast_lock();
			unlink_barrier_waiter_locked(&waiter);
			__plat_fast_unlock();
			__plat_sync_close(waiter.event);
		} else {
			/* pthread_barrier_wait() has no resource-error return. Retain
			 * generation polling only for degraded event-allocation failure. */
			while (data->generation == generation) alertable_yield();
		}
		return 0;
	}
	acquire_guard(&data->guard);
	generation = data->generation;
	if (++data->waiting == data->count) {
		data->waiting = 0;
		data->generation++;
		release_guard(&data->guard);
		return PTHREAD_BARRIER_SERIAL_THREAD;
	}
	release_guard(&data->guard);
	while (data->generation == generation) alertable_yield();
	return 0;
}


int pthread_barrierattr_init(pthread_barrierattr_t *attr construct(pthread_barrierattr))
{
	struct barrierattr_data *data;
	if (!attr) return EINVAL;
	memset(attr, 0, sizeof *attr);
	data = barrierattr_data(attr);
	data->magic = BARATTR_MAGIC;
	data->pshared = PTHREAD_PROCESS_PRIVATE;
	return 0;
}


int pthread_barrierattr_destroy(pthread_barrierattr_t *attr destroy(pthread_barrierattr))
{
	if (!attr || barrierattr_data(attr)->magic != BARATTR_MAGIC) return EINVAL;
	memset(attr, 0, sizeof *attr);
	return 0;
}


int pthread_barrierattr_getpshared(const pthread_barrierattr_t *__restrict attr handle(pthread_barrierattr),
	int *__restrict pshared)
{
	if (!attr || !pshared ||
	    const_barrierattr_data(attr)->magic != BARATTR_MAGIC) return EINVAL;
	*pshared = const_barrierattr_data(attr)->pshared;
	return 0;
}


int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr handle(pthread_barrierattr), int pshared)
{
	if (!attr || barrierattr_data(attr)->magic != BARATTR_MAGIC ||
	    (pshared != PTHREAD_PROCESS_PRIVATE &&
	     pshared != PTHREAD_PROCESS_SHARED)) return EINVAL;
	barrierattr_data(attr)->pshared = pshared;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
