/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include "pthread_impl.h"
#include "plat_thread.h"
#include "ownership_stubs.h"

struct key_slot {
	unsigned generation;
	int allocated;
	void (*destructor)(void *);
};

/* Guarded by the ntdll PEB lock -- every function below takes it via the
 * __plat_fast_lock()/__plat_fast_unlock() macros (src/internal/libc.h)
 * before touching a slot. */
static struct key_slot keys[PTHREAD_KEYS_MAX] SPICULE_GUARDED_BY(__spicule_peb_lock_token);

static unsigned key_index(pthread_key_t key)
{
	return key % PTHREAD_KEYS_MAX;
}

static pthread_key_t key_value(unsigned index, unsigned generation)
{
	return generation * PTHREAD_KEYS_MAX + index;
}

static int valid_key(pthread_key_t key)
    SPICULE_REQUIRES(__spicule_peb_lock_token);
static int valid_key(pthread_key_t key)
{
	unsigned index = key_index(key);
	return keys[index].allocated &&
	       key_value(index, keys[index].generation) == key;
}

int pthread_key_create(pthread_key_t *output, void (*destructor)(void *))
{
	unsigned index;
	if (!output) return EINVAL;
	__plat_fast_lock();
	for (index = 0; index < PTHREAD_KEYS_MAX; index++) {
		if (keys[index].allocated) continue;
		keys[index].allocated = 1;
		keys[index].destructor = destructor;
		*output = key_value(index, keys[index].generation);
		__plat_fast_unlock();
		return 0;
	}
	__plat_fast_unlock();
	return EAGAIN;
}

int pthread_key_delete(pthread_key_t key)
{
	unsigned index = key_index(key);
	__plat_fast_lock();
	if (!valid_key(key)) {
		__plat_fast_unlock();
		return EINVAL;
	}
	keys[index].allocated = 0;
	keys[index].destructor = 0;
	keys[index].generation++;
	__plat_fast_unlock();
	return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
	struct __pthread *self;
	unsigned index = key_index(key);
	__plat_fast_lock();
	if (!valid_key(key)) {
		__plat_fast_unlock();
		return 0;
	}
	__plat_fast_unlock();
	self = __pthread_current();
	if (!self || !self->specific || self->specific[index].key != key)
		return 0;
	return self->specific[index].value;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
	struct __pthread *self;
	unsigned index = key_index(key);
	__plat_fast_lock();
	if (!valid_key(key)) {
		__plat_fast_unlock();
		return EINVAL;
	}
	__plat_fast_unlock();
	self = __pthread_current();
	if (!self) return ENOMEM;
	if (!self->specific) {
		if (!value) return 0;
		self->specific = calloc(PTHREAD_KEYS_MAX, sizeof *self->specific);
		if (!self->specific) return ENOMEM;
	}
	self->specific[index].key = key;
	self->specific[index].value = (void *)value;
	return 0;
}

void __pthread_run_specific_destructors(struct __pthread *self)
{
	unsigned iteration, index;
	if (!self->specific) return;
	for (iteration = 0; iteration < PTHREAD_DESTRUCTOR_ITERATIONS; iteration++) {
		int called = 0;
		for (index = 0; index < PTHREAD_KEYS_MAX; index++) {
			struct __pthread_specific *specific = &self->specific[index];
			void (*destructor)(void *) = 0;
			void *value = specific->value;
			if (!value) continue;
			__plat_fast_lock();
			if (valid_key(specific->key))
				destructor = keys[index].destructor;
			specific->value = 0;
			__plat_fast_unlock();
			if (destructor) {
				called = 1;
				destructor(value);
			}
		}
		if (!called) break;
	}
	free(self->specific);
	self->specific = 0;
}

struct once_cleanup {
	pthread_once_t *control;
};

struct once_waiter {
	pthread_once_t *control;
	__plat_handle_t event;
	struct once_waiter *next;
};

/* The PEB lock protects both the once state and this waiter list. */
static struct once_waiter *once_waiters SPICULE_GUARDED_BY(__spicule_peb_lock_token);

/* Giving each caller its own event makes completion a broadcast: no
 * waiter can consume a shared auto-reset wake intended for another once
 * control. */
static void wake_once_waiters_locked(pthread_once_t *control)
    SPICULE_REQUIRES(__spicule_peb_lock_token);
static void wake_once_waiters_locked(pthread_once_t *control)
{
	struct once_waiter *waiter;
	for (waiter = once_waiters; waiter; waiter = waiter->next) {
		if (waiter->control == control)
			__plat_event_set(waiter->event);
	}
}

static void remove_once_waiter_locked(struct once_waiter *waiter)
    SPICULE_REQUIRES(__spicule_peb_lock_token);
static void remove_once_waiter_locked(struct once_waiter *waiter)
{
	struct once_waiter **link = &once_waiters;
	while (*link && *link != waiter) link = &(*link)->next;
	if (*link) *link = waiter->next;
}

static void reset_once(void *argument) __attribute__((nonnull(1)));
static void reset_once(void *argument)
{
	struct once_cleanup *cleanup = argument;
	__plat_fast_lock();
	/* cleanup->control is pthread_once()'s own control parameter, already
	 * dereferenced by that function before this cleanup handler could
	 * ever run -- not visible here across the struct field. */
	unsafe_assume_pointer_nonnull(cleanup->control);
	*cleanup->control = PTHREAD_ONCE_INIT;
	wake_once_waiters_locked(cleanup->control);
	__plat_fast_unlock();
}

int pthread_once(pthread_once_t *control, void (*initialize)(void))
{
	__plat_handle_t event = 0;
	struct once_waiter waiter;
	for (;;) {
		__plat_fast_lock();
		if (*control == 2) {
			__plat_fast_unlock();
			if (event) __plat_sync_close(event);
			return 0;
		}
		if (*control == PTHREAD_ONCE_INIT) {
			struct once_cleanup reset = { control };
			*control = 1;
			__plat_fast_unlock();
			if (event) { __plat_sync_close(event); event = 0; }
			pthread_cleanup_push(reset_once, &reset);
			initialize();
			pthread_cleanup_pop(0);
			__plat_fast_lock();
			*control = 2;
			wake_once_waiters_locked(control);
			__plat_fast_unlock();
			return 0;
		}
		if (event) {
			waiter.control = control;
			waiter.event = event;
			waiter.next = once_waiters;
			once_waiters = &waiter;
			__plat_fast_unlock();
			__plat_wait_one(event, 0, 0, 0);
			__plat_fast_lock();
			remove_once_waiter_locked(&waiter);
			__plat_fast_unlock();
			__plat_sync_close(event);
			event = 0;
			continue;
		}
		__plat_fast_unlock();
		{
			if (__plat_event_create(&event) < 0) {
				/* pthread_once() has no resource-error return. Preserve the old
				 * yield path only for this degraded event-allocation failure. */
				event = 0;
				sched_yield();
			}
		}
	}
}

// NOLINTEND(misc-include-cleaner)
