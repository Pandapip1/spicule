/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PTHREAD_IMPL_H
#define PTHREAD_IMPL_H

#include <pthread.h>
#include <signal.h>
#include "libc.h"
#include "plat_handle.h"

#define PTHREAD_MAGIC 0x50544852u
#define PTHREAD_ATTR_MAGIC ((ULONG_PTR)0x41545452u)

struct __pthread_attr_data {
	ULONG_PTR magic;
	size_t stack_size;
	void *stack_address;
	size_t guard_size;
	int detach_state;
	int scope;
	int inherit_sched;
	int sched_policy;
	int sched_priority;
};

struct __pthread_specific {
	pthread_key_t key;
	void *value;
};

struct __pthread {
	unsigned magic;
	__plat_handle_t handle;
	void *result;
	void *(*start)(void *);
	void *argument;
	int detached;
	int exited;
	int joining;
	int joined;
	int cancel_state;
	int cancel_type;
	int cancel_pending;
	int cancel_queued;
	volatile int cancel_running;
	volatile int cancel_unsafe_depth;
	const char *cancel_unsafe_region;
	volatile int cancel_defer_depth;
	int sched_policy;
	int sched_priority;
	sigset_t sigmask;
	struct __pthread_cleanup *cleanup;
	/* Allocated by pthread_setspecific(), released by
	 * __pthread_run_specific_destructors() -- marking the field lets
	 * AllocationLifetimeChecker see that assignment as a transfer, not a
	 * leak (same idiom as src/util/join.c's struct jline fields). */
	struct __pthread_specific *specific withtok(heap_allocated);
};

extern __thread struct __pthread *__pthread_self_control;
struct __pthread *__pthread_current(void);
/* self required: __sig_current_mask_install(&self->sigmask) at the end
 * of this function's own body dereferences it whenever
 * __pthread_self_control != self, which is every real call except the
 * narrow "already adopted" identity check right above it -- not a
 * documented NULL-tolerant case, just an early-out for repeat calls
 * with the same already-known thread. */
void __pthread_adopt_current(struct __pthread *) __attribute__((nonnull(1)));
int __pthread_is_current(struct __pthread *);
/* self required: dereferenced unconditionally at entry
 * (`if (!self->specific) return;`). */
void __pthread_run_specific_destructors(struct __pthread *) __attribute__((nonnull(1)));
void __pthread_cancel_current(void);
_Noreturn void __pthread_cancel_redirected(void);
void __pthread_testcancel(void);
void __pthread_cancel_unsafe_enter(const char *);
void __pthread_cancel_unsafe_leave(void);
int __pthread_cancel_unsafe_active(pthread_t);
void __pthread_cancel_defer_enter(void);
void __pthread_cancel_defer_leave(void);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
