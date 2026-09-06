/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * POSIX thread lifecycle over native NT threads.  A pthread_t names a small
 * process-local control block; the NT thread handle is retained until join
 * or detached termination and supplies the kernel-signalled completion
 * object.  Control blocks remain as tombstones after resource reclamation,
 * which makes stale IDs diagnosable without dereferencing freed storage. */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pthread_impl.h"
#include "plat_thread.h"
#include "plat_fd.h"

#define DEFAULT_STACK_SIZE ((size_t)1024 * 1024)
#define DEFAULT_GUARD_SIZE ((size_t)4096)

static int concurrency;
static int live_threads;

__thread struct __pthread *__pthread_self_control;

static struct __pthread_attr_data *attr_data(pthread_attr_t *attr)
{
	return (struct __pthread_attr_data *)(void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_attr_t is opaque storage for this ABI-defined internal layout
}

static const struct __pthread_attr_data *const_attr_data(const pthread_attr_t *attr)
{
	return (const struct __pthread_attr_data *)(const void *)attr; // NOLINT(bugprone-casting-through-void) -- public pthread_attr_t is opaque storage for this ABI-defined internal layout
}

static int valid_attr(const pthread_attr_t *attr)
{
	return attr && const_attr_data(attr)->magic == PTHREAD_ATTR_MAGIC;
}

struct __pthread *__pthread_current(void)
{
	struct __pthread *self = __pthread_self_control;
	if (self) return self;
	self = calloc(1, sizeof *self);
	if (!self) return 0;
	self->magic = PTHREAD_MAGIC;
	self->handle = __plat_thread_duplicate_self();
	self->cancel_state = PTHREAD_CANCEL_ENABLE;
	self->cancel_type = PTHREAD_CANCEL_DEFERRED;
	self->sched_policy = SCHED_OTHER;
	__sig_current_mask_copy(&self->sigmask);
	/* Uses the portable lock, unlike the rest of this (still NT-only) file,
	 * because pthread_mutex.c's mutex_ready()/mutex_acquire() depend on
	 * __pthread_current() working on non-NT backends too. */
	__plat_fast_lock();
	live_threads++;
	__plat_fast_unlock();
	__pthread_self_control = self;
	return self;
}

void __pthread_reset_after_fork(void)
{
	struct __pthread *self = __pthread_self_control;
	__plat_fast_lock();
	live_threads = self ? 1 : 0;
	if (self) {
		self->exited = 0;
		self->joined = 0;
		self->joining = 0;
		self->detached = 0;
		self->handle = __plat_thread_duplicate_self();
	}
	__plat_fast_unlock();
}

pthread_t pthread_self(void)
{
	return __pthread_current();
}

int pthread_equal(pthread_t left, pthread_t right)
{
	return left == right;
}

void __pthread_cleanup_push(struct __pthread_cleanup *cleanup)
{
	struct __pthread *self = __pthread_current();
	if (!self || !cleanup) return;
	cleanup->__previous = self->cleanup;
	self->cleanup = cleanup;
}

void __pthread_cleanup_pop(struct __pthread_cleanup *cleanup, int execute)
{
	struct __pthread *self = __pthread_current();
	if (!self || !cleanup || self->cleanup != cleanup) return;
	self->cleanup = cleanup->__previous;
	if (execute) cleanup->__routine(cleanup->__argument);
}

static void finish(struct __pthread *self, void *result)
{
	int detached;
	int last;
	while (self->cleanup) {
		struct __pthread_cleanup *cleanup = self->cleanup;
		self->cleanup = cleanup->__previous;
		cleanup->__routine(cleanup->__argument);
	}
	__pthread_run_specific_destructors(self);
	__plat_fast_lock();
	self->result = result;
	self->exited = 1;
	last = --live_threads == 0;
	detached = self->detached;
	__plat_fast_unlock();
	if (last) exit(0);
	if (detached && self->handle && self->handle != __plat_thread_current_pseudo()) {
		__plat_thread_close(self->handle);
		self->handle = 0;
	}
}

static unsigned __PLAT_APC_CALL thread_entry(void *argument)
    __attribute__((nonnull(1)));
static unsigned __PLAT_APC_CALL thread_entry(void *argument)
{
	struct __pthread *self = argument;
	void *result;
	/* First thing this thread ever does, before anything below can touch
	 * a __thread object -- see plat_thread.h's own declaration of this
	 * call for why it must run here, from the new thread itself, rather
	 * than from pthread_create(). */
	__plat_thread_tls_fixup();
	__pthread_adopt_current(self);
	result = self->start(self->argument);
	finish(self, result);
	return 0;
}

void __pthread_adopt_current(struct __pthread *self)
{
	if (__pthread_self_control == self) return;
	__pthread_self_control = self;
	__sig_current_mask_install(&self->sigmask);
}

int __pthread_is_current(struct __pthread *thread)
{
	return thread == __pthread_self_control;
}

int pthread_create(pthread_t *__restrict output,
	const pthread_attr_t *__restrict attr handle(pthread_attr), void *(*start)(void *),
	void *__restrict argument)
{
	const struct __pthread_attr_data *data = 0;
	struct __pthread *creator = 0;
	struct __pthread *thread;
	__plat_handle_t handle;

	if (!output || !start) return EINVAL;
	if (attr) {
		if (!valid_attr(attr)) return EINVAL;
		data = const_attr_data(attr);
	}
	if (!data || data->inherit_sched == PTHREAD_INHERIT_SCHED) {
		creator = __pthread_current();
		if (!creator) return EAGAIN;
	}
	thread = calloc(1, sizeof *thread);
	if (!thread) return EAGAIN;
	thread->magic = PTHREAD_MAGIC;
	thread->start = start;
	thread->argument = argument;
	thread->detached = data && data->detach_state == PTHREAD_CREATE_DETACHED;
	thread->cancel_state = PTHREAD_CANCEL_ENABLE;
	thread->cancel_type = PTHREAD_CANCEL_DEFERRED;
	__sig_current_mask_copy(&thread->sigmask);
	if (creator) {
		__plat_fast_lock();
		thread->sched_policy = creator->sched_policy;
		thread->sched_priority = creator->sched_priority;
		__plat_fast_unlock();
	} else {
		thread->sched_policy = data->sched_policy;
		thread->sched_priority = data->sched_priority;
	}
	if (__plat_thread_spawn(thread_entry, thread,
		data ? data->stack_size : DEFAULT_STACK_SIZE, 1, &handle) < 0) {
		free(thread);
		return EAGAIN;
	}
	thread->handle = handle;
	__plat_fast_lock();
	live_threads++;
	__plat_fast_unlock();
	*output = thread;
	if (__plat_thread_resume(handle) < 0) {
		__plat_thread_close(handle);
		thread->handle = 0;
		thread->joined = 1;
		__plat_fast_lock();
		live_threads--;
		__plat_fast_unlock();
		return EAGAIN;
	}
	return 0;
}

/* Undoes pthread_join()'s `joining` claim if a cancellation unwinds through
 * the wait below instead of that function returning normally -- otherwise a
 * canceled joiner would leave its target permanently unjoinable (thread_
 * usable()/pthread_join() itself both treat a stuck `joining` as ESRCH
 * forever after). */
static void join_cleanup(void *argument) __attribute__((nonnull(1)));
static void join_cleanup(void *argument)
{
	pthread_t thread = argument;
	__plat_fast_lock();
	thread->joining = 0;
	__plat_fast_unlock();
}

int pthread_join(pthread_t thread, void **result)
{
	int wait_result;
	if (!thread || thread->magic != PTHREAD_MAGIC) return ESRCH;
	if (thread == __pthread_current()) return EDEADLK;
	__plat_fast_lock();
	if (thread->detached) {
		__plat_fast_unlock();
		return EINVAL;
	}
	if (thread->joined || thread->joining || !thread->handle) {
		__plat_fast_unlock();
		return ESRCH;
	}
	thread->joining = 1;
	__plat_fast_unlock();
	/* pthread_join() is a POSIX cancellation point, the same way
	 * sem_wait()/sem_timedwait() are: __pthread_testcancel() before the
	 * wait catches a cancellation requested before this call was ever
	 * reached (pthread_cancel() sets cancel_pending unconditionally,
	 * independent of whether the target thread is blocked yet), and
	 * after the wait it distinguishes a real STATUS_USER_APC/ALERTED
	 * cancellation wakeup from any other alertable-wait return -- the
	 * target thread has NOT necessarily exited just because the wait
	 * was interrupted, so treating __PLAT_WAIT_INTR as "join complete"
	 * would read stale thread->result and close a handle the target may
	 * still own. */
	pthread_cleanup_push(join_cleanup, thread);
	__pthread_testcancel();
	for (;;) {
		wait_result = __plat_wait_one(thread->handle, 1, 0, 0);
		if (wait_result != __PLAT_WAIT_INTR) break;
		__pthread_testcancel();
	}
	pthread_cleanup_pop(0);
	if (wait_result == __PLAT_WAIT_ERROR) {
		__plat_fast_lock();
		thread->joining = 0;
		__plat_fast_unlock();
		return EINVAL;
	}
	if (result) *result = thread->result;
	__plat_thread_close(thread->handle);
	thread->handle = 0;
	thread->joining = 0;
	thread->joined = 1;
	return 0;
}

int pthread_detach(pthread_t thread)
{
	int close_handle;
	if (!thread || thread->magic != PTHREAD_MAGIC) return ESRCH;
	__plat_fast_lock();
	if (thread->joined || (!thread->handle && thread->exited)) {
		__plat_fast_unlock();
		return ESRCH;
	}
	if (thread->detached || thread->joining) {
		__plat_fast_unlock();
		return EINVAL;
	}
	thread->detached = 1;
	close_handle = thread->exited && thread->handle != 0;
	__plat_fast_unlock();
	if (close_handle) {
		__plat_thread_close(thread->handle);
		thread->handle = 0;
	}
	return 0;
}

_Noreturn void pthread_exit(void *result)
{
	struct __pthread *self = __pthread_current();
	if (self) finish(self, result);
	__plat_thread_terminate_self();
}

int pthread_attr_init(pthread_attr_t *attr construct(pthread_attr))
{
	struct __pthread_attr_data *data;
	if (!attr) return EINVAL;
	memset(attr, 0, sizeof *attr);
	data = attr_data(attr);
	data->magic = PTHREAD_ATTR_MAGIC;
	data->stack_size = DEFAULT_STACK_SIZE;
	data->guard_size = DEFAULT_GUARD_SIZE;
	data->detach_state = PTHREAD_CREATE_JOINABLE;
	data->scope = PTHREAD_SCOPE_SYSTEM;
	data->inherit_sched = PTHREAD_INHERIT_SCHED;
	data->sched_policy = SCHED_OTHER;
	return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr destroy(pthread_attr))
{
	if (!valid_attr(attr)) return EINVAL;
	memset(attr, 0, sizeof *attr);
	return 0;
}

int pthread_attr_getdetachstate(const pthread_attr_t *__restrict attr handle(pthread_attr),
	int *__restrict value)
{
	if (!valid_attr(attr) || !value) return EINVAL;
	*value = const_attr_data(attr)->detach_state;
	return 0;
}

int pthread_attr_getguardsize(const pthread_attr_t *__restrict attr handle(pthread_attr),
	size_t *__restrict value)
{
	if (!valid_attr(attr) || !value) return EINVAL;
	*value = const_attr_data(attr)->guard_size;
	return 0;
}

int pthread_attr_getinheritsched(const pthread_attr_t *__restrict attr handle(pthread_attr),
	int *__restrict value)
{
	if (!valid_attr(attr) || !value) return EINVAL;
	*value = const_attr_data(attr)->inherit_sched;
	return 0;
}

int pthread_attr_getschedpolicy(const pthread_attr_t *__restrict attr handle(pthread_attr),
	int *__restrict value)
{
	if (!valid_attr(attr) || !value) return EINVAL;
	*value = const_attr_data(attr)->sched_policy;
	return 0;
}

int pthread_attr_getscope(const pthread_attr_t *__restrict attr handle(pthread_attr),
	int *__restrict value)
{
	if (!valid_attr(attr) || !value) return EINVAL;
	*value = const_attr_data(attr)->scope;
	return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *__restrict attr handle(pthread_attr),
	size_t *__restrict value)
{
	if (!valid_attr(attr) || !value) return EINVAL;
	*value = const_attr_data(attr)->stack_size;
	return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr handle(pthread_attr), int value)
{
	if (!valid_attr(attr) || (value != PTHREAD_CREATE_JOINABLE &&
	    value != PTHREAD_CREATE_DETACHED)) return EINVAL;
	attr_data(attr)->detach_state = value;
	return 0;
}

int pthread_attr_setguardsize(pthread_attr_t *attr handle(pthread_attr), size_t value)
{
	if (!valid_attr(attr)) return EINVAL;
	attr_data(attr)->guard_size = value;
	return 0;
}

int pthread_attr_setinheritsched(pthread_attr_t *attr handle(pthread_attr), int value)
{
	if (!valid_attr(attr) || (value != PTHREAD_INHERIT_SCHED &&
	    value != PTHREAD_EXPLICIT_SCHED)) return EINVAL;
	attr_data(attr)->inherit_sched = value;
	return 0;
}

int pthread_attr_setschedpolicy(pthread_attr_t *attr handle(pthread_attr), int value)
{
	if (!valid_attr(attr) || value < SCHED_OTHER || value > SCHED_SPORADIC)
		return EINVAL;
	attr_data(attr)->sched_policy = value;
	return 0;
}

int pthread_attr_setscope(pthread_attr_t *attr handle(pthread_attr), int value)
{
	if (!valid_attr(attr)) return EINVAL;
	if (value == PTHREAD_SCOPE_PROCESS) return ENOTSUP;
	if (value != PTHREAD_SCOPE_SYSTEM) return EINVAL;
	attr_data(attr)->scope = value;
	return 0;
}

int pthread_attr_getschedparam(const pthread_attr_t *__restrict attr handle(pthread_attr),
	struct sched_param *__restrict parameter)
{
	if (!valid_attr(attr) || !parameter) return EINVAL;
	parameter->sched_priority = const_attr_data(attr)->sched_priority;
	return 0;
}

int pthread_attr_setschedparam(pthread_attr_t *__restrict attr handle(pthread_attr),
	const struct sched_param *__restrict parameter)
{
	const struct __pthread_attr_data *data;
	int minimum, maximum;
	if (!valid_attr(attr) || !parameter) return EINVAL;
	data = const_attr_data(attr);
	minimum = sched_get_priority_min(data->sched_policy);
	maximum = sched_get_priority_max(data->sched_policy);
	if (minimum < 0 || maximum < 0 || parameter->sched_priority < minimum ||
	    parameter->sched_priority > maximum) return EINVAL;
	attr_data(attr)->sched_priority = parameter->sched_priority;
	return 0;
}

int pthread_attr_getstack(const pthread_attr_t *__restrict attr handle(pthread_attr),
	void **__restrict address, size_t *__restrict size)
{
	if (!valid_attr(attr) || !address || !size) return EINVAL;
	*address = const_attr_data(attr)->stack_address;
	*size = const_attr_data(attr)->stack_size;
	return 0;
}

int pthread_attr_setstack(pthread_attr_t *attr handle(pthread_attr), void *address, size_t size)
{
	if (!valid_attr(attr) || !address || size < PTHREAD_STACK_MIN) return EINVAL;
	attr_data(attr)->stack_address = address;
	attr_data(attr)->stack_size = size;
	return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attr handle(pthread_attr), size_t size)
{
	if (!valid_attr(attr) || size < PTHREAD_STACK_MIN) return EINVAL;
	attr_data(attr)->stack_size = size;
	return 0;
}

int pthread_attr_getstackaddr(const pthread_attr_t *__restrict attr handle(pthread_attr),
	void **__restrict address)
{
	if (!valid_attr(attr) || !address) return EINVAL;
	*address = const_attr_data(attr)->stack_address;
	return 0;
}

int pthread_attr_setstackaddr(pthread_attr_t *attr handle(pthread_attr), void *address)
{
	if (!valid_attr(attr) || !address) return EINVAL;
	attr_data(attr)->stack_address = address;
	return 0;
}

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr)
{
	__plat_handle_t handle;
	void *stack_address;
	size_t stack_size;
	if (!thread || thread->magic != PTHREAD_MAGIC || !attr) return ESRCH;
	if (pthread_attr_init(attr)) return EINVAL;
	handle = thread == __pthread_current() ? __plat_thread_current_pseudo() : thread->handle;
	if (!handle) return ESRCH;
	if (__plat_thread_stack_extent(handle, &stack_address, &stack_size) < 0) return ESRCH;
	attr_data(attr)->stack_address = stack_address;
	attr_data(attr)->stack_size = stack_size;
	attr_data(attr)->detach_state = thread->detached ?
		PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE;
	return 0;
}

/* True if `thread` is a live control block: not stale/foreign, not
 * already joined, and not a fully reclaimed exited thread. */
static int thread_usable(pthread_t thread)
{
	return thread && thread->magic == PTHREAD_MAGIC && !thread->joined &&
	       (thread->handle || !thread->exited);
}

static int valid_policy(int policy)
{
	return policy == SCHED_OTHER || policy == SCHED_FIFO ||
	       policy == SCHED_RR || policy == SCHED_SPORADIC;
}

static int valid_priority(int policy, int priority) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int minimum = sched_get_priority_min(policy);
	int maximum = sched_get_priority_max(policy);
	return minimum >= 0 && maximum >= 0 && priority >= minimum &&
	       priority <= maximum;
}

int pthread_getschedparam(pthread_t thread, int *__restrict policy,
	struct sched_param *__restrict parameter)
{
	if (!thread_usable(thread)) return ESRCH;
	if (!policy || !parameter) return EINVAL;
	__plat_fast_lock();
	*policy = thread->sched_policy;
	parameter->sched_priority = thread->sched_priority;
	__plat_fast_unlock();
	return 0;
}

int pthread_setschedparam(pthread_t thread, int policy,
	const struct sched_param *parameter)
{
	if (!thread_usable(thread)) return ESRCH;
	if (!parameter || !valid_policy(policy) ||
	    !valid_priority(policy, parameter->sched_priority)) return EINVAL;
	__plat_fast_lock();
	thread->sched_policy = policy;
	thread->sched_priority = parameter->sched_priority;
	__plat_fast_unlock();
	return 0;
}

int pthread_setschedprio(pthread_t thread, int priority)
{
	int policy;
	if (!thread_usable(thread)) return ESRCH;
	policy = thread->sched_policy;
	if (!valid_priority(policy, priority)) return EINVAL;
	__plat_fast_lock();
	thread->sched_priority = priority;
	__plat_fast_unlock();
	return 0;
}

int pthread_getcpuclockid(pthread_t thread, clockid_t *clock)
{
	if (!thread_usable(thread)) return ESRCH;
	if (!clock) return EINVAL;
	/* clock_gettime() maps this ID to NT CPU-time accounting.  The clock
	 * implementation currently reports process aggregate time for it, but
	 * it retains the required monotonic CPU-time behavior and public ID. */
	*clock = CLOCK_THREAD_CPUTIME_ID;
	return 0;
}

int pthread_getconcurrency(void)
{
	return concurrency;
}

int pthread_setconcurrency(int level)
{
	if (level < 0) return EINVAL;
	concurrency = level;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
