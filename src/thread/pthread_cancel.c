/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include "pthread_impl.h"
#include "plat_thread.h"

_Noreturn void __pthread_cancel_trampoline(void); // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

/* x86 branch stays literal asm because the pinned tcc (the only compiler the
 * NT target builds with) has no __atomic_* builtins.  The NT/aarch64 tcc
 * target has no atomic mnemonics at all either, so that branch calls into
 * src/thread/nt/aarch64/atomic32.S's hand-encoded instructions instead. Any
 * other target is a real gcc/clang and uses the builtins directly. */
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

static int exchange_add(volatile int *address, int value)
{
#if defined(__i386__) || defined(__x86_64__)
	__asm__ __volatile__("lock; xaddl %0, %1"
		: "+r"(value), "+m"(*address) : : "memory");
	return value;
#elif defined(__aarch64__) && defined(_WIN32)
	extern int __spicule_aarch64_xadd32(volatile int *address, int value);
	return __spicule_aarch64_xadd32(address, value);
#else
	return __atomic_fetch_add(address, value, __ATOMIC_SEQ_CST);
#endif
}

static int atomic_load(volatile int *address)
{
	return compare_exchange(address, 0, 0);
}

/* POSIX only requires pthread_cancel/setcancelstate/setcanceltype to be
 * async-cancel-safe, so redirecting a thread elsewhere can abandon an
 * internal lock half-acquired; this diagnoses that at delivery time. The
 * write bypasses stdio/the fd table, and termination goes straight to NT
 * instead of abort()/__exit_internal(), since the suspended target may own
 * either's locks. */
static _Noreturn void cancel_unsafe_abort(const char *region)
{
	__plat_cancel_unsafe_abort(region);
}

void __pthread_cancel_unsafe_enter(const char *region)
{
	struct __pthread *self = __pthread_self_control;
	if (!self) return;
	if (atomic_load(&self->cancel_unsafe_depth) == 0)
		self->cancel_unsafe_region = region;
	exchange_add(&self->cancel_unsafe_depth, 1);
}

void __pthread_cancel_unsafe_leave(void)
{
	struct __pthread *self = __pthread_self_control;
	int previous;
	if (!self || atomic_load(&self->cancel_unsafe_depth) <= 0) return;
	previous = exchange_add(&self->cancel_unsafe_depth, -1);
	if (previous == 1) self->cancel_unsafe_region = 0;
}

/* Internal observation point used by the death tests to wait until a
 * wrapper has entered its real unsafe interval before cancelling it. */
int __pthread_cancel_unsafe_active(pthread_t thread)
{
	if (!thread || thread->magic != PTHREAD_MAGIC) return 0;
	return atomic_load(&thread->cancel_unsafe_depth) > 0;
}

/* Internal locks aren't cancellation boundaries: a pending async request is
 * remembered and acted on after the outermost protected transaction commits,
 * so the three POSIX async-cancel-safe operations never expose intermediate
 * state. */
void __pthread_cancel_defer_enter(void)
{
	struct __pthread *self = __pthread_self_control;
	if (self) exchange_add(&self->cancel_defer_depth, 1);
}

void __pthread_cancel_defer_leave(void)
{
	struct __pthread *self = __pthread_self_control;
	int previous;
	if (!self || atomic_load(&self->cancel_defer_depth) <= 0) return;
	previous = exchange_add(&self->cancel_defer_depth, -1);
	if (previous == 1 && self->cancel_state == PTHREAD_CANCEL_ENABLE &&
	    self->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS &&
	    self->cancel_pending)
		__pthread_cancel_current();
}

/* A normal user APC is only delivered when the target enters an alertable
 * wait.  Asynchronous cancellation also has to stop a thread which never
 * waits (the conformance test intentionally uses a tight loop), so redirect
 * the suspended target to an arch trampoline which cannot return. */
static int redirect_async_cancel(struct __pthread *thread)
{
	int handled = 0;
	int unsafe = 0;
	const char *unsafe_region = 0;

	if (__plat_thread_suspend(thread->handle) < 0) return 0;
	/* The target can consume the request at a cancellation point after
	 * pthread_cancel() drops the PEB lock but before it is suspended.  Do
	 * not redirect it a second time while its cleanup handlers are already
	 * running: that abandons the first handler's stack frame. */
	if (!thread->cancel_pending || thread->cancel_running || thread->exited) {
		handled = 1;
	} else if (thread->cancel_state == PTHREAD_CANCEL_ENABLE &&
	    thread->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS) {
		if (atomic_load(&thread->cancel_defer_depth) > 0) {
			/* The outermost leave observes cancel_pending and delivers it.
			 * Report failure so pthread_cancel() also queues the APC needed
			 * if the target is already in an alertable wait. */
			handled = 0;
		} else if (atomic_load(&thread->cancel_unsafe_depth) > 0) {
			unsafe_region = thread->cancel_unsafe_region;
			unsafe = 1;
			handled = 1;
		} else {
			/* Claim the cancellation before changing the instruction pointer.
			 * The target makes the same atomic claim on its cancellation-point
			 * path, closing the interval in which both paths used to observe the
			 * plain volatile marker as zero and enter cleanup twice. */
			if (compare_exchange(&thread->cancel_running, 0, 1) != 0) {
				handled = 1;
			} else {
				handled = __plat_thread_redirect_ip(thread->handle,
					(void *)__pthread_cancel_trampoline) == 0;
				if (!handled)
					compare_exchange(&thread->cancel_running, 1, 0);
			}
		}
	}
	__plat_thread_resume(thread->handle);
	if (unsafe) cancel_unsafe_abort(unsafe_region);
	return handled;
}

static _Noreturn void cancel_current_claimed(void)
{
	struct __pthread *self = __pthread_self_control;
	if (self) {
		__plat_fast_lock();
		self->cancel_pending = 0;
		self->cancel_queued = 0;
		self->cancel_state = PTHREAD_CANCEL_DISABLE;
		__plat_fast_unlock();
	}
	pthread_exit(PTHREAD_CANCELED);
}

void __pthread_cancel_current(void)
{
	struct __pthread *self = __pthread_self_control;
	if (self && atomic_load(&self->cancel_defer_depth) > 0) return;
	if (self && self->cancel_state == PTHREAD_CANCEL_ENABLE &&
	    self->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS &&
	    atomic_load(&self->cancel_unsafe_depth) > 0)
		cancel_unsafe_abort(self->cancel_unsafe_region);
	if (self && compare_exchange(&self->cancel_running, 0, 1) != 0) return;
	cancel_current_claimed();
}

/* The suspend/context path claimed cancel_running before publishing this
 * instruction pointer, so its trampoline must not try to claim it again. */
_Noreturn void __pthread_cancel_redirected(void)
{
	cancel_current_claimed();
}

void __pthread_testcancel(void)
{
	struct __pthread *self = __pthread_self_control;
	int cancel = 0;
	if (!self) return;
	__plat_fast_lock();
	if (self->cancel_state == PTHREAD_CANCEL_ENABLE && self->cancel_pending)
		cancel = 1;
	__plat_fast_unlock();
	if (cancel) __pthread_cancel_current();
}

static void __PLAT_APC_CALL cancel_apc(void *argument, void *unused1, void *unused2)
    __attribute__((nonnull(1)));
static void __PLAT_APC_CALL cancel_apc(void *argument, void *unused1, void *unused2) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __pthread *self = argument;
	int cancel = 0;
	(void)unused1;
	(void)unused2;
	__plat_fast_lock();
	self->cancel_queued = 0;
	if (self->cancel_state == PTHREAD_CANCEL_ENABLE && self->cancel_pending &&
	    self->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS)
		cancel = 1;
	__plat_fast_unlock();
	if (cancel) __pthread_cancel_current();
}

int pthread_cancel(pthread_t thread)
{
	int queue = 0;
	int redirect = 0;
	int cancel_self = 0;
	if (!thread || thread->magic != PTHREAD_MAGIC) return ESRCH;
	__pthread_cancel_defer_enter();
	__plat_fast_lock();
	if (thread->joined || (!thread->handle && thread->exited)) {
		__plat_fast_unlock();
		__pthread_cancel_defer_leave();
		return ESRCH;
	}
	thread->cancel_pending = 1;
	if (thread->cancel_state == PTHREAD_CANCEL_ENABLE &&
	    !thread->cancel_queued && thread->handle) {
		thread->cancel_queued = 1;
		redirect = thread != __pthread_self_control &&
			thread->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS;
		queue = !redirect;
	}
	cancel_self = thread == __pthread_self_control &&
		thread->cancel_state == PTHREAD_CANCEL_ENABLE &&
		thread->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS;
	__plat_fast_unlock();
	if (cancel_self) __pthread_cancel_current();
	if (redirect && !redirect_async_cancel(thread)) queue = 1;
	if (queue && __plat_thread_queue_apc(thread->handle, cancel_apc,
		thread, 0) < 0) {
		__plat_fast_lock();
		thread->cancel_queued = 0;
		__plat_fast_unlock();
	}
	__pthread_cancel_defer_leave();
	return 0;
}

int pthread_setcancelstate(int state, int *old_state)
{
	struct __pthread *self;
	int cancel;
	if (state != PTHREAD_CANCEL_ENABLE && state != PTHREAD_CANCEL_DISABLE)
		return EINVAL;
	self = __pthread_current();
	if (!self) return ENOMEM;
	__pthread_cancel_defer_enter();
	__plat_fast_lock();
	if (old_state) *old_state = self->cancel_state;
	self->cancel_state = state;
	cancel = state == PTHREAD_CANCEL_ENABLE && self->cancel_pending &&
	         self->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS;
	__plat_fast_unlock();
	if (cancel) __pthread_cancel_current();
	__pthread_cancel_defer_leave();
	return 0;
}

int pthread_setcanceltype(int type, int *old_type)
{
	struct __pthread *self;
	int cancel;
	if (type != PTHREAD_CANCEL_DEFERRED &&
	    type != PTHREAD_CANCEL_ASYNCHRONOUS) return EINVAL;
	self = __pthread_current();
	if (!self) return ENOMEM;
	__pthread_cancel_defer_enter();
	__plat_fast_lock();
	if (old_type) *old_type = self->cancel_type;
	self->cancel_type = type;
	cancel = type == PTHREAD_CANCEL_ASYNCHRONOUS && self->cancel_pending &&
	         self->cancel_state == PTHREAD_CANCEL_ENABLE;
	__plat_fast_unlock();
	if (cancel) __pthread_cancel_current();
	__pthread_cancel_defer_leave();
	return 0;
}

void pthread_testcancel(void)
{
	__pthread_testcancel();
}

// NOLINTEND(misc-include-cleaner)
