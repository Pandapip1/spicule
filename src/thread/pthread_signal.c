/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include "pthread_impl.h"
#include "plat_thread.h"

static void __PLAT_APC_CALL signal_apc(void *argument, void *signal_value, void *unused) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __pthread *thread = argument;
	(void)unused;
	/* Native user APCs queued immediately after creation may run before
	 * thread_entry().  Establish the control block and inherited mask before
	 * invoking user code so pthread_self() already names the target thread. */
	__pthread_adopt_current(thread);
	__sig_lock();
	__raise_thread_internal((int)(ULONG_PTR)signal_value);
	__sig_unlock();
}

int pthread_kill(pthread_t thread, int sig)
{
	if (!thread || thread->magic != PTHREAD_MAGIC) return ESRCH;
	if (sig < 0 || sig >= _NSIG) return EINVAL;
	__plat_fast_lock();
	if (thread->joined || (!thread->handle && thread->exited)) {
		__plat_fast_unlock();
		return ESRCH;
	}
	__plat_fast_unlock();
	if (!sig) return 0;
	if (__pthread_is_current(thread)) {
		signal_apc(thread, (void *)(ULONG_PTR)sig, 0);
		return 0;
	}
	return __plat_thread_queue_apc(thread->handle, signal_apc, thread,
		(void *)(ULONG_PTR)sig) == 0 ? 0 : ESRCH;
}

// NOLINTEND(misc-include-cleaner)
