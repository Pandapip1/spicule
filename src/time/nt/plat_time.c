/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_time.h -- see that header for
 * the contract each function makes.  Everything here was, until this
 * file existed, inline inside src/time/{time,clock,stime,timespec_get,
 * clock_gettime,timer}.c; nothing changed in substance, only location
 * and the addition of a POSIX-shaped return (0/-1 with errno set) in
 * place of a raw NTSTATUS where one of these calls used to leave that
 * for its caller to interpret.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include "libc.h"
#include "plat_time.h"

void __plat_realtime_get(long long *nt_ticks)
{
	LARGE_INTEGER now;
	NtQuerySystemTime(&now);
	*nt_ticks = now;
}

int __plat_realtime_set(long long nt_ticks)
{
	LARGE_INTEGER nt = nt_ticks;
	NTSTATUS st = NtSetSystemTime(&nt, NULL);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_perfcounter_get(long long *count, long long *freq) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	LARGE_INTEGER c, f;
	NTSTATUS st = NtQueryPerformanceCounter(&c, &f);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*count = c;
	*freq = f;
	return 0;
}

int __plat_process_cpu_ticks(long long *kernel, long long *user) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	KERNEL_USER_TIMES kt;
	NTSTATUS st = NtQueryInformationProcess(NtCurrentProcess(), ProcessTimes,
	                                        &kt, sizeof kt, NULL);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*kernel = kt.KernelTime;
	*user = kt.UserTime;
	return 0;
}

/* The manager thread's real NT entry point.  NtCreateThreadEx needs a
 * ULONG NTAPI(PVOID)-shaped callback; timer.c's `loop` is a plain
 * void(void) function with the POSIX-timer scanning logic in it, so this
 * trampoline is the whole adapter between the two.  A single static
 * holds the one loop function this process ever starts a manager thread
 * with -- timer.c's own manager_started latch guarantees there is never
 * more than one, so there is never more than one live value for this to
 * hold. */
static void (*manager_loop_fn)(void);

static ULONG NTAPI manager_trampoline(PVOID unused)
{
	(void)unused;
	manager_loop_fn();
	return 0;
}

int __plat_timer_manager_start(void (*loop)(void), __plat_handle_t *wake_out)
{
#ifdef _SPICULE_NATIVE_BUILD
	/* The native sanitizer shim has no NT thread or signal-delivery
	 * transport.  SIGEV_NONE timers need neither: their remaining time
	 * is derived from the selected clock whenever it is queried. */
	(void)loop;
	errno = EAGAIN;
	return -1;
#else
	OBJECT_ATTRIBUTES oa;
	HANDLE event, thread;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	st = NtCreateEvent(&event, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(st)) { errno = EAGAIN; return -1; }
	manager_loop_fn = loop;
	st = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, 0, NtCurrentProcess(),
	                      (PVOID)manager_trampoline, 0, 0, 0, 0, 0, 0);
	if (!NT_SUCCESS(st)) {
		NtClose(event);
		errno = EAGAIN;
		return -1;
	}
	NtClose(thread);
	*wake_out = event;
	return 0;
#endif
}

void __plat_timer_wake(__plat_handle_t wake)
{
	LONG previous;
	NtSetEvent(wake, &previous);
}

void __plat_timer_manager_wait(__plat_handle_t wake, long long ticks, int has_deadline) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	LARGE_INTEGER timeout, *wait = 0;
	if (has_deadline) {
		timeout = -ticks;
		wait = &timeout;
	}
	/* Auto-reset wake closes the scan/wait race: a settime() or
	 * delete() between the caller's scan and this wait leaves the event
	 * signalled, so the wait returns immediately and the caller
	 * recomputes state instead of blocking through the change. */
	NtWaitForSingleObject(wake, FALSE, wait);
}

// NOLINTEND(misc-include-cleaner)
