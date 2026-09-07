/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-time interface src/time/{time,clock,stime,timespec_get,
 * clock_gettime,timer}.c's POSIX-facing front doors call into instead of
 * a raw NtQuerySystemTime/NtSetSystemTime/NtQueryPerformanceCounter/
 * NtQueryInformationProcess(ProcessTimes) call, or the NT thread/event
 * calls timer.c's manager thread is built on.  See src/time/nt/plat_time.c
 * for the implementation these declare.
 *
 * Every function here takes/returns plain integers -- ticks in the
 * platform's own units (NT's 100ns system-time ticks since 1601, or its
 * free-running performance-counter units), never a raw NTSTATUS/
 * LARGE_INTEGER for the front door to interpret.  The epoch conversion
 * (NT ticks <-> unix-epoch seconds/nanoseconds) and the QPC-to-timespec
 * scaling are portable arithmetic, not NT-specific, so they stay exactly
 * where they already were -- src/internal/libc.h's __ticks_to_unix_sec()/
 * __unix_to_ticks()/__clock_qpc_to_timespec()/__clock_combine_cpu_ticks()
 * and friends -- and are NOT part of this interface.
 */
#ifndef _SPICULE_PLAT_TIME_H
#define _SPICULE_PLAT_TIME_H

#include "plat_handle.h"

/* NtQuerySystemTime(): the current value of the system's realtime clock,
 * in 100ns ticks since 1601-01-01 (NT's own epoch/unit).  This has no
 * documented failure mode on any NT/Wine implementation this library
 * targets, so -- like the code this replaces -- the result is never
 * checked for failure.
 *
 * nt_ticks is required: the NT backend (src/time/nt/plat_time.c) writes
 * `*nt_ticks = now;` unconditionally, and the Linux backend (src/time/
 * linux/plat_time.c) forwards it into __unix_to_ticks() the same way, with
 * no NULL check in either -- this one declaration covers both backends
 * (see src/process/find_program.c's __plat_process_fork()/_exit_code()/
 * _times() for the established precedent of one nonnull contract shared
 * across a platform split), and this file's own single real caller
 * (src/time/time.c/clock_gettime.c) never passes NULL. */
void __plat_realtime_get(long long *nt_ticks) __attribute__((nonnull(1)));

/* NtSetSystemTime(): set the system's realtime clock to `nt_ticks`.
 * 0/-1(errno) -- fails [EPERM] without SeSystemtimePrivilege, which a
 * normal process token does not hold. */
int __plat_realtime_set(long long nt_ticks);

/* NtQueryPerformanceCounter(): a free-running counter and its frequency
 * (both in the platform's own arbitrary units) -- the basis for
 * CLOCK_MONOTONIC and friends.  0/-1(errno).
 *
 * count/freq are both required: both backends write `*count = ...;
 * *freq = ...;` unconditionally on their own success path (NT:
 * plat_time.c's LARGE_INTEGER pair; Linux: the synthesized nanosecond
 * counter/fixed 1e9 "frequency"), with no NULL check on either -- the
 * checker's own report names only *count per backend (one finding per
 * function), but *freq's own direct store is exactly as unconditional,
 * verified by hand against both bodies. Every real call site
 * (src/time/clock_gettime.c's monotonic_get(), src/time/timer.c's
 * clock_ticks()) passes real on-stack locals, never NULL. */
int __plat_perfcounter_get(long long *count, long long *freq)
    __attribute__((nonnull(1, 2)));

/* NtQueryInformationProcess(ProcessTimes): the current process's
 * combined kernel+user CPU time, each in 100ns ticks.  0/-1(errno).
 *
 * kernel/user are both required, the same "both fields, one finding
 * shown" shape as __plat_perfcounter_get() above: both backends write
 * `*kernel = ...; *user = ...;` (or vice versa) unconditionally on
 * success, with no NULL check on either, and this file's own single real
 * caller (src/time/clock_gettime.c's cputime_get()) always passes real
 * on-stack locals. */
int __plat_process_cpu_ticks(long long *kernel, long long *user)
    __attribute__((nonnull(1, 2)));

/* Start timer.c's per-process manager thread, which runs `loop` (a
 * function that never returns) on its own native thread, and create the
 * auto-reset wake event it waits on.  Called at most once per process --
 * idempotency against a second call is the front door's job
 * (timer_create()'s `manager_started` latch), not this one's.
 * 0 with *wake_out set / -1(errno==EAGAIN) on failure -- including,
 * deliberately, under the native (non-NT) sanitizer/fuzz build, which has
 * no NT thread or signal-delivery transport to create either of these
 * against; SIGEV_NONE timers there need neither (see timer.c).
 *
 * wake_out is required: the NT backend writes `*wake_out = event;`
 * unconditionally on its only success path, with no NULL check -- the
 * Linux backend never reaches that store (it always fails with EAGAIN,
 * see that file's own long comment on why), but the shared declaration's
 * contract is set by whichever backend actually uses the value, the same
 * precedent as __plat_realtime_get() above, and this file's one real
 * caller (timer.c's start_manager()) always passes `&wake`, a real
 * on-stack local. loop is left unmarked: neither backend dereferences it
 * directly themselves (it is only stored into a file-static for a
 * trampoline function to call later, or ignored outright on Linux), so
 * there is nothing in either backend's OWN body for the attribute to
 * describe. */
int __plat_timer_manager_start(void (*loop)(void), __plat_handle_t *wake_out)
    __attribute__((nonnull(2)));

/* NtSetEvent(): wake the manager thread immediately rather than letting
 * it sleep until its current wait's deadline -- called by timer_settime()/
 * timer_delete() whenever a timer operation may have invalidated the
 * deadline the manager is currently waiting on. */
void __plat_timer_wake(__plat_handle_t wake);

/* NtWaitForSingleObject(): wait on the manager's (auto-reset) wake event
 * until it is signalled or, when `has_deadline` is nonzero, until `ticks`
 * (100ns units, relative, already clamped to >=0 by the caller) elapses,
 * whichever comes first.  `has_deadline` zero waits indefinitely -- no
 * timer in the process currently has a due time. */
void __plat_timer_manager_wait(__plat_handle_t wake, long long ticks, int has_deadline);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
