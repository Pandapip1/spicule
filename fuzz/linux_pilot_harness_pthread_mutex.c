/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the pthread_mutex_t front-door pilot --
 * NOT part of spicule, same standing as every other fuzz/
 * linux_pilot_harness_*.c file.
 *
 * src/thread/pthread_mutex.c's mutex_acquire() calls __sig_drain_pending()
 * unconditionally at its top, and src/thread/pthread.c's
 * __pthread_current() calls __sig_current_mask_copy() -- both real, but
 * genuinely NT-specific, functions in src/signal/{signal,sigdelivery}.c.
 * Stubbed here, local to this harness only: "no pending signals to
 * drain" and "an empty blocked-signal mask" are both honest answers for
 * a process with no real signal-delivery infrastructure on this backend
 * yet, since this test raises no signals.
 */
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include "libc.h"

void __sig_drain_pending(void)
{
}

void __sig_current_mask_copy(sigset_t *mask)
{
	int i;
	unsigned char *p = (unsigned char *)mask;
	for (i = 0; i < (int)sizeof *mask; i++) p[i] = 0;
}

/* __pthread_current() needs calloc() for its per-thread control block.
 * spicule's real malloc.c is built entirely on NT's process heap --
 * porting a real allocator is out of scope for proving the mutex works,
 * so a fixed-size static pool stands in (one call per real OS thread,
 * never freed -- this test doesn't exercise thread exit). */
#define POOL_SLOTS 64
static unsigned char pool[POOL_SLOTS][256];
static int pool_next;

void *calloc(size_t nmemb, size_t size)
{
	size_t total = nmemb * size;
	int i, slot;
	if (total > sizeof pool[0]) return 0;
	/* __atomic_fetch_add(), not a plain pool_next++: every worker
	 * thread's first mutex_acquire() calls this concurrently, and this
	 * stub has no mutex of its own to protect it with. */
	slot = __atomic_fetch_add(&pool_next, 1, __ATOMIC_RELAXED);
	if (slot >= POOL_SLOTS) return 0;
	for (i = 0; i < (int)sizeof pool[0]; i++) pool[slot][i] = 0;
	return pool[slot];
}

void free(void *p)
{
	(void)p;
}

/* Real bodies, matching src/misc/sched.c's own values exactly, but
 * duplicated rather than linking that file directly -- it would pull in
 * process_exists()/__child_find()/__plat_process_*, a whole separate
 * subsystem this test has no business standing up for two three-line
 * functions. */
int sched_get_priority_max(int policy)
{
	(void)policy;
	return 31;
}

int sched_get_priority_min(int policy)
{
	return policy == SCHED_OTHER ? 0 : 1;
}

/* The rest of src/thread/pthread.c beyond __pthread_current() --
 * pthread_join()/_detach()/_exit()/_getschedparam()/_setschedparam()/
 * _setschedprio() and finish()'s TSD-destructor-running path -- is out
 * of scope and unreached by this test, but pthread.c is linked here as a
 * whole object, so GNU ld still resolves every symbol those functions
 * reference. RtlAcquirePebLock()/RtlReleasePebLock() are stubbed here
 * (not routed through __plat_fast_lock()) because they're the literal
 * NT API names those unported functions call directly -- a no-op is the
 * honest stand-in for a code path that never actually runs in this
 * backend yet.
 *
 * RtlAcquirePebLock()/RtlReleasePebLock() are MACROS in libc.h (Thread
 * Safety Analysis wrappers around the two real raw ntdll functions of
 * the same name), active here too since this file includes libc.h.
 * #undef first so the stub bodies below can define the plain, real
 * ntdll symbol names the macro expands to. */
#undef RtlAcquirePebLock
#undef RtlReleasePebLock
void RtlAcquirePebLock(void) { }
void RtlReleasePebLock(void) { }
void __pthread_run_specific_destructors(void) { }

/* pthread_create()'s own path (__pthread_adopt_current()), unreached by
 * this test, which spawns workers via __plat_thread_spawn() directly. */
void __sig_current_mask_install(const sigset_t *mask) { (void)mask; }

/* src/thread/pthread_cancel.c is linked here for real now (pthread.c's
 * pthread_join() calls its __pthread_testcancel()), so
 * __pthread_cancel_defer_enter()/_leave() are no longer stubbed above --
 * this file supplies the genuine ones. redirect_async_cancel(), reached
 * only from pthread_cancel() itself (never called by this test), is the
 * one function in that file whose own reference this harness still can't
 * satisfy for real: arch/$(ARCH)/src/cancel_trampoline.S is real
 * assembly, out of scope for a mutex pilot the same way process_exists()
 * was above. Stubbed the same honest way: provably unreached here, so a
 * body that never returns is a truthful stand-in for its _Noreturn
 * contract. */
_Noreturn void __pthread_cancel_trampoline(void) { for (;;) ; }

/* __plat_thread_resume() is NOT stubbed here -- it would collide with
 * the real definition src/thread/linux/plat_thread.c carries, already
 * linked into this harness. Its suspend_table lookup simply finds
 * nothing and returns success, since pthread_create() is out of scope. */
