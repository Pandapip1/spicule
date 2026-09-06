/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the pthread_cond_t front-door pilot
 * (fuzz/linux_pilot_test_pthread_cond.c) -- NOT part of ntlibc, same
 * standing as every other fuzz/linux_pilot_harness_*.c file. Mirrors
 * fuzz/linux_pilot_harness_pthread_mutex.c's own stub set almost
 * verbatim (see that file's banner for the rationale behind each
 * stub), just with a bigger calloc() pool: this harness's test spawns
 * real pthread_create() threads (each needing its own struct __pthread
 * control block) AND has each one call pthread_cond_wait() (one struct
 * cond_waiter per call, from src/thread/pthread_cond.c's cond_wait()),
 * so it needs more concurrent live allocations than the mutex pilot's
 * single-threaded tests ever did.
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

#define POOL_SLOTS 4096
static unsigned char pool[POOL_SLOTS][256];
static int pool_next;

void *calloc(size_t nmemb, size_t size)
{
	size_t total = nmemb * size;
	int i, slot;
	if (total > sizeof pool[0]) return 0;
	slot = __atomic_fetch_add(&pool_next, 1, __ATOMIC_RELAXED);
	if (slot >= POOL_SLOTS) return 0;
	for (i = 0; i < (int)sizeof pool[0]; i++) pool[slot][i] = 0;
	return pool[slot];
}

void free(void *p)
{
	(void)p;
}

int sched_get_priority_max(int policy)
{
	(void)policy;
	return 31;
}

int sched_get_priority_min(int policy)
{
	return policy == SCHED_OTHER ? 0 : 1;
}

#undef RtlAcquirePebLock
#undef RtlReleasePebLock
void RtlAcquirePebLock(void) { }
void RtlReleasePebLock(void) { }
void __pthread_run_specific_destructors(void) { }

void __sig_current_mask_install(const sigset_t *mask) { (void)mask; }

_Noreturn void __pthread_cancel_trampoline(void) { for (;;) ; }
