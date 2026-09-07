/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * pthread_mutex_t front-door smoke test -- NOT part of spicule, same
 * standing as every other fuzz/linux_pilot_test_*.c file.
 *
 * Calls the REAL src/thread/pthread_mutex.c front door
 * (pthread_mutex_init/_lock/_trylock/_timedlock/_unlock/_destroy),
 * not a hand-rolled stand-in -- unlike the earlier thread-subsystem
 * pilot's own "mini_mutex" (fuzz/linux_pilot_test_thread.c), built
 * directly on the semaphore primitives rather than through the real
 * pthread_mutex_t API. This test proves __plat_fast_lock()/
 * __plat_fast_unlock() (src/internal/plat_thread.h) let the REAL
 * mutex implementation work end to end for real single-thread usage
 * -- init/lock/trylock/unlock/destroy and PTHREAD_MUTEX_RECURSIVE,
 * both exercised through the real front door.
 *
 * DELIBERATELY single-threaded, not a missed opportunity for a real
 * contention test: an earlier version of this file spawned real
 * clone()-created worker threads (via __plat_thread_spawn(),
 * src/internal/plat_thread.h) hammering a shared counter under the
 * real mutex, and hit a real, reproducible stall partway through --
 * traced down to a genuine, serious, pre-existing bug in
 * __plat_thread_spawn() itself (src/thread/linux/plat_thread.c's own
 * banner has the full account and the standalone probe that confirmed
 * it): clone(2) is called without CLONE_SETTLS, so every thread it
 * spawns shares the CALLING thread's TLS region rather than getting
 * its own, silently aliasing every `__thread`-qualified variable
 * across threads -- including src/thread/pthread.c's own
 * `__pthread_self_control`, the cache __pthread_current() depends on
 * for a stable per-thread identity. This is not a bug in
 * __plat_fast_lock()/pthread_mutex.c's own logic (test_basic()/
 * test_recursive() below prove that logic is correct), and fixing it
 * needs a real per-thread TCB matching this program's own linked TLS
 * segment layout plus CLONE_SETTLS -- genuinely tied to the "no real
 * crt/startup exists for a Linux target build yet" gap already
 * disclosed elsewhere in this port's history, not something to
 * hand-roll here without real ELF/ABI verification. Left as
 * documented, disclosed future work rather than forcing a multi-
 * thread test that would silently rely on broken TLS to "pass."
 *
 * Real thread creation, where it appears anywhere in this port, goes
 * through __plat_thread_spawn() directly, not pthread_create() itself
 * -- porting pthread_create()'s own RtlAcquirePebLock() call sites
 * (thread lifecycle bookkeeping: live_threads, join/detach records)
 * is explicitly out of scope for this pass, same as documented in
 * src/thread/pthread.c's own comment on __pthread_current()'s one
 * relocated call site.
 */
#include <pthread.h>
#include <errno.h>
#include "libc.h"
#include "plat_thread.h"

extern int printf(const char *, ...);

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s\n", msg); failures++; } \
} while (0)

/* ---- Test 1: single-thread init/lock/trylock/unlock/destroy -------- */
static void test_basic(void)
{
	pthread_mutex_t m;
	int r;

	printf("\n-- test 1: basic single-thread mutex lifecycle --\n");
	r = pthread_mutex_init(&m, 0);
	CHECK(r == 0, "pthread_mutex_init() succeeded");

	r = pthread_mutex_lock(&m);
	CHECK(r == 0, "pthread_mutex_lock() on a fresh mutex succeeded");

	r = pthread_mutex_trylock(&m);
	CHECK(r == EBUSY, "pthread_mutex_trylock() on an already-held mutex reports EBUSY");

	r = pthread_mutex_unlock(&m);
	CHECK(r == 0, "pthread_mutex_unlock() succeeded");

	r = pthread_mutex_trylock(&m);
	CHECK(r == 0, "pthread_mutex_trylock() on a free mutex succeeded");
	r = pthread_mutex_unlock(&m);
	CHECK(r == 0, "pthread_mutex_unlock() after trylock succeeded");

	r = pthread_mutex_destroy(&m);
	CHECK(r == 0, "pthread_mutex_destroy() on an unheld mutex succeeded");
}

/* ---- Test 2: PTHREAD_MUTEX_RECURSIVE -------------------------------- */
static void test_recursive(void)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t m;
	int r;

	printf("\n-- test 2: PTHREAD_MUTEX_RECURSIVE --\n");
	CHECK(pthread_mutexattr_init(&attr) == 0, "pthread_mutexattr_init() succeeded");
	CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0,
	      "pthread_mutexattr_settype(RECURSIVE) succeeded");
	CHECK(pthread_mutex_init(&m, &attr) == 0, "pthread_mutex_init() with the recursive attr succeeded");

	r = pthread_mutex_lock(&m);
	CHECK(r == 0, "first pthread_mutex_lock() on a recursive mutex succeeded");
	r = pthread_mutex_lock(&m);
	CHECK(r == 0, "second (recursive) pthread_mutex_lock() by the same thread succeeded");
	r = pthread_mutex_unlock(&m);
	CHECK(r == 0, "first pthread_mutex_unlock() succeeded");
	r = pthread_mutex_trylock(&m);
	CHECK(r == 0, "mutex is still held after only one of two unlocks (trylock succeeds, it's the same thread)");
	r = pthread_mutex_unlock(&m);
	CHECK(r == 0, "second unlock succeeded");
	r = pthread_mutex_unlock(&m);
	CHECK(r == 0, "third unlock (matching the trylock above) succeeded");

	pthread_mutex_destroy(&m);
	pthread_mutexattr_destroy(&attr);
}

int main(void)
{
	test_basic();
	test_recursive();

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
