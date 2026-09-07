/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux thread-subsystem pilot smoke test -- NOT part of spicule, same
 * standing as fuzz/ntstubs.c's own native-build scaffolding and fuzz/
 * linux_pilot_test.c (mman/unistd) before it.
 *
 * Unlike that first pilot, this one does NOT link a real spicule front
 * door (no src/thread/pthread_mutex.c here) -- see src/thread/linux/
 * plat_thread.c's own banner for exactly why that front door cannot be
 * linked against this backend without also porting RtlAcquirePebLock()
 * and __pthread_current(), a separate, larger piece of follow-up work.
 * What this DOES exercise is real: a minimal binary-semaphore mutex,
 * built directly on the real __plat_semaphore_create()/_post() and
 * __plat_wait_one() from src/thread/linux/plat_thread.c -- the same two
 * primitives pthread_mutex.c's own blocking slow path rests on -- tested
 * under genuine contention from real Linux kernel threads spawned via
 * __plat_thread_spawn() (clone(2) + src/thread/linux/aarch64/clone.S).
 *
 * Two runs, back to back, over the SAME shared counter and thread count:
 * one with no locking at all (expected, and required by this test, to
 * show a WRONG final count -- proof the threads are truly concurrent and
 * truly sharing memory, not accidentally serialized), and one guarded by
 * the mutex below (required to show the EXACT expected count, every
 * time). A single-threaded test proves nothing about lock correctness;
 * this is the real contention test that matters.
 */
#include <stddef.h>
#include "plat_thread.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);

#define SYS_wait4 260 /* aarch64; confirmed against asm-generic/unistd.h,
                       * same discipline as plat_thread.c's own numbers */

#define NTHREADS 16
#define NITERS   300000

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s\n", msg); failures++; } \
} while (0)

/* ---- a minimal mutex, built on the real plat_thread.h primitives ------- */

struct mini_mutex {
	__plat_handle_t sem; /* binary: created initial=1, max=1 */
};

static int mini_mutex_init(struct mini_mutex *m)
{
	return __plat_semaphore_create(1, 1, 0, &m->sem);
}

static void mini_mutex_lock(struct mini_mutex *m)
{
	/* Blocks (non-alertable, no timeout) until this thread is the one
	 * that decrements the semaphore from 1 to 0 -- exactly
	 * pthread_mutex.c's own mutex_acquire() slow-path wait, minus the
	 * owner/recursion bookkeeping that lives in mutex_data (see
	 * plat_thread.c's banner for why that part is not ported here). */
	int r = __plat_wait_one(m->sem, 0, 0, 0);
	if (r != __PLAT_WAIT_OK) {
		/* Only a real backend bug or a real kernel-level failure gets
		 * here -- there is no timeout and no APC to produce the other
		 * two outcomes. Fail loudly rather than silently proceed
		 * unlocked, which would corrupt the very count this test
		 * exists to verify. */
		printf("FAIL - mini_mutex_lock: __plat_wait_one returned %d, not OK\n", r);
		failures++;
	}
}

static void mini_mutex_unlock(struct mini_mutex *m)
{
	if (__plat_semaphore_post(m->sem) != 0) {
		printf("FAIL - mini_mutex_unlock: __plat_semaphore_post failed\n");
		failures++;
	}
}

/* ---- the shared state every worker thread contends over ---------------- */

struct shared_state {
	struct mini_mutex lock;
	long counter;
	int use_lock;
};

static struct shared_state g_state;

static unsigned worker(void *arg)
{
	struct shared_state *s = (struct shared_state *)arg;
	int i;
	for (i = 0; i < NITERS; i++) {
		if (s->use_lock) {
			mini_mutex_lock(&s->lock);
			s->counter++;
			mini_mutex_unlock(&s->lock);
		} else {
			/* Deliberately unprotected: this arm exists to PROVE real
			 * concurrency (a wrong count) before the locked arm proves
			 * real correctness (an exact one). */
			s->counter++;
		}
	}
	return 0;
}

/* Join by pid, not through __plat_wait_one(): see plat_thread.c's own
 * banner on why a thread handle from __plat_thread_spawn() cannot be
 * passed to __plat_wait_one() in this backend (a different handle
 * namespace than the futex-object handles __plat_wait_one understands).
 * This is a Linux-only, local, test-scaffolding-only extension -- a
 * real, correct wait4() rather than a stub, because
 * __plat_thread_spawn()'s own clone() flags (see plat_thread.c) were
 * chosen specifically to make the spawned thread visible to a plain
 * wait4() call. */
static void join_thread(__plat_handle_t h)
{
	long pid = (long)h - 1;
	long status = 0;
	long r = syscall(SYS_wait4, pid, &status, 0, 0);
	if (r < 0) {
		printf("FAIL - wait4(%ld) failed\n", pid);
		failures++;
	}
}

static void run_contention_test(int use_lock, long expect_exact)
{
	__plat_handle_t handles[NTHREADS];
	int i;
	long expected = (long)NTHREADS * NITERS;

	g_state.counter = 0;
	g_state.use_lock = use_lock;
	if (use_lock) {
		CHECK(mini_mutex_init(&g_state.lock) == 0,
		      "mini_mutex_init() created the semaphore-backed mutex");
	}

	for (i = 0; i < NTHREADS; i++) {
		int r = __plat_thread_spawn(worker, &g_state, 0, 0, &handles[i]);
		if (r != 0) {
			printf("FAIL - __plat_thread_spawn() #%d failed\n", i);
			failures++;
			return;
		}
	}
	for (i = 0; i < NTHREADS; i++) join_thread(handles[i]);

	printf("%s: %d threads x %d increments, expected=%ld actual=%ld\n",
	       use_lock ? "WITH mini_mutex" : "WITHOUT any lock (races expected)",
	       NTHREADS, NITERS, expected, g_state.counter);

	if (expect_exact) {
		CHECK(g_state.counter == expected,
		      "protected run's final count is EXACTLY the expected total");
	} else {
		CHECK(g_state.counter != expected,
		      "unprotected run's final count is WRONG (proves real concurrent, "
		      "genuinely shared-memory execution -- not proof of a bug)");
	}
}

int main(void)
{
	__plat_handle_t sem;
	__plat_handle_t ev;
	int value = -1;
	int pass;

	/* --- direct sanity checks of the individual primitives, before the
	 * real stress test --- */
	CHECK(__plat_semaphore_create(0, 5, 0, &sem) == 0,
	      "__plat_semaphore_create() succeeded");
	CHECK(__plat_semaphore_getvalue(sem, &value) == 0 && value == 0,
	      "fresh semaphore reads back its initial value (0)");
	CHECK(__plat_semaphore_post(sem) == 0, "__plat_semaphore_post() succeeded");
	CHECK(__plat_semaphore_getvalue(sem, &value) == 0 && value == 1,
	      "post() incremented the value to 1");
	CHECK(__plat_wait_one(sem, 0, 0, 0) == __PLAT_WAIT_OK,
	      "__plat_wait_one() consumed the posted count");
	CHECK(__plat_semaphore_getvalue(sem, &value) == 0 && value == 0,
	      "wait_one() decremented the value back to 0");

	CHECK(__plat_event_create(&ev) == 0, "__plat_event_create() succeeded");
	CHECK(__plat_event_set(ev) == 0, "__plat_event_set() succeeded");
	CHECK(__plat_wait_one(ev, 0, 0, 0) == __PLAT_WAIT_OK,
	      "__plat_wait_one() sees a set event immediately");
	CHECK(__plat_wait_one(ev, 0, 0, 0) == __PLAT_WAIT_OK,
	      "manual-reset event stays set across a second wait");

	/* A real, bounded timeout that must actually expire: an unset event,
	 * waited on with a 20ms relative timeout (100ns units), must return
	 * __PLAT_WAIT_TIMEOUT, not hang forever and not return OK. */
	{
		__plat_handle_t ev2;
		CHECK(__plat_event_create(&ev2) == 0,
		      "second __plat_event_create() succeeded");
		CHECK(__plat_wait_one(ev2, 0, 1, -200000LL) == __PLAT_WAIT_TIMEOUT,
		      "__plat_wait_one() times out on a never-set event within 20ms");
	}

	/* --- the real point of this test: real contention --- */
	run_contention_test(0, 0);
	run_contention_test(1, 1);
	run_contention_test(1, 1);
	run_contention_test(1, 1);

	pass = failures == 0;
	printf("\n%s\n", pass ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
	return pass ? 0 : 1;
}
