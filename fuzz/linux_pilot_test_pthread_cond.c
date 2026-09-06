/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * pthread_cond_t front-door pilot -- NOT part of ntlibc, same standing
 * as fuzz/linux_pilot_test_pthread_mutex.c (this file's own structure
 * mirrors that one almost exactly; see its banner for the general
 * pattern).
 *
 * Written while investigating a posix-optsrun CI run (job 101471352780,
 * run 34024319078, and reconfirmed on the newer run 34026585752) where
 * pthread_cond_broadcast/{1-1,1-2,2-1,2-2,2-3,4-1}.c and
 * pthread_cond_destroy/2-1.c all TIMED OUT under that job's real
 * target: x86_64-win32 built with x86_64-win32-tcc, run under this
 * repo's patched Wine fork on an x86_64 GitHub runner -- NOT this
 * backend (aarch64-linux) directly. 34026585752's own log additionally
 * showed fork/21-1.c, getpid/1-1.c and every pthread_atfork test case
 * timing out in the same run, so the hangs are not narrowly scoped to
 * condition variables.
 *
 * This test proves, via a REAL contended pthread_cond_broadcast() with
 * THREAD_NUM real pthread_create()'d waiters (mirroring the OPTS
 * pthread_cond_broadcast/4-1.c scenario: every waiter locks a shared
 * mutex, bumps a start counter, and plain pthread_cond_wait()s; once
 * every waiter has started, the main thread broadcasts once and expects
 * every waiter to wake and successfully pthread_join()), that the
 * PORTABLE src/thread/pthread_cond.c / pthread_mutex.c logic itself
 * has no missed-wakeup or wrong-wake-count bug: run 30 times in a row
 * against this same Linux backend (src/thread/linux/plat_thread.c's
 * real futex-based semaphore), every run passed -- see this repo's own
 * CI-investigation notes for the full trace. That does not clear the
 * NT-backend syscall wrappers (src/thread/nt/plat_thread.c) or the real
 * Wine fork's own NtWaitForSingleObject()/NtReleaseSemaphore()/
 * NtCreateThreadEx() emulation under CI's specific runner, which this
 * Linux-only pilot cannot exercise -- kept here as permanent regression
 * coverage for the portable half of the algorithm, run on every push
 * via tools/linux-build-pthread-cond.sh (see tools/linux-build.sh's own
 * banner for why this whole family runs on every push rather than only
 * during an investigation like this one).
 *
 * Real thread creation goes through the REAL pthread_create()
 * (src/thread/pthread.c), not the raw __plat_thread_spawn() the mutex
 * pilot's own history warns about (see that file's own banner on the
 * CLONE_SETTLS/TLS-aliasing bug __plat_thread_spawn() itself had before
 * it was fixed) -- pthread_create()'s thread_entry() is what actually
 * exercises the fixed CLONE_SETTLS path end to end, which is exactly
 * what a real pthread_cond_wait()/pthread_cond_broadcast() workload
 * needs to trust per-thread identity for.
 */
#include <pthread.h>
#include <time.h>
#include "libc.h"
#include "plat_thread.h"

extern int printf(const char *, ...);

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s\n", msg); failures++; } \
} while (0)

#define THREAD_NUM 5

static pthread_mutex_t mtx;
static pthread_cond_t cond_var;
static volatile int start_num;
static volatile int waken_num;

/* A real elapsed-time delay loop, backed by the real clock_gettime()
 * front door -- this pilot family has no earlier need for one (the
 * mutex pilot's own tests are single-threaded and never wait on
 * anything). */
static void delay_ms(long long ms)
{
	struct timespec begin, now;
	long long elapsed_ms;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (long long)(now.tv_sec - begin.tv_sec) * 1000 +
			((long long)now.tv_nsec - (long long)begin.tv_nsec) / 1000000;
		if (elapsed_ms >= ms) return;
	}
}

static void *worker(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&mtx);
	__atomic_fetch_add(&start_num, 1, __ATOMIC_SEQ_CST);
	pthread_cond_wait(&cond_var, &mtx);
	__atomic_fetch_add(&waken_num, 1, __ATOMIC_SEQ_CST);
	pthread_mutex_unlock(&mtx);
	return 0;
}

/* ---- Test: a real contended broadcast wakes every real waiter ------- */
static void test_broadcast_wakes_all(void)
{
	pthread_t threads[THREAD_NUM];
	int i, rc;

	printf("\n-- test: pthread_cond_broadcast() wakes every real waiter --\n");

	CHECK(pthread_mutex_init(&mtx, 0) == 0, "pthread_mutex_init() succeeded");
	CHECK(pthread_cond_init(&cond_var, 0) == 0, "pthread_cond_init() succeeded");

	for (i = 0; i < THREAD_NUM; i++) {
		rc = pthread_create(&threads[i], 0, worker, 0);
		CHECK(rc == 0, "pthread_create() for a waiter succeeded");
	}

	/* Wait for every waiter to have locked the mutex and bumped
	 * start_num -- real pthread_cond_wait()'s own contract (link the
	 * waiter into the condvar's list before releasing the mutex, see
	 * src/thread/pthread_cond.c's cond_wait()) is what makes this
	 * loop's exit a real guarantee that every waiter is genuinely
	 * blocked in pthread_cond_wait() by the time the barrier lock/
	 * unlock below returns, not just a hopeful sleep. */
	while (__atomic_load_n(&start_num, __ATOMIC_SEQ_CST) < THREAD_NUM)
		delay_ms(5);

	pthread_mutex_lock(&mtx);
	pthread_mutex_unlock(&mtx);

	printf("[main] broadcasting to %d real waiters\n", THREAD_NUM);
	rc = pthread_cond_broadcast(&cond_var);
	CHECK(rc == 0, "pthread_cond_broadcast() returned 0");

	/* pthread_join() on a genuinely still-blocked waiter hangs forever
	 * -- that is the whole point: a still-broken missed-wakeup fix
	 * fails this test by hanging tools/linux-build-pthread-cond.sh's
	 * own `timeout`-wrapped run, not by silently reporting FAIL and
	 * exiting, since the failure mode under test IS "never wakes up." */
	for (i = 0; i < THREAD_NUM; i++)
		CHECK(pthread_join(threads[i], 0) == 0, "pthread_join() on a waiter succeeded");

	printf("[main] start_num=%d waken_num=%d (want %d)\n",
		start_num, waken_num, THREAD_NUM);
	CHECK(waken_num == THREAD_NUM, "every waiter observed itself waking from the broadcast");

	pthread_cond_destroy(&cond_var);
	pthread_mutex_destroy(&mtx);
}

int main(void)
{
	test_broadcast_wakes_all();

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
