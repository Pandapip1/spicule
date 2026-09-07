/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Coverage fences for <pthread.h> -- POSIX.1-2017 (IEEE Std 1003.1-2017,
 * The Open Group Base Specifications Issue 7, 2018 Edition), the document
 * served at https://pubs.opengroup.org/onlinepubs/9699919799/ .  Clause
 * text quoted below was read from Ubuntu's manpages-posix-dev 2017a-2
 * package, whose every page carries the COPYRIGHT "reprinted and
 * reproduced in electronic form from IEEE Std 1003.1-2017 ... Issue 7,
 * 2018 Edition"; that is the same text, and it is what was reachable
 * from this container (pubs.opengroup.org is blocked).
 *
 * ==================== why this file exists ==========================
 *
 * A name-level cross-index of the 1190 distinct interfaces named in the
 * NAME sections of that package's 882 function pages against every
 * identifier appearing anywhere in the test/ tree finds 364 POSIX interfaces
 * with no mention at all.  <pthread.h> is far and away the largest
 * single block of them: 99 of the 364.  (The index is name-level, so it
 * over-reports -- prose-only coverage reads as absent -- which is the
 * right bias for finding gaps and the wrong one for a headline number.
 * The prose here is real: test/posix-stdio.c:2161 and test/posix-grp.c:1106
 * both note the absence.  What did not exist before this file is a
 * *fence*: an assertion, cited to a clause, that fails the day the
 * interface appears without the semantics.)
 *
 * Threads are not an option in this edition.  XSH 2.9 and the whole
 * pthread family are Base; only the sub-options each fence names below
 * (Thread Execution Scheduling, Thread Process-Shared Synchronization,
 * Robust Mutex Priority Protection, Barriers, Spin Locks, ...) are
 * conditional.  So "absent" here is a gap against the mandatory core,
 * not against an option this target declines.
 *
 * ==================== what a caller observes today ==================
 *
 * There is no include/pthread.h.  Every fence below therefore fails at
 * *compile* time on its own `#include <pthread.h>`, which is what makes
 * UNIMPL -- not BUG -- the correct disposition for all of them, and it
 * is what tools/test-policy.py --pedantic re-measures rather than takes
 * on trust.  lib/libpthread.a exists but is an empty archive (the
 * 8-byte "!<arch>\n" magic and nothing else), built only so that
 * `-lpthread` links; it supplies no symbol, so nothing here would reach
 * a link error even if the header appeared.
 *
 * Each fence's body is what should pass the day the interface works.
 * The bodies are deliberately written to be decidable by a single
 * thread wherever the clause allows it, so that the first day
 * <pthread.h> exists they are runnable without also needing a working
 * scheduler; the two that cannot be (create/join, barrier) start the
 * threads they need.
 *
 * NOT fenced here, and why -- see the report accompanying this file:
 * _SC_THREADS / _POSIX_THREADS (a `land/unimpl` commit is adding the
 * mandated _SC_ constants; fencing it here would collide), and
 * pthread_atfork (already named and reasoned about at test/exec.c:871).
 */

#include <stdio.h>

#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ==================================================================
 * Thread creation and termination
 * .../functions/pthread_create.html, pthread_join.html,
 * pthread_self.html, pthread_equal.html, pthread_detach.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_create_join_value)
#include <pthread.h>

static void *cj_start(void *arg)
{
	/* "The thread is created executing start_routine with arg as its
	 * sole argument."  -- pthread_create.html DESCRIPTION */
	CHECK(arg == (void *)&fails);
	return (void *)&fails;
}

static void test_pthread_create_join_value(void)
{
	pthread_t th, me;
	void *result = NULL;

	/* "Upon successful completion, pthread_create() shall store the ID
	 * of the created thread in the location referenced by thread."
	 * "If attr is NULL, the default attributes shall be used." */
	CHECK(pthread_create(&th, NULL, cj_start, (void *)&fails) == 0);

	/* "On return from a successful pthread_join() call with a non-NULL
	 * value_ptr argument, the value passed to pthread_exit() by the
	 * terminating thread shall be made available in the location
	 * referenced by value_ptr."  With a returning start_routine the
	 * effect "shall be as if there was an implicit call to
	 * pthread_exit() using the return value ... as the exit status." */
	CHECK(pthread_join(th, &result) == 0);
	CHECK(result == (void *)&fails);

	/* pthread_self.html: "shall return the thread ID of the calling
	 * thread."  pthread_equal.html: "shall return a non-zero value if
	 * t1 and t2 are equal; otherwise, zero shall be returned." */
	me = pthread_self();
	CHECK(pthread_equal(me, pthread_self()) != 0);
	CHECK(pthread_equal(me, th) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_detach_join_esrch)
#include <pthread.h>
#include <errno.h>

static void *dj_start(void *arg)
{
	(void)arg;
	/* pthread_exit.html: "shall terminate the calling thread and make
	 * the value value_ptr available to any successful join". */
	pthread_exit(NULL);
	return NULL;
}

static void test_pthread_detach_join_esrch(void)
{
	pthread_t th;

	CHECK(pthread_create(&th, NULL, dj_start, NULL) == 0);

	/* pthread_detach.html: "shall indicate to the implementation that
	 * storage for the thread thread can be reclaimed when that thread
	 * terminates." */
	CHECK(pthread_detach(th) == 0);

	/* pthread_join.html ERRORS: "[EINVAL] The implementation has
	 * detected that the value specified by thread does not refer to a
	 * joinable thread."  A detached thread is not joinable. */
	CHECK(pthread_join(th, NULL) == EINVAL);
}
#endif

/* ==================================================================
 * Thread attributes -- .../functions/pthread_attr_init.html and the
 * pthread_attr_get and pthread_attr_set pages
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_attr_roundtrip)
#include <pthread.h>
#include <limits.h>
#include <errno.h>

static void test_pthread_attr_roundtrip(void)
{
	static unsigned char stack_area[PTHREAD_STACK_MIN];
	pthread_attr_t attr, current;
	struct sched_param parameter;
	void *address = NULL;
	int state = -1, scope = -1, inherit = -1, policy = -1;
	size_t stack = 0, guard = (size_t)-1;

	/* pthread_attr_init.html: "shall initialize a thread attributes
	 * object attr with the default value for all of the individual
	 * attributes used by a given implementation." */
	CHECK(pthread_attr_init(&attr) == 0);

	/* "The detachstate attribute ... default value ... shall be
	 * PTHREAD_CREATE_JOINABLE."  -- pthread_attr_setdetachstate.html */
	CHECK(pthread_attr_getdetachstate(&attr, &state) == 0);
	CHECK(state == PTHREAD_CREATE_JOINABLE);
	CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0);
	CHECK(pthread_attr_getdetachstate(&attr, &state) == 0);
	CHECK(state == PTHREAD_CREATE_DETACHED);
	/* ERRORS: "[EINVAL] The value of detachstate was not valid." */
	CHECK(pthread_attr_setdetachstate(&attr, 0x5eed) == EINVAL);

	/* pthread_attr_setstacksize.html: "shall fail if: [EINVAL] The
	 * value of stacksize is less than {PTHREAD_STACK_MIN}".  The
	 * round-trip is the positive half of the same clause. */
	CHECK(pthread_attr_setstacksize(&attr, (size_t)PTHREAD_STACK_MIN * 4) == 0);
	CHECK(pthread_attr_getstacksize(&attr, &stack) == 0);
	CHECK(stack == (size_t)PTHREAD_STACK_MIN * 4);

	/* pthread_attr_setguardsize.html: "If guardsize is zero, a guard
	 * area shall not be provided for the thread." */
	CHECK(pthread_attr_setguardsize(&attr, 0) == 0);
	CHECK(pthread_attr_getguardsize(&attr, &guard) == 0);
	CHECK(guard == 0);

	/* pthread_attr_setscope.html / setinheritsched.html: the values
	 * are <pthread.h>'s own constants and must round-trip.  Which of
	 * PTHREAD_SCOPE_SYSTEM / PTHREAD_SCOPE_PROCESS is supported is
	 * implementation-defined, so assert only that the one that was
	 * read back is one of the two the header names. */
	CHECK(pthread_attr_getscope(&attr, &scope) == 0);
	CHECK(scope == PTHREAD_SCOPE_SYSTEM || scope == PTHREAD_SCOPE_PROCESS);
	CHECK(pthread_attr_getinheritsched(&attr, &inherit) == 0);
	CHECK(inherit == PTHREAD_INHERIT_SCHED || inherit == PTHREAD_EXPLICIT_SCHED);
	CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
	CHECK(pthread_attr_getinheritsched(&attr, &inherit) == 0);
	CHECK(inherit == PTHREAD_EXPLICIT_SCHED);
	CHECK(pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM) == 0);
	CHECK(pthread_attr_getscope(&attr, &scope) == 0);
	CHECK(scope == PTHREAD_SCOPE_SYSTEM);

	/* The scheduling policy and its parameter are a coupled attribute.
	 * Reading the defaults and writing that same valid pair back exercises
	 * both halves without assuming an implementation-specific priority. */
	CHECK(pthread_attr_getschedpolicy(&attr, &policy) == 0);
	CHECK(pthread_attr_getschedparam(&attr, &parameter) == 0);
	CHECK(pthread_attr_setschedpolicy(&attr, policy) == 0);
	CHECK(pthread_attr_setschedparam(&attr, &parameter) == 0);

	/* The obsolete get/setstackaddr pair remains declared for source
	 * compatibility, alongside the preferred combined get/setstack API. */
	CHECK(pthread_attr_setstack(&attr, stack_area, sizeof stack_area) == 0);
	CHECK(pthread_attr_getstack(&attr, &address, &stack) == 0);
	CHECK(address == stack_area);
	CHECK(stack == sizeof stack_area);
	CHECK(pthread_attr_setstackaddr(&attr, stack_area) == 0);
	address = NULL;
	CHECK(pthread_attr_getstackaddr(&attr, &address) == 0);
	CHECK(address == stack_area);

	/* pthread_getattr_np() is the live-thread counterpart: its result is
	 * an initialized attribute object with a nonempty current stack. */
	CHECK(pthread_getattr_np(pthread_self(), &current) == 0);
	CHECK(pthread_attr_getstack(&current, &address, &stack) == 0);
	CHECK(address != NULL);
	CHECK(stack >= PTHREAD_STACK_MIN);
	CHECK(pthread_attr_destroy(&current) == 0);

	/* "shall destroy a thread attributes object ... A destroyed attr
	 * attributes object can be reinitialized using
	 * pthread_attr_init()." */
	CHECK(pthread_attr_destroy(&attr) == 0);
	CHECK(pthread_attr_init(&attr) == 0);
	CHECK(pthread_attr_destroy(&attr) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_cleanup_push_pop)
#include <pthread.h>

static void cleanup_increment(void *argument)
{
	(*(int *)argument)++;
}

static void test_pthread_cleanup_push_pop(void)
{
	int calls = 0;

	/* The lexical pair executes its top handler exactly when pop's
	 * argument is nonzero, independently of thread cancellation. */
	pthread_cleanup_push(cleanup_increment, &calls);
	pthread_cleanup_pop(1);
	CHECK(calls == 1);

	pthread_cleanup_push(cleanup_increment, &calls);
	pthread_cleanup_pop(0);
	CHECK(calls == 1);
}
#endif

/* ==================================================================
 * Mutexes -- .../functions/pthread_mutex_lock.html,
 * pthread_mutex_init.html, pthread_mutexattr_settype.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_mutex_lock_unlock)
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <limits.h>

struct timed_mutex_case {
	pthread_mutex_t *mutex;
	sem_t ready;
};

static void *release_timed_mutex(void *argument)
{
	struct timed_mutex_case *test = argument;
	struct timespec delay = { 0, 20000000L };
	CHECK(pthread_mutex_lock(test->mutex) == 0);
	CHECK(sem_post(&test->ready) == 0);
	nanosleep(&delay, NULL);
	CHECK(pthread_mutex_unlock(test->mutex) == 0);
	return NULL;
}

static void test_pthread_mutex_lock_unlock(void)
{
	pthread_mutex_t stat_mtx = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t mtx;
	struct timed_mutex_case timed;
	struct timespec extreme_future = { LLONG_MAX, 999999999L };
	pthread_t releaser;

	/* pthread_mutex_init.html: "In cases where default mutex
	 * attributes are appropriate, the macro PTHREAD_MUTEX_INITIALIZER
	 * can be used to initialize mutexes that are statically
	 * allocated.  The effect shall be equivalent to dynamic
	 * initialization by a call to pthread_mutex_init() with parameter
	 * attr specified as NULL". */
	CHECK(pthread_mutex_lock(&stat_mtx) == 0);
	CHECK(pthread_mutex_unlock(&stat_mtx) == 0);
	CHECK(pthread_mutex_destroy(&stat_mtx) == 0);

	CHECK(pthread_mutex_init(&mtx, NULL) == 0);

	/* pthread_mutex_lock.html: "This operation shall return with the
	 * mutex object referenced by mutex in the locked state with the
	 * calling thread as its owner." */
	CHECK(pthread_mutex_lock(&mtx) == 0);

	/* "The pthread_mutex_trylock() function shall be equivalent to
	 * pthread_mutex_lock(), except that if the mutex object ... is
	 * currently locked ... the call shall return immediately."
	 * ERRORS: "[EBUSY] The mutex could not be acquired because it was
	 * already locked." */
	CHECK(pthread_mutex_trylock(&mtx) == EBUSY);
	CHECK(pthread_mutex_unlock(&mtx) == 0);

	/* A deadline at time_t's upper bound is valid and far in the future.
	 * The old signed conversion wrapped it into an expired timeout. */
	timed.mutex = &mtx;
	CHECK(sem_init(&timed.ready, 0, 0) == 0);
	CHECK(pthread_create(&releaser, NULL, release_timed_mutex, &timed) == 0);
	CHECK(sem_wait(&timed.ready) == 0);
	CHECK(pthread_mutex_timedlock(&mtx, &extreme_future) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	CHECK(pthread_join(releaser, NULL) == 0);
	CHECK(sem_destroy(&timed.ready) == 0);
	CHECK(pthread_mutex_trylock(&mtx) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	CHECK(pthread_mutex_destroy(&mtx) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_mutexattr_type_relock)
#include <pthread.h>
#include <errno.h>

static void test_pthread_mutexattr_type_relock(void)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t mtx;
	int type = -1;

	CHECK(pthread_mutexattr_init(&attr) == 0);

	/* pthread_mutexattr_gettype.html: "The default value of the type
	 * attribute is PTHREAD_MUTEX_DEFAULT." */
	CHECK(pthread_mutexattr_gettype(&attr, &type) == 0);
	CHECK(type == PTHREAD_MUTEX_DEFAULT);

	/* The Relock/Unlock-When-Not-Owner table in
	 * pthread_mutex_lock.html: PTHREAD_MUTEX_ERRORCHECK relock is
	 * "Returns error", and unlock when not owner is "Returns error"
	 * -- and ERRORS names the number: "[EDEADLK] ... the current
	 * thread already owns the mutex", "[EPERM] The mutex type is
	 * PTHREAD_MUTEX_ERRORCHECK ... and the current thread does not
	 * own the mutex." */
	CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) == 0);
	CHECK(pthread_mutexattr_gettype(&attr, &type) == 0);
	CHECK(type == PTHREAD_MUTEX_ERRORCHECK);
	CHECK(pthread_mutex_init(&mtx, &attr) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == EPERM);
	CHECK(pthread_mutex_lock(&mtx) == 0);
	CHECK(pthread_mutex_lock(&mtx) == EDEADLK);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	CHECK(pthread_mutex_destroy(&mtx) == 0);

	/* Same table, PTHREAD_MUTEX_RECURSIVE: relock "Succeeds", and
	 * "the mutex shall maintain the concept of a lock count ... The
	 * mutex shall become available when the count reaches zero." */
	CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
	CHECK(pthread_mutex_init(&mtx, &attr) == 0);
	CHECK(pthread_mutex_lock(&mtx) == 0);
	CHECK(pthread_mutex_lock(&mtx) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	/* Still held once: trylock from the owning thread succeeds again
	 * rather than reporting [EBUSY], and destroy of a locked mutex is
	 * what the count must still be preventing. */
	CHECK(pthread_mutex_trylock(&mtx) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	CHECK(pthread_mutex_destroy(&mtx) == 0);

	CHECK(pthread_mutexattr_destroy(&attr) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_pshared_recursive_owner_after_fork)
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

static void test_pthread_pshared_recursive_owner_after_fork(void)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t *mutex;
	pid_t child;
	int status;

	mutex = mmap(NULL, sizeof *mutex, PROT_READ | PROT_WRITE,
	             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mutex == MAP_FAILED) {
		CHECK(0);
		return;
	}
	CHECK(pthread_mutexattr_init(&attr) == 0);
	CHECK(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
	CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
	CHECK(pthread_mutex_init(mutex, &attr) == 0);
	CHECK(pthread_mutex_lock(mutex) == 0);

	child = fork();
	if (child == 0)
		_exit(pthread_mutex_trylock(mutex) == EBUSY ? 0 : 1);
	if (child < 0) {
		CHECK(0);
	} else {
		CHECK(waitpid(child, &status, 0) == child);
		/* fork() preserves the parent's pthread_t pointer value in the
		 * child, but the child is not the recursive mutex's owner. */
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}

	CHECK(pthread_mutex_unlock(mutex) == 0);
	CHECK(pthread_mutex_destroy(mutex) == 0);
	CHECK(pthread_mutexattr_destroy(&attr) == 0);
	CHECK(munmap(mutex, sizeof *mutex) == 0);
}
#endif

/* ==================================================================
 * Condition variables -- .../functions/pthread_cond_init.html,
 * pthread_cond_timedwait.html, pthread_condattr_getclock.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_cond_timedwait_etimedout)
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

struct timed_cond_case {
	pthread_cond_t *cond;
	pthread_mutex_t *mutex;
};

static void *signal_timed_cond(void *argument)
{
	struct timed_cond_case *test = argument;
	CHECK(pthread_mutex_lock(test->mutex) == 0);
	CHECK(pthread_cond_signal(test->cond) == 0);
	CHECK(pthread_mutex_unlock(test->mutex) == 0);
	return NULL;
}

static void test_pthread_cond_timedwait_etimedout(void)
{
	pthread_cond_t stat_cv = PTHREAD_COND_INITIALIZER;
	pthread_cond_t cv;
	pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
	struct timespec ts;
	struct timed_cond_case timed;
	pthread_t signaler;

	/* pthread_cond_init.html: "In cases where default condition
	 * variable attributes are appropriate, the macro
	 * PTHREAD_COND_INITIALIZER can be used to initialize condition
	 * variables that are statically allocated." */
	CHECK(pthread_cond_destroy(&stat_cv) == 0);

	CHECK(pthread_cond_init(&cv, NULL) == 0);

	/* "The pthread_cond_broadcast() function shall unblock all threads
	 * currently blocked ... The pthread_cond_signal() function shall
	 * unblock at least one ... If no threads are blocked ...
	 * pthread_cond_broadcast() and pthread_cond_signal() shall have no
	 * effect."  Nobody is blocked here, so both must simply succeed. */
	CHECK(pthread_cond_signal(&cv) == 0);
	CHECK(pthread_cond_broadcast(&cv) == 0);

	/* pthread_cond_timedwait.html: "shall be equivalent to
	 * pthread_cond_wait(), except that an error is returned if the
	 * absolute time specified by abstime passes ... before the
	 * condition cond is signaled or broadcasted".  ERRORS:
	 * "[ETIMEDOUT] The time specified by abstime to
	 * pthread_cond_timedwait() has passed."  An abstime already in the
	 * past must time out without blocking, and the clause "shall
	 * always be called with the mutex locked by the calling thread ...
	 * and shall reacquire the mutex before returning" means the mutex
	 * is held again on the ETIMEDOUT return, which the unlock proves. */
	CHECK(pthread_mutex_lock(&mtx) == 0);
	CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0);
	ts.tv_sec -= 1;
	CHECK(pthread_cond_timedwait(&cv, &mtx, &ts) == ETIMEDOUT);
	CHECK(pthread_mutex_unlock(&mtx) == 0);

	/* Registering the waiter while holding mtx forces the signaler below
	 * to run only after cond_wait has atomically released it. */
	timed.cond = &cv;
	timed.mutex = &mtx;
	CHECK(pthread_mutex_lock(&mtx) == 0);
	CHECK(pthread_create(&signaler, NULL, signal_timed_cond, &timed) == 0);
	ts.tv_sec = LLONG_MAX;
	ts.tv_nsec = 999999999L;
	CHECK(pthread_cond_timedwait(&cv, &mtx, &ts) == 0);
	CHECK(pthread_mutex_unlock(&mtx) == 0);
	CHECK(pthread_join(signaler, NULL) == 0);

	CHECK(pthread_cond_destroy(&cv) == 0);
	CHECK(pthread_mutex_destroy(&mtx) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_condattr_clock)
#include <pthread.h>
#include <time.h>

static void test_pthread_condattr_clock(void)
{
	pthread_condattr_t attr;
	clockid_t clk = (clockid_t)-1;
	int pshared = -1;

	CHECK(pthread_condattr_init(&attr) == 0);

	/* pthread_condattr_getclock.html: "The default value of the clock
	 * attribute shall refer to the system clock." */
	CHECK(pthread_condattr_getclock(&attr, &clk) == 0);
	CHECK(clk == CLOCK_REALTIME);

	/* "shall set the clock attribute in an initialized attributes
	 * object referenced by attr ... The clock attribute is the clock
	 * ID of the clock that shall be used to measure the timeout
	 * service of pthread_cond_timedwait()." */
	CHECK(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0);
	CHECK(pthread_condattr_getclock(&attr, &clk) == 0);
	CHECK(clk == CLOCK_MONOTONIC);

	/* pthread_condattr_getpshared.html: "The default value of the
	 * attribute shall be PTHREAD_PROCESS_PRIVATE."  (The
	 * process-shared attribute itself is the Thread Process-Shared
	 * Synchronization option; the default, and the round-trip to
	 * PRIVATE, are required of every implementation that supplies
	 * these two functions at all.) */
	CHECK(pthread_condattr_getpshared(&attr, &pshared) == 0);
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE);
	CHECK(pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE) == 0);

	CHECK(pthread_condattr_destroy(&attr) == 0);
}
#endif

/* ==================================================================
 * Read-write locks -- .../functions/pthread_rwlock_init.html,
 * pthread_rwlock_rdlock.html, pthread_rwlock_wrlock.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_rwlock_shared_read)
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <limits.h>

struct timed_rwlock_case {
	pthread_rwlock_t *lock;
	sem_t ready;
};

static void *release_timed_rwlock(void *argument)
{
	struct timed_rwlock_case *test = argument;
	struct timespec delay = { 0, 20000000L };
	CHECK(pthread_rwlock_rdlock(test->lock) == 0);
	CHECK(sem_post(&test->ready) == 0);
	nanosleep(&delay, NULL);
	CHECK(pthread_rwlock_unlock(test->lock) == 0);
	return NULL;
}

static void test_pthread_rwlock_shared_read(void)
{
	pthread_rwlock_t stat_rw = PTHREAD_RWLOCK_INITIALIZER;
	pthread_rwlock_t rw;
	pthread_rwlockattr_t attr;
	struct timed_rwlock_case timed;
	struct timespec extreme_future = { LLONG_MAX, 999999999L };
	pthread_t releaser;
	int pshared = -1;

	/* pthread_rwlock_init.html: "In cases where default read-write
	 * lock attributes are appropriate, the macro
	 * PTHREAD_RWLOCK_INITIALIZER can be used to initialize read-write
	 * locks that are statically allocated." */
	CHECK(pthread_rwlock_rdlock(&stat_rw) == 0);
	CHECK(pthread_rwlock_unlock(&stat_rw) == 0);
	CHECK(pthread_rwlock_destroy(&stat_rw) == 0);

	CHECK(pthread_rwlock_init(&rw, NULL) == 0);

	/* pthread_rwlock_rdlock.html: "A thread may hold multiple
	 * concurrent read locks on rwlock (that is, successfully call the
	 * pthread_rwlock_rdlock() function n times).  If so, the
	 * application shall ensure that the thread performs matching
	 * unlocks (that is, it calls the pthread_rwlock_unlock() function
	 * n times)."  That is the read lock's whole point, and it is
	 * decidable from one thread. */
	CHECK(pthread_rwlock_rdlock(&rw) == 0);
	CHECK(pthread_rwlock_rdlock(&rw) == 0);
	CHECK(pthread_rwlock_tryrdlock(&rw) == 0);

	/* pthread_rwlock_wrlock.html: "The calling thread acquires the
	 * write lock if no other thread (reader or writer) holds the
	 * read-write lock rwlock."  Read locks are held, so the
	 * non-blocking form must report the ERRORS clause "[EBUSY] The
	 * read-write lock could not be acquired for writing because it was
	 * already locked for reading or writing." */
	CHECK(pthread_rwlock_trywrlock(&rw) == EBUSY);
	CHECK(pthread_rwlock_unlock(&rw) == 0);
	CHECK(pthread_rwlock_unlock(&rw) == 0);
	CHECK(pthread_rwlock_unlock(&rw) == 0);

	timed.lock = &rw;
	CHECK(sem_init(&timed.ready, 0, 0) == 0);
	CHECK(pthread_create(&releaser, NULL, release_timed_rwlock, &timed) == 0);
	CHECK(sem_wait(&timed.ready) == 0);
	CHECK(pthread_rwlock_timedwrlock(&rw, &extreme_future) == 0);
	CHECK(pthread_rwlock_unlock(&rw) == 0);
	CHECK(pthread_join(releaser, NULL) == 0);
	CHECK(sem_destroy(&timed.ready) == 0);

	/* All reads released: the write lock is now available, and while
	 * it is held a read must report [EBUSY] in turn. */
	CHECK(pthread_rwlock_wrlock(&rw) == 0);
	CHECK(pthread_rwlock_tryrdlock(&rw) == EBUSY);
	CHECK(pthread_rwlock_unlock(&rw) == 0);
	CHECK(pthread_rwlock_destroy(&rw) == 0);

	/* pthread_rwlockattr_getpshared.html: "The default value of the
	 * process-shared attribute shall be PTHREAD_PROCESS_PRIVATE." */
	CHECK(pthread_rwlockattr_init(&attr) == 0);
	CHECK(pthread_rwlockattr_getpshared(&attr, &pshared) == 0);
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE);
	CHECK(pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE) == 0);
	CHECK(pthread_rwlockattr_destroy(&attr) == 0);
}
#endif

/* ==================================================================
 * Barriers -- .../functions/pthread_barrier_init.html,
 * pthread_barrier_wait.html  (Barriers option, _POSIX_BARRIERS)
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_barrier_serial_thread)
#include <pthread.h>
#include <errno.h>

static pthread_barrier_t bar_b;
static int bar_serial;

static void *bar_start(void *arg)
{
	int rc = pthread_barrier_wait(&bar_b);

	(void)arg;
	if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
		bar_serial++;
	else
		CHECK(rc == 0);
	return NULL;
}

static void test_pthread_barrier_serial_thread(void)
{
	pthread_t th;
	int rc;

	/* pthread_barrier_init.html: ERRORS "[EINVAL] The value specified
	 * by count is equal to zero." */
	CHECK(pthread_barrier_init(&bar_b, NULL, 0) == EINVAL);

	/* "shall allocate any resources required to use the barrier ...
	 * The count argument specifies the number of threads that must
	 * call pthread_barrier_wait() before any of them successfully
	 * return from the call." */
	CHECK(pthread_barrier_init(&bar_b, NULL, 2) == 0);
	CHECK(pthread_create(&th, NULL, bar_start, NULL) == 0);

	/* pthread_barrier_wait.html: "When the required number of threads
	 * have called pthread_barrier_wait() specifying the barrier, the
	 * constant PTHREAD_BARRIER_SERIAL_THREAD shall be returned to one
	 * unspecified thread and zero shall be returned to each of the
	 * remaining threads." */
	rc = pthread_barrier_wait(&bar_b);
	if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
		bar_serial++;
	else
		CHECK(rc == 0);

	CHECK(pthread_join(th, NULL) == 0);

	/* "its value shall be distinct from any other value returned by
	 * pthread_barrier_wait()" -- exactly one of the two saw it. */
	CHECK(bar_serial == 1);
	CHECK(PTHREAD_BARRIER_SERIAL_THREAD != 0);

	CHECK(pthread_barrier_destroy(&bar_b) == 0);
}
#endif

/* ==================================================================
 * Spin locks -- .../functions/pthread_spin_init.html,
 * pthread_spin_lock.html  (Spin Locks option, _POSIX_SPIN_LOCKS)
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_spin_lock_trylock)
#include <pthread.h>
#include <errno.h>

static void test_pthread_spin_lock_trylock(void)
{
	pthread_spinlock_t lock;

	/* pthread_spin_init.html: "shall allocate any resources required
	 * to use the spin lock referenced by lock and initialize the lock
	 * to an unlocked state." */
	CHECK(pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE) == 0);

	/* pthread_spin_lock.html: "The calling thread shall acquire the
	 * lock if it is not held by another thread."  Then, still holding
	 * it, ERRORS: "[EBUSY] A thread currently holds the lock."  (The
	 * blocking relock is explicitly undefined -- "The results are
	 * undefined if the calling thread holds the lock at the time the
	 * call is made" -- so only trylock is asserted from the owner.) */
	CHECK(pthread_spin_lock(&lock) == 0);
	CHECK(pthread_spin_trylock(&lock) == EBUSY);
	CHECK(pthread_spin_unlock(&lock) == 0);

	CHECK(pthread_spin_trylock(&lock) == 0);
	CHECK(pthread_spin_unlock(&lock) == 0);

	CHECK(pthread_spin_destroy(&lock) == 0);
}
#endif

/* ==================================================================
 * One-time initialization -- .../functions/pthread_once.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_once_runs_once)
#include <pthread.h>

static pthread_once_t once_ctl = PTHREAD_ONCE_INIT;
static int once_calls;

static void once_init(void)
{
	once_calls++;
}

static void test_pthread_once_runs_once(void)
{
	/* "The first call to pthread_once() by any thread in a process,
	 * with a given once_control, shall call the init_routine with no
	 * arguments.  Subsequent calls of pthread_once() with the same
	 * once_control shall not call the init_routine.  On return from
	 * pthread_once(), init_routine shall have completed." */
	CHECK(once_calls == 0);
	CHECK(pthread_once(&once_ctl, once_init) == 0);
	CHECK(once_calls == 1);
	CHECK(pthread_once(&once_ctl, once_init) == 0);
	CHECK(once_calls == 1);
	CHECK(pthread_once(&once_ctl, once_init) == 0);
	CHECK(once_calls == 1);
}
#endif

/* ==================================================================
 * Thread-specific data -- .../functions/pthread_key_create.html,
 * pthread_getspecific.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_specific_key)
#include <pthread.h>

static int tsd_destructor_calls;

static void tsd_destroy(void *value)
{
	(void)value;
	tsd_destructor_calls++;
}

static void *tsd_start(void *arg)
{
	pthread_key_t key = *(pthread_key_t *)arg;

	/* "Upon thread creation, the value NULL shall be associated with
	 * all defined keys in the new thread." */
	CHECK(pthread_getspecific(key) == NULL);
	CHECK(pthread_setspecific(key, (void *)&tsd_destructor_calls) == 0);
	CHECK(pthread_getspecific(key) == (void *)&tsd_destructor_calls);

	/* "At thread exit, if a key value has a non-NULL destructor
	 * pointer, and the thread has a non-NULL value associated with
	 * that key, the value of the key is set to NULL, and then the
	 * function pointed to is called". */
	return NULL;
}

static void test_pthread_specific_key(void)
{
	pthread_key_t key;
	pthread_t th;

	/* "Upon key creation, the value NULL shall be associated with the
	 * new key in all active threads." */
	CHECK(pthread_key_create(&key, tsd_destroy) == 0);
	CHECK(pthread_getspecific(key) == NULL);

	/* "the values bound to the key by pthread_setspecific() are
	 * maintained on a per-thread basis": the value this thread binds
	 * must not be visible to, or clobbered by, the other one. */
	CHECK(pthread_setspecific(key, (void *)&key) == 0);
	CHECK(pthread_getspecific(key) == (void *)&key);

	CHECK(pthread_create(&th, NULL, tsd_start, &key) == 0);
	CHECK(pthread_join(th, NULL) == 0);

	CHECK(pthread_getspecific(key) == (void *)&key);
	CHECK(tsd_destructor_calls == 1);

	/* pthread_key_delete.html: "shall delete a thread-specific data
	 * key previously returned by pthread_key_create() ... It is the
	 * responsibility of the application to free any application
	 * storage".  No destructor runs for the deleting thread's own
	 * still-bound value: "the destructor function ... shall not be
	 * invoked". */
	CHECK(pthread_key_delete(key) == 0);
	CHECK(tsd_destructor_calls == 1);
}
#endif

/* ==================================================================
 * Cancellation -- .../functions/pthread_cancel.html,
 * pthread_setcancelstate.html, pthread_cleanup_push.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_cancel_cleanup)
#include <pthread.h>
#include <semaphore.h>

/* Only pthread_cancel(), pthread_setcancelstate(), and
 * pthread_setcanceltype() are required to be async-cancel-safe.  Keep the
 * asynchronous redirect probe out of every other POSIX interface: cancelling
 * inside one of those has undefined behaviour and can strand that interface's
 * private state instead of measuring context redirection.  This direct,
 * alertable NT wait still leaves the target suspended inside a syscall when
 * pthread_cancel() redirects it, which is the boundary the probe needs. */
typedef int NTSTATUS;
typedef long long LARGE_INTEGER;
#ifdef __i386__
#define NTAPI __attribute__((stdcall))
#else
#define NTAPI
#endif
NTSTATUS NTAPI NtDelayExecution(unsigned char, LARGE_INTEGER *);

static int cleanup_ran;
static volatile int async_cleanup_ran;
static sem_t async_cancel_ready;
static sem_t async_cancel_returned;
static sem_t defer_cancel_ready;
static sem_t defer_cancel_release;
static volatile int defer_cleanup_ran;
static volatile int defer_operation_returned;

/* Internal hooks used here to deterministically put a target in the same
 * cancellation-deferred region which protects spicule's state locks. */
void __pthread_cancel_defer_enter(void);
void __pthread_cancel_defer_leave(void);

static void cleanup_handler(void *arg)
{
	CHECK(arg == (void *)&cleanup_ran);
	cleanup_ran++;
}

static void *cancel_start(void *arg)
{
	int old = -1;

	(void)arg;
	/* pthread_setcancelstate.html: "The cancelability state and type
	 * of any newly created threads, including the thread in which
	 * main() was first invoked, shall be PTHREAD_CANCEL_ENABLE and
	 * PTHREAD_CANCEL_DEFERRED respectively." */
	CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old) == 0);
	CHECK(old == PTHREAD_CANCEL_ENABLE);
	CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old) == 0);
	CHECK(old == PTHREAD_CANCEL_DEFERRED);

	/* pthread_cleanup_push.html: "shall push the specified
	 * cancellation cleanup handler routine onto the calling thread's
	 * cancellation cleanup stack." */
	pthread_cleanup_push(cleanup_handler, (void *)&cleanup_ran);

	/* pthread_cancel.html: "When the cancellation is acted on, the
	 * cancellation cleanup handlers for thread shall be called."
	 * pthread_testcancel.html: "shall create a cancellation point in
	 * the calling thread."  Loop so the request cannot be missed. */
	for (;;)
		pthread_testcancel();

	pthread_cleanup_pop(0);
	return NULL;
}

static void async_cleanup_handler(void *arg)
{
	(void)arg;
	if (sem_wait(&async_cancel_returned) == 0)
		async_cleanup_ran++;
}

static void *async_cancel_start(void *arg)
{
	LARGE_INTEGER delay = -10000; /* 1 ms, in relative 100 ns units */
	(void)arg;
	CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
	pthread_cleanup_push(async_cleanup_handler, NULL);
	CHECK(sem_post(&async_cancel_ready) == 0);
	for (;;)
		NtDelayExecution(1, &delay);
	pthread_cleanup_pop(0);
	return NULL;
}

enum defer_cancel_mode {
	DEFER_CANCEL_REMOTE,
	DEFER_CANCEL_SELF,
	DEFER_CANCEL_ENABLE,
	DEFER_CANCEL_TYPE
};

static void defer_cleanup_handler(void *arg)
{
	(void)arg;
	defer_cleanup_ran++;
}

static void *defer_cancel_start(void *arg)
{
	enum defer_cancel_mode mode = (enum defer_cancel_mode)(long long)arg;

	if (mode == DEFER_CANCEL_ENABLE) {
		/* Both auto-delivery checks below (pthread_setcancelstate()'s own
		 * and __pthread_cancel_defer_leave()'s) require ASYNCHRONOUS
		 * type; without setting it here the state stayed DEFERRED (the
		 * thread's default), so a pending request could never be
		 * delivered anywhere in this function -- there is no explicit
		 * cancellation point after the re-enable below -- and this
		 * mode's CHECK(0 && "...") was unreachable-in-reverse: always
		 * hit, regardless of any library behavior. */
		CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
		CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
	} else if (mode == DEFER_CANCEL_TYPE)
		CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0);
	else
		CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);

	pthread_cleanup_push(defer_cleanup_handler, NULL);
	__pthread_cancel_defer_enter();
	CHECK(sem_post(&defer_cancel_ready) == 0);
	if (mode == DEFER_CANCEL_REMOTE) {
		CHECK(sem_wait(&defer_cancel_release) == 0);
	} else {
		CHECK(pthread_cancel(pthread_self()) == 0);
		if (mode == DEFER_CANCEL_ENABLE)
			CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
		else if (mode == DEFER_CANCEL_TYPE)
			CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
		defer_operation_returned++;
	}
	__pthread_cancel_defer_leave();
	CHECK(0 && "pending asynchronous cancellation was not delivered");
	pthread_cleanup_pop(0);
	return NULL;
}

static void check_deferred_cancel(enum defer_cancel_mode mode)
{
	pthread_t th;
	void *result = NULL;

	defer_cleanup_ran = 0;
	defer_operation_returned = 0;
	CHECK(sem_init(&defer_cancel_ready, 0, 0) == 0);
	CHECK(sem_init(&defer_cancel_release, 0, 0) == 0);
	CHECK(pthread_create(&th, NULL, defer_cancel_start,
		(void *)(long long)mode) == 0);
	CHECK(sem_wait(&defer_cancel_ready) == 0);
	if (mode == DEFER_CANCEL_REMOTE) {
		CHECK(pthread_cancel(th) == 0);
		CHECK(defer_cleanup_ran == 0);
		CHECK(sem_post(&defer_cancel_release) == 0);
	}
	CHECK(pthread_join(th, &result) == 0);
	CHECK(result == PTHREAD_CANCELED);
	CHECK(defer_cleanup_ran == 1);
	CHECK(defer_operation_returned == (mode == DEFER_CANCEL_REMOTE ? 0 : 1));
	CHECK(sem_destroy(&defer_cancel_ready) == 0);
	CHECK(sem_destroy(&defer_cancel_release) == 0);
}

static void test_pthread_cancel_cleanup(void)
{
	pthread_t th;
	void *result = NULL;

	CHECK(pthread_create(&th, NULL, cancel_start, NULL) == 0);
	CHECK(pthread_cancel(th) == 0);
	CHECK(pthread_join(th, &result) == 0);

	/* pthread_join.html: "if the target thread was canceled, then
	 * PTHREAD_CANCELED shall be placed in *value_ptr." */
	CHECK(result == PTHREAD_CANCELED);
	CHECK(cleanup_ran == 1);

	/* A cancellation point may consume an asynchronous request while
	 * pthread_cancel() is preparing its suspension fallback.  The fallback
	 * must not redirect a cleanup handler which has already started. */
	async_cleanup_ran = 0;
	CHECK(sem_init(&async_cancel_ready, 0, 0) == 0);
	CHECK(sem_init(&async_cancel_returned, 0, 0) == 0);
	CHECK(pthread_create(&th, NULL, async_cancel_start, NULL) == 0);
	CHECK(sem_wait(&async_cancel_ready) == 0);
	CHECK(pthread_cancel(th) == 0);
	CHECK(sem_post(&async_cancel_returned) == 0);
	CHECK(pthread_join(th, &result) == 0);
	CHECK(result == PTHREAD_CANCELED);
	CHECK(async_cleanup_ran > 0);
	CHECK(sem_destroy(&async_cancel_ready) == 0);
	CHECK(sem_destroy(&async_cancel_returned) == 0);

	/* Delivery is postponed until the outer state transaction commits.
	 * Cover a remote redirect and all three current-thread transitions:
	 * self cancellation, enabling a pending request, and making a pending
	 * request asynchronous.  Cleanup proves the request is delivered once. */
	check_deferred_cancel(DEFER_CANCEL_REMOTE);
	check_deferred_cancel(DEFER_CANCEL_SELF);
	check_deferred_cancel(DEFER_CANCEL_ENABLE);
	check_deferred_cancel(DEFER_CANCEL_TYPE);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_cancel_huge_timeouts)
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <limits.h>

enum huge_wait_kind {
	HUGE_NANOSLEEP,
	HUGE_CLOCK_RELATIVE,
	HUGE_CLOCK_ABSOLUTE
};

static volatile int huge_wait_returned;

static void *huge_wait_start(void *argument)
{
	enum huge_wait_kind kind = (enum huge_wait_kind)(long long)argument;
	struct timespec request = { LLONG_MAX, 999999999L };
	int result;

	if (kind == HUGE_NANOSLEEP)
		result = nanosleep(&request, NULL);
	else if (kind == HUGE_CLOCK_RELATIVE)
		result = clock_nanosleep(CLOCK_MONOTONIC, 0, &request, NULL);
	else
		result = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME,
			&request, NULL);
	huge_wait_returned = 1;
	return (void *)(long long)(result + 2);
}

static void test_pthread_cancel_huge_timeouts(void)
{
	int kind;
	for (kind = HUGE_NANOSLEEP; kind <= HUGE_CLOCK_ABSOLUTE; kind++) {
		pthread_t thread;
		void *result = NULL;
		int i;
		huge_wait_returned = 0;
		CHECK(pthread_create(&thread, NULL, huge_wait_start,
			(void *)(long long)kind) == 0);
		/* __alertable_delay() no longer marks an unsafe interval (see
		 * src/unistd/sleep.c), so there is nothing left to poll for
		 * "still waiting". A generous yield budget serves the same
		 * purpose: the pre-fix multiplication wraps before entering
		 * the wait, making these valid huge waits return almost
		 * immediately instead of actually blocking, and this budget
		 * is far larger than any such immediate return would need to
		 * set the flag below. */
		for (i = 0; i < 1000000 && !huge_wait_returned; i++)
			sched_yield();
		CHECK(!huge_wait_returned);
		CHECK(pthread_cancel(thread) == 0);
		CHECK(pthread_join(thread, &result) == 0);
		CHECK(result == PTHREAD_CANCELED);
	}
}
#endif

/* ==================================================================
 * Thread scheduling and concurrency --
 * .../functions/pthread_getschedparam.html,
 * pthread_setschedprio.html, pthread_getcpuclockid.html,
 * pthread_getconcurrency.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_schedparam_self)
#include <pthread.h>
#include <sched.h>

static void test_pthread_schedparam_self(void)
{
	struct sched_param param;
	int policy = -1;

	/* pthread_getschedparam.html: "shall get the scheduling policy and
	 * parameters of individual threads ... For SCHED_FIFO and
	 * SCHED_RR, the only required member of the sched_param structure
	 * is the priority sched_priority."  (Thread Execution Scheduling
	 * option; the round-trip below asserts only that what was read
	 * back can be written back, which is required whenever the two
	 * functions exist at all.) */
	CHECK(pthread_getschedparam(pthread_self(), &policy, &param) == 0);
	CHECK(policy == SCHED_FIFO || policy == SCHED_RR || policy == SCHED_OTHER
	      || policy == SCHED_SPORADIC);
	CHECK(param.sched_priority >= sched_get_priority_min(policy));
	CHECK(param.sched_priority <= sched_get_priority_max(policy));
	CHECK(pthread_setschedparam(pthread_self(), policy, &param) == 0);

	/* pthread_setschedprio.html: "shall set the scheduling priority
	 * for the thread whose thread ID is given by thread to the value
	 * given by prio." */
	CHECK(pthread_setschedprio(pthread_self(), param.sched_priority) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_concurrency_default)
#include <pthread.h>
#include <errno.h>

static void test_pthread_concurrency_default(void)
{
	/* pthread_getconcurrency.html: "shall return the value set by a
	 * previous call to pthread_setconcurrency().  If ...
	 * pthread_setconcurrency() was not previously called, this
	 * function shall return zero to indicate that the implementation
	 * is maintaining the concurrency level."  "A call to
	 * pthread_setconcurrency() shall inform the implementation of its
	 * desired concurrency level ... The implementation is free to
	 * ignore this."  So the only assertable behaviour is the
	 * read-back, and the [EINVAL] for a negative level. */
	CHECK(pthread_getconcurrency() == 0);
	CHECK(pthread_setconcurrency(4) == 0);
	CHECK(pthread_getconcurrency() == 4);
	CHECK(pthread_setconcurrency(-1) == EINVAL);
	CHECK(pthread_getconcurrency() == 4);
	CHECK(pthread_setconcurrency(0) == 0);
	CHECK(pthread_getconcurrency() == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_getcpuclockid)
#include <pthread.h>
#include <time.h>

static void test_pthread_getcpuclockid(void)
{
	clockid_t clk = (clockid_t)-1;
	struct timespec a, b;

	/* pthread_getcpuclockid.html: "shall return in clock_id the clock
	 * ID of the CPU-time clock of the thread specified by thread_id,
	 * if the thread specified by thread_id exists."  (Thread CPU-Time
	 * Clocks option.)  The clock must then be usable with the
	 * <time.h> clock functions, and CPU time is monotonically
	 * non-decreasing. */
	CHECK(pthread_getcpuclockid(pthread_self(), &clk) == 0);
	CHECK(clock_gettime(clk, &a) == 0);
	CHECK(clock_gettime(clk, &b) == 0);
	CHECK(b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec));
}
#endif

/* ==================================================================
 * Per-thread signal interfaces.  POSIX declares both in <signal.h>, not
 * <pthread.h>.  The runtime keeps masks and thread-directed pending signals
 * in TLS, inherits the creator's mask, and delivers pthread_kill() through a
 * native APC on the selected thread.
 * .../functions/pthread_kill.html, pthread_sigmask.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_pthread_sigmask_roundtrip)
#include <signal.h>

static void test_pthread_sigmask_roundtrip(void)
{
	sigset_t block, old, now;

	/* pthread_sigmask.html: "shall examine or change (or both) the
	 * calling thread's signal mask ... the behavior ... shall be
	 * equivalent to sigprocmask(), without the restriction that the
	 * call be made in a single-threaded process." */
	CHECK(sigemptyset(&block) == 0);
	CHECK(sigaddset(&block, SIGUSR1) == 0);
	CHECK(pthread_sigmask(SIG_BLOCK, &block, &old) == 0);

	CHECK(pthread_sigmask(SIG_BLOCK, NULL, &now) == 0);
	CHECK(sigismember(&now, SIGUSR1) == 1);

	/* "If the argument set is a null pointer, the value of the
	 * argument how is not significant and the thread's signal mask
	 * shall be unchanged". */
	CHECK(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0);
	CHECK(pthread_sigmask(SIG_BLOCK, NULL, &now) == 0);
	CHECK(sigismember(&now, SIGUSR1) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_pthread_kill_signal_zero)
#include <signal.h>
#include <pthread.h>
#include <errno.h>

static void test_pthread_kill_signal_zero(void)
{
	/* pthread_kill.html: "shall request that a signal be delivered to
	 * the specified thread.  As in kill(), if sig is zero, error
	 * checking is performed but no signal is actually sent." */
	CHECK(pthread_kill(pthread_self(), 0) == 0);

	/* ERRORS: "[EINVAL] The value of the sig argument is an invalid or
	 * unsupported signal number." */
	CHECK(pthread_kill(pthread_self(), -1) == EINVAL);
}
#endif

int main(void)
{
	/* Every case in this file is fenced: <pthread.h> does not exist in
	 * this tree, so there is nothing here that can run today.  The
	 * fences are the coverage; tools/test-policy.py --pedantic is what
	 * re-decides each one, and the day include/pthread.h appears the
	 * probe stops agreeing and the fence has to be re-adjudicated. */
	if (!fails) printf("posix-pthread: all tests passed\n");
	return fails != 0;
}
