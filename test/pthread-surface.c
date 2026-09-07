/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
/* clock_gettime()/CLOCK_REALTIME are feature-test gated in
 * include/time.h; same define most other tests in test/ already carry for
 * the same reason (see test/posix-glob.c's comment on this exact
 * define). */
#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <stdio.h>
#include <time.h>

static int fails;

#define CHECK(condition) do { \
	if (!(condition)) { \
		fails++; \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
	} \
} while (0)

static void test_atfork(void)
{
	int i;
	/* Cross the initial eight-handler allocation so the checked
	 * collection-growth path is part of the public integration test. */
	for (i = 0; i < 10; i++) CHECK(pthread_atfork(0, 0, 0) == 0);
}

static void test_barrier_attributes(void)
{
	pthread_barrierattr_t attr;
	int pshared = -1;

	CHECK(pthread_barrierattr_init(&attr) == 0);
	CHECK(pthread_barrierattr_getpshared(&attr, &pshared) == 0);
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE);
	CHECK(pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE) == 0);
	CHECK(pthread_barrierattr_destroy(&attr) == 0);
}

static void test_mutex_extensions(void)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t mutex;
	struct timespec now;
	int ceiling = -1, old_ceiling = -1;
	int protocol = -1, pshared = -1, robust = -1;

	CHECK(pthread_mutexattr_init(&attr) == 0);
	CHECK(pthread_mutexattr_getpshared(&attr, &pshared) == 0);
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE);
	CHECK(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE) == 0);
	CHECK(pthread_mutexattr_getprotocol(&attr, &protocol) == 0);
	CHECK(protocol == PTHREAD_PRIO_NONE);
	CHECK(pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE) == 0);
	CHECK(pthread_mutexattr_getprioceiling(&attr, &ceiling) == 0);
	CHECK(pthread_mutexattr_setprioceiling(&attr, ceiling) == 0);
	CHECK(pthread_mutexattr_getrobust(&attr, &robust) == 0);
	CHECK(robust == PTHREAD_MUTEX_STALLED);
	CHECK(pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_STALLED) == 0);

	CHECK(pthread_mutex_init(&mutex, &attr) == 0);
	CHECK(pthread_mutex_getprioceiling(&mutex, &old_ceiling) == 0);
	CHECK(old_ceiling == ceiling);
	CHECK(pthread_mutex_setprioceiling(&mutex, ceiling, &old_ceiling) == 0);
	CHECK(old_ceiling == ceiling);
	CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
	CHECK(pthread_mutex_timedlock(&mutex, &now) == 0);
	CHECK(pthread_mutex_unlock(&mutex) == 0);
	CHECK(pthread_mutex_consistent(&mutex) == EINVAL);
	CHECK(pthread_mutex_destroy(&mutex) == 0);
	CHECK(pthread_mutexattr_destroy(&attr) == 0);
}

static void test_condition_validation(void)
{
	CHECK(pthread_cond_wait(0, 0) == EINVAL);
}

static void test_rwlock_timed_acquisition(void)
{
	pthread_rwlock_t lock;
	struct timespec now;

	CHECK(pthread_rwlock_init(&lock, 0) == 0);
	CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
	CHECK(pthread_rwlock_timedrdlock(&lock, &now) == 0);
	CHECK(pthread_rwlock_unlock(&lock) == 0);
	CHECK(pthread_rwlock_timedwrlock(&lock, &now) == 0);
	CHECK(pthread_rwlock_unlock(&lock) == 0);
	CHECK(pthread_rwlock_destroy(&lock) == 0);
}

/* XBD 2.3 Error Numbers: "For each thread of a process, the value of
 * errno shall not be affected by function calls or assignments to
 * errno by other threads."  src/internal/errno.c already implements
 * this as a real `static __thread int __errno_val` (cited there
 * against the same clause plus C11 7.5p2); this is the live,
 * two-thread proof that the promise holds end to end rather than just
 * at the storage-class level -- a thread's own errno must read back
 * unchanged across a sibling thread's own concurrent errno write, and
 * a freshly created thread must not see a value the creator set in
 * its own errno beforehand. */
struct errno_isolation_case {
	sem_t child_set;
	sem_t parent_checked;
	int child_saw_parent_value;
};

static void *errno_isolation_thread(void *argument)
{
	struct errno_isolation_case *c = argument;

	/* Distinct per-thread storage, not a cell shared with the creator:
	 * a brand new thread must not read back the sentinel the parent
	 * set in its own errno before creating this one. */
	c->child_saw_parent_value = (errno == EACCES);

	errno = ENOMEM;
	CHECK(errno == ENOMEM);
	CHECK(sem_post(&c->child_set) == 0);

	/* Held here, still with errno == ENOMEM, while the parent checks
	 * that this write left its own errno untouched. */
	CHECK(sem_wait(&c->parent_checked) == 0);
	return NULL;
}

static void test_errno_thread_isolation(void)
{
#ifdef _SPICULE_NATIVE_BUILD
	/* fuzz/ntstubs.c deliberately refuses NtCreateThreadEx: the native
	 * sanitizer harness has no NT thread/TEB substrate to test against. */
	printf("note: native sanitizer shim has no NT thread substrate; errno isolation skipped\n");
#else
	struct errno_isolation_case c;
	pthread_t th;

	errno = EACCES;
	CHECK(sem_init(&c.child_set, 0, 0) == 0);
	CHECK(sem_init(&c.parent_checked, 0, 0) == 0);
	c.child_saw_parent_value = -1;

	CHECK(pthread_create(&th, NULL, errno_isolation_thread, &c) == 0);

	/* Blocks until the child has both read its own initial errno and
	 * overwritten it with ENOMEM, so the checks below are ordered
	 * after both. */
	CHECK(sem_wait(&c.child_set) == 0);

	CHECK(c.child_saw_parent_value == 0);
	/* The child's assignment to its own errno must not leak back:
	 * this thread's errno is still exactly what it set before
	 * pthread_create(), not the child's ENOMEM. */
	CHECK(errno == EACCES);

	CHECK(sem_post(&c.parent_checked) == 0);
	CHECK(pthread_join(th, NULL) == 0);
	/* The join happens-after the child's own errno write; this
	 * thread's errno must still be untouched by it. */
	CHECK(errno == EACCES);

	CHECK(sem_destroy(&c.child_set) == 0);
	CHECK(sem_destroy(&c.parent_checked) == 0);
#endif
}

/* A REAL, CONFIRMED bug distinct from test_errno_thread_isolation() above:
 * pthread_mutex_destroy() and sem_destroy() (plus several other release
 * paths across pthread_cond.c/pthread_rwlock.c/pthread_sync.c/
 * pthread_tsd.c/mqueue.c) used to release their internal semaphore/event
 * handle via plat_fd.h's generic __plat_close() instead of the sync-domain
 * __plat_sync_close() (see plat_thread.h's own __plat_sync_close() banner).
 * On the Linux backend that handle is a raw mmap(2)'d pointer, not a boxed
 * fd+1, so that close(2) truncated it to a bogus "fd" and clobbered the
 * caller's own errno with EBADF on every one of these teardown paths --
 * confirmed the same way test_errno_thread_isolation() confirms
 * pthread_join()'s: errno must still read back exactly what was set
 * beforehand, immediately after a successful teardown call that has no
 * business touching errno at all.
 *
 * Deliberately does not exercise pthread_cond_wait()/pthread_cond_timedwait()
 * here even though cond_wait()'s per-wait semaphore hits the very same
 * release path: a real, separate, pre-existing bug (cond_wait() calls
 * pthread_mutex_unlock() while still holding __plat_fast_lock(), which
 * pthread_mutex_unlock() also acquires -- a self-deadlock on this
 * non-recursive process-wide spinlock) hangs both forever on this backend,
 * confirmed independently of this fix and disclosed, not addressed, here. */
static void test_errno_sync_close_isolation(void)
{
	pthread_mutex_t mutex;
	sem_t sem;

	errno = EACCES;
	CHECK(pthread_mutex_init(&mutex, 0) == 0);
	CHECK(pthread_mutex_destroy(&mutex) == 0);
	CHECK(errno == EACCES);

	errno = EACCES;
	CHECK(sem_init(&sem, 0, 0) == 0);
	CHECK(sem_destroy(&sem) == 0);
	CHECK(errno == EACCES);
}

int main(void)
{
	test_atfork();
	test_barrier_attributes();
	test_mutex_extensions();
	test_condition_validation();
	test_rwlock_timed_acquisition();
	test_errno_thread_isolation();
	test_errno_sync_close_isolation();
	return fails != 0;
}
