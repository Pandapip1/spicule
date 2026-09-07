/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Coverage fences for the POSIX Realtime option groups: semaphores,
 * message queues, asynchronous I/O, per-process timers, and process
 * scheduling.  Their formerly absent fences stay here as required PASS
 * assertions now that each interface family exists.  POSIX.1-2017
 * (IEEE Std 1003.1-2017, The
 * Open Group Base Specifications Issue 7, 2018 Edition), served at
 * https://pubs.opengroup.org/onlinepubs/9699919799/ .  Clause text was
 * read from Ubuntu's manpages-posix-dev 2017a-2, whose pages carry that
 * edition's COPYRIGHT verbatim; pubs.opengroup.org is unreachable here.
 *
 * ==================== why these are one file =========================
 *
 * The same name-level cross-index that found <pthread.h> (see
 * test/posix-pthread.c's banner: 1190 interfaces from 882 function
 * pages, 364 with no mention anywhere in the test/ tree) puts these five
 * groups together for a reason that is not just their original absence.  They are
 * the option groups an NT libc has the most obvious machinery for and
 * the least excuse to skip: NT has real semaphore objects, real
 * overlapped I/O with completion notification, and real waitable
 * timers.  Keeping the original clauses as PASS assertions makes those
 * interfaces unable to disappear silently again.
 *
 * Counts from that index: <semaphore.h> 10 interfaces, <mqueue.h> 10,
 * <aio.h> 8, the timer_* family 5, the missing <sched.h> half 5.
 *
 * `tools/test-policy.py --pedantic` re-decides every fence and remains
 * the authority: an interface regression turns a required PASS into a
 * build or runtime policy failure instead of making the old gap silent.
 * The XSI IPC group (<sys/ipc.h> / <sys/shm.h> / <sys/msg.h> /
 * <sys/sem.h>) is out of scope here; it is fenced separately.
 */

#include <stdio.h>

#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ==================================================================
 * Unnamed semaphores -- .../functions/sem_init.html,
 * sem_trywait.html (which also specifies sem_wait/sem_timedwait),
 * sem_post.html, sem_getvalue.html, sem_destroy.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_realtime_sem_init_count)
#include <semaphore.h>
#include <errno.h>

static void test_posix_realtime_sem_init_count(void)
{
	sem_t sem;
	int value = -1;

	/* sem_init.html: "shall initialize the unnamed semaphore referred
	 * to by sem.  The value of the initialized semaphore shall be
	 * value." */
	CHECK(sem_init(&sem, 0, 2) == 0);

	/* sem_getvalue.html: "shall update the location referenced by the
	 * sval argument to have the value of the semaphore referenced by
	 * sem without affecting the state of the semaphore." */
	CHECK(sem_getvalue(&sem, &value) == 0);
	CHECK(value == 2);

	/* sem_trywait.html: "The sem_wait() function shall lock the
	 * semaphore referenced by sem by performing a semaphore lock
	 * operation on that semaphore ... Upon successful return, the
	 * state of the semaphore shall be locked and shall remain locked
	 * until sem_post() is executed". */
	CHECK(sem_wait(&sem) == 0);
	CHECK(sem_getvalue(&sem, &value) == 0);
	CHECK(value == 1);

	/* "The sem_trywait() function shall lock the semaphore referenced
	 * by sem only if the semaphore is currently not locked; that is,
	 * if the semaphore value is currently positive."  It is 1, so
	 * this must succeed and take it to zero. */
	CHECK(sem_trywait(&sem) == 0);
	CHECK(sem_getvalue(&sem, &value) == 0);
	CHECK(value == 0);

	/* Now zero: "Otherwise, it shall not lock the semaphore", with
	 * ERRORS "[EAGAIN] The semaphore was already locked, so it cannot
	 * be immediately locked by the sem_trywait() operation". */
	CHECK(sem_trywait(&sem) == -1);
	CHECK(errno == EAGAIN);

	/* sem_post.html: "If the semaphore value resulting from this
	 * operation is positive, then no threads were blocked waiting for
	 * the semaphore to become unlocked; the semaphore value is simply
	 * incremented." */
	CHECK(sem_post(&sem) == 0);
	CHECK(sem_post(&sem) == 0);
	CHECK(sem_getvalue(&sem, &value) == 0);
	CHECK(value == 2);

	/* sem_destroy.html: "shall destroy the unnamed semaphore indicated
	 * by sem.  Only a semaphore that was created using sem_init() may
	 * be destroyed using sem_destroy()". */
	CHECK(sem_destroy(&sem) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_sem_timedwait_etimedout)
#include <semaphore.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

static sem_t *timed_sem_to_post;

static void *post_timed_sem(void *unused)
{
	struct timespec delay = { 0, 20000000L };
	(void)unused;
	nanosleep(&delay, NULL);
	CHECK(sem_post(timed_sem_to_post) == 0);
	return NULL;
}

static void test_posix_realtime_sem_timedwait_etimedout(void)
{
	sem_t sem;
	struct timespec ts;
	pthread_t poster;

	CHECK(sem_init(&sem, 0, 0) == 0);

	/* sem_timedwait.html: "shall lock the semaphore referenced by sem
	 * as in the sem_wait() function.  However, if the semaphore cannot
	 * be locked without waiting for another process or thread to
	 * unlock the semaphore by performing a sem_post() function, this
	 * wait shall be terminated when the specified timeout expires."
	 * ERRORS: "[ETIMEDOUT] The semaphore could not be locked before
	 * the specified timeout expired."  The timeout "shall be based on
	 * the CLOCK_REALTIME clock" and is absolute, so one already in the
	 * past must fail without blocking. */
	CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0);
	ts.tv_sec -= 1;
	CHECK(sem_timedwait(&sem, &ts) == -1);
	CHECK(errno == ETIMEDOUT);

	/* And with a value available, the same call must succeed rather
	 * than consult the (expired) timeout at all: "If the semaphore can
	 * be locked immediately, the value of abstime shall not be
	 * checked." */
	CHECK(sem_post(&sem) == 0);
	CHECK(sem_timedwait(&sem, &ts) == 0);

	/* Force the timeout conversion before another thread makes the
	 * semaphore available.  LLONG_MAX used to wrap to a past deadline. */
	timed_sem_to_post = &sem;
	CHECK(pthread_create(&poster, NULL, post_timed_sem, NULL) == 0);
	ts.tv_sec = LLONG_MAX;
	ts.tv_nsec = 999999999L;
	CHECK(sem_timedwait(&sem, &ts) == 0);
	CHECK(pthread_join(poster, NULL) == 0);

	CHECK(sem_destroy(&sem) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_sem_timedwait_remote_signal_eintr)
#include <semaphore.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static volatile sig_atomic_t sem_interrupt_seen;

static void sem_interrupt_handler(int signo)
{
	(void)signo;
	sem_interrupt_seen = 1;
}

static void test_posix_realtime_sem_timedwait_remote_signal_eintr(void)
{
	struct sigaction action;
	struct timespec deadline, settle = { 0, 100000000L };
	sem_t sem;
	pid_t child;
	int ready[2], status;
	char byte;

	if (sem_init(&sem, 0, 0) != 0) {
		CHECK(0);
		return;
	}
	if (pipe(ready) != 0) {
		CHECK(0);
		sem_destroy(&sem);
		return;
	}
	child = fork();
	if (child < 0) {
		CHECK(0);
		close(ready[0]);
		close(ready[1]);
		sem_destroy(&sem);
		return;
	}
	if (child == 0) {
		close(ready[0]);
		memset(&action, 0, sizeof action);
		action.sa_handler = sem_interrupt_handler;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGUSR1, &action, NULL) != 0 ||
		    write(ready[1], "x", 1) != 1 ||
		    clock_gettime(CLOCK_REALTIME, &deadline) != 0)
			_exit(2);
		close(ready[1]);
		deadline.tv_sec += 3;
		errno = 0;
		if (sem_timedwait(&sem, &deadline) != -1 || errno != EINTR ||
		    !sem_interrupt_seen)
			_exit(1);
		_exit(0);
	}
	if (child > 0) {
		close(ready[1]);
		CHECK(read(ready[0], &byte, 1) == 1);
		/* The byte says the disposition is installed.  Give the child a
		 * scheduling turn to enter the semaphore wait so this checks an
		 * interruption, rather than a signal completed before the call. */
		nanosleep(&settle, NULL);
		CHECK(kill(child, SIGUSR1) == 0);
		CHECK(waitpid(child, &status, 0) == child);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(ready[0]);
	}
	CHECK(sem_destroy(&sem) == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_sem_open_named)
#include <semaphore.h>
#include <fcntl.h>
#include <errno.h>

static void test_posix_realtime_sem_open_named(void)
{
	sem_t *a, *b;
	int value = -1;

	/* sem_open.html: "shall establish a connection between a named
	 * semaphore and a process ... If O_CREAT is specified and the
	 * semaphore already exists, O_CREAT has no effect ... the value
	 * argument shall specify the initial value for the semaphore."
	 * The name "conforms to the construction rules for a pathname"; a
	 * leading <slash> is the portable form. */
	a = sem_open("/spicule_posix_realtime", O_CREAT | O_EXCL, 0600, 1);
	CHECK(a != SEM_FAILED);

	/* ERRORS: "[EEXIST] O_CREAT and O_EXCL are set and the named
	 * semaphore already exists." */
	b = sem_open("/spicule_posix_realtime", O_CREAT | O_EXCL, 0600, 1);
	CHECK(b == SEM_FAILED);
	CHECK(errno == EEXIST);

	/* Reopening without O_EXCL returns a usable reference to the same
	 * semaphore, whose value is the one it was created with. */
	b = sem_open("/spicule_posix_realtime", 0);
	CHECK(b != SEM_FAILED);
	CHECK(sem_getvalue(b, &value) == 0);
	CHECK(value == 1);

	/* sem_close.html: "shall indicate that the calling process is
	 * finished using the named semaphore indicated by sem."
	 * sem_unlink.html: "shall remove the semaphore named by the string
	 * name.  If the semaphore named by name is currently referenced by
	 * other processes, then sem_unlink() shall have no effect on the
	 * state of the semaphore.  If one or more processes have the
	 * semaphore open when sem_unlink() is called, destruction of the
	 * semaphore is postponed". */
	CHECK(sem_close(a) == 0);
	CHECK(sem_close(b) == 0);
	CHECK(sem_unlink("/spicule_posix_realtime") == 0);

	/* ERRORS: "[ENOENT] The named semaphore does not exist." */
	CHECK(sem_unlink("/spicule_posix_realtime") == -1);
	CHECK(errno == ENOENT);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_sem_open_recovers_interrupted_publish)
#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

static void test_posix_realtime_sem_open_recovers_interrupted_publish(void)
{
	const char *dir = getenv("TMPDIR");
	const char *name = "/spicule_posix_realtime_stale";
	char namespace[PATH_MAX], record[PATH_MAX];
	sem_t *sem;
	int fd;

	if (!dir || !*dir) dir = getenv("TMP");
	if (!dir || !*dir) dir = getenv("TEMP");
	if (!dir || !*dir) dir = ".";
	CHECK(snprintf(namespace, sizeof namespace, "%s/spicule-sem", dir)
	      < (int)sizeof namespace);
	CHECK(snprintf(record, sizeof record, "%s/spicule_posix_realtime_stale",
	               namespace) < (int)sizeof record);
	CHECK(mkdir(namespace, 0777) == 0 || errno == EEXIST);
	/* This is the durable state left if a creator dies between publishing
	 * the record and filling it with the NT object name.  O_CREAT must be
	 * able to create the named semaphore, rather than leaving this POSIX
	 * name permanently poisoned. */
	unlink(record);
	fd = open(record, O_CREAT | O_EXCL | O_WRONLY, 0600);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(close(fd) == 0);

	sem = sem_open(name, O_CREAT, 0600, 1);
	CHECK(sem != SEM_FAILED);
	if (sem == SEM_FAILED) {
		unlink(record);
		return;
	}
	CHECK(sem_trywait(sem) == 0);
	CHECK(sem_close(sem) == 0);
	CHECK(sem_unlink(name) == 0);
}
#endif

/* ==================================================================
 * Message queues -- .../functions/mq_open.html, mq_send.html,
 * mq_receive.html, mq_getattr.html, mq_notify.html, mq_close.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_realtime_mq_send_receive_priority)
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static void test_posix_realtime_mq_send_receive_priority(void)
{
	struct mq_attr attr;
	mqd_t q;
	char buf[64];
	unsigned prio = 0;

	memset(&attr, 0, sizeof attr);
	attr.mq_maxmsg = 4;
	attr.mq_msgsize = (long)sizeof buf;

	/* mq_open.html: "shall establish the connection between a process
	 * and a message queue with a message queue descriptor ... If
	 * O_CREAT is specified ... the message queue is created ... the
	 * attr argument [when not NULL] specifies the maximum number of
	 * messages and the maximum size of each message." */
	q = mq_open("/spicule_posix_realtime_q", O_CREAT | O_EXCL | O_RDWR,
		    0600, &attr);
	CHECK(q != (mqd_t)-1);

	/* mq_receive.html: "shall receive the oldest of the highest
	 * priority message(s) from the message queue".  Send low, high,
	 * low again: the high-priority message must come out first, then
	 * the two equal-priority ones in the order they were sent. */
	CHECK(mq_send(q, "low1", 4, 1) == 0);
	CHECK(mq_send(q, "high", 4, 9) == 0);
	CHECK(mq_send(q, "low2", 4, 1) == 0);

	CHECK(mq_receive(q, buf, sizeof buf, &prio) == 4);
	CHECK(memcmp(buf, "high", 4) == 0);
	CHECK(prio == 9);

	CHECK(mq_receive(q, buf, sizeof buf, &prio) == 4);
	CHECK(memcmp(buf, "low1", 4) == 0);
	CHECK(prio == 1);

	CHECK(mq_receive(q, buf, sizeof buf, &prio) == 4);
	CHECK(memcmp(buf, "low2", 4) == 0);

	/* "If the size of the buffer in bytes, specified by the msg_len
	 * argument, is less than the mq_msgsize attribute of the message
	 * queue, the function shall fail and return an error."  ERRORS:
	 * "[EMSGSIZE] The specified message buffer size, msg_len, is less
	 * than the message size attribute of the message queue." */
	CHECK(mq_receive(q, buf, 1, NULL) == -1);
	CHECK(errno == EMSGSIZE);

	/* mq_send.html: "The value of msg_len shall be less than or equal
	 * to the mq_msgsize attribute of the message queue, or mq_send()
	 * shall fail", same [EMSGSIZE]. */
	CHECK(mq_send(q, buf, sizeof buf + 1, 0) == -1);
	CHECK(errno == EMSGSIZE);

	CHECK(mq_close(q) == 0);
	CHECK(mq_unlink("/spicule_posix_realtime_q") == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_mq_timed_extreme_past)
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>

struct timed_mq_case {
	mqd_t q;
	int send;
};

static void *release_timed_mq(void *argument)
{
	struct timed_mq_case *test = argument;
	struct timespec delay = { 0, 20000000L };
	char byte;
	nanosleep(&delay, NULL);
	if (test->send)
		CHECK(mq_send(test->q, "x", 1, 0) == 0);
	else
		CHECK(mq_receive(test->q, &byte, 1, NULL) == 1);
	return NULL;
}

static void test_posix_realtime_mq_timed_extreme_past(void)
{
	struct mq_attr attr;
	struct timespec future = { LLONG_MAX, 999999999L };
	struct timed_mq_case timed;
	pthread_t releaser;
	mqd_t q;
	char byte;

	memset(&attr, 0, sizeof attr);
	attr.mq_maxmsg = 1;
	attr.mq_msgsize = 1;
	mq_unlink("/spicule_posix_realtime_timed");
	q = mq_open("/spicule_posix_realtime_timed",
		O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
	CHECK(q != (mqd_t)-1);
	if (q == (mqd_t)-1) return;

	/* Both interfaces must keep waiting on a valid extreme-future
	 * deadline until the peer makes progress; the old subtraction and
	 * nanosecond multiplication wrapped and reported ETIMEDOUT. */
	timed.q = q;
	timed.send = 1;
	CHECK(pthread_create(&releaser, NULL, release_timed_mq, &timed) == 0);
	CHECK(mq_timedreceive(q, &byte, 1, NULL, &future) == 1);
	CHECK(byte == 'x');
	CHECK(pthread_join(releaser, NULL) == 0);
	CHECK(mq_send(q, "x", 1, 0) == 0);
	timed.send = 0;
	CHECK(pthread_create(&releaser, NULL, release_timed_mq, &timed) == 0);
	CHECK(mq_timedsend(q, "y", 1, 0, &future) == 0);
	CHECK(pthread_join(releaser, NULL) == 0);

	CHECK(mq_close(q) == 0);
	CHECK(mq_unlink("/spicule_posix_realtime_timed") == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_mq_attr_nonblock)
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static void test_posix_realtime_mq_attr_nonblock(void)
{
	struct mq_attr attr, back;
	mqd_t q;
	char buf[32];

	memset(&attr, 0, sizeof attr);
	attr.mq_maxmsg = 1;
	attr.mq_msgsize = (long)sizeof buf;

	q = mq_open("/spicule_posix_realtime_a", O_CREAT | O_EXCL | O_RDWR,
		    0600, &attr);
	CHECK(q != (mqd_t)-1);

	/* mq_getattr.html: "Upon return, the following members shall have
	 * the values associated with the open message queue description as
	 * set when the message queue was opened ... mq_maxmsg ...
	 * mq_msgsize ... mq_curmsgs [is] the number of messages currently
	 * on the queue." */
	memset(&back, 0, sizeof back);
	CHECK(mq_getattr(q, &back) == 0);
	CHECK(back.mq_maxmsg == 1);
	CHECK(back.mq_msgsize == (long)sizeof buf);
	CHECK(back.mq_curmsgs == 0);
	CHECK((back.mq_flags & O_NONBLOCK) == 0);

	/* mq_setattr.html: "The value of this member is the bitwise-
	 * logical OR of zero or more of O_NONBLOCK and any
	 * implementation-defined flags", and only mq_flags is settable --
	 * "the values of the mq_maxmsg, mq_msgsize, and mq_curmsgs members
	 * ... are ignored by mq_setattr()." */
	back.mq_flags = O_NONBLOCK;
	back.mq_maxmsg = 99;
	CHECK(mq_setattr(q, &back, NULL) == 0);
	CHECK(mq_getattr(q, &back) == 0);
	CHECK((back.mq_flags & O_NONBLOCK) != 0);
	CHECK(back.mq_maxmsg == 1);

	/* mq_send.html: "If the message queue is full, and O_NONBLOCK is
	 * set in the message queue description associated with mqdes, the
	 * message shall not be queued and mq_send() shall return an
	 * error", ERRORS "[EAGAIN] The O_NONBLOCK flag is set in the
	 * message queue description ... and the specified message queue is
	 * full." */
	CHECK(mq_send(q, "x", 1, 0) == 0);
	CHECK(mq_send(q, "y", 1, 0) == -1);
	CHECK(errno == EAGAIN);

	CHECK(mq_receive(q, buf, sizeof buf, NULL) == 1);

	/* mq_receive.html, same flag on the empty side: "[EAGAIN]
	 * O_NONBLOCK was set in the message description associated with
	 * mqdes, and the specified message queue is empty." */
	CHECK(mq_receive(q, buf, sizeof buf, NULL) == -1);
	CHECK(errno == EAGAIN);

	CHECK(mq_close(q) == 0);
	CHECK(mq_unlink("/spicule_posix_realtime_a") == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_mq_notify_single_registration)
#include <mqueue.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static void test_posix_realtime_mq_notify_single_registration(void)
{
	struct mq_attr attr;
	struct sigevent ev;
	mqd_t q;

	memset(&attr, 0, sizeof attr);
	attr.mq_maxmsg = 2;
	attr.mq_msgsize = 8;

	q = mq_open("/spicule_posix_realtime_n", O_CREAT | O_EXCL | O_RDWR,
		    0600, &attr);
	CHECK(q != (mqd_t)-1);

	memset(&ev, 0, sizeof ev);
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGUSR1;

	/* mq_notify.html: "If the argument notification is not NULL, this
	 * function shall register the calling process to be notified of
	 * message arrival at an empty message queue". */
	CHECK(mq_notify(q, &ev) == 0);

	/* "At any time, only one process may be registered for
	 * notification by a message queue.  If the calling process or any
	 * other process has already registered for notification of message
	 * arrival at the specified message queue, subsequent attempts to
	 * register for that message queue shall fail."  ERRORS: "[EBUSY]
	 * There is already a process registered for notification for the
	 * message queue." */
	CHECK(mq_notify(q, &ev) == -1);
	CHECK(errno == EBUSY);

	/* "If notification is NULL and the process is currently registered
	 * for notification by the specified message queue, the existing
	 * registration shall be removed." -- after which registering
	 * again must succeed. */
	CHECK(mq_notify(q, NULL) == 0);
	CHECK(mq_notify(q, &ev) == 0);
	CHECK(mq_notify(q, NULL) == 0);

	CHECK(mq_close(q) == 0);
	CHECK(mq_unlink("/spicule_posix_realtime_n") == 0);
}
#endif

/* ==================================================================
 * Asynchronous I/O -- .../functions/aio_read.html, aio_write.html,
 * aio_error.html, aio_return.html, aio_suspend.html, aio_fsync.html,
 * aio_cancel.html, lio_listio.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_realtime_aio_write_read_roundtrip)
#include <aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void test_posix_realtime_aio_write_read_roundtrip(void)
{
	struct aiocb cb;
	const struct aiocb *list[1];
	char out[16] = "asynchronous-io";
	char in[16];
	int fd, err;

	fd = open("spicule-aio.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd < 0)
		return;

	/* aio_write.html: "shall write aiocbp->aio_nbytes to the file
	 * associated with aiocbp->aio_fildes from the buffer pointed to by
	 * aiocbp->aio_buf ... The aiocbp value may be used as an argument
	 * to aio_error() and aio_return() in order to determine the error
	 * status and return status ... of the asynchronous operation." */
	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_buf = out;
	cb.aio_nbytes = sizeof out;
	cb.aio_offset = 0;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_write(&cb) == 0);

	/* aio_suspend.html: "shall suspend the calling thread until at
	 * least one of the asynchronous I/O operations referenced by the
	 * list argument has completed". */
	list[0] = &cb;
	CHECK(aio_suspend(list, 1, NULL) == 0);

	/* aio_error.html: "shall return the error status associated with
	 * the aiocb structure ... If the operation has not yet completed,
	 * then the error status shall be equal to [EINPROGRESS]."  It has
	 * completed, so the status is the one the corresponding write()
	 * would have set: zero. */
	err = aio_error(&cb);
	CHECK(err == 0);

	/* aio_return.html: "The return status for an asynchronous I/O
	 * operation is the value that would be returned by the
	 * corresponding read(), write(), or fsync() function call."  And
	 * exactly once: "may be called exactly once to retrieve the return
	 * status ... thereafter, if the same aiocb structure [is used] the
	 * results are undefined." */
	CHECK(aio_return(&cb) == (ssize_t)sizeof out);

	/* aio_fsync.html: "shall asynchronously force all I/O operations
	 * associated with the file indicated by the file descriptor
	 * aio_fildes member of the aiocb structure referenced by the
	 * aiocbp argument and queued at the time of the call ... to the
	 * synchronized I/O completion state." */
	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_fsync(O_SYNC, &cb) == 0);
	list[0] = &cb;
	CHECK(aio_suspend(list, 1, NULL) == 0);
	CHECK(aio_error(&cb) == 0);
	CHECK(aio_return(&cb) == 0);

	/* aio_read.html: "shall read aiocbp->aio_nbytes from the file
	 * associated with aiocbp->aio_fildes into the buffer pointed to by
	 * aiocbp->aio_buf", at aio_offset -- so the bytes just written
	 * must come back. */
	memset(&cb, 0, sizeof cb);
	memset(in, 0, sizeof in);
	cb.aio_fildes = fd;
	cb.aio_buf = in;
	cb.aio_nbytes = sizeof in;
	cb.aio_offset = 0;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_read(&cb) == 0);
	list[0] = &cb;
	CHECK(aio_suspend(list, 1, NULL) == 0);
	CHECK(aio_error(&cb) == 0);
	CHECK(aio_return(&cb) == (ssize_t)sizeof in);
	CHECK(memcmp(in, out, sizeof out) == 0);

	CHECK(close(fd) == 0);
	CHECK(unlink("spicule-aio.tmp") == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_lio_listio_wait)
#include <aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void test_posix_realtime_lio_listio_wait(void)
{
	struct aiocb a, b, nop;
	struct aiocb *list[3];
	char first[4] = "AAAA";
	char second[4] = "BBBB";
	char back[8];
	int fd;

	fd = open("spicule-lio.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd < 0)
		return;

	memset(&a, 0, sizeof a);
	a.aio_fildes = fd;
	a.aio_buf = first;
	a.aio_nbytes = sizeof first;
	a.aio_offset = 0;
	a.aio_lio_opcode = LIO_WRITE;
	a.aio_sigevent.sigev_notify = SIGEV_NONE;

	memset(&b, 0, sizeof b);
	b.aio_fildes = fd;
	b.aio_buf = second;
	b.aio_nbytes = sizeof second;
	b.aio_offset = (off_t)sizeof first;
	b.aio_lio_opcode = LIO_WRITE;
	b.aio_sigevent.sigev_notify = SIGEV_NONE;

	/* lio_listio.html: "The aio_lio_opcode field of each aiocb
	 * structure specifies the operation to be performed ... LIO_NOP,
	 * [for which] the list entry shall be ignored". */
	memset(&nop, 0, sizeof nop);
	nop.aio_lio_opcode = LIO_NOP;

	list[0] = &a;
	list[1] = &nop;
	list[2] = &b;

	/* "If the mode argument is LIO_WAIT, the lio_listio() function
	 * shall wait until all I/O is complete and the sig argument shall
	 * be ignored." */
	CHECK(lio_listio(LIO_WAIT, list, 3, NULL) == 0);
	CHECK(aio_error(&a) == 0);
	CHECK(aio_return(&a) == (ssize_t)sizeof first);
	CHECK(aio_error(&b) == 0);
	CHECK(aio_return(&b) == (ssize_t)sizeof second);

	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(read(fd, back, sizeof back) == (ssize_t)sizeof back);
	CHECK(memcmp(back, "AAAABBBB", 8) == 0);

	/* ERRORS: "[EINVAL] The mode argument is not a proper value, or
	 * the value of nent was greater than {AIO_LISTIO_MAX}." */
	CHECK(lio_listio(0x5eed, list, 3, NULL) == -1);
	CHECK(errno == EINVAL);

	CHECK(close(fd) == 0);
	CHECK(unlink("spicule-lio.tmp") == 0);
}
#endif

#if SPICULE_TEST(PASS, posix_realtime_aio_cancel_notcanceled)
#include <aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void test_posix_realtime_aio_cancel_notcanceled(void)
{
	struct aiocb cb;
	const struct aiocb *list[1];
	char out[8] = "cancelme";
	int fd, rc;

	fd = open("spicule-aiocancel.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd < 0)
		return;

	memset(&cb, 0, sizeof cb);
	cb.aio_fildes = fd;
	cb.aio_buf = out;
	cb.aio_nbytes = sizeof out;
	cb.aio_offset = 0;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	CHECK(aio_write(&cb) == 0);

	/* aio_cancel.html: "shall attempt to cancel one or more
	 * asynchronous I/O requests currently outstanding against file
	 * descriptor fildes ... shall return AIO_CANCELED if the requested
	 * operation(s) were canceled.  ... shall return AIO_NOTCANCELED if
	 * at least one of the requested operation(s) cannot be canceled
	 * because it is in progress.  ... shall return AIO_ALLDONE if all
	 * of the operations have already completed."  Which of the three
	 * happens is a race, so assert only that the value is one of the
	 * three the header names -- and, per "The return values ... are
	 * defined in <aio.h>", that they are distinct. */
	rc = aio_cancel(fd, &cb);
	CHECK(rc == AIO_CANCELED || rc == AIO_NOTCANCELED || rc == AIO_ALLDONE);
	CHECK(AIO_CANCELED != AIO_NOTCANCELED);
	CHECK(AIO_NOTCANCELED != AIO_ALLDONE);
	CHECK(AIO_CANCELED != AIO_ALLDONE);

	if (rc != AIO_ALLDONE) {
		list[0] = &cb;
		aio_suspend(list, 1, NULL);
	}

	/* "The error status for each control block that is canceled shall
	 * be set to [ECANCELED]" -- for the canceled case only; a
	 * completed one keeps its ordinary status.  Either way aio_error()
	 * must no longer say [EINPROGRESS]. */
	CHECK(aio_error(&cb) != EINPROGRESS);
	aio_return(&cb);

	CHECK(close(fd) == 0);
	CHECK(unlink("spicule-aiocancel.tmp") == 0);
}
#endif

/* ==================================================================
 * Per-process timers -- .../functions/timer_create.html,
 * timer_settime.html (which also specifies timer_gettime and
 * timer_getoverrun), timer_delete.html.  The fence is retained as a
 * direct standards assertion now that all five interfaces exist.
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_realtime_timer_settime_gettime)
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static void test_posix_realtime_timer_settime_gettime(void)
{
	struct sigevent ev;
	struct itimerspec its, back;
	timer_t tid;

	memset(&ev, 0, sizeof ev);
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGALRM;

	/* timer_create.html: "shall create a per-process timer using the
	 * specified clock, clock_id, as the timing base.  The
	 * timer_create() function shall return, in the location referenced
	 * by timerid, a timer ID of type timer_t used to identify the
	 * timer in timer requests.  This timer ID shall be unique within
	 * the calling process until the timer is deleted.  The particular
	 * clock, clock_id, is defined in <time.h>." */
	CHECK(timer_create(CLOCK_REALTIME, &ev, &tid) == 0);

	/* timer_settime.html: "shall store, in the location referenced by
	 * ovalue, a value representing the previous amount of time before
	 * the timer would have expired ... or zero if the timer was
	 * disarmed".  A newly created timer is disarmed. */
	memset(&its, 0, sizeof its);
	its.it_value.tv_sec = 3600;
	memset(&back, 0xff, sizeof back);
	CHECK(timer_settime(tid, 0, &its, &back) == 0);
	CHECK(back.it_value.tv_sec == 0 && back.it_value.tv_nsec == 0);

	/* timer_gettime(): "shall store the amount of time until the
	 * specified timer, timerid, expires and the reload value of the
	 * timer into the space pointed to by the value argument.  The
	 * it_value member of this structure shall contain the amount of
	 * time before the timer expires, or zero if the timer is
	 * disarmed."  It is armed for an hour, so the remaining time is
	 * positive and no greater than what was set. */
	memset(&back, 0, sizeof back);
	CHECK(timer_gettime(tid, &back) == 0);
	CHECK(back.it_value.tv_sec > 0);
	CHECK(back.it_value.tv_sec <= 3600);
	/* "The it_interval member ... shall contain the reload value last
	 * set by timer_settime()" -- zero, a one-shot. */
	CHECK(back.it_interval.tv_sec == 0 && back.it_interval.tv_nsec == 0);

	/* timer_getoverrun(): "shall return the timer expiration overrun
	 * count for the specified timer ... only for the timer expiration
	 * that caused the signal to be queued or delivered"; nothing has
	 * expired, so the count is zero. */
	CHECK(timer_getoverrun(tid) == 0);

	/* The timer engine stores 100ns ticks.  Cover both ways a valid
	 * timespec can exceed that representation: multiplication itself,
	 * and a maximum representable relative interval added to a nonzero
	 * current clock.  A failed set leaves the prior one-hour timer armed. */
	memset(&its, 0, sizeof its);
	its.it_value.tv_sec = LLONG_MAX;
	errno = 0;
	CHECK(timer_settime(tid, 0, &its, NULL) == -1);
	CHECK(errno == EOVERFLOW);
	its.it_value.tv_sec = LLONG_MAX / 10000000LL;
	its.it_value.tv_nsec = (long)(LLONG_MAX % 10000000LL) * 100L;
	errno = 0;
	CHECK(timer_settime(tid, 0, &its, NULL) == -1);
	CHECK(errno == EOVERFLOW);
	memset(&back, 0, sizeof back);
	CHECK(timer_gettime(tid, &back) == 0);
	CHECK(back.it_value.tv_sec > 0 && back.it_value.tv_sec <= 3600);

	/* The reload value has the same representation and must be checked
	 * even when a zero it_value would otherwise disarm the timer. */
	memset(&its, 0, sizeof its);
	its.it_interval.tv_sec = LLONG_MAX;
	errno = 0;
	CHECK(timer_settime(tid, 0, &its, NULL) == -1);
	CHECK(errno == EOVERFLOW);

	/* "If the it_value member of value is zero, the timer shall be
	 * disarmed." */
	memset(&its, 0, sizeof its);
	CHECK(timer_settime(tid, 0, &its, NULL) == 0);
	CHECK(timer_gettime(tid, &back) == 0);
	CHECK(back.it_value.tv_sec == 0 && back.it_value.tv_nsec == 0);

	/* timer_delete.html: "shall delete the specified timer, timerid,
	 * previously created by the timer_create() function." */
	CHECK(timer_delete(tid) == 0);

	/* ERRORS: "[EINVAL] The timerid argument does not correspond to an
	 * ID returned by timer_create() but not yet deleted by
	 * timer_delete()." */
	CHECK(timer_delete(tid) == -1);
	CHECK(errno == EINVAL);
}
#endif

/* ==================================================================
 * The missing half of <sched.h> -- .../functions/sched_getparam.html,
 * sched_getscheduler.html, sched_get_priority_max.html,
 * sched_rr_get_interval.html.  include/sched.h supplies sched_yield()
 * and struct sched_param and says in its banner that it supplies
 * nothing else; this is that sentence, made testable.
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_realtime_sched_policy_priorities)
#include <sched.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static void test_posix_realtime_sched_policy_priorities(void)
{
	struct sched_param param;
	struct timespec interval;
	int policy;

	/* sched_get_priority_max.html: "The sched_get_priority_max() and
	 * sched_get_priority_min() functions shall return the appropriate
	 * maximum or minimum, respectively, for the scheduling policy
	 * specified by policy.  The value of policy shall be one of the
	 * scheduling policy values defined in <sched.h>."  The header page
	 * names SCHED_FIFO, SCHED_RR, SCHED_SPORADIC and SCHED_OTHER, and
	 * requires their values to be distinct. */
	CHECK(SCHED_FIFO != SCHED_RR);
	CHECK(SCHED_RR != SCHED_OTHER);
	CHECK(SCHED_FIFO != SCHED_OTHER);

	CHECK(sched_get_priority_max(SCHED_FIFO) >= 0);
	CHECK(sched_get_priority_min(SCHED_FIFO) >= 0);
	CHECK(sched_get_priority_max(SCHED_FIFO)
	      >= sched_get_priority_min(SCHED_FIFO));
	CHECK(sched_get_priority_max(SCHED_RR)
	      >= sched_get_priority_min(SCHED_RR));

	/* ERRORS: "[EINVAL] The value of the policy parameter does not
	 * represent a defined scheduling policy." */
	CHECK(sched_get_priority_max(0x5eed) == -1);
	CHECK(errno == EINVAL);

	/* sched_getscheduler.html: "shall return the scheduling policy of
	 * the process specified by pid ... If pid is zero, the scheduling
	 * policy ... of the calling process shall be [returned]."  The
	 * values "are defined in the <sched.h> header", so whatever comes
	 * back must be one of them. */
	policy = sched_getscheduler(0);
	CHECK(policy == SCHED_FIFO || policy == SCHED_RR
	      || policy == SCHED_OTHER || policy == SCHED_SPORADIC);

	/* sched_getparam.html: "shall return the scheduling parameters of
	 * a process specified by pid in the sched_param structure pointed
	 * to by param."  The priority it returns has to be inside the
	 * range the policy itself reports. */
	CHECK(sched_getparam(0, &param) == 0);
	CHECK(param.sched_priority >= sched_get_priority_min(policy));
	CHECK(param.sched_priority <= sched_get_priority_max(policy));
	CHECK(sched_setparam(0, &param) == 0);
	CHECK(sched_setscheduler(0, policy, &param) == policy);

	/* sched_rr_get_interval.html: "shall update the timespec structure
	 * referenced by the interval argument to contain the current
	 * execution time limit (that is, time quantum) for the process
	 * specified by pid." */
	CHECK(sched_rr_get_interval(0, &interval) == 0);
	CHECK(interval.tv_nsec >= 0 && interval.tv_nsec < 1000000000L);
	CHECK(interval.tv_sec > 0 || interval.tv_nsec > 0);
}
#endif

int main(void)
{
	/* tools/test-policy.py --pedantic re-decides every case.  When a
	 * missing interface arrives, its probe stops agreeing and the fence
	 * has to be re-adjudicated against real behaviour. */
	if (!fails) printf("posix-realtime: all tests passed\n");
	return fails != 0;
}
