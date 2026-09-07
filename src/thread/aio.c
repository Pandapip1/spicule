/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * POSIX asynchronous I/O.  A single detached native worker services a
 * bounded FIFO: besides avoiding a thread-per-request explosion, serial
 * service keeps a blocked request's later siblings genuinely queued and
 * cancelable.  The queue is protected by the signal subsystem's recursive
 * event mutex, reused here because it's already initialized before AIO
 * can be used and is safe to enter from completion handlers.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libc.h"
#include "plat_thread.h"
#include "plat_fd.h"
#include "unsafe_pointer.h"
#include "ownership_stubs.h"

enum request_state {
	REQ_FREE,
	REQ_QUEUED,
	REQ_RUNNING,
	REQ_DONE
};

enum request_op {
	OP_READ,
	OP_WRITE,
	OP_SYNC
};

struct aio_group {
	int active;
	int remaining;
	struct sigevent event;
};

struct aio_request {
	int state;
	int op;
	int error;
	ssize_t result;
	unsigned long long sequence;
	struct aiocb *cb;
	struct aio_group *group;
};

/* Each aio_suspend() call registers one of these on the stack while blocked;
 * a completion sets every matching waiter's event under the queue lock, so
 * one completion can't be consumed by an unrelated waiter. */
struct aio_waiter {
	const struct aiocb *const *list;
	int count;
	int triggered;
	__plat_handle_t event;
	struct aio_waiter *next;
};

struct thread_notice {
	void (*function)(union sigval);
	union sigval value;
};

/* Guarded by __sig_lock()/__sig_unlock() (see file banner). */
static struct aio_request requests[AIO_MAX] NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static struct aio_group groups[AIO_MAX] NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static unsigned long long next_sequence NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static __plat_handle_t worker_wake NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static int worker_started NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static int worker_synchronous NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static struct aio_waiter *waiters NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);

/* Worker teardown. On Linux, __plat_thread_spawn() clones the worker WITHOUT
 * CLONE_THREAD, so it's a separate process (own pid/tgid) invisible to
 * exit_group(2); NtTerminateProcess kills every thread at once, so this bug
 * only shows up on Linux. `worker_shutdown` is what stops the idle worker
 * from blocking forever once the queue drains; `worker_done_event` is what
 * aio_worker_atexit() blocks on so process exit can't race a running worker.
 * `worker_atexit_registered` is reset on fork so a forked child's first
 * submit() re-registers its own shutdown hook for its own lazily-started
 * worker. */
static int worker_shutdown NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static int worker_exited NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static __plat_handle_t worker_done_event NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static int worker_atexit_registered NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);

/* request is always a pointer into the file-static requests[] table, never
 * NULL, so nonnull isn't declared on it (not expressible for a struct
 * field's own conditional liveness). */
static void wake_waiters_locked(const struct aio_request *request)
    __attribute__((nonnull(1)))
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static void wake_waiters_locked(const struct aio_request *request)
{
	struct aio_waiter *waiter;
	int i;
	for (waiter = waiters; waiter; waiter = waiter->next) {
		/* waiter->list is aio_suspend()'s own list parameter, already
		 * indexed at this same count by that function's two
		 * suspend_list_ready() calls before this waiter was ever
		 * registered -- not visible here across the struct field. */
		__ownership_pointer_nonnull(waiter->list);
		for (i = 0; i < waiter->count; i++) {
			if (waiter->list[i] != request->cb) continue;
			waiter->triggered = 1;
			__plat_event_set(waiter->event);
			break;
		}
	}
}

/* argument is always a freshly malloc()'d, already null-checked notice. */
static unsigned __PLAT_APC_CALL notice_thread(void *argument)
    __attribute__((nonnull(1)));
static unsigned __PLAT_APC_CALL notice_thread(void *argument)
{
	struct thread_notice *notice = argument;
	void (*function)(union sigval) = notice->function;
	union sigval value = notice->value;
	free(notice);
	function(value);
	return 0;
}

/* SIGEV_NONE never notifies; SIGEV_SIGNAL naming signal 0 is also silence,
 * mirroring kill()/raise()'s "signal 0 is a null signal" rule. */
static int event_wants_notify(const struct sigevent *event)
{
	return event->sigev_notify != SIGEV_NONE &&
	       (event->sigev_notify != SIGEV_SIGNAL || event->sigev_signo != 0);
}

static void notify(const struct sigevent *event)
{
	if (!event || event->sigev_notify == SIGEV_NONE) return;
	if (event->sigev_notify == SIGEV_SIGNAL) {
		siginfo_t info;
		if (event->sigev_signo <= 0 || event->sigev_signo >= _NSIG) return;
		memset(&info, 0, sizeof info);
		info.si_signo = event->sigev_signo;
		info.si_code = SI_ASYNCIO;
		info.si_value = event->sigev_value;
		__sig_lock();
		(void)__raise_internal_info(info.si_signo, &info);
		__sig_unlock();
		return;
	}
	if (event->sigev_notify == SIGEV_THREAD && event->sigev_notify_function) {
		struct thread_notice *notice = malloc(sizeof *notice);
		__plat_handle_t thread;
		if (!notice) return;
		notice->function = event->sigev_notify_function;
		notice->value = event->sigev_value;
		if (__plat_thread_spawn(notice_thread, notice, 0, 0, &thread) < 0) {
			free(notice);
			return;
		}
		__plat_thread_close(thread);
	}
}

/* Complete one member while the queue lock is held.  The caller sends the
 * copied notifications only after unlocking: a handler is allowed to call
 * aio_return(), which can immediately release and reuse this request slot.
 * `list` isn't marked nonnull since it's only written inside the group
 * branch, not on every call. */
static void finish_locked(struct aio_request *request, int error, ssize_t result,
	struct sigevent *individual, int *have_individual,
	struct sigevent *list, int *have_list)
    __attribute__((nonnull(1, 4, 5, 7)))
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static void finish_locked(struct aio_request *request, int error, ssize_t result, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	struct sigevent *individual, int *have_individual,
	struct sigevent *list, int *have_list)
{
	struct aiocb *cb = request->cb;
	request->error = error;
	request->result = result;
	request->state = REQ_DONE;
	/* Every caller (aio_worker, submit()'s synchronous path, aio_cancel())
	 * only reaches this with a queued or running request, whose cb was
	 * already set by submit() -- not visible here across the struct
	 * field. Read into a local once: re-reading request->cb after any of
	 * this function's own callers passed request through another call
	 * (perform(), in submit()'s synchronous path) makes the checker treat
	 * each re-read as a fresh, unrelated value. wake_waiters_locked() runs
	 * last since it doesn't need any of this. */
	__ownership_pointer_nonnull(cb);
	*individual = cb->aio_sigevent;
	*have_individual = event_wants_notify(individual);
	*have_list = 0;
	if (request->group && request->group->active && --request->group->remaining == 0) {
		*list = request->group->event;
		*have_list = event_wants_notify(list);
		request->group->active = 0;
	}
	wake_waiters_locked(request);
}

static ssize_t perform(struct aio_request *request, int *error)
    __attribute__((nonnull(1, 2)));
static ssize_t perform(struct aio_request *request, int *error)
{
	struct aiocb *cb = request->cb;
	struct __fd *fd;
	ssize_t result;

	/* request is always REQ_QUEUED/REQ_RUNNING here (next_queued() and
	 * submit()'s synchronous path both only reach this with cb already
	 * set), an invariant established in those other functions that this
	 * one can't see through the struct field. */
	__ownership_pointer_nonnull(cb);
	errno = 0;
	if (request->op == OP_SYNC) {
		result = fsync(cb->aio_fildes);
	} else {
		fd = __fd_get(cb->aio_fildes);
		if (!fd) result = -1;
		else if (fd->type == __FD_FILE) {
			if (request->op == OP_READ) {
				/* cb->aio_buf/cb->aio_nbytes are the application's own
				 * request buffer and length, POSIX's aio_read() contract
				 * (mirroring read()'s own withtok(writable_span(count))
				 * on its buffer parameter) -- not locally derivable from
				 * these struct fields alone. */
				__ownership_writable_span(cb->aio_buf, cb->aio_nbytes);
				result = pread(cb->aio_fildes, (void *)cb->aio_buf,
				               cb->aio_nbytes, cb->aio_offset);
			} else {
				__ownership_readable_span(cb->aio_buf, cb->aio_nbytes);
				result = pwrite(cb->aio_fildes, (const void *)cb->aio_buf,
				                cb->aio_nbytes, cb->aio_offset);
			}
		} else if (request->op == OP_READ) {
			__ownership_writable_span(cb->aio_buf, cb->aio_nbytes);
			result = read(cb->aio_fildes, (void *)cb->aio_buf, cb->aio_nbytes);
		} else {
			__ownership_readable_span(cb->aio_buf, cb->aio_nbytes);
			result = write(cb->aio_fildes, (const void *)cb->aio_buf, cb->aio_nbytes);
		}
	}
	*error = result < 0 ? errno : 0;
	return result;
}

static struct aio_request *next_queued(void)
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static struct aio_request *next_queued(void)
{
	struct aio_request *best = 0;
	int i;
	for (i = 0; i < AIO_MAX; i++)
		if (requests[i].state == REQ_QUEUED &&
		    (!best || requests[i].sequence < best->sequence))
			best = &requests[i];
	return best;
}

static unsigned __PLAT_APC_CALL aio_worker(void *unused)
{
	__plat_handle_t done;
	(void)unused;
	for (;;) {
		struct aio_request *request;
		__plat_handle_t wake;
		struct sigevent individual, list;
		int have_individual, have_list, error, shutdown;
		ssize_t result;

		__sig_lock();
		request = next_queued();
		if (request) request->state = REQ_RUNNING;
		wake = worker_wake;
		shutdown = worker_shutdown;
		__sig_unlock();
		if (!request) {
			/* Checked here, not just before the wait, so a shutdown
			 * requested mid-queue still lets outstanding AIO finish
			 * before the worker exits. */
			if (shutdown) break;
			__plat_wait_one(wake, 0, 0, 0);
			continue;
		}

		result = perform(request, &error);
		__sig_lock();
		finish_locked(request, error, result, &individual, &have_individual,
		              &list, &have_list);
		__sig_unlock();
		if (have_individual) notify(&individual);
		if (have_list) notify(&list);
	}
	/* Publish exit before returning so aio_worker_atexit() can't let
	 * process exit proceed while this worker is still winding down. */
	__sig_lock();
	worker_exited = 1;
	done = worker_done_event;
	__sig_unlock();
	if (done) __plat_event_set(done);
	return 0;
}

/* Registered once by start_worker() the first time a real background worker
 * spawns (the worker_synchronous fallback has nothing to clean up). Blocks
 * until aio_worker() has actually finished, closing the gap where
 * exit_group(2) on Linux would otherwise tear the process down without
 * reaching a worker spawned as a separate tgid. */
static void aio_worker_atexit(void)
{
	__plat_handle_t done;
	int need_wait;

	__sig_lock();
	worker_shutdown = 1;
	if (worker_wake) __plat_event_set(worker_wake);
	need_wait = !worker_exited && worker_done_event != 0;
	done = worker_done_event;
	__sig_unlock();

	if (need_wait) __plat_wait_one(done, 0, 0, 0);
}

static int start_worker(void) NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static int start_worker(void)
{
	__plat_handle_t thread, event, done;
	int result;
	if (worker_started) return 0;
	result = __plat_event_create(&event);
	if (result == -2) {
		worker_synchronous = 1;
		worker_started = 1;
		return 0;
	}
	if (result < 0) { errno = EAGAIN; return -1; }
	/* Created alongside worker_wake, before the worker can run, so both
	 * handles are valid for its whole lifetime. */
	result = __plat_event_create(&done);
	if (result < 0) {
		__plat_close(event);
		errno = EAGAIN;
		return -1;
	}
	worker_wake = event;
	worker_done_event = done;
	result = __plat_thread_spawn(aio_worker, 0, 0, 0, &thread);
	if (result < 0) {
		worker_wake = 0;
		worker_done_event = 0;
		__plat_close(event);
		__plat_close(done);
		if (result == -2) {
			worker_synchronous = 1;
			worker_started = 1;
			return 0;
		}
		errno = EAGAIN;
		return -1;
	}
	worker_started = 1;
	__plat_thread_close(thread);
	if (!worker_atexit_registered) {
		/* atexit()'s own table is a separate, already process-wide-safe
		 * structure, so calling it while holding this file's lock isn't
		 * an ordering hazard. A failed registration isn't fatal (the
		 * worker is already usable); it just means exit() won't wait
		 * for it to drain, so worker_atexit_registered stays clear. */
		if (atexit(aio_worker_atexit) == 0)
			worker_atexit_registered = 1;
	}
	return 0;
}

static int valid_event(const struct sigevent *event)
{
	if (event->sigev_notify == SIGEV_NONE) return 1;
	if (event->sigev_notify == SIGEV_SIGNAL)
		return event->sigev_signo >= 0 && event->sigev_signo < _NSIG;
	if (event->sigev_notify == SIGEV_THREAD)
		return event->sigev_notify_function != 0;
	return 0;
}

static int submit(struct aiocb *cb, int op, struct aio_group *group)
{
	struct aio_request *request = 0;
	struct sigevent individual, list;
	ssize_t result;
	int error, have_individual, have_list, i;

	if (!cb ||
	    ((op == OP_READ || op == OP_WRITE) &&
	     (cb->aio_reqprio < 0 || cb->aio_reqprio > AIO_PRIO_DELTA_MAX ||
	      cb->aio_offset < 0 || cb->aio_nbytes > (size_t)SSIZE_MAX ||
	      (cb->aio_nbytes && !cb->aio_buf))) ||
	    !valid_event(&cb->aio_sigevent)) {
		errno = EINVAL;
		return -1;
	}

	__sig_lock();
	if (cb->__opaque) {
		__sig_unlock();
		errno = EINVAL;
		return -1;
	}
	if (start_worker() < 0) { __sig_unlock(); return -1; }
	for (i = 0; i < AIO_MAX; i++)
		if (requests[i].state == REQ_FREE) { request = &requests[i]; break; }
	if (!request) {
		__sig_unlock();
		errno = EAGAIN;
		return -1;
	}
	memset(request, 0, sizeof *request);
	request->state = REQ_QUEUED;
	request->op = op;
	request->sequence = ++next_sequence;
	request->cb = cb;
	request->group = group;
	cb->__opaque = request;
	if (worker_synchronous) {
		request->state = REQ_RUNNING;
		__sig_unlock();
		result = perform(request, &error);
		__sig_lock();
		finish_locked(request, error, result, &individual, &have_individual,
		              &list, &have_list);
		__sig_unlock();
		if (have_individual) notify(&individual);
		if (have_list) notify(&list);
		return 0;
	}
	__plat_event_set(worker_wake);
	__sig_unlock();
	return 0;
}

int aio_read(struct aiocb *cb) { return submit(cb, OP_READ, 0); }
int aio_write(struct aiocb *cb) { return submit(cb, OP_WRITE, 0); }

int aio_fsync(int op, struct aiocb *cb)
{
	if (op != O_SYNC && op != O_DSYNC) { errno = EINVAL; return -1; }
	/* Unlike read/write initiation, aio_fsync() lists EBADF as a
	 * synchronous failure and the descriptor contributes no deferred
	 * transfer whose error could usefully be retrieved later. */
	if (!cb || !__fd_get(cb->aio_fildes)) return -1;
	return submit(cb, OP_SYNC, 0);
}

static struct aio_request *lookup(const struct aiocb *cb)
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static struct aio_request *lookup(const struct aiocb *cb)
{
	struct aio_request *request;
	if (!cb || !cb->__opaque) return 0;
	request = cb->__opaque;
	/* request is cb->__opaque, an opaque value submit() populated by
	 * storing a pointer into the fixed `requests` table -- an invariant
	 * established by that DIFFERENT function, earlier in the program,
	 * that this function's own body cannot see. */
	if (unsafe_assume_shared_provenance(request < requests) ||
	    unsafe_assume_shared_provenance(request >= requests + AIO_MAX) ||
	    request->state == REQ_FREE || request->cb != cb) return 0;
	return request;
}

int aio_error(const struct aiocb *cb)
{
	struct aio_request *request;
	int result;
	__sig_lock();
	request = lookup(cb);
	if (!request) result = EINVAL;
	else if (request->state == REQ_DONE) result = request->error;
	else result = EINPROGRESS;
	__sig_unlock();
	return result;
}

ssize_t aio_return(struct aiocb *cb)
{
	struct aio_request *request;
	ssize_t result;
	int error;
	__sig_lock();
	request = lookup(cb);
	if (!request || request->state != REQ_DONE) {
		__sig_unlock();
		errno = EINVAL;
		return -1;
	}
	result = request->result;
	error = request->error;
	cb->__opaque = 0;
	memset(request, 0, sizeof *request);
	__sig_unlock();
	if (result < 0) errno = error;
	return result;
}

static int timeout_valid(const struct timespec *timeout)
{
	return !timeout || (timeout->tv_sec >= 0 && timeout->tv_nsec >= 0 &&
	                    timeout->tv_nsec < 1000000000L);
}

/* Called with the queue lock held. An invalid/stale request identity counts
 * as ready, same as one already completed and collected via aio_return(). */
static int suspend_list_ready(const struct aiocb *const list[], int count,
	int *any) __attribute__((nonnull(1, 3)))
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static int suspend_list_ready(const struct aiocb *const list[], int count,
	int *any)
{
	int i;
	*any = 0;
	for (i = 0; i < count; i++) {
		struct aio_request *request;
		if (!list[i]) continue;
		request = lookup(list[i]);
		if (!request || request->state == REQ_DONE) return 1;
		*any = 1;
	}
	return 0;
}

/* The `now`-relative deadline, in 100ns ticks, for a POSIX timespec
 * timeout -- saturating at LLONG_MAX rather than overflowing, both when
 * converting the timespec itself to ticks and when adding it to `now`. */
static long long timeout_deadline(const struct timespec *timeout, long long now)
    __attribute__((nonnull(1)));
static long long timeout_deadline(const struct timespec *timeout, long long now)
{
	long long subsecond = (timeout->tv_nsec + 99) / 100;
	long long ticks;
	if (timeout->tv_sec > (LLONG_MAX - subsecond) / 10000000LL)
		ticks = LLONG_MAX;
	else
		ticks = (long long)timeout->tv_sec * 10000000LL + subsecond;
	return ticks > LLONG_MAX - now ? LLONG_MAX : now + ticks;
}

static void remove_waiter_locked(struct aio_waiter *waiter)
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static void remove_waiter_locked(struct aio_waiter *waiter)
{
	struct aio_waiter **link = &waiters;
	while (*link && *link != waiter) link = &(*link)->next;
	if (*link) *link = waiter->next;
}

int aio_suspend(const struct aiocb *const list[], int count,
	const struct timespec *timeout)
{
	struct aio_waiter waiter;
	long long start = 0, deadline = 0;
	__plat_handle_t handles[2];
	__plat_handle_t signal_event;
	unsigned long caught = __sig_caught_count();
	int any, handle_count;
	if (count < 0 || !timeout_valid(timeout)) { errno = EINVAL; return -1; }
	if (timeout) {
		start = __plat_query_system_time();
		deadline = timeout_deadline(timeout, start);
	}

	/* Avoids creating an event on the synchronous fallback path, where every
	 * valid request is already done. */
	__sig_lock();
	if (suspend_list_ready(list, count, &any) || !any) {
		__sig_unlock();
		return 0;
	}
	__sig_unlock();

	if (__plat_event_create(&waiter.event) < 0) { errno = EAGAIN; return -1; }
	waiter.list = list;
	waiter.count = count;
	waiter.triggered = 0;

	/* The second state check and registration share the producer's lock. A
	 * completion can therefore occur before the check or after registration,
	 * but never in a lost-wakeup gap between them. */
	__sig_lock();
	if (suspend_list_ready(list, count, &any) || !any) {
		__sig_unlock();
		__plat_close(waiter.event);
		return 0;
	}
	if (timeout && deadline <= start) {
		__sig_unlock();
		__plat_close(waiter.event);
		errno = EAGAIN;
		return -1;
	}
	waiter.next = waiters;
	waiters = &waiter;
	__sig_unlock();

	handles[0] = waiter.event;
	handle_count = 1;
	signal_event = __sig_delivery_event();
	if (signal_event) handles[handle_count++] = signal_event;
	for (;;) {
		long long now;
		int status;
		if (timeout) {
			now = __plat_query_system_time();
			if (now >= deadline) status = __PLAT_WAIT_TIMEOUT;
			else status = __plat_wait_any(handles, (unsigned)handle_count, 1,
			                              1, -(deadline - now));
		} else {
			status = __plat_wait_any(handles, (unsigned)handle_count, 1, 0, 0);
		}

		__sig_drain_pending();
		__sig_lock();
		if (waiter.triggered || suspend_list_ready(list, count, &any) || !any) {
			remove_waiter_locked(&waiter);
			__sig_unlock();
			__plat_close(waiter.event);
			return 0;
		}
		if (__sig_caught_count() != caught || status == __PLAT_WAIT_TIMEOUT ||
		    status == __PLAT_WAIT_ERROR) {
			int wait_error = status == __PLAT_WAIT_ERROR;
			remove_waiter_locked(&waiter);
			__sig_unlock();
			__plat_close(waiter.event);
			errno = status == __PLAT_WAIT_TIMEOUT ? EAGAIN : wait_error ? EINVAL : EINTR;
			return -1;
		}
		__sig_unlock();
	}
}

/* cb is deliberately not required: POSIX says a NULL aiocbp cancels every
 * outstanding cancelable I/O operation, which `cb && request->cb != cb`
 * below implements. */
int aio_cancel(int fd, struct aiocb *cb)
{
	struct sigevent notifications[AIO_MAX * 2];
	int notification_count = 0;
	int matched = 0, canceled = 0, running = 0;
	int i;
	if (!__fd_get(fd)) return -1;
	__sig_lock();
	for (i = 0; i < AIO_MAX; i++) {
		struct aio_request *request = &requests[i];
		struct aiocb *req_cb;
		struct sigevent individual, group;
		int have_individual, have_group;
		if (request->state == REQ_FREE) continue;
		req_cb = request->cb;
		/* req_cb is set together with leaving REQ_FREE in submit(), and
		 * cleared together with returning to it -- not visible here
		 * across the struct field. Read into a local once: re-reading
		 * request->cb after finish_locked() (below) has already taken
		 * request through another call makes the checker treat each
		 * re-read as a fresh, unrelated value. */
		__ownership_pointer_nonnull(req_cb);
		if (req_cb->aio_fildes != fd || (cb && req_cb != cb))
			continue;
		matched = 1;
		if (request->state == REQ_RUNNING) { running = 1; continue; }
		if (request->state == REQ_DONE) continue;
		finish_locked(request, ECANCELED, -1, &individual, &have_individual,
		              &group, &have_group);
		canceled = 1;
		if (have_individual) notifications[notification_count++] = individual;
		if (have_group) notifications[notification_count++] = group;
	}
	__sig_unlock();
	for (i = 0; i < notification_count; i++) notify(&notifications[i]);
	if (running) return AIO_NOTCANCELED;
	if (canceled) return AIO_CANCELED;
	(void)matched;
	return AIO_ALLDONE;
}

static struct aio_group *group_alloc(int count, const struct sigevent *event)
{
	struct aio_group *group = 0;
	int i;
	__sig_lock();
	for (i = 0; i < AIO_MAX; i++)
		if (!groups[i].active) { group = &groups[i]; break; }
	if (group) {
		memset(group, 0, sizeof *group);
		group->active = 1;
		group->remaining = count;
		if (event) group->event = *event;
		else group->event.sigev_notify = SIGEV_NONE;
	}
	__sig_unlock();
	return group;
}

static void group_drop(struct aio_group *group)
{
	struct sigevent event;
	int send = 0;
	if (!group) return;
	__sig_lock();
	if (group->active && --group->remaining == 0) {
		event = group->event;
		send = event_wants_notify(&event);
		group->active = 0;
	}
	__sig_unlock();
	if (send) notify(&event);
}

int lio_listio(int mode, struct aiocb *const list[], int count,
	struct sigevent *event)
{
	struct aio_group *group = 0;
	const struct aiocb *pending[AIO_LISTIO_MAX];
	int candidates = 0, submitted = 0, failed = 0;
	int i, remaining;
	if ((mode != LIO_WAIT && mode != LIO_NOWAIT) || count < 0 ||
	    count > AIO_LISTIO_MAX || (event && !valid_event(event))) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < count; i++)
		if (list[i] && (list[i]->aio_lio_opcode == LIO_READ ||
		                list[i]->aio_lio_opcode == LIO_WRITE)) candidates++;
	if (mode == LIO_NOWAIT && candidates) {
		group = group_alloc(candidates, event);
		if (!group) { errno = EAGAIN; return -1; }
	}
	for (i = 0; i < count; i++) {
		struct aiocb *cb = list[i];
		int op;
		if (!cb || cb->aio_lio_opcode == LIO_NOP) continue;
		if (cb->aio_lio_opcode == LIO_READ) op = OP_READ;
		else if (cb->aio_lio_opcode == LIO_WRITE) op = OP_WRITE;
		else { failed = 1; continue; }
		if (submit(cb, op, group) < 0) {
			failed = 1;
			group_drop(group);
		} else pending[submitted++] = cb;
	}
	if (mode == LIO_NOWAIT) {
		if (!candidates && event) notify(event);
		if (failed) { errno = EIO; return -1; }
		return 0;
	}
	/* LIO_WAIT waits for every operation that was successfully queued,
	 * even when another list member had an invalid opcode. */
	remaining = submitted;
	while (remaining) {
		for (i = 0; i < submitted; i++) {
			if (!pending[i] || aio_error(pending[i]) == EINPROGRESS) continue;
			pending[i] = 0;
			remaining--;
		}
		if (remaining && aio_suspend(pending, submitted, 0) < 0) return -1;
	}
	if (failed) { errno = EIO; return -1; }
	return 0;
}

void __aio_reset_after_fork(void) NTLIBC_NO_THREAD_SAFETY_ANALYSIS;
void __aio_reset_after_fork(void)
{
	int i;
	for (i = 0; i < AIO_MAX; i++)
		if (requests[i].state != REQ_FREE && requests[i].cb)
			requests[i].cb->__opaque = 0;
	memset(requests, 0, sizeof requests);
	memset(groups, 0, sizeof groups);
	worker_wake = 0;
	worker_started = 0;
	worker_synchronous = 0;
	waiters = 0;
	next_sequence = 0;
	/* fork() carries over only the calling thread, never a worker spawned
	 * via __plat_thread_spawn(); the child has no worker until its own
	 * start_worker() call. worker_atexit_registered is deliberately NOT
	 * reset: fork() already copied the atexit() registration, and that
	 * entry re-reads these same globals at the child's own exit(). */
	worker_shutdown = 0;
	worker_exited = 0;
	worker_done_event = 0;
}

// NOLINTEND(misc-include-cleaner)
