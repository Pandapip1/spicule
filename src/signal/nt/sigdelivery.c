/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Cross-process signal delivery, phase 1.
 *
 * Every process that has run __signal_init() owns a named pipe
 * (\Device\NamedPipe\ntlibc-sig.<pid>) and a dedicated thread blocked
 * reading it. kill() to another ntlibc process writes a packet to that
 * pipe instead of guessing its disposition; the target's own delivery
 * thread queues it, and an eligible application thread drains it at a
 * signal-aware safe point under its own sigprocmask().
 *
 * Deliberately NOT implemented: thread-context hijacking (interrupting
 * a thread mid-instruction, as a real kernel or Cygwin's exceptions.cc
 * would). A signal that arrives while the target thread is off running
 * ordinary code stays pending until its next safe point; only
 * select()'s poll loop is taught to notice a fresh delivery early,
 * since it already polls. NtCancelSynchronousIoFile, which would let a
 * blocked read()/write() be interrupted too, is a stub in ReactOS's
 * ntdll and unused here for that reason.
 *
 * Two NT pipe mechanics this leans on (verified against ReactOS's
 * npfs.sys, the only available source for this wire behavior):
 *   - Opening a pipe path with no listener fails synchronously
 *     (STATUS_OBJECT_NAME_NOT_FOUND), not the Win32 CreateFile
 *     "wait for a free instance" behavior -- so kill() to a pid with no
 *     listener fails fast, never hangs.
 *   - A server instance is only readable once "connected"; a fresh
 *     instance starts "listening", and reading it directly fails with
 *     STATUS_PIPE_LISTENING instead of blocking. FSCTL_PIPE_LISTEN is
 *     what actually blocks for a client -- skipping it works once, for
 *     the first sender, then silently drops every sender after.
 *
 * Whether a reused pipe instance can safely go back through
 * FSCTL_PIPE_LISTEN after its client disconnects is untested (a
 * plausible driver-bugcheck route in ReactOS, and real Windows behavior
 * here isn't inspectable), so this code never reuses an instance: it
 * always publishes a fresh listening instance before acknowledging the
 * request it just served, serialized across processes by a per-target
 * named NT mutant.
 *
 * Locking: sig_delivery_thread() calls __raise_internal() concurrently
 * with the application thread, both touching signal.c's shared
 * dispositions and pending queue. __sig_lock()/__sig_unlock() below are
 * a recursive mutex (the application's handler callback runs with it
 * released) that signal.c acquires around every entry point and every
 * __raise_internal() call; __raise_internal() itself assumes the caller
 * already holds it. */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <signal.h>
#include <unistd.h>
#include <unistd.h>
#include <string.h>
#include "libc.h"
#include "plat_signal.h"
#include "plat_fd.h"
#include "conin.h"

/* One fixed-size NT message per signal. FILE_PIPE_MESSAGE_TYPE makes
 * "one NtWriteFile call == one NtReadFile call" an NT-enforced guarantee,
 * unlike src/unistd/pipe.c's byte-stream anonymous pipes. */
struct sigpacket {
	ULONG magic;
	ULONG signo;
	ULONG flags;
	ULONG sender_pid;
	ULONG sender_uid;
	LONG code;
	union sigval value;
};
#define SIGPACKET_MAGIC 0x736c746eu /* "ntls", little-endian as stored */
#define SIGPACKET_NONDEFAULT_ONLY 1u

static __plat_handle_t wake_event;   /* auto-reset; set on every packet arrival. 0 = not running. */
static HANDLE lock_event;   /* auto-reset-as-mutex, initially signalled (free). 0 = no locking done. */
static __plat_handle_t send_mutant;  /* named per target; serializes clients across processes. */

/* RECURSIVE, deliberately: internal signal paths can nest before or after a
 * user handler, even though the handler callback itself temporarily drops the
 * lock. lock_owner/lock_depth let the owning thread re-enter without waiting
 * on itself, while a genuinely different thread still blocks for real; a torn
 * read of a stale owner only ever costs a spurious real wait, never a wrong
 * grant, since lock_event is the actual exclusion. */
static pid_t lock_owner;
static int lock_depth;

/* Not exposed as a variable so a caller outside this file can never
 * accidentally close or signal wake_event directly. */
__plat_handle_t __sig_delivery_event(void) { return wake_event; }

/* Waits alertably so timer APCs remain deliverable. A set that lands between
 * a caller's state check and this wait is retained by the auto-reset event,
 * closing the lost-wakeup window without a polling slice.
 *
 * Signature (NTSTATUS return, LARGE_INTEGER* parameter) is fixed: src/unistd/
 * sleep.c calls this directly with a LARGE_INTEGER it builds itself. No
 * caller inspects the returned status. */
NTSTATUS __sig_wait_delivery(LARGE_INTEGER *timeout)
{
	__plat_signal_wait(wake_event, timeout != 0, timeout ? (long long)*timeout : 0);
	return STATUS_SUCCESS;
}

void __sig_notify_delivery(void)
{
	if (wake_event) __plat_event_set(wake_event);
}

/* NTLIBC_NO_THREAD_SAFETY_ANALYSIS: this and the next three functions are
 * __ntlibc_sig_lock_token's actual implementation over the raw NT primitives
 * (lock_event/lock_owner/lock_depth), which a lockset checker cannot see
 * through; every caller still sees the ACQUIRE()/RELEASE() contract from
 * libc.h. */
void __sig_lock(void) NTLIBC_NO_THREAD_SAFETY_ANALYSIS
{
	pid_t me;
	if (!lock_event) return;
	/* Deferred, not unsafe: __sig_lock()/__sig_unlock() run around ordinary
	 * POSIX-legal blocking calls (sleep(), sigwait(), ...), not only inside
	 * calls the application made async-cancel-unsafe on purpose. Treating this
	 * region as unsafe would abort the process if an async cancellation lands
	 * while a thread is merely checking pending signals. Deferring lets the
	 * cancellation wait for this lock to be released and then deliver promptly. */
	__pthread_cancel_defer_enter();
	me = gettid();
	if (lock_depth > 0 && lock_owner == me) { lock_depth++; return; }
	NtWaitForSingleObject(lock_event, 0, 0);
	lock_owner = me;
	lock_depth = 1;
}

void __sig_unlock(void) NTLIBC_NO_THREAD_SAFETY_ANALYSIS
{
	LONG prev;
	if (!lock_event) return;
	if (--lock_depth > 0) {
		__pthread_cancel_defer_leave();
		return;
	}
	lock_owner = 0;
	NtSetEvent(lock_event, &prev);
	__pthread_cancel_defer_leave();
}

/* Publish delivery state before entering application code, then let other
 * threads make progress while the handler runs. Preserve recursion depth so
 * the internal caller which eventually unwinds still owns exactly the
 * acquisitions it made before the callback. */
int __sig_unlock_for_handler(void) NTLIBC_NO_THREAD_SAFETY_ANALYSIS
{
	LONG previous;
	int depth;
	if (!lock_event) return 0;
	depth = lock_depth;
	lock_depth = 0;
	lock_owner = 0;
	NtSetEvent(lock_event, &previous);
	return depth;
}

void __sig_relock_after_handler(int depth) NTLIBC_NO_THREAD_SAFETY_ANALYSIS
{
	if (!lock_event || depth <= 0) return;
	__sig_lock();
	lock_depth = depth;
}

/* \Device\NamedPipe\ntlibc-sig.<pid, 8 hex digits> -- one signal pipe per
 * process, named by the pid kill()'s caller already has in hand. */
static void sig_pipe_name(pid_t pid, WCHAR *name, UNICODE_STRING *us)
{
	static const char pfx[] = "\\Device\\NamedPipe\\ntlibc-sig.";
	int i = 0;

	for (; pfx[i]; i++) name[i] = (unsigned char)pfx[i];
	i = __nt_append_hex32(name, i, (unsigned)pid);
	name[i] = 0;
	us->Buffer = name;
	if ((size_t)i > __US_MAX_WCHARS) {
		us->Length = us->MaximumLength = 0;
		return;
	}
	us->Length = (USHORT)(i * sizeof(WCHAR));
	us->MaximumLength = (USHORT)(us->Length + sizeof(WCHAR));
}

/* All clients of one target take this named kernel mutant around their
 * request/reply exchange.  A process-private pthread lock cannot order
 * kill() calls made by different processes, while an NT mutant is shared by
 * name and is released by the kernel if a sender dies while owning it. */
static void sig_send_lock_name(pid_t pid, WCHAR *name, UNICODE_STRING *us)
{
	static const char pfx[] = "\\BaseNamedObjects\\ntlibc-sig-send.";
	int i = 0;

	for (; pfx[i]; i++) name[i] = (unsigned char)pfx[i];
	i = __nt_append_hex32(name, i, (unsigned)pid);
	name[i] = 0;
	us->Buffer = name;
	if ((size_t)i > __US_MAX_WCHARS) {
		us->Length = us->MaximumLength = 0;
		return;
	}
	us->Length = (USHORT)(i * sizeof(WCHAR));
	us->MaximumLength = (USHORT)(us->Length + sizeof(WCHAR));
}

/* One per process, started by __sig_delivery_init() and never joined or
 * cancelled -- NT tears down every thread at process exit. `arg` is the
 * first listening pipe, created synchronously by init so a kill() sender
 * can never race this thread's own not-yet-scheduled startup. */
static ULONG NTAPI sig_delivery_thread(PVOID arg)
{
	pid_t pid = getpid();
	WCHAR name[40];
	UNICODE_STRING us;
	__plat_handle_t pipe = (__plat_handle_t)arg;

	sig_pipe_name(pid, name, &us);

	for (;;) {
		if (!pipe) pipe = __plat_signal_pipe_create(&us);
		if (!pipe) {
			/* No caller to report failure to; retry after a backoff rather than
			 * leaving this process deaf to cross-process signals permanently. */
			__plat_signal_backoff();
			continue;
		}

		/* Block until a client connects -- see this file's banner for
		 * why a plain read here would only ever work once. */
		if (__plat_signal_pipe_listen(pipe)) {
			struct sigpacket pkt;
			size_t got = 0;
			memset(&pkt, 0, sizeof pkt);
			if (__plat_signal_pipe_read(pipe, &pkt, sizeof pkt, &got) == 0 && got == sizeof pkt) {
				siginfo_t si;
				__plat_handle_t next;
				unsigned char accepted = pkt.magic == SIGPACKET_MAGIC &&
					pkt.signo > 0 && pkt.signo < _NSIG;

				if (accepted && (pkt.flags & SIGPACKET_NONDEFAULT_ONLY)) {
					__sig_lock();
					if (__sig_disposition_is_default((int)pkt.signo))
						accepted = 0;
					__sig_unlock();
				}

				/* Publish the next listening instance before acknowledging this
				 * one; send_mutant keeps other senders out of NtOpenFile until
				 * this reply releases it, so there's no close/recreate race. */
				next = __plat_signal_pipe_create(&us);
				if (!next) accepted = 0;

				if (accepted) {
					memset(&si, 0, sizeof si);
					si.si_signo = (int)pkt.signo;
					si.si_code = (int)pkt.code;
					si.si_pid = (pid_t)pkt.sender_pid;
					si.si_uid = (uid_t)pkt.sender_uid;
					si.si_value = pkt.value;
					/* Never deliver on this service thread: its empty TLS mask is
					 * unrelated to every POSIX application thread's mask. */
					__sig_queue_process_info((int)pkt.signo, &si);
					/* Publish the wake only after the record is visible.  A waiter
					 * which drains immediately must not observe an empty queue. */
					__sig_notify_delivery();
				}

				{
					size_t sent = 0;
					__plat_signal_pipe_write(pipe, &accepted, sizeof accepted, &sent);
				}
				__plat_close(pipe);
				pipe = next;
				continue;
			}
		}

		/* Same handoff invariant as the acknowledged path: publish a
		 * replacement even for a malformed or disconnected client. */
		{
			__plat_handle_t next = __plat_signal_pipe_create(&us);
			__plat_close(pipe);
			pipe = next;
		}
	}
	/* Unreachable; present only because NTAPI thread functions return ULONG
	 * and tools/lint.sh's gcc pass wants an explicit return after for(;;). */
	return 0;
}

/* __signal_init() calls this once at process startup. Every failure here
 * degrades rather than aborting startup: __sig_try_deliver_remote() below
 * simply never succeeds for this process, and kill() falls back to
 * default-disposition-only behaviour, same as targeting a non-ntlibc process. */
void __sig_delivery_init(void)
{
	UNICODE_STRING lock_us, pipe_us;
	WCHAR lock_name[48], pipe_name[40];
	__plat_handle_t ev, mutant, pipe, thr;
	pid_t pid;

	/* The mutex is created independently of everything below: every signal.c
	 * entry point calls __sig_lock()/__sig_unlock() regardless of whether
	 * this process ever gets a working pipe or delivery thread. */
	ev = __plat_sigevent_create(1);
	if (ev) lock_event = ev;

	ev = __plat_sigevent_create(0);
	if (!ev) return;

	pid = getpid();
	sig_send_lock_name(pid, lock_name, &lock_us);
	mutant = __plat_signal_mutant_create(&lock_us);
	if (!mutant) { __plat_close(ev); return; }
	send_mutant = mutant;

	/* Created and published here, not in the new thread: NtCreateThreadEx
	 * returning only means the thread object exists, not that it has run,
	 * so a not-yet-scheduled listener could otherwise miss an early sender.
	 * A client connecting before the thread reaches FSCTL_PIPE_LISTEN is
	 * handled as STATUS_PIPE_CONNECTED by the loop above. */
	sig_pipe_name(pid, pipe_name, &pipe_us);
	pipe = __plat_signal_pipe_create(&pipe_us);
	if (!pipe) {
		send_mutant = __PLAT_HANDLE_NULL;
		__plat_close(mutant);
		__plat_close(ev);
		return;
	}

	if (__plat_thread_start((void *)sig_delivery_thread, pipe, &thr) < 0) {
		send_mutant = __PLAT_HANDLE_NULL;
		__plat_close(pipe);
		__plat_close(mutant);
		__plat_close(ev);
		return;
	}

	/* Published only after the thread exists: select() reads wake_event from
	 * another thread's writes, and a not-yet-set event is indistinguishable
	 * from "not running" for its purposes, so there's no benefit to earlier. */
	wake_event = ev;
	__plat_close(thr);  /* the thread runs detached; nothing here ever waits on or terminates it */
}

/* RtlCloneUserProcess clones only the calling thread, so sig_delivery_thread()
 * does not exist in the child; wake_event/lock_event/send_mutant are stale
 * handle values naming nothing live in this process (or worse, whatever the
 * kernel has since recycled onto that slot). Never NtClose()'d or waited on
 * for that reason -- just forget them and build fresh ones under the child's
 * own pid. */
void __sig_delivery_reinit_after_fork(void)
{
	wake_event = 0;
	lock_event = 0;
	send_mutant = 0;
	__sig_pending_reset_after_fork();
	__timer_reinit_after_fork();
	__conin_reinit_after_fork();
	__sig_delivery_init();
}

/* kill()'s cross-process arm, called before its default-action-only
 * (NtTerminateProcess) fallback. Returns nonzero only if the target's own
 * listener accepted the packet; any failure -- no such process, a
 * non-ntlibc process, or one still inside __signal_init() -- returns 0 and
 * lets kill() fall through unchanged.
 *
 * Catchable stop signals set nondefault_only: the target snapshots its
 * disposition under __sig_lock() and replies zero when the sender must use
 * the default NtSuspendProcess action instead. */
static int sig_try_deliver_remote_info(int pid, int sig, const void *data, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
				       int nondefault_only)
{
	const siginfo_t *si = data;
	WCHAR name[48];
	UNICODE_STRING us, lock_us;
	__plat_handle_t h, mutant;
	struct sigpacket pkt;
	unsigned char accepted = 0;
	size_t sent, got;

	sig_send_lock_name(pid, name, &lock_us);
	mutant = __plat_signal_mutant_create(&lock_us);
	if (!mutant) return 0;
	if (!__plat_wait_acquire(mutant)) { __plat_close(mutant); return 0; }

	sig_pipe_name(pid, name, &us);
	/* The named mutant plus replacement-before-reply handoff means a
	 * cooperating sender never observes a missing or busy instance between
	 * two successful requests; no retry or timeout needed. */
	h = __plat_signal_pipe_open(&us);
	if (!h) goto out;

	pkt.magic = SIGPACKET_MAGIC;
	pkt.signo = (ULONG)sig;
	pkt.flags = nondefault_only ? SIGPACKET_NONDEFAULT_ONLY : 0;
	pkt.sender_pid = (ULONG)(si ? si->si_pid : getpid());
	pkt.sender_uid = (ULONG)(si ? si->si_uid : getuid());
	pkt.code = (LONG)(si ? si->si_code : SI_USER);
	if (si) pkt.value = si->si_value;
	else memset(&pkt.value, 0, sizeof pkt.value);
	sent = 0; got = 0;
	if (__plat_signal_pipe_write(h, &pkt, sizeof pkt, &sent) == 0 && sent == sizeof pkt) {
		if (__plat_signal_pipe_read(h, &accepted, sizeof accepted, &got) != 0 || got != sizeof accepted)
			accepted = 0;
	}
	__plat_close(h);
out:
	__plat_mutant_release(mutant);
	__plat_close(mutant);
	return accepted != 0;
}

int __sig_try_deliver_remote_info(int pid, int sig, const void *data)
{
	return sig_try_deliver_remote_info(pid, sig, data, 0);
}

int __sig_try_deliver_remote(int pid, int sig)
{
	return __sig_try_deliver_remote_info(pid, sig, 0);
}

int __sig_try_deliver_remote_nondefault(int pid, int sig)
{
	return sig_try_deliver_remote_info(pid, sig, 0, 1);
}

// NOLINTEND(misc-include-cleaner)
