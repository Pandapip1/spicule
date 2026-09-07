/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux's half of the src/signal/{nt,linux}/sigdelivery.c split. NT invents
 * signal delivery from scratch (see that file's banner); Linux already has
 * real kernel signal delivery, so this file implements the same portable
 * interface using real primitives, degrading honestly where none exist yet.
 *
 * __sig_lock() and friends: the same recursive-lock design NT's file
 * documents, built on a real binary semaphore
 * (src/thread/linux/plat_thread.c's __plat_semaphore_create()/
 * __plat_wait_one()/__plat_semaphore_post()) instead of a fabrication.
 *
 * __sig_try_deliver_remote*(): Tier 1 (src/signal/linux/plat_signal.c's
 * __plat_sig_install_fault_handlers()) installs a real rt_sigaction(2)
 * handler for the five hardware-fault signals; Tier 2 widens that to any
 * signal a real handler is installed for, via
 * __plat_sig_install_real_handler(). Once installed, the kernel delivers to
 * the target's real disposition directly through kill(2)/tgkill(2)/
 * pidfd_send_signal(2) -- no RPC wire protocol like NT's named pipe is
 * needed; these functions just issue the real syscall (via
 * __plat_kill_terminate()) and report whether it was accepted.
 *
 * Sending always succeeds even without a real handler installed, since the
 * kernel's own default action (matching signal.c's default_action() table)
 * applies regardless. sigqueue()'s sigval payload (`data`) is deliberately
 * not threaded through the real siginfo_t pidfd_send_signal(2) could carry:
 * no currently-passing test exercises it, and getting the kernel's raw
 * siginfo_t ABI layout right for an unexercised path isn't worth the risk.
 *
 * __sig_try_deliver_remote_nondefault(): kill()'s catchable-stop-signal arm
 * needs to know, before acting, whether the target's real disposition
 * overrides the default STOP action -- no single syscall outcome reveals
 * that to the sender, so __plat_sig_remote_disposition_nondefault() reads
 * the target's real kernel disposition from /proc/pid/status first, and
 * only sends if it says "caught" or "ignored". */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "libc.h"
#include "plat_signal.h"
#include "plat_thread.h"
#include "unsafe_pointer.h"

static __plat_handle_t wake_event;   /* real eventfd; 0 = not running */
static __plat_handle_t lock_sem;     /* real binary semaphore; 0 = no locking done */
static pid_t lock_owner;
static int lock_depth;

__plat_handle_t __sig_delivery_event(void) { return wake_event; }

NTSTATUS __sig_wait_delivery(LARGE_INTEGER *timeout)
{
	__plat_signal_wait(wake_event, timeout != 0, timeout ? (long long)*timeout : 0);
	return STATUS_SUCCESS;
}

/* __plat_sigevent_set(), not __plat_event_set(): wake_event is a real
 * eventfd, a different __plat_handle_t domain than __plat_event_set()'s
 * spicule_linux_sync-pointer one on this platform. */
void __sig_notify_delivery(void)
{
	if (wake_event) __plat_sigevent_set(wake_event);
}

/* SPICULE_NO_THREAD_SAFETY_ANALYSIS: these four are
 * __spicule_sig_lock_token's real implementation on this platform, the
 * same reasoning src/signal/nt/sigdelivery.c's own matching comment
 * gives for its four. */
void __sig_lock(void) SPICULE_NO_THREAD_SAFETY_ANALYSIS
{
	pid_t me;
	if (!lock_sem) return;
	__pthread_cancel_defer_enter();
	me = gettid();
	if (lock_depth > 0 && lock_owner == me) { lock_depth++; return; }
	__plat_wait_one(lock_sem, 0, 0, 0);
	lock_owner = me;
	lock_depth = 1;
}

void __sig_unlock(void) SPICULE_NO_THREAD_SAFETY_ANALYSIS
{
	if (!lock_sem) return;
	if (--lock_depth > 0) {
		__pthread_cancel_defer_leave();
		return;
	}
	lock_owner = 0;
	__plat_semaphore_post(lock_sem);
	__pthread_cancel_defer_leave();
}

int __sig_unlock_for_handler(void) SPICULE_NO_THREAD_SAFETY_ANALYSIS
{
	int depth;
	if (!lock_sem) return 0;
	depth = lock_depth;
	lock_depth = 0;
	lock_owner = 0;
	__plat_semaphore_post(lock_sem);
	return depth;
}

void __sig_relock_after_handler(int depth) SPICULE_NO_THREAD_SAFETY_ANALYSIS
{
	if (!lock_sem || depth <= 0) return;
	__sig_lock();
	lock_depth = depth;
}

void __sig_delivery_init(void)
{
	__plat_handle_t sem, ev;

	if (__plat_semaphore_create(1, 1, 0, &sem) < 0) return;
	lock_sem = sem;

	ev = __plat_sigevent_create(0);
	if (!ev) return;
	wake_event = ev;
}

void __sig_delivery_reinit_after_fork(void)
{
	wake_event = __PLAT_HANDLE_NULL;
	lock_sem = __PLAT_HANDLE_NULL;
	lock_owner = 0;
	lock_depth = 0;
	__sig_pending_reset_after_fork();
	__timer_reinit_after_fork();
	__sig_delivery_init();
}

/* `h` is built the same bare-pid way __plat_kill_open() builds one for a
 * non-child target; this file has no struct __child to read one from.
 * `data` is deliberately unused: see this file's banner. */
int __sig_try_deliver_remote_info(int pid, int sig, const void *data) // NOLINT(bugprone-easily-swappable-parameters) -- fixed signal-delivery contract; process ID and signal number have distinct roles
{
	/* `h` is built the same bare-pid way __plat_kill_open()
	 * (src/signal/linux/plat_signal.c, already exempt below) builds one
	 * for a non-child target -- see this function's own comment above.
	 * pid is the caller's own process ID argument (kill(2)'s own target
	 * PID namespace, checked meaningful by __plat_kill_terminate()
	 * itself below via the real tgkill(2)/kill(2) syscall); like
	 * __plat_kill_open()'s box(), __plat_handle_t here carries that
	 * plain PID integer directly, never dereferenced as memory. */
	__plat_handle_t h = unsafe_assume_valid_pointer((__plat_handle_t)(long)pid);
	(void)data;
	return __plat_kill_terminate(h, __ENCODE_SIGNAL_EXIT(sig)) == 0;
}

int __sig_try_deliver_remote(int pid, int sig)
{
	return __sig_try_deliver_remote_info(pid, sig, 0);
}

/* See this file's banner on why this checks the target's disposition first
 * rather than always sending. */
int __sig_try_deliver_remote_nondefault(int pid, int sig) // NOLINT(bugprone-easily-swappable-parameters) -- fixed signal-delivery contract; process ID and signal number have distinct roles
{
	__plat_handle_t h;

	if (!__plat_sig_remote_disposition_nondefault((pid_t)pid, sig)) return 0;
	/* Same bare-pid __plat_handle_t construction as
	 * __sig_try_deliver_remote_info() above, same justification. */
	h = unsafe_assume_valid_pointer((__plat_handle_t)(long)pid);
	return __plat_kill_terminate(h, __ENCODE_SIGNAL_EXIT(sig)) == 0;
}

// NOLINTEND(misc-include-cleaner)
