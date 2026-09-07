/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Signals, as far as they can be had.
 *
 * Self-generated signals (raise(), abort(), a broken-pipe write, hardware
 * faults arriving as NT exceptions via the vectored exception handler)
 * are synchronous: __raise_internal() runs directly on the generating
 * thread, as always.
 *
 * kill() to another process hands the target's own listener a packet (see
 * sigdelivery.c) so ITS delivery thread drives its real disposition
 * through __raise_internal(); this never hijacks the target thread's
 * register state (no SuspendThread/SetThreadContext IP rewrite, the way a
 * kernel or Cygwin does it), so delivery is only guaranteed the next time
 * the target thread checks for a signal -- sig_delivery_thread() itself,
 * or a signal-aware wait.
 *
 * Console control events arrive through kernel32's console control handler,
 * not NT exceptions: conhost dispatches them by having user32 inject a
 * thread into this process, so there really is no ntdll path to them. With
 * NTLIBC_USE_KERNEL32, __signal_init() turns CTRL_C_EVENT/CTRL_BREAK_EVENT
 * into SIGINT the same way the vectored handler turns DBG_CONTROL_C/
 * DBG_CONTROL_BREAK into one.
 *
 * Ctrl-C does have an ntdll path, just not that one: a program that leaves
 * canonical mode takes the console's line discipline over
 * (src/internal/nt/conin.c), and the interrupt character then arrives as
 * an ordinary 0x03 byte that this library turns into SIGINT itself. Ctrl-C
 * outside that case, and Ctrl-Break in every case, still need the control
 * handler above; without it the default console behavior (ending the
 * process) stands.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "libc.h"
#include "plat_signal.h"
#include "plat_fd.h"
#include "plat_misc.h"
#include "unsafe_pointer.h"
#ifdef NTLIBC_USE_KERNEL32
#include "kernel32.h"
#endif

/* Dispositions, guarded by __sig_lock()/__sig_unlock() -- see this file's
 * own note further down and sigdelivery.c's banner ("Locking."), which
 * says outright that signal.c acquires that lock around every external
 * entry point touching this state. */
static void (*handlers[_NSIG])(int) NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static __thread sigset_t blocked;

/* Standard signals coalesce while pending. Real-time signals retain one
 * record per generation, in FIFO order within a signal number.  Selection
 * scans signal numbers first, which gives POSIX's lowest-real-time-signal
 * priority without disturbing that FIFO. */
struct pending_state {
	sigset_t set;
	siginfo_t info[SIGQUEUE_MAX];
	int count;
};
/* The process-wide queue, guarded the same way handlers[] above is; the
 * per-thread one right below it is TLS and needs no lock at all. */
static struct pending_state process_pending NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static __thread struct pending_state thread_pending;
/* raise() is thread-directed.  Other entries into __raise_internal_info()
 * are process-directed and retain the shared pending queue used by the
 * cross-process delivery thread. */
static __thread int thread_directed;
static __thread sigset_t waiting_set;
static __thread int wait_active;

/* Per-signal sa_mask/sa_flags, as installed by sigaction().  signal()
 * and sigset() leave these at their zero-initialized defaults (empty
 * mask, no flags), matching their simpler contract.  Same lock as
 * handlers[] above -- sigaction() installs all three together. */
static sigset_t act_mask[_NSIG] NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);
static int act_flags[_NSIG] NTLIBC_GUARDED_BY(__ntlibc_sig_lock_token);

static int sig_valid(int sig) { return sig > 0 && sig < _NSIG; }

void __sig_current_mask_copy(sigset_t *mask)
{
	*mask = blocked;
}

void __sig_current_mask_install(const sigset_t *mask)
{
	blocked = *mask;
	memset(&thread_pending, 0, sizeof thread_pending);
}

/* Set only by exception_handler(), immediately around its call into
 * __raise_internal(), so a SIGSEGV/SIGBUS/SIGILL/SIGFPE handler installed
 * with SA_SIGINFO can distinguish a hardware fault from kill()/raise(). The
 * metadata is thread-local because the signal lock is released around the
 * user callback and another thread may deliver independently. */
static __thread int fault_active;
static __thread void *fault_addr;
static __thread int fault_si_code;   /* computed by exception_handler(), see there */

static void make_siginfo(siginfo_t *si, int sig)
{
	memset(si, 0, sizeof *si);
	si->si_signo = sig;
	if (fault_active) {
		si->si_code = fault_si_code;
		si->si_addr = fault_addr;
	} else {
		si->si_code = SI_USER;
		si->si_pid = getpid();
		si->si_uid = getuid();
	}
}

static int queue_pending_to(struct pending_state *state, int sig,
			    const siginfo_t *si)
{
	int realtime = sig >= SIGRTMIN && sig <= SIGRTMAX;
	if (!realtime && sigismember(&state->set, sig)) return 0;
	if (state->count >= SIGQUEUE_MAX) { errno = EAGAIN; return -1; }
	state->info[state->count++] = *si;
	sigaddset(&state->set, sig);
	__sig_notify_delivery();
	return 0;
}

static int queue_pending(int sig, const siginfo_t *si)
{
	return queue_pending_to(thread_directed ? &thread_pending : &process_pending,
	                        sig, si);
}

static int take_pending_signal_from(struct pending_state *state, int sig,
				    siginfo_t *si)
{
	int i;
	for (i = 0; i < state->count; i++) {
		if (state->info[i].si_signo != sig) continue;
		if (si) *si = state->info[i];
		state->count--;
		for (; i < state->count; i++) state->info[i] = state->info[i + 1];
		for (i = 0; i < state->count; i++)
			if (state->info[i].si_signo == sig) return 1;
		sigdelset(&state->set, sig);
		return 1;
	}
	/* Accommodate pending state copied from an older process image or
	 * produced before the queue existed: it has no payload, but it is
	 * still a real pending signal and must remain consumable. */
	if (sigismember(&state->set, sig)) {
		if (si) make_siginfo(si, sig);
		sigdelset(&state->set, sig);
		return 1;
	}
	return 0;
}

static int pending_member(int sig)
{
	return sigismember(&thread_pending.set, sig) ||
	       sigismember(&process_pending.set, sig);
}

static int take_pending_signal(int sig, siginfo_t *si)
{
	if (sigismember(&thread_pending.set, sig))
		return take_pending_signal_from(&thread_pending, sig, si);
	return take_pending_signal_from(&process_pending, sig, si);
}

static int take_pending_from_set(const sigset_t *set, siginfo_t *si)
{
	int sig;
	for (sig = 1; sig < _NSIG; sig++)
		if (sigismember(set, sig) && pending_member(sig)) {
			take_pending_signal(sig, si);
			return sig;
		}
	return 0;
}

/* Entry count for signal-catching functions, read via __sig_caught_count()
 * by sleep()/nanosleep() to distinguish "handler ran" (ends the wait with
 * EINTR) from "signal ignored" (interval keeps running) -- a counter, not
 * a flag, so a caller can diff against a value taken before the wait.
 * Separate process/thread counters keep one thread's handler from
 * spuriously interrupting another thread's wait. */
static unsigned long caught_count;
static __thread unsigned long thread_caught_count;
static __thread unsigned long thread_restart_count;

unsigned long __sig_caught_count(void) { return caught_count; }
unsigned long __sig_thread_caught_count(void) { return thread_caught_count; }
unsigned long __sig_thread_restart_count(void) { return thread_restart_count; }

static int default_action(int sig);
static int sig_stops(int sig);

/* SA_NOCLDWAIT: a later wait()/waitpid() must not find a child born while
 * it's set (POSIX wait.html ECHILD: "status information is not
 * retained"). children.c's __child_add() checks this before tracking a
 * new child, the same "leave it untracked" degrade used when the table
 * itself cannot grow. */
int __sigchld_nocldwait(void)
{
	int result;
	__sig_lock();
	result = (act_flags[SIGCHLD] & SA_NOCLDWAIT) != 0;
	__sig_unlock();
	return result;
}

/* Called by sig_delivery_thread() with the signal lock held.  Stop-shaped
 * signals need this distinction before kill() chooses between running the
 * target's caught/ignored disposition and applying the default NT process
 * suspension itself. */
int __sig_disposition_is_default(int sig)
{
	return !sig_valid(sig) || handlers[sig] == SIG_DFL;
}

void (*signal(int sig, void (*h)(int)))(int)
{
	void (*old)(int);
	if (!sig_valid(sig) || sig == SIGKILL || sig == SIGSTOP) { errno = EINVAL; return SIG_ERR; }
	__sig_lock();
	old = handlers[sig];
	handlers[sig] = h;
	/* See plat_signal.h's own comment on __plat_sig_sync_kernel(): keeps
	 * a signal the kernel itself can raise synchronously out of a
	 * syscall (SIGPIPE from write(), chief among them) actually ignored/
	 * restored at the point the kernel decides whether to act, matching
	 * what `old`/`h` already say here. */
	if (h == SIG_IGN) __plat_sig_sync_kernel(sig, 1);
	else if (old == SIG_IGN) __plat_sig_sync_kernel(sig, 0);
#ifdef __linux__
	/* Mirror a catchable disposition into a real rt_sigaction(2) too, so
	 * kill()/tgkill()/pidfd_send_signal() from another process reach it
	 * (see plat_signal.h, linux/sigdelivery.c). Not needed for SIG_IGN/
	 * SIG_DFL -- a previously installed real dispatch is safe to leave
	 * in place. */
	if (h != SIG_IGN && h != SIG_DFL) __plat_sig_install_real_handler(sig);
#endif
	if (h == SIG_IGN || (h == SIG_DFL && !default_action(sig))) {
		sigdelset(&process_pending.set, sig);
		sigdelset(&thread_pending.set, sig);
	}
	__sig_unlock();
	return old;
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
{
	if (!sig_valid(sig) || sig == SIGKILL || sig == SIGSTOP) { errno = EINVAL; return -1; }
	/* Locked for the whole read-then-write: sig_delivery_thread()
	 * (src/signal/sigdelivery.c) reads handlers[]/act_mask[]/act_flags[]
	 * inside __raise_internal() on its own thread, and a caller reading
	 * `old` back here is entitled to a consistent snapshot rather than
	 * one torn between an in-flight update and a concurrent delivery. */
	__sig_lock();
	if (old) {
		memset(old, 0, sizeof *old);
		old->sa_handler = handlers[sig];
		old->sa_mask = act_mask[sig];
		old->sa_flags = act_flags[sig];
	}
	if (act) {
		void (*prev)(int) = handlers[sig];
		handlers[sig] = act->sa_handler;
		/* signal()'s own matching call above -- see plat_signal.h's
		 * comment on __plat_sig_sync_kernel(). */
		if (act->sa_handler == SIG_IGN) __plat_sig_sync_kernel(sig, 1);
		else if (prev == SIG_IGN) __plat_sig_sync_kernel(sig, 0);
#ifdef __linux__
		/* signal()'s own matching call above -- see plat_signal.h's
		 * comment on __plat_sig_install_real_handler(). */
		if (act->sa_handler != SIG_IGN && act->sa_handler != SIG_DFL)
			__plat_sig_install_real_handler(sig);
#endif
		if (act->sa_handler == SIG_IGN ||
		    (act->sa_handler == SIG_DFL && !default_action(sig))) {
			sigdelset(&process_pending.set, sig);
			sigdelset(&thread_pending.set, sig);
		}
		act_mask[sig] = act->sa_mask;
		/* SA_RESTART only matters to select()/pselect() (see select.c);
		 * every other blocking point can't be interrupted mid-syscall
		 * (no NtCancelSynchronousIoFile, see sigdelivery.c), so elsewhere
		 * it's just round-tripped through sigaction(..., &old).
		 *
		 * SA_ONSTACK is implemented: sig_dispatch() switches to the
		 * sigaltstack() stack around the handler call, cheap because
		 * delivery is synchronous and this library owns the call site
		 * (src/signal/$ARCH/altstack.S).
		 *
		 * SA_NOCLDSTOP suppresses SIGCHLD when kill() stops/continues a
		 * tracked child. SA_RESTORER is stored but unused. SA_NODEFER,
		 * SA_RESETHAND and SA_SIGINFO are genuinely implemented. */
		act_flags[sig] = act->sa_flags;
	}
	__sig_unlock();
	return 0;
}

static int default_action(int sig)
{
	switch (sig) {
	case SIGCHLD: case SIGURG: case SIGWINCH: case SIGCONT:
		return 0;   /* ignore */
	default:
		return 1;   /* terminate */
	}
}

/* A process that stops itself cannot update its parent's private child
 * table.  Publish the transition through an auto-reset named event before
 * entering NtSuspendProcess; waitpid() consumes that one notification and
 * records the ordinary __W_STOPPED status in its own table. */
static __plat_handle_t self_stop_event;
static pid_t self_stop_owner;
static int self_stop_signal;

static void stop_event_name(pid_t pid, int sig, WCHAR name[56], // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
			    UNICODE_STRING *us)
{
	static const char prefix[] = "\\BaseNamedObjects\\ntlibc-stop.";
	unsigned upid = (unsigned)pid;
	unsigned usig = (unsigned)sig;
	int i = 0, n;

	for (; prefix[i]; i++) name[i] = (unsigned char)prefix[i];
	for (n = 8; n > 0;) {
		n--;
		name[i++] = (unsigned char)"0123456789abcdef"[(upid >> (n * 4)) & 15];
	}
	name[i++] = '.';
	name[i++] = (unsigned char)"0123456789abcdef"[(usig >> 4) & 15];
	name[i++] = (unsigned char)"0123456789abcdef"[usig & 15];
	name[i] = 0;
	us->Buffer = name;
	if ((size_t)i > __US_MAX_WCHARS) {
		us->Length = us->MaximumLength = 0;
		return;
	}
	us->Length = (USHORT)(i * sizeof(WCHAR));
	us->MaximumLength = (USHORT)(us->Length + sizeof(WCHAR));
}

static int stop_self(int sig)
{
	UNICODE_STRING us;
	WCHAR name[56];
	pid_t pid = getpid();

	/* RtlCloneUserProcess copied only the numeric value of a parent's
	 * private handle.  A different pid makes that copy stale, just as for
	 * the process-group publication event in src/unistd/ids.c. */
	if (self_stop_owner != pid) self_stop_event = __PLAT_HANDLE_NULL;
	if (!self_stop_event || self_stop_signal != sig) {
		if (self_stop_event) __plat_close(self_stop_event);
		stop_event_name(pid, sig, name, &us);
		self_stop_event = __plat_stop_event_create(&us);
		if (!self_stop_event) return -1;
		self_stop_owner = pid;
		self_stop_signal = sig;
	}
	if (__plat_event_set(self_stop_event) < 0) return -1;
	if (__plat_process_suspend_self() < 0) {
		/* Retract a notification for a stop that did not happen. */
		__plat_event_peek(self_stop_event);
		return -1;
	}
	/* Reached only after another process sends SIGCONT. */
	return 0;
}

int __sig_consume_child_stop(pid_t pid)
{
	static const int stops[] = { SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU };
	UNICODE_STRING us;
	WCHAR name[56];
	__plat_handle_t h;
	int already_existed;
	size_t i;

	for (i = 0; i < sizeof stops / sizeof stops[0]; i++) {
		stop_event_name(pid, stops[i], name, &us);
		if (__plat_stop_event_probe(&us, &h, &already_existed) < 0) continue;
		if (already_existed && __plat_event_peek(h)) {
			__plat_close(h);
			return stops[i];
		}
		__plat_close(h);
	}
	return 0;
}

/* Deliver a signal to this process now.  Returns 0 if it was handled or
 * ignored and control may continue; does not return if the default
 * action is to die. */
static __thread stack_t alt_stack;   /* ss_sp == 0 means none is installed */
static __thread int alt_active;      /* nonzero while a handler runs on it */

/* Defined in src/signal/$ARCH/altstack.S (PE and native Linux/ELF): since
 * delivery is always synchronous on this library's own call site, not a
 * kernel sigreturn frame, SA_ONSTACK is just a stack switch either way.
 *
 * tools/asan-build.sh and tools/fuzz.sh compile natively with clang, link
 * no .S, and -U__linux__ every file (see exec.c's real-vs-emulated
 * split), so this declaration and the call below stay out of that build
 * even though it runs on real Linux/ELF -- the x86_64/i386 asm couldn't
 * be reused there anyway, since it takes arguments per the Windows x64
 * ABI (rcx/rdx/r8), not SysV's. */
#if defined(_WIN32) || defined(__linux__)
void __sig_call_on_altstack(void *sp, void (*fn)(void *), void *arg); // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
#endif

/* One shape for both handler signatures, so the stack switch below has a
 * single void(*)(void *) to call whichever kind of handler is installed. */
struct sig_delivery {
	void (*h)(int);
	void (*hsi)(int, siginfo_t *, void *);
	siginfo_t *si;
	int sig;
};

/* nonnull is safe: both callers (sig_dispatch()'s direct call and its
 * altstack trampoline) always pass __raise_internal_info()'s own `&d`
 * stack local, never NULL. */
static void sig_deliver(void *p) __attribute__((nonnull(1)));
static void sig_deliver(void *p)
{
	struct sig_delivery *d = p;
	if (d->hsi) d->hsi(d->sig, d->si, NULL);
	else d->h(d->sig);
}

/* Run one delivery on the alternate stack, if the disposition asked for
 * one and it's installed. !alt_active matters: a signal raised from a
 * handler already on the alt stack must stay on it, or the nested
 * delivery would reset the stack pointer to the top and overwrite its
 * own caller's frames (sigaltstack.html: alt stack is in use "until the
 * handler returns"). */
static void sig_dispatch(struct sig_delivery *d, int flags)
{
#if defined(_WIN32) || defined(__linux__)
	if ((flags & SA_ONSTACK) && alt_stack.ss_sp && !alt_active) {
		void *top = (char *)alt_stack.ss_sp + alt_stack.ss_size;
		alt_active = 1;
		__sig_call_on_altstack(top, sig_deliver, d);
		alt_active = 0;
	} else {
		sig_deliver(d);
	}
#else
	/* Native ASan/libFuzzer build: deliver on the current stack. A raw
	 * stack switch is actively wrong under ASan (it tracks frames on
	 * stacks it knows about; __sanitizer_start_switch_fiber() exists for
	 * exactly this and isn't used here), and this build's subject is
	 * memory safety of OS-independent code, not signal delivery.
	 *
	 * alt_active stays unset: setting it would make sigaltstack() falsely
	 * report SS_ONSTACK. SA_ONSTACK itself is covered by `make check`
	 * under Wine/real Windows, where the switch is real. */
	(void)flags;
	sig_deliver(d);
#endif
}

// NOLINTNEXTLINE(misc-no-recursion) -- resumed pending delivery consumes a queued record after restoring the handler mask
int __raise_internal_info(int sig, const void *data)
{
	void (*h)(int);
	siginfo_t generated;
	const siginfo_t *supplied = data;
	if (!sig_valid(sig)) { errno = EINVAL; return -1; }
	if (!supplied) {
		make_siginfo(&generated, sig);
		supplied = &generated;
	}
	if (sigismember(&blocked, sig) ||
	    (wait_active && sigismember(&waiting_set, sig)))
		return queue_pending(sig, supplied);
	h = handlers[sig];
	if (h == SIG_IGN) return 0;
	if (h == SIG_DFL) {
		if (sig_stops(sig)) return stop_self(sig);
		if (!default_action(sig)) return 0;
		/* SIGABRT only: XSH 2.4.3 says a default-terminate signal
		 * terminates "as if by a call to _exit()", and _exit() must
		 * NOT flush open streams -- so flushing here is normally
		 * forbidden. abort.html carves out SIGABRT as a MAY ("an
		 * attempt to effect fclose() on all open streams"), which is
		 * the useful choice: src/exit/abort.c reaches this path, and
		 * a program dying on a failed assertion having silently
		 * dropped its diagnostics is worse to debug for no
		 * conformance gain. See src/stdio/file.c's __stdio_exit() for
		 * why the flush there is guarded against re-entrancy. */
		if (sig == SIGABRT) __stdio_exit();
		__exit_internal(__ENCODE_SIGNAL_EXIT(sig));
	}
	/* else, not fallthrough: cppcheck doesn't know __exit_internal is
	 * _Noreturn, so a fallthrough reads as h(sig) reachable with
	 * h == SIG_DFL (NULL).
	 *
	 * BSD semantics: the disposition stays installed across delivery
	 * unless SA_RESETHAND, unlike System V which always restores
	 * SIG_DFL first. */
	else {
		sigset_t saved = blocked;
		int flags = act_flags[sig];
		int delivery_lock_depth;
		struct sig_delivery d;
		int i;

		/* Zeroed so sig_deliver() can tell the two handler shapes
		 * apart by which pointer is set; it lives on the ordinary
		 * stack and is read from the alternate one, which is fine --
		 * switching stacks does not unmap the old one. */
		memset(&d, 0, sizeof d);
		d.sig = sig;

		/* sigaction.html DESCRIPTION, SA_RESETHAND: "the disposition of
		 * the signal shall be reset to SIG_DFL ... on entry to the
		 * signal handler." Reset before calling h(), same as the real
		 * clause requires, and drop the recorded mask/flags with it --
		 * they belong to the sigaction() call that installed this
		 * handler, and a plain SIG_DFL has neither. */
		if (flags & SA_RESETHAND) {
			handlers[sig] = SIG_DFL;
			sigemptyset(&act_mask[sig]);
			act_flags[sig] = 0;
		}

		/* sigaction.html: sa_mask plus (unless SA_NODEFER) the signal
		 * itself is added to the mask for the handler's duration --
		 * matters only for a signal raised from within the handler,
		 * since delivery here is always synchronous. sigorset() would
		 * do this in one call but needs _BSD_SOURCE/_GNU_SOURCE, which
		 * this file doesn't define. */
		for (i = 1; i < _NSIG; i++)
			if (sigismember(&act_mask[sig], i)) sigaddset(&blocked, i);
		if (!(flags & SA_NODEFER)) sigaddset(&blocked, sig);
		sigdelset(&blocked, SIGKILL);
		sigdelset(&blocked, SIGSTOP);

		/* Counted before the call, not after: a handler that never
		 * returns (longjmp out, _exit) still ran, and a sleep it
		 * interrupted still has to see that it did. */
		caught_count++;
		thread_caught_count++;
		if (flags & SA_RESTART) thread_restart_count++;
		__sig_notify_delivery();

		/* SA_SIGINFO: sa_handler and sa_sigaction share a union slot
		 * (struct sigaction, include/signal.h), so h already holds the
		 * right pointer -- this just casts it back to its real
		 * three-argument type. */
		delivery_lock_depth = __sig_unlock_for_handler();
		if (flags & SA_SIGINFO) {
			void (*hsi)(int, siginfo_t *, void *) =
				(void (*)(int, siginfo_t *, void *))(void *)h; // NOLINT(bugprone-casting-through-void) -- sigaction's union ABI requires recovering the three-argument handler from the shared slot
			d.hsi = hsi;
			d.si = (siginfo_t *)supplied;
			sig_dispatch(&d, flags);
		} else {
			d.h = h;
			sig_dispatch(&d, flags);
		}
		__sig_relock_after_handler(delivery_lock_depth);

		blocked = saved;
		/* raise() and pthread_kill() are thread-directed.  If the handler
		 * deferred one of those signals, restoring its entry mask is the
		 * point at which the newly-unblocked pending signal is delivered. */
		for (i = 1; i < _NSIG; i++) {
			while (sigismember(&thread_pending.set, i) &&
			       !sigismember(&blocked, i)) {
				siginfo_t info;
				take_pending_signal_from(&thread_pending, i, &info);
				thread_directed++;
				__raise_internal_info(i, &info);
				thread_directed--;
			}
		}
	}
	return 0;
}

int __raise_internal(int sig) { return __raise_internal_info(sig, 0); }

/* Queue a process-directed signal without consulting this helper thread's
 * signal mask: the cross-process listener is an internal NT service thread
 * whose empty TLS mask must not make a signal eligible. An application
 * thread drains it against its own mask at a safe point. */
int __sig_queue_process_info(int sig, const void *data)
{
	siginfo_t generated;
	const siginfo_t *supplied = data;
	int result;

	if (!sig_valid(sig)) { errno = EINVAL; return -1; }
	if (!supplied) {
		make_siginfo(&generated, sig);
		supplied = &generated;
	}
	__sig_lock();
	result = queue_pending_to(&process_pending, sig, supplied);
	__sig_unlock();
	return result;
}

int __raise_thread_internal(int sig)
{
	int pending_sig;
	int result;

	/* A process-directed signal generated by a thread which blocks it is
	 * left process-pending.  A later thread-directed delivery is a safe
	 * point on the target thread: claim every process-pending signal that
	 * this thread can accept before delivering the requested one. */
	for (pending_sig = 1; pending_sig < _NSIG; pending_sig++) {
		while (sigismember(&process_pending.set, pending_sig) &&
		       !sigismember(&blocked, pending_sig)) {
			siginfo_t info;
			take_pending_signal_from(&process_pending, pending_sig, &info);
			__raise_internal_info(pending_sig, &info);
		}
	}
	thread_directed++;
	result = __raise_internal(sig);
	thread_directed--;
	return result;
}

int raise(int sig)
{
	int r;
	__sig_lock();
	r = __raise_thread_internal(sig);
	__sig_unlock();
	return r < 0 ? -1 : 0;
}

/* Signals whose default action is "stop the process" (signal.h.html):
 * SIGSTOP and the three terminal-related stops SIGTSTP/SIGTTIN/SIGTTOU.
 * The latter three go through the target-disposition handshake below
 * first, since their caught/ignored dispositions can override the default;
 * SIGSTOP can't be caught or ignored, so it always stops. */
static int sig_stops(int sig)
{
	return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

/* kill.html's stop and continue signals, for a child of this process.
 *
 * NT has NtSuspendProcess/NtResumeProcess (src/internal/nt.h) but no
 * stop *notification* -- a process object signals only on termination --
 * so the stop this library just performed is recorded directly in the
 * child table, and waitpid(WUNTRACED)/waitid(WSTOPPED) read it back from
 * there (wait.c). A child suspended by something outside this library
 * (a debugger, etc.) stays invisible, which matches what kill()/wait()
 * describe anyway.
 *
 * `c` is 0 for a non-child: still suspended/resumed on NT's side, just
 * not recorded, since there's no entry and no wait() to report it.
 *
 * The two guards keep NT's suspend count (a real counter: two suspends
 * need two resumes) in step with POSIX's one-bit view (a second SIGSTOP
 * or SIGCONT is a no-op) -- otherwise a repeated SIGSTOP could deepen the
 * suspension past what one SIGCONT can undo. Returns 1 for a real
 * transition, 0 if already satisfied, -1 on NT failure. */
static int sig_job_control(struct __child *c, __plat_handle_t h, int sig)
{
	if (sig == SIGCONT) {
		/* kill.html: SIGCONT continues a stopped process.  Sent to one
		 * that is already running it does nothing -- and in particular
		 * produces no WCONTINUED status, which is reserved for a child
		 * that actually was continued. */
		if (c && !c->stopsig) return 0;
		if (__plat_process_resume(h) < 0) return -1;
		if (c) { c->stopsig = 0; c->jobstat = __W_CONTINUED; }
		return 1;
	}
	if (c && c->stopsig) return 0;
	if (__plat_process_suspend(h) < 0) return -1;
	if (c) { c->stopsig = sig; c->jobstat = __W_STOPPED(sig); }
	return 1;
}

/* sigaction.html: unless SA_NOCLDSTOP is set, stopping a child or
 * continuing a stopped child generates SIGCHLD in the parent, with the
 * transition described by siginfo_t.  NT does not announce suspension
 * changes, but kill() is the actor performing this one and therefore has
 * the complete child identity and transition at the point it succeeds. */
void __sigchld_job_control(struct __child *c, int sig)
{
	siginfo_t si;

	if (!c) return;
	__sig_lock();
	if (!(act_flags[SIGCHLD] & SA_NOCLDSTOP)) {
		memset(&si, 0, sizeof si);
		si.si_signo = SIGCHLD;
		si.si_code = sig == SIGCONT ? CLD_CONTINUED : CLD_STOPPED;
		si.si_pid = c->pid;
		si.si_uid = getuid();
		si.si_status = sig;
		__raise_internal_info(SIGCHLD, &si);
	}
	__sig_unlock();
}

int kill(pid_t pid, int sig)
{
	struct __child *c;
	__plat_handle_t h;

	/* kill.html ERRORS EINVAL for a bad sig, except sig==0 ("no signal is
	 * sent" but existence/permission checks still apply) -- sig_valid()
	 * itself answers false for 0, so it's exempted here explicitly.
	 * Validation has to happen in THIS process: the cross-process arm
	 * below (sigdelivery.c's __sig_try_deliver_remote()) only checks
	 * inside the target process, whose errno this one can't read back. */
	if (sig != 0 && !sig_valid(sig)) { errno = EINVAL; return -1; }

	/* pid==0 (own process group) and pid==-1 (every permitted process)
	 * both name sets ntlibc can't enumerate in general, but under the
	 * group-of-one model (src/unistd/ids.c: every process is its own
	 * group, no process list beyond our own children) both sets provably
	 * contain only the caller -- so "send to {caller}" is the real thing
	 * here, not a stand-in, and -1 is folded into this fast path too.
	 *
	 * getpgrp() belongs here for the same reason (killpg(getpgrp(), sig)
	 * == kill(getpgrp(), sig)), but is checked separately because it is
	 * neither pid==0 nor pid==getpid(): an unset process group answers
	 * the sentinel 1 (ids.c), which names no real process, so without
	 * this arm killpg(getpgrp(), sig) would wrongly fall through to the
	 * cross-process ESRCH path below. */
	if (pid == getpid() || pid == getpgrp() || pid == 0 || pid == -1) {
		int result;
		if (!sig) return 0;
		/* kill() is process-directed even when its target set contains only
		 * this process.  Do not route it through raise(), whose pending state
		 * belongs specifically to the calling thread.  The shared internal
		 * path still handles self-stops by publishing a waitable marker for
		 * the parent before suspending this process. */
		__sig_lock();
		result = __raise_internal(sig);
		__sig_unlock();
		return result < 0 ? -1 : 0;
	}
	if (pid < 0) { errno = ESRCH; return -1; }
	c = __child_find(pid);
	if (c) h = c->h;
	else {
		/* The access mask decides which errno the caller sees: EPERM
		 * comes entirely from NT's own access check on the target
		 * process object, not any identity comparison of ours. Measured
		 * on Windows 11 Pro 22621 against the System process (pid 4),
		 * elevated token:
		 *
		 *   PROCESS_TERMINATE | QUERY_LIMITED_INFORMATION -> c0000022 (ACCESS_DENIED)
		 *   PROCESS_QUERY_LIMITED_INFORMATION alone       -> 00000000 (SUCCESS)
		 *   PROCESS_TERMINATE alone                       -> c0000022 (ACCESS_DENIED)
		 *
		 * The denial is specific to PROCESS_TERMINATE on a protected
		 * process, so narrowing the mask to query-only would turn a
		 * correct EPERM into a silent success (test/posix-kill-perm-win.c
		 * catches this). A nonexistent pid answers STATUS_INVALID_CID
		 * (c000000b) instead, so ESRCH stays distinguishable. */
		/* PROCESS_SUSPEND_RESUME is requested only when the signal needs
		 * it: an unneeded bit in the mask can turn the measured EPERM
		 * above into an EPERM for targets that today accept a plain
		 * signal. */
		if (__plat_kill_open((int)pid, sig_stops(sig) || sig == SIGCONT, &h) < 0) return -1;
#ifdef _WIN32
		/* wait.c's waitpid() (see its own comment on this exact NT quirk)
		 * won't reopen an untracked pid at all, because on real Windows the
		 * kernel process object outlives its last handle: an already-
		 * reaped, no-longer-existing child can still be opened above and
		 * hand back a live-looking handle for a pid NT has quietly recycled
		 * or is about to. kill() can't refuse the open outright the way
		 * waitpid() does -- an untracked pid legitimately names a real,
		 * unrelated process most of the time -- so instead confirm the
		 * object __plat_kill_open() just handed back is still the live
		 * process it claims to be before this pid is allowed to touch any
		 * of the SIGSTOP/SIGCONT/stop-signal/remote-delivery/termination
		 * paths below. __plat_process_alive() sets errno to ESRCH itself on
		 * the not-alive path. Linux needs no equivalent: its
		 * __plat_kill_open() hands back a pidfd, immune to this race by
		 * construction (see that function's own comment) -- and calling
		 * __plat_process_alive() on Linux would misinterpret the bare pid
		 * __plat_kill_open() built as a boxed pidfd, the same handle-
		 * domain mismatch plat_signal.h's wake_event banner already
		 * documents as a real, previously-crashing bug. */
		if (!__plat_process_alive(h)) { __plat_close(h); return -1; }
#endif
	}
	if (!sig) { if (!c) __plat_close(h); return 0; }
	if (sig == SIGSTOP) {
		int changed = sig_job_control(c, h, sig);
		if (changed > 0) __sigchld_job_control(c, sig);
		if (!c) __plat_close(h);
		return changed < 0 ? -1 : 0;
	}
	/* SIGCONT resumes before it is delivered, even when caught or ignored.
	 * Its default action is already ignore, so ordinary one-way delivery is
	 * sufficient and avoids waiting for a disposition acknowledgement from
	 * a child that may have stopped while holding its signal lock. */
	if (sig == SIGCONT) {
		int changed = sig_job_control(c, h, sig);
		if (changed < 0) { if (!c) __plat_close(h); return -1; }
		if (changed > 0) __sigchld_job_control(c, sig);
		if (__sig_try_deliver_remote((int)pid, sig)) {
			if (!c) __plat_close(h);
			return 0;
		}
		if (!c) __plat_close(h);
		return 0;
	}
	/* SIGTSTP/SIGTTIN/SIGTTOU are catchable: ask the target (sigdelivery.c
	 * -- NT's named-pipe listener, or Linux's real kernel disposition) to
	 * accept it only when its own disposition is non-default. If it
	 * declines, fall back to the NT suspend/resume default action. */
	if (sig_stops(sig) && __sig_try_deliver_remote_nondefault((int)pid, sig)) {
		if (!c) __plat_close(h);
		return 0;
	}
	if (sig_stops(sig)) {
		int changed = sig_job_control(c, h, sig);
		if (changed > 0) __sigchld_job_control(c, sig);
		if (!c) __plat_close(h);
		return changed < 0 ? -1 : 0;
	}
	/* Try the target's own real disposition before this process's blind
	 * default_action() guess. sigdelivery.c's __sig_try_deliver_remote()
	 * applies THAT process's real sa_handler/SIG_IGN -- on NT via its
	 * named-pipe listener and __raise_internal(); on Linux via a real
	 * rt_sigaction(2) dispatch that kill(2)/tgkill(2)/pidfd_send_signal(2)
	 * invoke directly. Success here is strictly more correct than the
	 * termination path below, so no fallthrough on success; failure (no
	 * listener, or the real send failed) falls through unchanged. */
	if (__sig_try_deliver_remote((int)pid, sig)) {
		if (!c) __plat_close(h);
		return 0;
	}
	{
		int r = __plat_kill_terminate(h, __ENCODE_SIGNAL_EXIT(sig));
		if (!c) __plat_close(h);
		return r;
	}
}

int killpg(pid_t pg, int sig) { return kill(pg, sig); }

int sigemptyset(sigset_t *s) { memset(s, 0, sizeof *s); return 0; }
int sigfillset(sigset_t *s) { memset(s, 0xff, sizeof *s); return 0; }
int sigaddset(sigset_t *s, int sig) { if (!sig_valid(sig)) { errno = EINVAL; return -1; } s->__bits[sig / (8 * sizeof(long))] |= 1UL << (sig % (8 * sizeof(long))); return 0; }
int sigdelset(sigset_t *s, int sig) { if (!sig_valid(sig)) { errno = EINVAL; return -1; } s->__bits[sig / (8 * sizeof(long))] &= ~(1UL << (sig % (8 * sizeof(long)))); return 0; }
int sigismember(const sigset_t *s, int sig) { if (!sig_valid(sig)) { errno = EINVAL; return -1; } return !!(s->__bits[sig / (8 * sizeof(long))] & (1UL << (sig % (8 * sizeof(long))))); }
int sigisemptyset(const sigset_t *s) { size_t i; for (i = 0; i < sizeof s->__bits / sizeof s->__bits[0]; i++) if (s->__bits[i]) return 0; return 1; }
int sigorset(sigset_t *d, const sigset_t *a, const sigset_t *b) { size_t i; for (i = 0; i < sizeof d->__bits / sizeof d->__bits[0]; i++) d->__bits[i] = a->__bits[i] | b->__bits[i]; return 0; }

/* Called with the signal lock held. Delivery drops it only around the user
 * callback and reacquires it before returning here. */
static void drain_unblocked_pending(void)
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
static void drain_unblocked_pending(void)
{
	int i;
	for (i = 1; i < _NSIG; i++) {
		while (pending_member(i) && !sigismember(&blocked, i)) {
			siginfo_t si;
			take_pending_signal(i, &si);
			__raise_internal_info(i, &si);
		}
	}
}

void __sig_drain_pending(void)
{
	__sig_lock();
	drain_unblocked_pending();
	__sig_unlock();
}

int sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
	int i;
	/* Locked for the whole call, `old` snapshot included -- this is why
	 * __raise_internal() below can assume its caller already holds the
	 * lock (sigdelivery.c's invariant). A handler callback runs outside
	 * the lock, so mask changes it makes acquire it normally. */
	__sig_lock();
	if (old) *old = blocked;
	if (set) {
		switch (how) {
		case SIG_BLOCK: sigorset(&blocked, &blocked, set); break;
		case SIG_UNBLOCK: for (i = 1; i < _NSIG; i++) if (sigismember(set, i)) sigdelset(&blocked, i); break;
		case SIG_SETMASK: blocked = *set; break;
		default: __sig_unlock(); errno = EINVAL; return -1;
		}
		sigdelset(&blocked, SIGKILL);
		sigdelset(&blocked, SIGSTOP);
		/* deliver anything unblocked and pending */
		drain_unblocked_pending();
	}
	__sig_unlock();
	return 0;
}

/* pthread_sigmask.html gives this the same mask operation as
 * sigprocmask(), but pthread interfaces return the error number directly
 * and do not report it through errno.  There is one process-wide mask while
 * ntlibc has only its initial thread; keeping the wrapper here makes that
 * contract usable now and leaves the storage boundary obvious when real
 * per-thread masks arrive. */
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old)
{
	int saved = errno;
	int result = sigprocmask(how, set, old);
	int error = errno;

	errno = saved;
	return result == 0 ? 0 : error;
}

int sigpending(sigset_t *s)
{
	__sig_lock();
	sigorset(s, &process_pending.set, &thread_pending.set);
	__sig_unlock();
	return 0;
}

int __sig_pending_member(int sig) { return pending_member(sig); }

int sigsuspend(const sigset_t *s)
{
	sigset_t old;
	unsigned long caught;

	if (!s) { errno = EFAULT; return -1; }
	/* Installing the temporary mask and taking the handler-count snapshot
	 * are one locked operation.  A remote delivery can therefore happen
	 * either before both or after both, never in the lost-wakeup gap that
	 * would leave this wait asleep after its signal already ran. */
	__sig_lock();
	old = blocked;
	caught = caught_count;
	blocked = *s;
	sigdelset(&blocked, SIGKILL);
	sigdelset(&blocked, SIGSTOP);
	drain_unblocked_pending();
	__sig_unlock();

	/* Drain on this application thread so its temporary mask, not the
	 * listener thread's TLS mask, decides which signals are eligible. The
	 * delivery event retains a wake that lands after the state check, so no
	 * bounded polling interval is needed. */
	while (__sig_caught_count() == caught) {
		__sig_drain_pending();
		if (__sig_caught_count() != caught) break;
		__sig_wait_delivery(0);
	}

	/* Restoring the old mask may itself release a signal that arrived
	 * while the temporary mask blocked it; sigprocmask() performs that
	 * pending delivery before returning. */
	(void)sigprocmask(SIG_SETMASK, &old, NULL);
	errno = EINTR;
	return -1;
}

void __sig_pending_reset_after_fork(void)
{
	memset(&process_pending, 0, sizeof process_pending);
	memset(&thread_pending, 0, sizeof thread_pending);
	wait_active = 0;
}

int sigqueue(pid_t pid, int sig, union sigval value)
{
	siginfo_t si;
	int r;

	if (sig < 0 || sig >= _NSIG) { errno = EINVAL; return -1; }
	if (!sig) return kill(pid, 0);
	memset(&si, 0, sizeof si);
	si.si_signo = sig;
	si.si_code = SI_QUEUE;
	si.si_pid = getpid();
	si.si_uid = getuid();
	si.si_value = value;

	if (pid == getpid()) {
		__sig_lock();
		r = __raise_internal_info(sig, &si);
		__sig_unlock();
		return r < 0 ? -1 : 0;
	}
	/* kill(pid, 0) supplies the common existence and permission check
	 * without generating anything.  Once it succeeds, failure to hand
	 * the payload to the target listener means the bounded delivery
	 * resource was unavailable. */
	if (kill(pid, 0) < 0) return -1;
	if (__sig_try_deliver_remote_info((int)pid, sig, &si)) return 0;
	errno = EAGAIN;
	return -1;
}
/* sigwait.html: select a pending signal from set, clear it, and return its
 * number; block until one is pending if none is. errno is saved/restored
 * since RETURN VALUE reports the error "through the ... return value
 * alone", not errno.
 *
 * Selection is lowest-numbered-first, satisfying the one ordering clause
 * the page states (lowest of a pending SIGRTMIN..SIGRTMAX range wins).
 *
 * Signal numbers in set outside [1, _NSIG) are ignored, not rejected:
 * ERRORS makes that a may-fail, and rejecting would break the common
 * `sigfillset(&s); sigwait(&s, &sig);` idiom (sigfillset() sets 1024 bits
 * for only 64 real signals); glibc measured the same way.
 *
 * The suspend path is a real wait: self-generated delivery is synchronous
 * (see this file's banner), but the NTLIBC_USE_KERNEL32 console-control
 * handler and the cross-process delivery thread (sigdelivery.c) can still
 * queue a blocked signal from outside while this loop is parked; the same
 * delivery event wakes it either way, and state is always rechecked after
 * waking. Where nothing can ever signal this process, this waits forever,
 * which is what POSIX specifies rather than fabricating an EINTR/EAGAIN. */
#ifdef __linux__
/* sigwait()/sigwaitinfo()/sigtimedwait() must catch and queue a signal in
 * `set` even when the caller never called sigaction()/signal() for it --
 * __plat_sig_install_real_handler() (plat_signal.h) only widens on a real
 * disposition change, so an untouched SIG_DFL signal would otherwise still
 * hit the kernel's own default action on a real cross-process delivery
 * instead of being queued here. Reproduced by test/posix-signal-crossproc.c:
 * a remote SIGUSR1 killed a waiting child outright before this existed. */
static void install_real_for_set(const sigset_t *set)
{
	int sig;
	for (sig = 1; sig < _NSIG; sig++)
		if (sig != SIGKILL && sig != SIGSTOP && sigismember(set, sig))
			__plat_sig_install_real_handler(sig);
}
#endif

int sigwait(const sigset_t *s, int *sig)
{
	int saved_errno = errno;
	int selected;

	__sig_lock();
	waiting_set = *s;
	wait_active = 1;
#ifdef __linux__
	install_real_for_set(s);
#endif
	__sig_unlock();
	for (;;) {
		__sig_lock();
		selected = take_pending_from_set(s, 0);
		if (selected) {
			wait_active = 0;
			__sig_unlock();
			if (sig) *sig = selected;
			errno = saved_errno;
			return 0;
		}
		__sig_unlock();
		__sig_wait_delivery(0);
	}
}

int sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
	int selected;
	__sig_lock();
	waiting_set = *set;
	wait_active = 1;
#ifdef __linux__
	install_real_for_set(set);
#endif
	__sig_unlock();
	for (;;) {
		__sig_lock();
		selected = take_pending_from_set(set, info);
		if (selected) {
			wait_active = 0;
			__sig_unlock();
			return selected;
		}
		__sig_unlock();
		__sig_wait_delivery(0);
	}
}

int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)
{
	struct timespec start, now;
	long long limit, elapsed;
	int selected;

	if (!timeout || timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
	    timeout->tv_nsec >= 1000000000L) {
		errno = EINVAL;
		return -1;
	}
	limit = __duration_ticks(timeout->tv_sec, timeout->tv_nsec);
	clock_gettime(CLOCK_MONOTONIC, &start);
	__sig_lock();
	waiting_set = *set;
	wait_active = 1;
#ifdef __linux__
	install_real_for_set(set);
#endif
	__sig_unlock();
	for (;;) {
		__sig_lock();
		selected = take_pending_from_set(set, info);
		if (selected) {
			wait_active = 0;
			__sig_unlock();
			return selected;
		}
		__sig_unlock();
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed = __timespec_diff_ticks(now.tv_sec, now.tv_nsec,
			start.tv_sec, start.tv_nsec);
		if (elapsed >= limit) {
			__sig_lock();
			wait_active = 0;
			__sig_unlock();
			errno = EAGAIN;
			return -1;
		}
		{
			long long left = limit - elapsed;
			LARGE_INTEGER d = -left;
			if (!d) d = -1;
			__sig_wait_delivery(&d);
		}
	}
}
/* siginterrupt() is a no-op: SA_RESTART clearing/setting has no effect,
 * since select()/pselect() always return EINTR regardless of the flag
 * (sigdelivery.c), and every other blocking call can't be interrupted
 * mid-syscall at all (no NtCancelSynchronousIoFile). [EINVAL] for a bad
 * sig is still enforced -- an argument check, not an effect. SIGKILL/
 * SIGSTOP are accepted since this page lists no uncatchable-signal error. */
int siginterrupt(int sig, int flag) { if (!sig_valid(sig)) { errno = EINVAL; return -1; } (void)flag; return 0; } // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
/* The alternate signal stack, and whether a handler is running on it.
 * Silently no-opping (report SS_DISABLE, return 0) is the worst shape for
 * an unimplemented function: callers believe the stack was installed. 26
 * Open POSIX sigaction cases died on exactly that, exiting 255 (ABNORMAL)
 * instead of failing cleanly.
 *
 * Both values are thread-local, as POSIX alternate stacks are; the signal
 * lock serializes disposition/pending-state changes from this
 * async-signal-safe entry point. */

int sigaltstack(const stack_t *ss, stack_t *old)
{
	__sig_lock();
	/* sigaltstack.html: old is filled in before any change from ss is
	 * applied, so a caller may swap stacks in one call. */
	if (old) {
		old->ss_sp = alt_stack.ss_sp;
		old->ss_size = alt_stack.ss_size;
		old->ss_flags = alt_stack.ss_sp
			? (alt_active ? SS_ONSTACK : 0)
			: SS_DISABLE;
	}
	if (ss) {
		/* "[EPERM] An attempt was made to modify an active stack." */
		if (alt_active) { __sig_unlock(); errno = EPERM; return -1; }
		/* "[EINVAL] The ss argument is not a null pointer, and the
		 * ss_flags member ... contains flags other than SS_DISABLE." */
		if (ss->ss_flags & ~(int)SS_DISABLE) { __sig_unlock(); errno = EINVAL; return -1; }
		if (ss->ss_flags & SS_DISABLE) {
			alt_stack.ss_sp = 0;
			alt_stack.ss_size = 0;
			alt_stack.ss_flags = SS_DISABLE;
		} else {
			/* "[ENOMEM] The size of the alternate stack area is less
			 * than MINSIGSTKSZ." */
			if (ss->ss_size < MINSIGSTKSZ) { __sig_unlock(); errno = ENOMEM; return -1; }
			if (!ss->ss_sp) { __sig_unlock(); errno = EINVAL; return -1; }
			alt_stack.ss_sp = ss->ss_sp;
			alt_stack.ss_size = ss->ss_size;
			alt_stack.ss_flags = 0;
		}
	}
	__sig_unlock();
	return 0;
}

int __libc_current_sigrtmin(void) { return 35; }
int __libc_current_sigrtmax(void) { return _NSIG - 1; }

/* sigignore.html is the disposition-only half of sigset(sig, SIG_IGN):
 * it makes sig ignored without changing whether it is blocked.  Keeping
 * this as sigaction(), rather than spelling it as signal(), also makes the
 * POSIX requirement explicit: SIGKILL, SIGSTOP and invalid signal numbers
 * fail with EINVAL through the same validation used by every other
 * disposition-setting interface. */
int sigignore(int sig)
{
	struct sigaction act;

	memset(&act, 0, sizeof act);
	act.sa_handler = SIG_IGN;
	return sigaction(sig, &act, 0);
}

/* sigaddset() is the only place these two look at sig, so its failure is
 * the whole of sigset.html's EINVAL for them -- without this early
 * return, a bad sig would just leave the set empty, and sigprocmask()
 * reports success for an empty mask instead of failing as it must. */
int sighold(int sig) { sigset_t s; sigemptyset(&s); if (sigaddset(&s, sig) < 0) return -1; return sigprocmask(SIG_BLOCK, &s, 0); }
int sigrelse(int sig) { sigset_t s; sigemptyset(&s); if (sigaddset(&s, sig) < 0) return -1; return sigprocmask(SIG_UNBLOCK, &s, 0); }

/* sigset() differs from signal() entirely in the mask: it unblocks sig
 * (unless func == SIG_HOLD, which only blocks it and installs nothing) and
 * reports SIG_HOLD as the return value when the signal had been blocked,
 * so the two clauses are implemented together.
 *
 * The unblock happens after the new disposition is installed: a signal
 * that arrived while sig was held then belongs to the handler being
 * installed now, not the one it replaces. */
void (*sigset(int sig, void (*h)(int)))(int)
{
	void (*old)(int);
	int was_blocked;
	sigset_t one;

	if (!sig_valid(sig) || sig == SIGKILL || sig == SIGSTOP) { errno = EINVAL; return SIG_ERR; }
	was_blocked = sigismember(&blocked, sig);
	sigemptyset(&one);
	sigaddset(&one, sig);

	if (h == SIG_HOLD) {
		__sig_lock();
		old = handlers[sig];   /* read before the mask moves: sigprocmask()
		                        * runs whatever became deliverable, and a
		                        * handler may install a new disposition */
		__sig_unlock();
		if (sigprocmask(SIG_BLOCK, &one, 0) < 0) return SIG_ERR;
		return was_blocked ? SIG_HOLD : old;
	}

	old = signal(sig, h);
	if (old == SIG_ERR) return SIG_ERR;
	if (!was_blocked) return old;
	if (sigprocmask(SIG_UNBLOCK, &one, 0) < 0) return SIG_ERR;
	return SIG_HOLD;
}
int sigpause(int sig)
{
	sigset_t mask;

	if (!sig_valid(sig)) { errno = EINVAL; return -1; }
	mask = blocked;
	sigdelset(&mask, sig);
	return sigsuspend(&mask);
}

/* SEGV_MAPERR vs SEGV_ACCERR for an access-violation/in-page-error fault:
 * NT's EXCEPTION_RECORD only says read/write/execute, not whether the
 * page was unmapped or merely off-limits, so NtQueryVirtualMemory's State
 * decides (src/internal/nt.h):
 *
 *   MEM_FREE     nothing mapped                          -> SEGV_MAPERR
 *   MEM_RESERVE  no page, unless a live lazy PROT_NONE mmap -> SEGV_ACCERR
 *   MEM_COMMIT   real page; Protect denies this access     -> SEGV_ACCERR
 *
 * TOCTOU: the query runs after the fault, so another thread could remap
 * the address in between; not practically an issue for a synchronous
 * fault on its own thread, which is the only case tested. If the query
 * itself fails, SEGV_MAPERR is the honest fallback ("cannot even ask" is
 * closer to "not mapped" than to "mapped but protected"). */
/* The backend classifies raw NT state. The mapping registry supplies the
 * one distinction NT state cannot: a lazy PROT_NONE mmap is reserved but
 * still mapped in POSIX terms. */
static int segv_code(void *addr)
{
	int code = __plat_segv_code(addr);
	if (code == SEGV_MAPERR && __mman_address_is_live(addr))
		return SEGV_ACCERR;
	return code;
}

/* NT exceptions mapped to synchronous signals, with the si_code that
 * names each fault precisely -- siginfo_t DESCRIPTION requires a
 * fault-specific value here, not a generic SI_KERNEL, for SIGILL/SIGFPE/
 * SIGSEGV/SIGBUS. Most codes fall straight out of ExceptionCode; only
 * SEGV_MAPERR/SEGV_ACCERR need the NtQueryVirtualMemory() lookup above. */
/* ep is required: its only real caller is NT itself, invoking every
 * vectored exception handler (RtlAddVectoredExceptionHandler(),
 * __signal_init() below) with a real, non-NULL EXCEPTION_POINTERS*. */
static LONG NTAPI exception_handler(EXCEPTION_POINTERS *ep) __attribute__((nonnull(1)));
static LONG NTAPI exception_handler(EXCEPTION_POINTERS *ep)
{
	int sig, code;
	ULONG excode = ep->ExceptionRecord->ExceptionCode;

	switch (excode) {
	case EXCEPTION_ACCESS_VIOLATION: {
		/* ExceptionInformation[1] is the CPU-supplied faulting address
		 * for access-violation exceptions in NT's own EXCEPTION_RECORD
		 * -- the hardware fault handler produced this value, not any C
		 * expression this function's body could derive it from (see
		 * this function's own fault_addr assignment below for the
		 * identical pattern). */
		void *addr = unsafe_assume_valid_pointer(
		    (void *)ep->ExceptionRecord->ExceptionInformation[1]);
		code = segv_code(addr);
		if (code == SEGV_MAPERR && __mman_fault_is_object_error(addr)) {
			sig = SIGBUS;
			code = BUS_OBJERR;
		} else {
			sig = SIGSEGV;
		}
		break;
	}
	case EXCEPTION_IN_PAGE_ERROR:
		/* The address is mapped, but its backing object could not supply
		 * the page (including a whole page beyond a mapped file's end).
		 * That is SIGBUS/BUS_OBJERR, not an address/protection SIGSEGV. */
		sig = SIGBUS;
		code = BUS_OBJERR;
		break;
	case EXCEPTION_STACK_OVERFLOW:
		/* Running off the reserved stack region: no committed page was
		 * denied, so this is a mapping failure (SEGV_MAPERR), and
		 * unambiguous enough not to need the query above --
		 * ExceptionInformation[1] isn't even reliable here the way it
		 * is for access-violation. */
		sig = SIGSEGV;
		code = SEGV_MAPERR;
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT: sig = SIGBUS; code = BUS_ADRALN; break;
	case EXCEPTION_ILLEGAL_INSTRUCTION: sig = SIGILL; code = ILL_ILLOPC; break;
	case EXCEPTION_PRIV_INSTRUCTION: sig = SIGILL; code = ILL_PRVOPC; break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO: sig = SIGFPE; code = FPE_INTDIV; break;
	case EXCEPTION_INT_OVERFLOW: sig = SIGFPE; code = FPE_INTOVF; break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO: sig = SIGFPE; code = FPE_FLTDIV; break;
	case EXCEPTION_FLT_INVALID_OPERATION: sig = SIGFPE; code = FPE_FLTINV; break;
	case EXCEPTION_FLT_OVERFLOW: sig = SIGFPE; code = FPE_FLTOVF; break;
	case EXCEPTION_FLT_UNDERFLOW: sig = SIGFPE; code = FPE_FLTUND; break;
	case EXCEPTION_FLT_INEXACT_RESULT: sig = SIGFPE; code = FPE_FLTRES; break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		/* FPE_FLTSUB ("subscript out of range") is a name-for-name match
		 * for #BR. SIGFPE not SIGILL: the instruction was legal, only
		 * the operand was out of range. Only i386 can raise it (long
		 * mode has no BOUND), but the case stays unconditional since
		 * dispatch is on the exception code, not the arch. */
		sig = SIGFPE;
		code = FPE_FLTSUB;
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		/* A real FP condition, but POSIX's FPE_* list has no member for
		 * "denormal operand". Rather than misreport the cause with the
		 * closest-sounding code, fall back to the honest SI_KERNEL. */
		sig = SIGFPE;
		code = SI_KERNEL;
		break;
	case EXCEPTION_BREAKPOINT: sig = SIGTRAP; code = SI_KERNEL; break;
	case DBG_CONTROL_C:
	case DBG_CONTROL_BREAK: sig = SIGINT; code = SI_KERNEL; break;
	case STATUS_GUARD_PAGE_VIOLATION:
		/* Distinct from EXCEPTION_ACCESS_VIOLATION, raised on touching a
		 * PAGE_GUARD page. This library never sets PAGE_GUARD itself, so
		 * there's no case to fold into SIGSEGV -- fall through to the
		 * next handler instead of guessing a signal. */
	default: return EXCEPTION_CONTINUE_SEARCH;
	}
	__sig_lock();
	if (handlers[sig] == SIG_DFL) {
		/* No flush, for two reasons. Conformance: the same SIG_DFL
		 * clause as __raise_internal() above forbids flushing on a
		 * default-terminate signal, and SIGABRT (POSIX's only exemption)
		 * can never reach this function. Practically: this runs on
		 * whatever stack is left at the fault -- almost none for
		 * EXCEPTION_STACK_OVERFLOW -- and __stdio_exit() walking every
		 * open FILE would re-enter the very cycle that caused it (see
		 * src/stdio/file.c). */
		__exit_internal(__ENCODE_SIGNAL_EXIT(sig));
	}
	if (handlers[sig] == SIG_IGN) {
		/* Ignoring a fault would loop forever; POSIX says undefined. Die. */
		if (sig != SIGINT && sig != SIGTRAP) __exit_internal(__ENCODE_SIGNAL_EXIT(sig));
		__sig_unlock();
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	/* si_addr is only meaningful for access-violation-shaped exceptions
	 * (ExceptionInformation[1] is the faulting address there); the rest
	 * carry no address, so fault_addr stays NULL for them. */
	/* Fault metadata is thread-local, so another thread may deliver while the
	 * application handler runs without inheriting this exception's siginfo. */
	fault_active = 1;
	/* ExceptionInformation[1] is the CPU-supplied faulting address for
	 * access-violation exceptions in NT's own EXCEPTION_RECORD -- the
	 * hardware fault handler produced this value, not any C expression
	 * this function's body could derive it from. */
	fault_addr = (excode == EXCEPTION_ACCESS_VIOLATION || excode == EXCEPTION_IN_PAGE_ERROR)
	           ? unsafe_assume_valid_pointer(
	                 (void *)ep->ExceptionRecord->ExceptionInformation[1])
	           : NULL;
	fault_si_code = code;
	__raise_internal(sig);
	fault_active = 0;
	__sig_unlock();
	/* A handler that returns from a fault re-executes the instruction,
	 * as on Unix; for SIGINT/SIGTRAP continuing is the right thing. */
	return EXCEPTION_CONTINUE_EXECUTION;
}

#ifdef NTLIBC_USE_KERNEL32
/* Runs on a thread kernel32 creates, not the main thread -- races a main
 * thread inside sigprocmask() touching the same handlers/blocked/
 * process_pending globals, exactly like sigdelivery.c's delivery thread;
 * __sig_lock()/__sig_unlock() cover both. The unlocked `handlers[SIGINT]
 * == SIG_DFL` read below is deliberate: it's a fast-path check that
 * __raise_internal() (locked) re-derives correctly regardless, so a torn
 * read costs at most one redundant dispatch, never a wrong outcome. */
static BOOL NTAPI ctrl_handler(DWORD type)
{
	switch (type) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		/* Same signal for both, same as the vectored handler does
		 * for DBG_CONTROL_C/DBG_CONTROL_BREAK: this library has no
		 * SIGBREAK, and neither does POSIX. */
		if (handlers[SIGINT] == SIG_DFL) return FALSE;  /* let the default action run */
		__sig_lock();
		__raise_internal(SIGINT);
		__sig_unlock();
		return TRUE;
	default:
		/* CTRL_CLOSE_EVENT/CTRL_LOGOFF_EVENT/CTRL_SHUTDOWN_EVENT: no
		 * POSIX signal maps cleanly onto these, and kernel32 kills the
		 * process on a short clock regardless -- leave the default
		 * (process ends) in effect. */
		return FALSE;
	}
}
#endif

#ifdef NTLIBC_USE_KERNEL32
/* Reached via LdrLoadDll()/LdrGetProcedureAddress() (ntdll exports) rather
 * than linking kernel32's import library, so NTLIBC_USE_KERNEL32 stays a
 * load-time decision: the binary still only links against ntdll (see
 * CONTRIBUTING.md for why kernel32 is meant to stay the exception). */
static void install_ctrl_handler(void)
{
	UNICODE_STRING dllname;
	ANSI_STRING procname;
	PVOID kernel32, proc;

	RtlInitUnicodeString(&dllname, L"kernel32.dll");
	if (!NT_SUCCESS(LdrLoadDll(NULL, NULL, &dllname, &kernel32))) return;

	procname.Buffer = "SetConsoleCtrlHandler";
	procname.Length = procname.MaximumLength =
		sizeof "SetConsoleCtrlHandler" - 1;
	if (!NT_SUCCESS(LdrGetProcedureAddress(kernel32, &procname, 0, &proc))) return;

	((BOOL (NTAPI *)(PHANDLER_ROUTINE, BOOL))proc)(ctrl_handler, TRUE);
}
#endif

void __signal_init(void)
{
#ifdef _WIN32
	/* NT hardware faults (SIGSEGV/SIGFPE/SIGILL/SIGBUS) arrive as NT
	 * exceptions and are turned into signals by this vectored handler
	 * -- see this file's own banner. */
	RtlAddVectoredExceptionHandler(1, exception_handler);
#elif defined(__linux__)
	/* Linux delivers these as real kernel signals; __plat_sig_install_
	 * fault_handlers() (linux/plat_signal.c) installs a real
	 * rt_sigaction(2) handler for SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP
	 * that routes into __raise_internal_info() the same way the NT call
	 * above does. Cross-process delivery via kill()/tgkill() is separate
	 * work (linux/sigdelivery.c). */
	__plat_sig_install_fault_handlers();
#endif
#ifdef NTLIBC_USE_KERNEL32
	install_ctrl_handler();
#else
	/* No ntdll path to console control events exists (see
	 * CONTRIBUTING.md); nothing to install.  Ctrl-C keeps ending the
	 * process via the console's own default handling. */
#endif
	/* Cross-process signal delivery (sigdelivery.c): mutex, listener pipe
	 * and delivery thread that this process's kill()/select() need.
	 * Last, deliberately -- it starts a real thread that can immediately
	 * call __raise_internal(), so everything above is already installed
	 * before it could race it. */
	__sig_delivery_init();
}

/* psignal.html: writes "message: " plus the strsignal() text to stderr,
 * or just the strsignal() text if message is NULL or empty. */
void psignal(int sig, const char *s)
{
	/* psignal() is itself the diagnostic and has no return channel through
	 * which a secondary stderr failure could be reported. */
	if (s && *s) (void)fprintf(stderr, "%s: %s\n", s, strsignal(sig));
	else (void)fprintf(stderr, "%s\n", strsignal(sig));
}

/* psiginfo.html DESCRIPTION: same message shape as psignal(), driven
 * off a siginfo_t's si_signo instead of a bare signal number -- "as if
 * generated by strsignal()". RETURN VALUE: "no return value" for
 * either. */
void psiginfo(const siginfo_t *pinfo, const char *s)
{
	psignal(pinfo->si_signo, s);
}

// NOLINTEND(misc-include-cleaner)
