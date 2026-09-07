/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/signal/signal.c and sigdelivery.c's
 * POSIX-facing front doors call into instead of raw
 * Nt{CreateEvent,SetEvent,WaitForSingleObject,CreateMutant,
 * ReleaseMutant,CreateNamedPipeFile,OpenFile,FsControlFile,ReadFile,
 * WriteFile,CreateThreadEx,SuspendProcess,ResumeProcess,OpenProcess,
 * TerminateProcess,Close,DelayExecution,QueryVirtualMemory} calls. See
 * src/signal/nt/plat_signal.c for the implementation these declare.
 *
 * __sig_lock()/__sig_unlock()/__sig_unlock_for_handler()/
 * __sig_relock_after_handler() (sigdelivery.c) are NOT part of this
 * interface and are untouched by this migration: they are this
 * project's Clang-Thread-Safety-Analysis-annotated recursive lock, out
 * of scope by explicit instruction.  __sig_wait_delivery() (also
 * sigdelivery.c) keeps its own pre-existing NTSTATUS/LARGE_INTEGER*
 * signature unconverted too, for a narrower reason: src/unistd/sleep.c
 * -- outside this migration's scope -- calls it directly with a
 * LARGE_INTEGER it constructs itself, so that signature cannot change
 * without touching a file this migration does not own.  Its raw wait
 * calls are still relocated, via __plat_signal_wait() below; only the
 * thin NTSTATUS/LARGE_INTEGER* wrapper stays in sigdelivery.c, and its
 * return value is never once inspected by any of its callers, so
 * collapsing every NT wait outcome into a single reported status there
 * is not a behavior change.
 *
 * This subsystem's own wire protocol (sigdelivery.c's named pipes and
 * mutants) has no POSIX shape to begin with -- it is this library's own
 * invented cross-process RPC, built entirely out of NT object-manager
 * primitives -- so several functions below necessarily take an NT
 * UNICODE_STRING* for an object name, the same way src/internal/
 * plat_mem.h's __plat_mem_map_file() necessarily takes an off_t: there
 * is no POSIX-shaped alternative for what these operations are.  What
 * IS relocated, per the general contract, is every NTSTATUS-level
 * interpretation step: STATUS_PENDING waits, STATUS_PIPE_CONNECTED/
 * STATUS_OBJECT_NAME_EXISTS/STATUS_PROCESS_IS_TERMINATING special-
 * casing, and the [EPERM]-vs-[ESRCH] decision on a failed process open
 * that needs the real status in hand (see __plat_kill_open() below and
 * the matching note in plat_misc.h, whose sched.c call site makes
 * exactly the same decision for exactly the same reason).
 */
#ifndef _SPICULE_PLAT_SIGNAL_H
#define _SPICULE_PLAT_SIGNAL_H

#include <sys/types.h>
#include "plat_handle.h"

struct _UNICODE_STRING;

/* ---- sigdelivery.c -------------------------------------------------- */

/* Create a SynchronizationEvent, initially signalled iff
 * `initially_signalled`.  __PLAT_HANDLE_NULL on failure.  Named
 * __plat_sigevent_create(), not __plat_event_create(), to stay distinct
 * from plat_thread.h's __plat_event_create(__plat_handle_t *) -- same
 * underlying NT primitive, different calling convention (this one
 * returns the handle directly rather than through an out-param, and
 * takes an initial-signal-state flag thread's does not need). */
__plat_handle_t __plat_sigevent_create(int initially_signalled);

/* Signal `ev`.  0/-1(errno) via return. */
int __plat_event_set(__plat_handle_t ev);

/* Linux only: post one unit to `ev`, an eventfd created by __plat_
 * sigevent_create() above -- __sig_notify_delivery()'s (sigdelivery.c)
 * real, correct wake for `wake_event`. NOT the same operation as
 * __plat_event_set() just above for this platform, and calling that
 * function on an eventfd handle is a real, confirmed bug, not a
 * theoretical one: __plat_sigevent_create()'s return value lives in
 * src/signal/linux/plat_signal.c's own box()/unbox() eventfd domain
 * (fd+1), but __plat_event_set()'s one Linux implementation
 * (src/thread/linux/plat_thread.c) casts its argument straight to
 * `struct spicule_linux_sync *` and dereferences it -- a completely
 * different __plat_handle_t domain that only happens to share this
 * project's one universal handle typedef, the identical class of
 * mismatch this header's own __plat_kill_open()/__plat_process_suspend()
 * banner already discloses for the bare-pid convention. Confirmed by
 * crashing for real (SIGSEGV inside __plat_event_set(), dereferencing a
 * small integer as a pointer) the first time __raise_internal_info()
 * ever reached a real, non-default handler through a genuine kernel-
 * delivered signal on this platform -- which, before real rt_sigaction(2)
 * fault delivery existed, had never happened: __signal_init() itself was
 * never called from Linux's own crt1.c until that same change, so
 * wake_event was always still 0 (the `if (wake_event) ...` guard this
 * header used to cite as proof no real caller passes a bad handle
 * through skipped the call every time, for an unrelated reason -- not
 * because the domain was ever actually correct). NT needs no such split:
 * NT's own __plat_sigevent_create() (src/signal/nt/plat_signal.c) returns
 * a real NT event HANDLE, the one object domain NT's __plat_event_set()
 * already expects, so this function is Linux-only and NT's sigdelivery.c
 * keeps calling __plat_event_set() for wake_event exactly as before. */
int __plat_sigevent_set(__plat_handle_t ev);

/* Wait (alertably, so timer APCs stay deliverable) on `wake_event` if it
 * is not __PLAT_HANDLE_NULL, for up to `ticks` 100ns units (NT's own
 * relative/absolute LARGE_INTEGER encoding, passed through unchanged)
 * when `has_timeout`, or indefinitely when not; when `wake_event` IS
 * __PLAT_HANDLE_NULL (this process's delivery event was never created --
 * a degraded startup, see sigdelivery.c's own comment), sleep for
 * `ticks`/indefinitely the same way, or for a fixed 100ms fallback when
 * neither a timeout nor an event is available.  No return value: every
 * caller of __sig_wait_delivery() (signal.c, unistd/sleep.c) discards
 * what woke it and just rechecks its own state. */
void __plat_signal_wait(__plat_handle_t wake_event, int has_timeout, long long ticks);

/* Create (FILE_OPEN_IF) the named, message-mode signal-delivery pipe
 * object `name` -- sigdelivery.c's sig_create_pipe().
 * __PLAT_HANDLE_NULL on failure. */
__plat_handle_t __plat_signal_pipe_create(const struct _UNICODE_STRING *name);

/* Block until a client connects to `pipe` (FSCTL_PIPE_LISTEN, with the
 * STATUS_PIPE_CONNECTED-means-already-connected normalization
 * sigdelivery.c's banner explains). 1 connected, 0 on any failure. */
int __plat_signal_pipe_listen(__plat_handle_t pipe);

/* Read up to `len` bytes from `h` into `buf` (STATUS_PENDING handled
 * internally). 0 with *received set on success, -1 on failure.
 * received is required: written unconditionally on the success path
 * with no NULL check (the outputs being left untouched on FAILURE is
 * a fact about the value, not about whether the pointer itself may be
 * NULL -- d24fe86's own __plat_process_fork() precedent); both real
 * call sites (src/signal/nt/sigdelivery.c) pass &got, never NULL. */
int __plat_signal_pipe_read(__plat_handle_t h, void *buf, size_t len, size_t *received)
    __attribute__((nonnull(4)));

/* Write `len` bytes of `buf` to `h` (STATUS_PENDING handled
 * internally). 0 with *sent set on success, -1 on failure. sent
 * required, same reasoning and both real call sites (&sent) as
 * __plat_signal_pipe_read() above. */
int __plat_signal_pipe_write(__plat_handle_t h, const void *buf, size_t len, size_t *sent)
    __attribute__((nonnull(4)));

/* 100ms backoff delay -- sig_delivery_thread()'s retry pause after a
 * failed pipe (re)create. */
void __plat_signal_backoff(void);

/* Create-or-open (OBJ_OPENIF) the named mutant `name` -- used both by
 * __sig_delivery_init() (this process's own send-serializing mutant)
 * and kill()'s cross-process arm (the target's).  __PLAT_HANDLE_NULL on
 * failure. */
__plat_handle_t __plat_signal_mutant_create(const struct _UNICODE_STRING *name);

/* Acquire `h` (wait indefinitely, non-alertable) -- sig_try_deliver_
 * remote_info()'s mutant acquisition. 1 success, 0 any failure. */
int __plat_wait_acquire(__plat_handle_t h);

/* Release the mutant `h`. */
void __plat_mutant_release(__plat_handle_t h);

/* Zero-timeout peek at `ev`: 1 if it was signalled (and, being
 * auto-reset, is now consumed), 0 if not.  Used both to check a
 * candidate stop-event (__sig_consume_child_stop(), signal.c) and to
 * retract a stop notification that turned out not to be needed
 * (stop_self(), signal.c). */
int __plat_event_peek(__plat_handle_t ev);

/* Open the client end of pid's signal pipe (see sigdelivery.c's
 * sig_pipe_name()), for a kill() sender's request/reply exchange.
 * __PLAT_HANDLE_NULL if the pipe does not currently name a listener --
 * sig_try_deliver_remote_info()'s caller draws no distinction between
 * that and any other open failure (see sigdelivery.c's own banner). */
__plat_handle_t __plat_signal_pipe_open(const struct _UNICODE_STRING *name);

/* Start a new NT thread running `entry(arg)` (calling convention/
 * signature `ULONG NTAPI entry(void *arg)`, NtCreateThreadEx's own
 * requirement) -- runs detached, as every thread this library ever
 * creates does (NT tears down every thread of a process at exit).
 * 0/-1 via return, *out set to the new thread's still-open handle on
 * success. out required: written unconditionally on success, no NULL
 * check; its one real call site (src/signal/nt/sigdelivery.c) passes
 * &thr, never NULL. NT-only (this header's own banner on
 * src/signal/linux/plat_signal.c: the pipe/mutant transport this
 * thread serves is not yet ported, so there is no Linux definition to
 * cross-check against). */
int __plat_thread_start(void *entry, void *arg, __plat_handle_t *out)
    __attribute__((nonnull(3)));

/* ---- signal.c --------------------------------------------------------- */

/* Create-or-open (OBJ_OPENIF) the named, initially-unsignalled
 * SynchronizationEvent `name` -- stop_self()'s self-stop marker.
 * __PLAT_HANDLE_NULL with errno set (__set_errno_status()'s generic
 * mapping -- there is no per-status decision to make for this one) on
 * failure. */
__plat_handle_t __plat_stop_event_create(const struct _UNICODE_STRING *name);

/* __sig_consume_child_stop()'s per-candidate-signal probe: create-or-
 * open the named event; on ANY failure simply report "not this one",
 * touching no errno (unlike __plat_stop_event_create() above, which IS
 * meant to report a failure to its caller) so the loop's next candidate
 * is tried exactly as before. *already_existed is set only on success,
 * to 1 iff the name already lived (STATUS_OBJECT_NAME_EXISTS) --
 * exactly the distinguishing fact the loop needs the real status in
 * hand for: an event this call created fresh cannot possibly have a
 * stop already recorded in it. 0/-1 via return. out/already_existed
 * both required: both backends (NT and Linux) write both
 * unconditionally on the success path with no NULL check, and the
 * one real call site (src/signal/signal.c's __sig_consume_child_stop())
 * passes &h/&already_existed, never NULL. */
int __plat_stop_event_probe(const struct _UNICODE_STRING *name, __plat_handle_t *out, int *already_existed)
    __attribute__((nonnull(2, 3)));

/* Suspend/resume THIS process (NtSuspendProcess(NtCurrentProcess())) --
 * stop_self()'s own suspend; distinct from __plat_process_suspend()/
 * __plat_process_resume() below, which act on a handle to some OTHER
 * process (kill()'s job-control arm). 0/-1(errno) via return. */
int __plat_process_suspend_self(void);

/* Suspend/resume the process `h` refers to -- kill()'s SIGSTOP/SIGCONT
 * job-control arm (sig_job_control(), signal.c). 0/-1(errno) via
 * return. */
int __plat_process_suspend(__plat_handle_t h);
int __plat_process_resume(__plat_handle_t h);

/* Open pid's process object for kill()'s cross-process operations --
 * PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION always,
 * PROCESS_SUSPEND_RESUME too when `want_suspend_resume` (job-control
 * signals only). [EPERM] on failure iff the platform's own access
 * check specifically refused (STATUS_ACCESS_DENIED); [ESRCH] for every
 * other reason (no such process). The distinction is made here, with
 * the real status still in hand -- see this header's own banner. out
 * required: both backends write it unconditionally on the success
 * path with no NULL check, and the one real call site
 * (src/signal/signal.c's kill()) passes &h, never NULL. */
int __plat_kill_open(pid_t pid, int want_suspend_resume, __plat_handle_t *out)
    __attribute__((nonnull(3)));

/* NtTerminateProcess(h, exitcode), with kill()'s own tolerance: a
 * target already exiting reports STATUS_PROCESS_IS_TERMINATING, which
 * kill() treats as success rather than the [ESRCH] the generic status
 * table would give it (see __errno_from_status()) -- POSIX's kill() to
 * a process that no longer meaningfully exists as a live target is not
 * a failure the caller can act on. 0/-1(errno) via return. */
int __plat_kill_terminate(__plat_handle_t h, int exitcode);

/* SEGV_MAPERR vs SEGV_ACCERR for a fault at `addr` -- see signal.c's
 * own comment on segv_code() (moved here verbatim) for the full
 * MEM_COMMIT/Protect reasoning. */
int __plat_segv_code(void *addr);

/* Synchronize `sig`'s disposition with the real, kernel-level signal
 * disposition, for the two dispositions the kernel already implements
 * entirely on its own with no userspace callback at all: SIG_IGN
 * (`ignore` nonzero) and SIG_DFL (`ignore` zero). signal()/sigaction()
 * (src/signal/signal.c) call this on every disposition change, so that a
 * signal the KERNEL itself can raise synchronously out of a syscall --
 * SIGPIPE from write() to a reader-less pipe is the motivating case, see
 * src/unistd/linux/plat_fd.c's own banner -- is actually ignored/restored
 * to default at the point the kernel decides whether to act, rather than
 * always running the kernel's inherited-at-exec disposition regardless of
 * what this library's own handlers[] table says.
 *
 * Deliberately narrower than "make signal() work on Linux": a real
 * user-defined handler is NOT installed at the kernel level by this call
 * (or by anything else yet) -- doing that needs a real
 * rt_sigaction(2)-installed entry point with its own sigreturn trampoline,
 * disclosed and left for later exactly where src/signal/linux/
 * sigdelivery.c's own banner already discloses the identical gap on the
 * delivery side. A signal caught by a real spicule handler still only
 * fires for what this library synthesizes itself -- raise(), abort(), a
 * hardware fault turned into a signal, kill() to self (see signal.c's own
 * header comment) -- exactly as before this function existed; this call
 * only ever asks the kernel for SIG_IGN or SIG_DFL, never a function
 * pointer, so no trampoline is ever needed.
 *
 * No-op where there is no real kernel signal delivery to synchronize
 * with in the first place (the NT backend, which already gets this
 * right by construction: every signal reaching __raise_internal() on NT
 * was synthesized by this library, which always consults handlers[]
 * itself -- see src/signal/nt/plat_signal.c's own definition). */
void __plat_sig_sync_kernel(int sig, int ignore);

/* End THIS process exactly as if by sig's real default action -- the
 * meaning every __ENCODE_SIGNAL_EXIT(sig)-encoded code passed to
 * __exit_internal() (src/exit/exit.c, libc.h) carries: kill()/raise()'s
 * own default-terminate path in src/signal/signal.c, abort()'s
 * guaranteed-termination fallback (which reaches here even with sig
 * blocked, ignored, or caught by a handler that returned -- abort.html
 * requires overriding all three), the exec() stand-in re-raising a
 * child's own termination signal, the vectored exception handler.
 *
 * __exit_internal() calls this FIRST for such a code, before falling
 * back to its own NT-shaped simulation of one (an ordinary process exit
 * whose status ENCODES the signal number, decoded back out by
 * src/process/wait.c's __wait_encode_status()). That simulation is the
 * only option NT has, and is exactly right there -- see this header's
 * own __plat_sig_sync_kernel comment: every signal reaching this point
 * on NT was already synthesized by this library. Linux is different: it
 * has a real per-signal kernel default action of its own, and
 * src/process/linux/plat_process.c's own __plat_process_wait() already
 * expects to read back a REAL WIFSIGNALED wait4(2) status for a child
 * that died this way, not an encoded exit code -- simulating one there
 * is not merely unnecessary, it is wrong: a plain exit_group(2) is
 * reported WIFEXITED to this process's own parent, not WIFSIGNALED.
 *
 * Returns, instead of ending the process, when raising sig for real did
 * not end it -- __exit_internal() falls back to its own simulated
 * termination in that case, same as if this function had never been
 * called. Always simply returns on NT, which has no kernel signal of
 * its own to raise (this header's own __plat_sig_sync_kernel comment,
 * same paragraph), so __exit_internal()'s fallback is what actually
 * ends the process there, same as before this function existed. */
void __plat_sig_default_terminate(int sig);

/* Install a REAL rt_sigaction(2) handler for SIGSEGV/SIGBUS/SIGILL/
 * SIGFPE/SIGTRAP -- unlike __plat_sig_sync_kernel() above, this installs
 * an actual function, with a real sigreturn trampoline
 * (arch/aarch64/src/sigreturn_trampoline.S), so a genuine hardware fault
 * reaches __raise_internal_info() the same way any other signal source
 * does, instead of running the kernel's own default action unseen by
 * this library. src/signal/linux/plat_signal.c's own comment on this
 * function has the full story, including why only these five signals and
 * not every signal number (that is real cross-process delivery via kill()/
 * tgkill(), a distinct, larger piece of work left for later). Called once,
 * from __signal_init()'s Linux path (src/signal/signal.c), which is also
 * why this returns nothing to check: same as __plat_sig_sync_kernel()'s
 * own rt_sigaction(2) calls, there is nothing a caller at process startup
 * could usefully do differently on a failure here besides continue with
 * hardware faults falling back to the kernel's own default action --
 * exactly the pre-existing behavior this call is adding to, not replacing
 * outright. NT-only builds never declare or call this at all (see this
 * header's own banner on scope); on Linux it is declared unconditionally
 * like every other function here, matching this header's own convention. */
void __plat_sig_install_fault_handlers(void);

/* Install the SAME real rt_sigaction(2) dispatch __plat_sig_install_
 * fault_handlers() above installs for its fixed five, but for exactly
 * one caller-chosen `sig` -- signal()/sigaction()'s own Linux widening
 * (src/signal/signal.c), called whenever either one installs a REAL,
 * catchable disposition (sa_handler/h neither SIG_IGN nor SIG_DFL) for
 * ANY signal, not only the hardware-fault five. This is what makes
 * src/signal/linux/sigdelivery.c's cross-process delivery real: once
 * installed, tgkill(2)/kill(2)/pidfd_send_signal(2) FROM ANOTHER PROCESS
 * invoke this dispatch directly through the kernel, which then re-reads
 * handlers[sig] itself (via __raise_internal_info()) and does whatever
 * that table currently says -- so a later signal()/sigaction() call that
 * changes the disposition back to SIG_IGN/SIG_DFL needs no matching
 * "uninstall" here: __plat_sig_sync_kernel() above already keeps the
 * kernel's own SIG_IGN/SIG_DFL state in step for the *decision* dispatch
 * makes, and this function's own installed entry point is safe to leave
 * in place regardless, exactly as it already is for the fixed five
 * fault signals once installed once at __signal_init() time. Idempotent
 * (a second call for the same `sig` just repeats the identical
 * rt_sigaction(2)), so callers never need to track whether they already
 * called it. No return value, for the same reason
 * __plat_sig_install_fault_handlers() has none: nothing a caller holding
 * signal.c's own lock could usefully do differently on a failure here
 * besides continue with that one signal's remote delivery falling back
 * to the pre-Tier-2 default-action guess, exactly as it already does
 * when this is never called at all. */
void __plat_sig_install_real_handler(int sig);

/* Read the TARGET process `pid`'s own real, kernel-level disposition for
 * `sig` straight out of /proc/pid/status (proc(5): SigCgt and SigIgn are
 * both 64-bit hex bitmasks, one bit per signal, matching this project's
 * own _NSIG(64) exactly -- the same fact src/signal/linux/plat_signal.c's
 * own struct kernel_sigaction comment already relies on for sigsetsize)
 * and report whether it is anything other than the default action: a bit
 * set in SigCgt means a real handler is installed there (this file's own
 * __plat_sig_install_real_handler() is the only thing that ever sets one,
 * for a signal outside the fixed hardware-fault five __plat_sig_install_
 * fault_handlers() covers unconditionally), and a bit set in SigIgn means
 * SIG_IGN (__plat_sig_sync_kernel()). 1 for either, 0 for SIG_DFL AND for
 * any failure reading the target's own state at all (a process that has
 * already exited, one this call raced, or a /proc that for whatever
 * reason cannot be read) -- the safe default either way, since 0 is
 * exactly what a caller already does today when this capability plain
 * does not exist: kill()'s own sig_job_control() fallback (src/signal/
 * signal.c), unaffected either way. The one real caller is src/signal/
 * linux/sigdelivery.c's __sig_try_deliver_remote_nondefault(): kill()'s
 * catchable-stop-signal arm (SIGTSTP/SIGTTIN/SIGTTOU) needs to know
 * BEFORE acting whether the target's disposition overrides the default
 * stop action, since unlike every other signal there is no single real
 * syscall whose own outcome would tell this sending process that
 * afterwards -- a real SIGTSTP either invokes a caught handler (this
 * process never sees that happen) or genuinely stops the target (this
 * process needs to record that transition in its OWN child table for
 * waitpid() to report, which needs deciding, not discovering, the
 * outcome). Linux-only in practice (the one caller is Linux's own
 * sigdelivery.c) but declared unconditionally like every other function
 * in this header. */
int __plat_sig_remote_disposition_nondefault(pid_t pid, int sig);

/* ---- children.c -------------------------------------------------------- */

/* Can kill(pid, SIGHUP) to some OTHER process actually deliver a real
 * SIGHUP there -- applying THAT process's own real disposition for it --
 * instead of being forced through __plat_kill_terminate()'s
 * unconditional-destroy fallback (NT's only option -- see kill()'s own
 * comment in src/signal/signal.c)?  The one caller is children.c's
 * clear_stops(): exit.html's orphaned-stopped-process-group clause wants
 * SIGHUP before SIGCONT, but only where sending it is not itself the
 * strictly-worse outcome the clause is trying to avoid -- see the big
 * comment above __child_resume_stopped() for the full reasoning on both
 * platforms.
 *
 * True on Linux: kill()'s own cross-process arm
 * (src/signal/linux/sigdelivery.c's __sig_try_deliver_remote()) sends a
 * genuine pidfd_send_signal(2) of the real signal number, applying
 * whatever real KERNEL-level disposition the TARGET process itself last
 * synced for it -- SIG_IGN is a real no-op, SIG_DFL runs the real
 * default action (Term, for SIGHUP), and, as of this Tier-2 widening
 * (signal()/sigaction()'s own __plat_sig_install_real_handler() call,
 * this header's own comment), a real caught handler now genuinely runs
 * too, if the target installed one. False on NT, where that same
 * fallback is NtTerminateProcess unconditionally regardless of
 * disposition. */
int __plat_sig_deliverable_to_other_process(void);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
