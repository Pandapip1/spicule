/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-thread interface src/thread/{pthread,pthread_cancel,
 * pthread_cond,pthread_mutex,pthread_rwlock,pthread_signal,pthread_sync,
 * pthread_tsd,semaphore,mqueue,aio}.c's POSIX-facing front doors call into
 * instead of raw Nt{CreateThreadEx,SuspendThread,ResumeThread,
 * GetContextThread,SetContextThread,QueueApcThread,WaitForSingleObject,
 * WaitForMultipleObjects,CreateEvent,SetEvent,CreateSemaphore,
 * OpenSemaphore,ReleaseSemaphore,QuerySemaphore,CreateMutant,
 * ReleaseMutant,DuplicateObject,QueryInformationThread,TerminateThread,
 * TerminateProcess,DelayExecution,QuerySystemTime,ReadFile,WriteFile}
 * calls.  See src/thread/nt/plat_thread.c for the implementation these
 * declare.
 *
 * Every function here takes POSIX/opaque-shaped arguments and returns a
 * POSIX-shaped result -- errno already set on failure, never a raw NTSTATUS
 * for the front door to interpret.  A handful of exceptions are
 * deliberate, not oversights, and each is called out at its own
 * declaration below:
 *
 *   - __plat_wait_one()/__plat_wait_any() return a small fixed enum
 *     (__PLAT_WAIT_*) rather than 0/-1.  Every wait-with-retry loop across
 *     this subsystem's mutex/cond/rwlock/barrier/once/semaphore/aio code
 *     branches on strictly the same four outcomes -- object acquired,
 *     timed out, woken by an APC/alert with nothing to show for it yet, or
 *     a real error -- so this is the POSIX-shaped vocabulary those loops
 *     already speak, not raw NT status leaking through.  The loop
 *     structure itself (what to DO with each outcome: retry, translate to
 *     ETIMEDOUT, run __pthread_testcancel(), ...) stays in the front door
 *     exactly as before; only the individual NtWaitFor{Single,Multiple}
 *     Object() call at the bottom of each loop iteration moves here.
 *
 *   - __plat_event_create() and __plat_thread_spawn() additionally return
 *     -2 (distinct from the usual -1/errno) for NT's STATUS_NOT_IMPLEMENTED
 *     -- observed on some sandboxed hosts that have no event/thread
 *     objects at all.  aio.c's start_worker() has a real degraded-but-
 *     correct fallback (run every request synchronously) that must trigger
 *     on exactly that condition and no other failure; reconstructing "was
 *     it specifically STATUS_NOT_IMPLEMENTED" from a generic errno
 *     afterward is exactly the trap this interface exists to avoid, so the
 *     decision is made here, once, while the real status is still in hand.
 *
 *   - __plat_thread_entry_t/__plat_apc_fn are NT's own native-thread-start
 *     and asynchronous-procedure-call callback shapes.  There is no POSIX
 *     vocabulary for "a function the kernel invokes directly in a target
 *     thread it does not otherwise control" -- pthread_create()'s native
 *     thread entry and pthread_cancel()'s/pthread_kill()'s APC-delivered
 *     signal trampoline all need exactly this shape, and inventing a
 *     POSIX-looking wrapper around it would hide, not remove, the
 *     platform dependency.  The callback BODIES (thread_entry(),
 *     notice_thread(), aio_worker(), signal_apc(), cancel_apc()) all stay
 *     in their front doors, unmoved: every one of them operates on
 *     private front-door state (struct __pthread, the aio request table,
 *     ...) that has no business being visible from src/thread/nt/.
 */
#ifndef _NTLIBC_PLAT_THREAD_H
#define _NTLIBC_PLAT_THREAD_H

#include <stddef.h>
#include <sys/types.h>
#include "plat_handle.h"
#include "thread_annotations.h"

#ifdef NTLIBC_LOCKSET_ANALYSIS
/* The fast lock is the ntdll PEB lock on NT and the corresponding
 * process-wide futex lock on Linux.  The capability token names the
 * logical lock, independently of which backend supplies it. */
extern __ntlibc_lock_capability __ntlibc_peb_lock_token;
#endif

/* NT's __stdcall on i386, the only calling convention x86_64 has -- the
 * exact condition src/internal/nt.h's own NTAPI macro gates on, reproduced
 * here rather than pulled in via nt.h so this header stays free of every
 * other NT declaration a hypothetical future backend would have no use
 * for. */
#if defined(__i386__)
#define __PLAT_APC_CALL __attribute__((stdcall))
#else
#define __PLAT_APC_CALL
#endif

/* pthread_create()'s native thread entry point shape (NtCreateThreadEx's
 * StartRoutine) and NT's asynchronous-procedure-call callback shape
 * (NtQueueApcThread's ApcRoutine) -- see this file's banner for why both
 * are exposed as-is rather than behind a POSIX-looking wrapper. */
typedef unsigned (__PLAT_APC_CALL *__plat_thread_entry_t)(void *);
typedef void (__PLAT_APC_CALL *__plat_apc_fn)(void *, void *, void *);

/* ---- waiting ------------------------------------------------------------
 * See this file's banner for why these four outcomes, not a raw NTSTATUS,
 * are the interface. */
#define __PLAT_WAIT_OK      0   /* the object was acquired/signalled */
#define __PLAT_WAIT_TIMEOUT 1   /* the requested interval elapsed first */
#define __PLAT_WAIT_INTR    2   /* alertable wait woken by an APC/alert;
                                 * nothing acquired -- go around again */
#define __PLAT_WAIT_ERROR   3   /* a genuine failure; errno is set */

/* Wait on one object.  `alertable` matches NtWaitForSingleObject's own
 * Alertable argument.  `has_timeout` zero means block indefinitely
 * (a NULL LARGE_INTEGER timeout pointer); nonzero means `relative_ticks`
 * (100ns units, already negative/relative or exactly zero for an
 * immediate poll -- the caller's own convention, unchanged) is passed
 * through verbatim. */
/* h is required: the Linux backend (src/thread/linux/plat_thread.c) casts
 * it straight to `struct ntlibc_linux_sync *obj` and dereferences
 * obj->kind/obj->futex unconditionally, with no NULL check -- the NT
 * backend merely forwards h to NtWaitForSingleObject() as an opaque
 * value, but this one shared declaration's contract is set by whichever
 * backend actually dereferences it (the same precedent as plat_time.h's
 * own __plat_realtime_get()/__plat_timer_manager_start() comments), and
 * no real caller anywhere in this tree ever passes a zero/uninitialized
 * handle -- several (src/signal/signal.c's own `if (__plat_event_set(
 * self_stop_event) < 0) ...` guard on the ntlibc_linux_sync-pointer
 * domain this platform's __plat_event_set() really expects; src/signal/
 * nt/sigdelivery.c's own `if (wake_event) __plat_event_set(wake_event);`
 * on NT's own single real handle domain) explicitly skip the call instead
 * of ever passing a null one through. NOT src/signal/linux/sigdelivery.c's
 * OWN wake_event, which is a genuinely different domain (a real eventfd)
 * this platform's __plat_event_set() must never be called on at all --
 * see src/internal/plat_signal.h's __plat_sigevent_set() comment for the
 * real, confirmed crash that shape of mismatch caused here. */
int __plat_wait_one(__plat_handle_t h, int alertable, int has_timeout,
                    long long relative_ticks) __attribute__((nonnull(1)));
/* Same, for NtWaitForMultipleObjects' WaitAny mode -- the only mode any
 * caller in this subsystem uses.  Which of `handles[0..count)` woke the
 * wait is never reported: no existing caller needs it (each re-derives
 * what happened from its own state under its own lock after the wait
 * returns), matching NtWaitForMultipleObjects' STATUS_WAIT_0+n encoding
 * folding uniformly into __PLAT_WAIT_OK here.
 *
 * handles is required: the Linux backend subscripts it directly
 * (`handles[i]`) to build each element's own obj cast, unconditionally
 * whenever count > 0, and this subsystem's one real caller (aio.c's
 * aio_suspend(), via its own on-stack `handles[2]`) never passes NULL. */
int __plat_wait_any(__plat_handle_t *handles, unsigned count, int alertable,
                    int has_timeout, long long relative_ticks)
    __attribute__((nonnull(1)));

/* ---- events (SynchronizationEvent, initially unset) ---------------------
 * __plat_event_create()'s -2 is explained in this file's banner.
 *
 * out is required in both: each backend writes `*out = ...;`
 * unconditionally on its own success path (the NT backend via
 * NtCreateEvent()'s own out-param convention, the Linux backend directly),
 * with no NULL check in either, and every real call site in this tree
 * passes the address of a real on-stack/struct-field handle, never NULL.
 * __plat_event_set()'s h is required the same way __plat_wait_one()'s is
 * above -- the Linux backend dereferences it (cast to obj) unconditionally,
 * with no NULL check, and no real caller ever passes a null one through
 * (the same `if (handle) ...`-before-calling pattern documented on
 * __plat_wait_one() above). */
int __plat_event_create(__plat_handle_t *out) __attribute__((nonnull(1)));
int __plat_event_set(__plat_handle_t h) __attribute__((nonnull(1)));

/* ---- unnamed semaphores --------------------------------------------------
 * `inheritable` requests OBJ_INHERIT, needed only by sem_init()'s
 * process-shared/fork-surviving semaphores -- every internal wait object
 * this subsystem builds for its own bookkeeping (a mutex/cond/rwlock
 * waiter's private wake object) passes 0.
 *
 * out is required the same way __plat_event_create()'s is above. */
int __plat_semaphore_create(long initial, long maximum, int inheritable,
                            __plat_handle_t *out) __attribute__((nonnull(4)));
/* Release by exactly 1 -- the only count any caller in this subsystem
 * ever releases by.  NT's STATUS_SEMAPHORE_LIMIT_EXCEEDED becomes
 * [EOVERFLOW] here, not reconstructed afterward: see write.c's SIGPIPE
 * comment (src/unistd/nt/plat_fd.c) for why this class of decision belongs
 * inside the backend function that still has the real status in hand.
 *
 * h is required the same way __plat_event_set()'s is above. */
int __plat_semaphore_post(__plat_handle_t h) __attribute__((nonnull(1)));
/* h/value are both required: the Linux backend dereferences h (cast to
 * obj) and writes `*value = ...;` unconditionally, with no NULL check on
 * either; the NT backend writes `*value = info.CurrentCount;`
 * unconditionally on its own success path too. Every real call site
 * (src/thread/semaphore.c's own `sem->__handle`/`value`) passes real,
 * non-null arguments. */
int __plat_semaphore_getvalue(__plat_handle_t h, int *value)
    __attribute__((nonnull(1, 2)));

/* ---- named objects under \BaseNamedObjects -------------------------------
 * `name` is the already-fully-qualified NT object-manager path, ASCII
 * (every name this subsystem builds is ASCII by construction -- a hash or
 * a pid/sequence pair formatted with snprintf), built by the front door;
 * everything UNICODE_STRING/OBJECT_ATTRIBUTES-shaped about turning it into
 * an NT object lives entirely inside the backend. */

/* A fresh, believed-unique name (the front door has already embedded a
 * pid/sequence counter in it) -- collision is a plain error, not a
 * create-or-open contract. */
/* out is required the same way __plat_event_create()'s is above: every
 * backend writes `*out = ...;` unconditionally on its own success path
 * (the Linux backend's implementation of this one always fails first,
 * see that file's own banner, but the shared contract is set by the
 * backend that actually uses it, the same precedent as
 * __plat_thread_stack_extent() below), and this subsystem's real call
 * sites (src/thread/semaphore.c's own `&h`) never pass NULL. */
int __plat_named_semaphore_create(const char *name, long initial,
                                  long maximum, __plat_handle_t *out)
    __attribute__((nonnull(4)));
/* -2 (distinct from the usual -1/errno), rather than a generic ENOENT,
 * reports NT's STATUS_OBJECT_NAME_NOT_FOUND specifically: sem_open()'s
 * O_CREAT-without-O_EXCL recovery path (a creator can die after
 * publishing the filesystem record but before filling it in with a real
 * object name) must fire on exactly that condition and no other -- see
 * this file's banner on why that decision is made here, not
 * reconstructed from errno afterward.
 *
 * out is required the same way. */
int __plat_named_semaphore_open(const char *name, __plat_handle_t *out)
    __attribute__((nonnull(2)));
/* Create it, or open the existing one if the name is already taken.
 * Wine reports an existing named semaphore as the ERROR status
 * STATUS_OBJECT_NAME_COLLISION rather than NT's own informational
 * STATUS_OBJECT_NAME_EXISTS; falling back to an open on exactly that
 * status -- decided here, while it is still in hand -- is what makes this
 * a create-or-open primitive at all rather than one that merely fails
 * under Wine every time the name is reused.
 *
 * out is required the same way. */
int __plat_named_semaphore_open_or_create(const char *name, long initial,
                                          long maximum, __plat_handle_t *out)
    __attribute__((nonnull(4)));

/* A named binary mutant used as a cross-process advisory lock: create-or-
 * open it (NT's OBJ_OPENIF) and wait on it, infinitely and non-alertably,
 * as one call -- the two steps NT's own object manager makes atomic
 * against a second creator racing the same name, so splitting them across
 * two backend calls would reintroduce exactly the race this pattern
 * exists to avoid. */
/* out is required the same way __plat_event_create()'s is above: both
 * backends write `*out = ...;` unconditionally on their own success
 * path, with no NULL check, and this subsystem's real call sites
 * (src/thread/semaphore.c's own `out`, itself the front door's already-
 * required output) never pass NULL. */
int __plat_named_mutant_acquire(const char *name, __plat_handle_t *out)
    __attribute__((nonnull(2)));
void __plat_named_mutant_release(__plat_handle_t lock);

/* Releases a handle from ANY of __plat_event_create()/
 * __plat_semaphore_create()/__plat_named_semaphore_create()/
 * __plat_named_semaphore_open()/__plat_named_semaphore_open_or_create()/
 * __plat_named_mutant_acquire() once no caller will wait on, post, or set
 * it again -- deliberately its own call, NOT plat_fd.h's generic
 * __plat_close(), for exactly the class of reason __plat_thread_close()
 * above is its own call: on NT every one of those handles IS a real
 * NtClose()-able HANDLE, so that backend's implementation just forwards to
 * __plat_close(). On Linux, though, every one of those handles is a raw
 * `struct ntlibc_linux_sync *` -- an mmap(2)'d pointer (src/thread/linux/
 * plat_thread.c's own banner and src/internal/linux/sync.h), not a boxed
 * fd+1 -- so __plat_close() there truncates that pointer to a 32-bit "fd"
 * and issues close(2) on it: a real, confirmed bug, generalizing
 * __plat_thread_close()'s own banner to a second boxed-handle domain.
 * Typically this just clobbers the caller's own errno with a bogus EBADF
 * (the truncated pointer essentially never names a real open descriptor,
 * but close(2) still fails and still sets errno) immediately after an
 * otherwise-successful mutex/cond/rwlock/once/semaphore/mqueue teardown;
 * in principle, if the truncated value ever did collide with a real open
 * fd, it would close that unrelated descriptor instead. Worse than the
 * thread-handle case in a second way even when errno is the only casualty:
 * close(2) never releases the underlying mmap()'d page either way, so
 * every wrongly-__plat_close()'d sync handle also leaks a full page --
 * unbounded under sustained load from call sites (pthread_cond.c's
 * cond_wait(), pthread_rwlock.c's rwlock_acquire(), pthread_sync.c's
 * pthread_once()/pthread_barrier_wait()) that allocate a fresh one per
 * wait, not once per object lifetime.
 *
 * h is required: neither backend dereferences it (NT forwards it opaquely
 * to __plat_close(); Linux's munmap(2) takes the raw pointer value
 * itself), but every real call site across pthread_cond.c/pthread_mutex.c/
 * pthread_rwlock.c/pthread_sync.c/pthread_tsd.c/semaphore.c/mqueue.c either
 * guards with an explicit `if (handle) ...` (where a degraded creation
 * failure can legitimately leave it zero) or calls unconditionally on a
 * handle already known non-null by construction (an object whose creation
 * already succeeded) -- never a null one through either way. */
int __plat_sync_close(__plat_handle_t h) __attribute__((nonnull(1)));

/* ---- thread lifecycle ----------------------------------------------------
 * __plat_thread_spawn()'s -2 is explained in this file's banner.
 * `stack_size` 0 requests the image's own default (NtCreateThreadEx's own
 * meaning for a zero reserve/commit size); nonzero is used for both the
 * reserve and commit size, matching every existing call site, which never
 * asked for the two to differ.
 *
 * out is required the same way: both backends write `*out = ...;`
 * unconditionally on their own success path (the NT backend via
 * NtCreateThreadEx()'s own out-param convention, the Linux backend
 * directly, `*out = (__plat_handle_t)(pid + 1);`), with no NULL check
 * in either, and every real call site (pthread.c's pthread_create(),
 * aio.c's start_worker()/notify()) passes a real on-stack local. */
int __plat_thread_spawn(__plat_thread_entry_t entry, void *arg,
                        size_t stack_size, int create_suspended,
                        __plat_handle_t *out) __attribute__((nonnull(5)));
/* Called once by a freshly spawned thread, on itself, before it runs any
 * of the caller-supplied entry function -- src/thread/pthread.c's
 * thread_entry() is the one real call site. On NT this rebuilds the
 * calling thread's own TLS block by hand (see src/thread/nt/plat_thread.c
 * for why: a pinned bootstrap-tcc PE linker bug the platform loader's own
 * automatic per-thread TLS allocation cannot be trusted to get the
 * alignment of, and why this must run from the new thread itself rather
 * than from the thread that spawned it). A no-op on Linux, whose TLS setup
 * is unrelated (see src/internal/linux/tls_setup.c). */
void __plat_thread_tls_fixup(void);
/* Releases a thread handle once it will never be waited on or resumed
 * again (pthread_join(), pthread_detach()'s already-exited case,
 * finish()'s own detached self-cleanup, and pthread_create()'s
 * error-unwind when __plat_thread_resume() fails) -- deliberately its
 * own call, NOT plat_fd.h's generic __plat_close(): on NT a thread
 * handle IS a real NtClose()-able HANDLE, so that backend's
 * implementation just forwards to __plat_close(). On Linux, though, a
 * thread handle is a boxed pid+1 (see src/thread/linux/plat_thread.c's
 * own banner) that shares its small-integer ENCODING with plat_fd.c's
 * boxed fd+1 file handles despite being a completely different KERNEL
 * namespace -- calling __plat_close() on one is a real, confirmed bug:
 * it issues close(2) on whatever fd number the pid happens to equal,
 * which either fails with a bogus EBADF (silently clobbering the
 * calling thread's own errno right after a successful pthread_join(),
 * confirmed via test/pthread-surface.c's test_errno_thread_isolation())
 * or, worse, actually closes a real, unrelated, currently-open file
 * descriptor if the numbers collide. The Linux backend's own
 * implementation is a real no-op: __plat_wait_one()'s wait4(2) (the
 * join path) already reaps the exited thread-group-leader process, and
 * there is no Linux-side resource left for this call to release. */
int __plat_thread_close(__plat_handle_t h);
int __plat_thread_resume(__plat_handle_t h);
int __plat_thread_suspend(__plat_handle_t h);
/* Queue `fn(arg1, arg2, 0)` to run the next time `h` becomes alertable
 * (or immediately, if it is already inside an alertable wait). */
int __plat_thread_queue_apc(__plat_handle_t h, __plat_apc_fn fn, void *arg1,
                            void *arg2);
/* Force `h` -- which the caller has already suspended -- to resume
 * execution at `target` (a _Noreturn trampoline) rather than wherever it
 * was interrupted.  The GetContextThread/patch-one-field/SetContextThread
 * sequence this takes is NT/arch-ABI-specific CONTEXT-record knowledge
 * with no POSIX-facing decision anywhere inside it, so it stays one call
 * rather than being fragmented across the suspend/resume bracketing it in
 * the front door (see pthread_cancel.c's redirect_async_cancel(), which
 * still owns every pthread-cancellation-policy decision around this
 * call). */
int __plat_thread_redirect_ip(__plat_handle_t h, void *target);
/* The stack [base, base+size) of a live thread, read via its TEB --
 * pthread_getattr_np()'s one platform-specific step.
 *
 * base/size are required: the NT backend writes `*base = ...; *size =
 * ...;` unconditionally on its own success path, with no NULL check on
 * either (the Linux backend always fails with ENOSYS first, `(void)h;
 * (void)base; (void)size;`, but the shared contract is set by the
 * backend that actually uses them). h is deliberately NOT marked:
 * neither backend dereferences it directly itself (NT only forwards it
 * to NtQueryInformationThread(); the flagged `teb->NtTib` finding is
 * about `teb`, a LOCAL derived from that syscall's own out-param, a
 * kernel-trusted pointer this checker already has an established "trust
 * NT's own returned pointers" precedent for -- not about h, base, or
 * size at all). */
int __plat_thread_stack_extent(__plat_handle_t h, void **base, size_t *size)
    __attribute__((nonnull(2, 3)));
/* A durable handle on the calling thread, safe to store past this call
 * (unlike NtCurrentThread()'s pseudo-handle, which is only ever valid for
 * an operation performed *by* that thread on itself).  Always succeeds
 * from the caller's perspective: a duplication failure falls back to the
 * pseudo-handle itself, exactly as before this call existed -- there is
 * no POSIX-facing decision inside this fallback, only NT plumbing. */
__plat_handle_t __plat_thread_duplicate_self(void);
/* NtCurrentThread()'s pseudo-handle -- valid only for an operation the
 * calling thread performs on itself within this same call (unlike the
 * durable handle above), used by pthread_getattr_np() to query its own
 * TEB without needing a duplicate. */
__plat_handle_t __plat_thread_current_pseudo(void);
/* Never returns -- retries forever defensively, matching the exact
 * pre-existing pthread_exit() idiom this replaces. */
_Noreturn void __plat_thread_terminate_self(void);
/* The bypass-everything emergency abort __pthread_cancel_unsafe_enter()'s
 * documented regions use: write a fixed diagnostic straight to the
 * process's standard error handle (bypassing stdio and the fd table,
 * which the suspended target may itself own the locks of) and terminate
 * the whole process immediately with this library's signal-exit encoding
 * for SIGABRT.  One call because there is no POSIX-facing decision
 * anywhere inside it to leave in a front door -- see
 * pthread_cancel.c's cancel_unsafe_abort() banner for why this exists at
 * all.
 *
 * region is deliberately NOT marked nonnull, even though the Linux
 * backend dereferences it unconditionally (`while (region[len])
 * len++;`, no NULL check) and every real caller in this tree already
 * only ever passes a string literal: the NT backend has a genuine, live
 * fallback for it (`if (!region) region = "an async-cancel-unsafe
 * operation";`), the same "one backend defensively checks what the
 * other doesn't" shape 9be895e's own setenv()/unsetenv() precedent
 * established for a single-backend function -- marking nonnull here
 * would tell the compiler NT's own real, working fallback is dead code,
 * which is false. A latent inconsistency between the two backends
 * (disclosed, not fixed: no real caller reaches it either way), not a
 * reachable bug. */
_Noreturn void __plat_cancel_unsafe_abort(const char *region);
/* An alertable, zero-length delay -- "yield the processor, but let a
 * pending APC run first if there is one." */
void __plat_thread_alertable_yield(void);
/* The current NT system time, 100ns ticks since 1601 -- aio_suspend()'s
 * own clock for measuring its deadline against, kept as NT ticks (not
 * translated through clock_gettime()/struct timespec) because that is
 * what it already used and this is a relocation, not a redesign. */
long long __plat_query_system_time(void);

/* ---- mqueue.c's queue-file I/O --------------------------------------------
 * A positioned transfer at a fixed byte offset, non-alertable (mqueue's
 * own retry loops are driven by wait_count()'s separate alertable
 * semaphore waits, never by this transfer itself), with NO end-of-file
 * short-circuit: an incomplete transfer against the queue's own backing
 * file is always a real error condition for the caller's retry loop to
 * evaluate (see mqueue.c's raw_io()), never the "read() hit a legitimate
 * EOF, report 0" case unistd's own __plat_pread (src/internal/plat_fd.h)
 * exists to provide.  Returns bytes transferred (may be less than `count`
 * -- the caller loops) or -1/errno. */
ssize_t __plat_thread_file_io(__plat_handle_t h, void *buf, size_t count,
                              off_t off, int write_op);

/* ---- src/thread/pthread_mutex.c's/pthread.c's process-wide fast lock ------
 *
 * NT's own PEB lock (RtlAcquirePebLock()/RtlReleasePebLock()), used
 * directly by both files today to guard pthread_mutex_t's own internal
 * bookkeeping (owner/recursion/waiters/robust_state) and (in
 * __pthread_current()) the process-wide live_threads counter -- the
 * same "this library's real userspace CRT would have one process-wide
 * fast lock for exactly this" primitive every real libc keeps
 * somewhere, just not previously named as a seam of its own because
 * NT hands it to every process pre-built and pre-initialized.
 *
 * Unlike every other function in this header, this pair needs no
 * _create() call and no __plat_handle_t: it is available from the
 * very first call, always exactly one, process-wide, on every backend
 * -- NT's PEB lock already has this property (the OS sets it up before
 * any user code runs), and a backend with no such OS-provided lock
 * (Linux) can give it the same property for free with a single
 * zero-initialized static word, no allocation and no lazy-init race to
 * get wrong. Recursive acquisition by the SAME thread is UNDEFINED --
 * neither RtlAcquirePebLock() nor a plain futex-based mutex supports
 * it, and no caller in this tree relies on it (pthread_mutex.c's own
 * recursive-mutex support is layered on TOP of this lock, in its own
 * bookkeeping, never by re-entering the lock itself). */
void __plat_fast_lock(void) NTLIBC_ACQUIRE(__ntlibc_peb_lock_token);
void __plat_fast_unlock(void) NTLIBC_RELEASE(__ntlibc_peb_lock_token);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
