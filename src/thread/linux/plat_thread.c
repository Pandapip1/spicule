/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of a DELIBERATELY SMALL SLICE of src/internal/
 * plat_thread.h: enough of clone(2)/futex(2) for a real, contention-tested
 * mutex (__plat_semaphore_create/_post/_getvalue, __plat_event_create/_set,
 * __plat_wait_one single-handle, __plat_thread_spawn). Everything else
 * plat_thread.h declares is left undefined here, not stubbed -- open
 * follow-up work.
 *
 * Every syscall here goes through raw_syscall() (below) rather than the
 * `extern long syscall(...)` declaration src/mman/linux/plat_mem.c and
 * src/unistd/linux/plat_fd.c use: that symbol resolves to the HOST's real
 * glibc syscall() at link time, which on failure sets glibc's OWN errno
 * rather than handing back the raw kernel -errno -- confirmed to make
 * plat_mem.c/plat_fd.c's shared `errno = (int)-ret` compute EPERM on every
 * failure, a latent bug this file avoids via a direct inline `svc #0`.
 *
 * clone(2) needs more than a raw syscall can give it: the syscall
 * instruction returns twice, once in the caller and once in the child on
 * the CHILD's own fresh stack, so the child must not unwind back into this
 * C function's stack frame. That's assembly-level work; see
 * aarch64/clone.S.
 *
 * One deliberate simplification remains:
 *
 *   __plat_thread_spawn() clones with CLONE_VM|CLONE_FS|CLONE_FILES|
 *   CLONE_SIGHAND|CLONE_SETTLS plus the SIGCHLD exit-signal bit, but NOT
 *   CLONE_THREAD -- real concurrent execution sharing one address space,
 *   with a real, independent TLS block per thread (see this function's
 *   own comment for how that block is built), but still not a full
 *   NPTL-style pthread: without CLONE_THREAD the new thread is its own
 *   thread-group leader, joined with plain wait4() rather than a
 *   futex-on-ctid join. Omitting the SIGCHLD exit-signal bit from the
 *   clone() flags word was confirmed by testing to make the child
 *   invisible to wait4() (ECHILD) despite being real and running.
 *
 *   __plat_wait_one() below understands two, structurally distinguished
 *   handle domains rather than unifying every waitable kind the way NT's
 *   HANDLE does: a struct ntlibc_linux_sync* this file produced via
 *   __plat_semaphore_create()/__plat_event_create() (always mmap(2)-page-
 *   aligned), or a boxed pid+1 thread handle from __plat_thread_spawn()
 *   (essentially never page-aligned) -- pthread_join()'s own generic
 *   __plat_wait_one() call needs the latter to work, joining via a plain
 *   wait4(2) (see __plat_thread_spawn()'s own comment on why this backend's
 *   spawned "threads" are wait4()-joinable in the first place).
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include "plat_thread.h"
#include "linux/sync.h"
#include "unsafe_pointer.h"
#if defined(__aarch64__)
#include "linux/tls.h"
#endif

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * <sys/syscall.h>; x86_64 confirmed against a real x86_64-linux-gnu
 * glibc's own asm/unistd_64.h, a genuinely different table, not
 * aarch64's numbers plus a fixed offset (see src/signal/linux/
 * plat_signal.c's own updated banner for the same warning). */
#if defined(__aarch64__)
#define SYS_mmap   222
#define SYS_munmap 215
#define SYS_futex  98
#define SYS_wait4  260
#elif defined(__x86_64__)
#define SYS_mmap   9
#define SYS_munmap 11
#define SYS_futex  202
#define SYS_wait4  61
#elif defined(__i386__)
/* SYS_mmap2, not the old single-struct-arg SYS_mmap (90) -- takes six
 * plain-register arguments like every other syscall this file calls,
 * at the cost of the offset argument being in PAGE units (moot here,
 * every mmap call site below passes offset 0). */
#define SYS_mmap   192
#define SYS_munmap 91
#define SYS_futex  240
#define SYS_wait4  114
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

#define FUTEX_WAIT         0
#define FUTEX_WAKE         1
#define FUTEX_PRIVATE_FLAG 128

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

/* clone(2)'s flags word, narrowed from a full NPTL pthread (see banner),
 * plus SIGCHLD (17) in the low byte -- the exit-signal field -- so the
 * spawned thread stays visible to a plain wait4(). */
#define CLONE_VM      0x00000100
#define CLONE_FS      0x00000200
#define CLONE_FILES   0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_SETTLS  0x00080000
#define LINUX_SIGCHLD 17

#define DEFAULT_STACK_BYTES ((size_t)1 << 20) /* 1 MiB, matches pthread.c's
                                                * own DEFAULT_STACK_SIZE */

/* A minimal 6-argument raw syscall, one calling convention per arch
 * below (see this file's banner for why no host libc wrapper). aarch64:
 * x8 = syscall number, x0..x5 = up to 6 arguments, result (or -errno in
 * [-4095,-1]) in x0. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#endif

/* src/thread/linux/$(ARCH)/clone.S's hand-written trampoline -- see
 * that file's own banner (aarch64/clone.S's in particular) for why a
 * raw syscall cannot do clone()'s job by itself. All three arches this
 * tree targets have a real sibling trampoline file now (aarch64/
 * clone.S, x86_64/clone.S, i386/clone.S), each following its own
 * arch's calling convention and clone(2) register ABI -- see
 * x86_64/clone.S's and i386/clone.S's own banners for the real,
 * genuinely-different-per-arch CLONE_BACKWARDS argument-ordering split
 * this needed, confirmed against the kernel's own arch/x86/Kconfig and
 * kernel/fork.c source rather than assumed. */
extern long __ntlibc_linux_clone(__plat_thread_entry_t fn, void *stack_top, // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
                                 long flags, void *arg, void *tls);

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

/* The raw kernel `struct timespec` shape (two `long`s, seconds then
 * nanoseconds) -- defined locally rather than pulling in ntlibc's own
 * <time.h> type, since this is what the futex(2) syscall ABI expects. */
struct linux_timespec { long tv_sec; long tv_nsec; };

/* NOT FUTEX_PRIVATE_FLAG -- a real, confirmed bug fix, not a missed
 * optimization. These helpers back every futex word this file hands out,
 * including the cross-process objects map_named_sem()/
 * __plat_named_mutant_acquire() create (MAP_SHARED, backed by a file under
 * /tmp, opened independently by every process that touches it).
 * FUTEX_PRIVATE_FLAG hashes a waiter by (this process's mm_struct,
 * virtual address), which is wrong across processes: two separate
 * processes mmap()ing the same MAP_SHARED file get the same physical page
 * but different virtual addresses, so a FUTEX_WAKE_PRIVATE from one hashes
 * to a different key than the other's FUTEX_WAIT_PRIVATE, and the wakeup
 * is silently dropped. Confirmed as the root cause of intermittent
 * cross-process hangs (fork, pthread_atfork, sem_*, mqueue, sigsuspend,
 * sigwait) via instrumented tracing showing identical inodes but different
 * mapped addresses. Dropping FUTEX_PRIVATE_FLAG makes the kernel hash by
 * inode and page offset instead, correct for both MAP_PRIVATE and
 * MAP_SHARED callers here, at the cost of FUTEX_PRIVATE_FLAG's
 * (unmeasured, secondary) single-process performance benefit. */
static long futex_wait(int *uaddr, int expected, const struct linux_timespec *timeout)
{
	return raw_syscall(SYS_futex, (long)uaddr,
	                   FUTEX_WAIT, (long)expected,
	                   (long)timeout, 0, 0);
}

static long futex_wake(int *uaddr, int count)
{
	return raw_syscall(SYS_futex, (long)uaddr,
	                   FUTEX_WAKE, (long)count, 0, 0, 0);
}

/* One mmap()'d page per synchronization object -- no allocator dependency,
 * at the cost of a whole page for a handful of bytes; fine at this port's
 * scale, a real port would suballocate. `kind` distinguishes a counting
 * semaphore (P/V, __plat_wait_one decrements) from a manual-reset event
 * (__plat_wait_one only checks nonzero, never consumes). struct
 * ntlibc_linux_sync itself lives in src/internal/linux/sync.h, shared with
 * named semaphores and stop-events. */
static int alloc_sync(struct ntlibc_linux_sync **out)
{
	long ret = raw_syscall(SYS_mmap, 0, (long)sizeof(struct ntlibc_linux_sync),
	                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	                       -1, 0);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register; this page's whole point is being reinterpreted
	 * as struct ntlibc_linux_sync. */
	*out = unsafe_assume_valid_pointer((struct ntlibc_linux_sync *)ret);
	return 0;
}

/* ---- events (manual-reset, initially unset) ----------------------------
 * __plat_event_set() is explicitly this file's to implement per
 * plat_thread.h's banner (it is also declared in plat_signal.h, whose
 * canonical owner is thread, not signal). */
int __plat_event_create(__plat_handle_t *out)
{
	struct ntlibc_linux_sync *obj;
	if (alloc_sync(&obj)) return -1;
	obj->futex = 0;
	obj->max = 0;
	obj->kind = NTLIBC_LX_SYNC_EVENT;
	*out = (__plat_handle_t)obj;
	return 0;
}

int __plat_event_set(__plat_handle_t h)
{
	struct ntlibc_linux_sync *obj = (struct ntlibc_linux_sync *)h;
	__atomic_store_n(&obj->futex, 1, __ATOMIC_RELEASE);
	/* Manual-reset, unlike NT's auto-reset SynchronizationEvent, so every
	 * current waiter must wake here, not just one. */
	futex_wake(&obj->futex, 0x7fffffff);
	return 0;
}

/* ---- unnamed counting semaphores ---------------------------------------
 * `inheritable` (OBJ_INHERIT on NT) has no separate concept here: a
 * MAP_PRIVATE|MAP_ANONYMOUS mapping is already inherited by a fork()'d
 * child via ordinary copy-on-write, unconditionally. */
int __plat_semaphore_create(long initial, long maximum, int inheritable, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; initial, maximum, and inheritance values have distinct roles
                            __plat_handle_t *out)
{
	struct ntlibc_linux_sync *obj;
	(void)inheritable;
	if (alloc_sync(&obj)) return -1;
	obj->futex = (int)initial;
	obj->max = (int)maximum;
	obj->kind = NTLIBC_LX_SYNC_SEMAPHORE;
	*out = (__plat_handle_t)obj;
	return 0;
}

int __plat_semaphore_post(__plat_handle_t h)
{
	struct ntlibc_linux_sync *obj = (struct ntlibc_linux_sync *)h;
	int cur = __atomic_load_n(&obj->futex, __ATOMIC_RELAXED);
	for (;;) {
		if (cur >= obj->max) {
			/* [EOVERFLOW] decided here while the real state is still in
			 * hand, matching plat_thread.h's own comment on why NT's
			 * STATUS_SEMAPHORE_LIMIT_EXCEEDED is translated at this
			 * exact call site rather than reconstructed later. */
			errno = EOVERFLOW;
			return -1;
		}
		if (__atomic_compare_exchange_n(&obj->futex, &cur, cur + 1, 1,
		                                __ATOMIC_RELEASE, __ATOMIC_RELAXED))
			break;
	}
	futex_wake(&obj->futex, 1);
	return 0;
}

int __plat_semaphore_getvalue(__plat_handle_t h, int *value)
{
	struct ntlibc_linux_sync *obj = (struct ntlibc_linux_sync *)h;
	*value = __atomic_load_n(&obj->futex, __ATOMIC_ACQUIRE);
	return 0;
}

/* ---- waiting -------------------------------------------------------------
 * Single-handle only: __plat_wait_any() (NtWaitForMultipleObjects'
 * WaitAny mode) is out of this port's chosen scope -- no caller here
 * needs it -- and is left undefined rather than stubbed. */
int __plat_wait_one(__plat_handle_t h, int alertable, int has_timeout, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; alert and timeout flags have distinct roles
                    long long relative_ticks)
{
	struct ntlibc_linux_sync *obj;
	struct linux_timespec ts, *tsp = 0;
	(void)alertable; /* Linux has no APC-alertable-wait concept; every wait
	                  * here is non-alertable, so __PLAT_WAIT_INTR is never
	                  * produced. */
	/* A boxed pid+1 thread handle from __plat_thread_spawn(), not a
	 * struct ntlibc_linux_sync* -- pthread_join() (src/thread/pthread.c)
	 * calls this same generic front door on a THREAD handle exactly the
	 * way it does for a mutex/cond/rwlock wait object, but this backend's
	 * thread handle is a different domain (see this file's banner).
	 * Distinguished the same structural way __plat_wait_any()'s
	 * handle_is_boxed_fd() below tells a boxed fd apart from a real
	 * sync object: every sync object this file hands out is mmap(2)-
	 * page-aligned, while a boxed pid (pid+1) essentially never is.
	 * wait4(2) is this backend's real join primitive -- this file's own
	 * banner: spawned threads are "joined with plain wait4() rather than
	 * a futex-on-ctid join". No caller anywhere in this tree asks for a
	 * TIMED wait on a thread handle (no pthread_timedjoin_np() exists
	 * here), so has_timeout is not honored on this path. */
	if (((unsigned long)h & 4095UL) != 0) {
		long pid = (long)h - 1;
		long status = 0;
		long r = raw_syscall(SYS_wait4, pid, (long)&status, 0L, 0L, 0L, 0L);
		if (is_sys_error(r)) { errno = (int)-r; return __PLAT_WAIT_ERROR; }
		return __PLAT_WAIT_OK;
	}
	obj = (struct ntlibc_linux_sync *)h;
	if (has_timeout) {
		long long ticks = relative_ticks < 0 ? -relative_ticks : relative_ticks;
		ts.tv_sec = (long)(ticks / 10000000LL);
		ts.tv_nsec = (long)((ticks % 10000000LL) * 100);
		tsp = &ts;
	}
	for (;;) {
		long r;
		if (obj->kind == NTLIBC_LX_SYNC_EVENT) {
			if (__atomic_load_n(&obj->futex, __ATOMIC_ACQUIRE) != 0)
				return __PLAT_WAIT_OK;
		} else {
			int cur = __atomic_load_n(&obj->futex, __ATOMIC_ACQUIRE);
			while (cur > 0) {
				if (__atomic_compare_exchange_n(&obj->futex, &cur, cur - 1, 1,
				                                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
					return __PLAT_WAIT_OK;
			}
		}
		r = futex_wait(&obj->futex, 0, tsp);
		if (r == 0) continue;             /* real wake: recheck the word */
		if (r == -EAGAIN) continue;       /* word changed before we slept;
		                                   * benign per futex(2), retry. */
		if (r == -EINTR) continue;        /* spurious signal; restart the wait
		                                   * without re-deriving a shortened
		                                   * remaining timeout (disclosed
		                                   * inaccuracy). */
		if (r == -ETIMEDOUT) return __PLAT_WAIT_TIMEOUT;
		errno = (int)-r;
		return __PLAT_WAIT_ERROR;
	}
}

/* ---- thread lifecycle ----------------------------------------------------
 * `create_suspended` invariant (WHY this matters, not just NT plumbing):
 * pthread_create() (src/thread/pthread.c) spawns the new thread suspended,
 * THEN stores thread->handle, increments the process-wide live_threads
 * count, and stores *output -- all while the new thread is provably not
 * yet running -- and only resumes it once that bookkeeping is committed.
 * If the new thread could start running thread_entry() before that
 * bookkeeping lands, and it happens to run to completion immediately (a
 * trivial start routine, entirely plausible on real hardware racing a
 * multi-instruction window), finish() would decrement live_threads before
 * pthread_create()'s own increment ever executed -- undercounting a live
 * thread by one, in the worst case racing live_threads down to 0 while
 * the main thread is still running and triggering finish()'s `if (last)
 * exit(0);` to tear down the whole process out from under its creator.
 * This is a real ordering hazard, not an NT-only convenience: it applies
 * identically here since CLONE_VM starts the child running concurrently,
 * on a real separate CPU, the instant clone(2) returns in it. So this
 * backend gives create_suspended a real primitive rather than passing
 * create_suspended=0 from pthread_create() on this platform: clone(2) has
 * no OS-level "start suspended" concept, but the same net effect -- the
 * child provably cannot execute the caller's entry point until told to --
 * is achieved by starting every clone()'d thread at a small trampoline
 * (start_trampoline() below) that blocks on a manual-reset event
 * (`gate`) the parent only sets from __plat_thread_resume(), once its own
 * bookkeeping is done.
 *
 * `suspend_table` bridges __plat_thread_spawn()'s local `gate` object to
 * the LATER, separate __plat_thread_resume(handle) call: the boxed pid+1
 * handle this function returns carries no room for a second pointer, so
 * the association is kept in this small fixed table (same technique
 * src/process/linux/plat_process.c's own reap_cache uses for pid ->
 * exit-status), keyed by tid and cleared once resumed.
 *
 * FIXED, previously a SERIOUS CONFIRMED bug: without CLONE_SETTLS, every
 * spawned thread shared the CALLING thread's TLS region, since aarch64
 * Linux TLS is addressed through TPIDR_EL0 and clone(2) only
 * reinitializes it when CLONE_SETTLS is passed. Confirmed empirically (a
 * `__thread int marker` probe showed every spawned thread and the caller
 * reporting the identical address). That meant every `__thread`
 * variable, including src/thread/pthread.c's `__pthread_self_control`
 * and errno itself, silently ALIASED across every thread this function
 * created -- confirmed to stall a multi-thread pthread_mutex_t stress
 * test because every worker unknowingly shared one control block.
 *
 * Fixed by giving every spawned thread its own real TCB, the same shape
 * (and same code path -- src/internal/linux/tls_setup.c's
 * __ntlibc_linux_tls_block_create(), see that file's own banner) that
 * crt/linux/crt1.c already builds for the initial thread, then passing
 * its `tp` as clone(2)'s tls argument with CLONE_SETTLS set: the kernel
 * installs it as the child's TPIDR_EL0 before the child ever executes
 * an instruction, so start_trampoline() below -- and everything it
 * calls, including thread_entry()'s first `__pthread_self_control`
 * write -- already sees a private TLS block, never the creator's. */
struct linux_thread_start {
	__plat_thread_entry_t entry;
	void *arg;
	struct ntlibc_linux_sync *gate; /* NULL: run immediately, not suspended */
};

static unsigned __PLAT_APC_CALL start_trampoline(void *argument)
{
	struct linux_thread_start *start = argument;
	__plat_thread_entry_t entry = start->entry;
	void *arg = start->arg;
	struct ntlibc_linux_sync *gate = start->gate;
	/* Every field is copied out to locals before this waits (or, on the
	 * un-suspended path, before entry() ever touches the stack): the
	 * header lives at the LOW end of this thread's own mmap()'d stack
	 * (see __plat_thread_spawn() below), which entry()'s own real stack
	 * usage will eventually grow down into. */
	if (gate) __plat_wait_one((__plat_handle_t)gate, 0, 0, 0);
	return entry(arg);
}

#define SUSPEND_SLOTS 64
struct suspend_slot { int tid; struct ntlibc_linux_sync *gate; };
static struct suspend_slot suspend_table[SUSPEND_SLOTS];

static int suspend_table_store(int tid, struct ntlibc_linux_sync *gate)
{
	int i, stored = -1;
	__plat_fast_lock();
	for (i = 0; i < SUSPEND_SLOTS; i++) {
		if (!suspend_table[i].tid) {
			suspend_table[i].tid = tid;
			suspend_table[i].gate = gate;
			stored = 0;
			break;
		}
	}
	__plat_fast_unlock();
	return stored;
}

static struct ntlibc_linux_sync *suspend_table_take(int tid)
{
	int i;
	struct ntlibc_linux_sync *gate = 0;
	__plat_fast_lock();
	for (i = 0; i < SUSPEND_SLOTS; i++) {
		if (suspend_table[i].tid == tid) {
			gate = suspend_table[i].gate;
			suspend_table[i].tid = 0;
			suspend_table[i].gate = 0;
			break;
		}
	}
	__plat_fast_unlock();
	return gate;
}

int __plat_thread_spawn(__plat_thread_entry_t entry, void *arg,
                        size_t stack_size, int create_suspended, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; stack size and suspension flag have distinct roles
                        __plat_handle_t *out)
{
	size_t sz;
	long stack_ret, pid, flags;
	void *top;
	struct linux_thread_start *start;
	struct ntlibc_linux_sync *gate = 0;
#if defined(__aarch64__)
	void *tls;
#endif

	sz = stack_size ? stack_size : DEFAULT_STACK_BYTES;
	stack_ret = raw_syscall(SYS_mmap, 0, (long)sz, PROT_READ | PROT_WRITE,
	                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (is_sys_error(stack_ret)) { errno = (int)-stack_ret; return -1; }
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register; `top` is that same mapping's high end. */
	top = unsafe_assume_valid_pointer((void *)(stack_ret + (long)sz));

#if defined(__aarch64__)
	/* Built BEFORE `gate`, not after: on failure here only the stack
	 * above needs cleanup, matching alloc_sync()'s own single-resource
	 * cleanup shape just below rather than adding a second one. tls != 0
	 * is a hard precondition for CLONE_SETTLS below -- see linux/tls.h's
	 * own comment on why a thread must never actually start running with
	 * TPIDR_EL0 == 0. */
	tls = __ntlibc_linux_tls_block_create();
	if (!tls) {
		raw_syscall(SYS_munmap, stack_ret, (long)sz, 0, 0, 0, 0);
		errno = ENOMEM;
		return -1;
	}
#endif

	if (create_suspended) {
		if (alloc_sync(&gate) < 0) {
			int e = errno;
			raw_syscall(SYS_munmap, stack_ret, (long)sz, 0, 0, 0, 0);
			errno = e;
			return -1;
		}
		gate->futex = 0;
		gate->max = 0;
		gate->kind = NTLIBC_LX_SYNC_EVENT;
	}

	/* The header start_trampoline() reads sits at the LOW end of the
	 * mmap()'d region -- the stack grows down from `top`, so this is the
	 * address furthest from where the stack pointer starts. Same
	 * mmap(2)-returned address as `top` above, reinterpreted as the
	 * header struct this mapping's own low end holds. */
	start = unsafe_assume_valid_pointer((struct linux_thread_start *)stack_ret);
	start->entry = entry;
	start->arg = arg;
	start->gate = gate;

	flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | LINUX_SIGCHLD;
#if defined(__aarch64__)
	flags |= CLONE_SETTLS;
	pid = __ntlibc_linux_clone(start_trampoline, top, flags, start, tls);
#else
	/* No clone(2) trampoline exists for this arch at all (see the extern
	 * __ntlibc_linux_clone() declaration's own comment) -- this call
	 * survives only because nothing in this port's curated build FILES
	 * lists reaches it, letting --gc-sections drop the whole function.
	 * tls=0/no CLONE_SETTLS here is unreachable dead weight, not a real
	 * per-arch choice. */
	pid = __ntlibc_linux_clone(start_trampoline, top, flags, start, 0);
#endif
	if (pid < 0) {
		/* `tls` (aarch64 only) is intentionally leaked here too, joining
		 * the stack/gate leaks this same rare clone()-failure path
		 * already accepts below -- see this function's own closing
		 * comment on why no destroy path exists yet. */
		int e = (int)-pid;
		raw_syscall(SYS_munmap, stack_ret, (long)sz, 0, 0, 0, 0);
		errno = e;
		return -1;
	}
	if (gate && suspend_table_store((int)pid, gate) < 0) {
		/* Table exhausted: the child is already running and blocked on
		 * `gate` forever with no way for a future __plat_thread_resume()
		 * to find it. Wake it immediately instead of leaving it stuck --
		 * degrades create_suspended to a (rare, disclosed) no-op rather
		 * than losing the thread. */
		__plat_event_set((__plat_handle_t)gate);
	}
	/* Boxed as pid+1, echoing plat_fd.c's fd+1 encoding, but this is a
	 * DIFFERENT handle namespace and the two must never be crossed. The
	 * mmap()'d stack (and, for a suspended create, the `gate` event, and
	 * on aarch64, `tls`'s TCB/DTV blocks -- now genuinely owned by the
	 * running thread, not a leak in the usual sense) is intentionally
	 * left unreclaimed; no destroy path exists yet. __plat_handle_t is
	 * an opaque one-word carrier shared with the NT backend; the real
	 * payload is the bare pid, never dereferenced. */
	*out = unsafe_assume_valid_pointer((__plat_handle_t)(pid + 1));
	return 0;
}

/* A no-op here: the pinned bootstrap tcc PE-linker alignment bug
 * src/thread/nt/plat_thread.c's own implementation of this function works
 * around is specific to that backend's IMAGE_TLS_DIRECTORY-based TLS
 * layout. This backend's own TLS setup (clone() plus src/internal/linux/
 * tls_setup.c) is unrelated and already correct. */
void __plat_thread_tls_fixup(void)
{
}

/* Boxed like __plat_thread_spawn() above (tid+1): gettid(2) never fails
 * and is stable for the thread's whole lifetime. */
#if defined(__aarch64__)
#define SYS_gettid 178
#elif defined(__x86_64__)
#define SYS_gettid 186
#elif defined(__i386__)
#define SYS_gettid 224
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif
__plat_handle_t __plat_thread_duplicate_self(void)
{
	long tid = raw_syscall(SYS_gettid, 0L, 0L, 0L, 0L, 0L, 0L);
	/* Boxing, not dereference -- see __plat_thread_spawn()'s own
	 * comment above on the identical pid+1 encoding. */
	return unsafe_assume_valid_pointer((__plat_handle_t)(tid + 1));
}

/* ---- src/thread/pthread_mutex.c's/pthread.c's process-wide fast lock -----
 *
 * Available from the first call, always exactly one, process-wide, no
 * creation step: a zero-initialized static word (BSS), no lazy-init race.
 *
 * A plain spinlock, not a futex-based sleep/wake mutex, deliberately:
 * every critical section this protects is a handful of plain field
 * reads/writes on pthread_mutex_t's bookkeeping, never blocking or
 * unbounded, so the lock is never held longer than a few instructions by
 * a thread that is definitionally currently running. A first
 * implementation used the standard three-state futex mutex algorithm and
 * hit a real, reproducible stall under contention testing (16 threads x
 * 50000 lock/unlock cycles stopped making progress, everything asleep on
 * a futex with nothing left to wake it) -- rather than keep chasing a
 * concurrency bug in a wakeup protocol this lock doesn't need, it spins,
 * yielding the CPU between attempts so a contended spin cannot starve the
 * holder. Recursive acquisition by the same thread deadlocks here exactly
 * like RtlAcquirePebLock() would on NT. */
static int fast_lock_word;

#if defined(__aarch64__)
#define SYS_sched_yield 124
#elif defined(__x86_64__)
#define SYS_sched_yield 24
#elif defined(__i386__)
#define SYS_sched_yield 158
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

void __plat_fast_lock(void) NTLIBC_NO_THREAD_SAFETY_ANALYSIS;
void __plat_fast_lock(void)
{
	int c;
	for (;;) {
		c = 0;
		if (__atomic_compare_exchange_n(&fast_lock_word, &c, 1, 1,
		                                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			return;
		raw_syscall(SYS_sched_yield, 0L, 0L, 0L, 0L, 0L, 0L);
	}
}

void __plat_fast_unlock(void) NTLIBC_NO_THREAD_SAFETY_ANALYSIS;
void __plat_fast_unlock(void)
{
	__atomic_store_n(&fast_lock_word, 0, __ATOMIC_RELEASE);
}

/* ---- waiting on more than one object -------------------------------------
 * Linux has no single primitive matching NtWaitForMultipleObjects' WaitAny
 * mode across arbitrary futex words, so this polls every handle's state
 * check in a loop, sleeping briefly between passes. The only caller
 * (src/thread/aio.c) waits on a small, fixed handful of handles for a
 * coarse aio deadline, so a millisecond poll interval is an acceptable
 * tradeoff.
 *
 * A second __plat_handle_t domain has to be handled here: aio_suspend()'s
 * handles[0] is always this file's own sync object, but handles[1], when
 * present, is __sig_delivery_event() -- a raw Linux eventfd(2) boxed as
 * (fd + 1), a completely different encoding. Blindly casting it to
 * `struct ntlibc_linux_sync *` would dereference a small integer as a
 * pointer, an almost-guaranteed SIGSEGV.
 *
 * The two domains are distinguished structurally: mmap(2) is guaranteed to
 * return page-aligned addresses, so every sync object this file produces
 * has its low 12 bits zero, while a boxed eventfd only aligns that way for
 * an fd far past anything this tree's fd table reaches. "Not page-aligned"
 * is therefore treated as a boxed fd and read via a zero-timeout
 * ppoll(POLLIN) peek, matching the EVENT-kind branch below (also peek-only;
 * aio_suspend()'s __sig_drain_pending() call actually consumes it). */
#if defined(__aarch64__)
#define SYS_nanosleep_wa 101
#define SYS_ppoll_wa     73
#elif defined(__x86_64__)
#define SYS_nanosleep_wa 35
#define SYS_ppoll_wa     271
#elif defined(__i386__)
#define SYS_nanosleep_wa 162
#define SYS_ppoll_wa     309
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* See this function's own banner just above: a `struct ntlibc_linux_sync *`
 * this file's own alloc_sync() produced is always mmap(2)-page-aligned;
 * a boxed eventfd (fd + 1) essentially never is. */
static int handle_is_boxed_fd(__plat_handle_t h)
{
	return ((unsigned long)h & 4095UL) != 0;
}

/* Zero-timeout POLLIN peek on a boxed-fd handle. Peeks only, same as the
 * NTLIBC_LX_SYNC_EVENT branch below: never consumes. */
static int fd_handle_ready(__plat_handle_t h)
{
	struct pollfd pfd;
	struct linux_timespec zero;
	long ret;

	pfd.fd = (int)((long)h - 1);
	pfd.events = POLLIN;
	pfd.revents = 0;
	zero.tv_sec = 0; zero.tv_nsec = 0;
	ret = raw_syscall(SYS_ppoll_wa, (long)&pfd, 1L, (long)&zero, 0L, 0L, 0L);
	if (is_sys_error(ret)) return 0;
	return (pfd.revents & POLLIN) != 0;
}

int __plat_wait_any(__plat_handle_t *handles, unsigned count, int alertable, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; count and alert flag have distinct roles
                    int has_timeout, long long relative_ticks)
{
	long long remaining_ns;
	(void)alertable;

	remaining_ns = has_timeout
		? (relative_ticks < 0 ? -relative_ticks : relative_ticks) * 100LL
		: -1;

	for (;;) {
		unsigned i;
		for (i = 0; i < count; i++) {
			struct ntlibc_linux_sync *obj;
			if (handle_is_boxed_fd(handles[i])) {
				if (fd_handle_ready(handles[i])) return __PLAT_WAIT_OK;
				continue;
			}
			obj = (struct ntlibc_linux_sync *)handles[i];
			if (obj->kind == NTLIBC_LX_SYNC_EVENT) {
				if (__atomic_load_n(&obj->futex, __ATOMIC_ACQUIRE) != 0)
					return __PLAT_WAIT_OK;
			} else {
				int cur = __atomic_load_n(&obj->futex, __ATOMIC_ACQUIRE);
				while (cur > 0) {
					if (__atomic_compare_exchange_n(&obj->futex, &cur, cur - 1, 1,
					                                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
						return __PLAT_WAIT_OK;
				}
			}
		}
		if (has_timeout) {
			if (remaining_ns <= 0) return __PLAT_WAIT_TIMEOUT;
			remaining_ns -= 1000000L; /* 1ms poll interval */
		}
		{
			struct linux_timespec ts;
			ts.tv_sec = 0; ts.tv_nsec = 1000000L;
			raw_syscall(SYS_nanosleep_wa, (long)&ts, 0L, 0L, 0L, 0L, 0L);
		}
	}
}

/* ---- named objects, keyed by the filesystem namespace ---------------------
 * NT's \BaseNamedObjects gives create-or-open-by-name, race-free, as one
 * syscall; Linux has no equivalent, but the filesystem namespace under
 * /tmp plus O_CREAT|O_EXCL for atomic "did I just create this" detection
 * gets the same property: open/create a small backing file sized to one
 * struct ntlibc_linux_sync and MAP_SHARED it, so every process that opens
 * the same path sees the same futex word. */
#if defined(__aarch64__)
#define SYS_openat    56
#define SYS_ftruncate 46
#define SYS_close     57
#elif defined(__x86_64__)
#define SYS_openat    257
#define SYS_ftruncate 77
#define SYS_close     3
#elif defined(__i386__)
#define SYS_openat    295
#define SYS_ftruncate 93
#define SYS_close     6
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif
#define AT_FDCWD_LX   (-100)
#define O_RDWR_LX     02
#define O_CREAT_LX    0100
#define O_EXCL_LX     0200
#define MAP_SHARED_LX 0x01

static void named_sem_path(const char *name, char *buf, size_t bufsz)
{
	static const char prefix[] = "/tmp/.ntlibc-sem.";
	size_t plen = sizeof(prefix) - 1, i, j = 0;
	for (i = 0; i < plen && j < bufsz - 1; i++) buf[j++] = prefix[i];
	for (i = 0; name[i] && j < bufsz - 1; i++)
		buf[j++] = (name[i] == '/') ? '_' : name[i];
	buf[j] = 0;
}

/* Opens (with `flags`) the backing file for `name`, sizes it on O_CREAT,
 * and hands back the MAP_SHARED mapping. A real, disclosed race: if two
 * processes race __plat_named_semaphore_open_or_create() for the same
 * brand-new name, the second one's O_CREAT|O_EXCL fails and falls back to
 * a plain open() that can, in principle, observe the file before the
 * first process's ftruncate() has run. Narrow in practice; a real fix
 * would retry the mmap on failure. */
static int map_named_sem(const char *name, long flags, long mode,
                         struct ntlibc_linux_sync **out)
{
	char path[160];
	long fd, r;

	named_sem_path(name, path, sizeof path);
	fd = raw_syscall(SYS_openat, AT_FDCWD_LX, (long)path, flags, mode, 0, 0);
	if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	if (flags & O_CREAT_LX)
		raw_syscall(SYS_ftruncate, fd, (long)sizeof(struct ntlibc_linux_sync), 0, 0, 0, 0);
	r = raw_syscall(SYS_mmap, 0, (long)sizeof(struct ntlibc_linux_sync),
	                PROT_READ | PROT_WRITE, MAP_SHARED_LX, fd, 0);
	raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
	if (is_sys_error(r)) { errno = (int)-r; return -1; }
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register; this backing store's whole point is being
	 * reinterpreted as struct ntlibc_linux_sync. */
	*out = unsafe_assume_valid_pointer((struct ntlibc_linux_sync *)r);
	return 0;
}

/* A fresh, believed-unique name -- collision is a plain error, not a
 * create-or-open contract, matching plat_thread.h's own contract for
 * this function. */
int __plat_named_semaphore_create(const char *name, long initial, long maximum, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; initial and maximum counts have distinct roles
                                  __plat_handle_t *out)
{
	struct ntlibc_linux_sync *obj;
	if (map_named_sem(name, O_RDWR_LX | O_CREAT_LX | O_EXCL_LX, 0600, &obj) < 0)
		return -1;
	obj->futex = (int)initial;
	obj->max = (int)maximum;
	obj->kind = NTLIBC_LX_SYNC_SEMAPHORE;
	*out = (__plat_handle_t)obj;
	return 0;
}

/* -2 reports "no such name" specifically (this backend's ENOENT),
 * matching plat_thread.h's own contract for the STATUS_OBJECT_NAME_NOT_FOUND
 * case sem_open()'s O_CREAT-without-O_EXCL recovery path needs. */
int __plat_named_semaphore_open(const char *name, __plat_handle_t *out)
{
	struct ntlibc_linux_sync *obj;
	if (map_named_sem(name, O_RDWR_LX, 0, &obj) < 0)
		return errno == ENOENT ? -2 : -1;
	*out = (__plat_handle_t)obj;
	return 0;
}

int __plat_named_semaphore_open_or_create(const char *name, long initial, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; initial and maximum counts have distinct roles
                                          long maximum, __plat_handle_t *out)
{
	struct ntlibc_linux_sync *obj;
	if (map_named_sem(name, O_RDWR_LX | O_CREAT_LX | O_EXCL_LX, 0600, &obj) == 0) {
		obj->futex = (int)initial;
		obj->max = (int)maximum;
		obj->kind = NTLIBC_LX_SYNC_SEMAPHORE;
		*out = (__plat_handle_t)obj;
		return 0;
	}
	if (map_named_sem(name, O_RDWR_LX, 0, &obj) < 0) return -1;
	*out = (__plat_handle_t)obj;
	return 0;
}

/* ---- named mutant: semaphore.c's cross-process advisory lock -------------
 * semaphore.c's namespace_lock()/namespace_unlock() (not just
 * sigdelivery.c, contrary to this file's own earlier assumption --
 * confirmed by grep, not guessed) need a real create-or-open,
 * cross-process binary lock keyed by name. Modeled as a
 * ntlibc_linux_sync semaphore with initial=1,max=1, the same
 * shared-file-plus-mmap technique __plat_named_semaphore_*() above
 * already uses, under its own path prefix so a mutant name can never
 * collide with a semaphore name that happens to hash to the same
 * bytes. */
static void named_mutant_path(const char *name, char *buf, size_t bufsz)
{
	static const char prefix[] = "/tmp/.ntlibc-mutant.";
	size_t plen = sizeof(prefix) - 1, i, j = 0;
	for (i = 0; i < plen && j < bufsz - 1; i++) buf[j++] = prefix[i];
	for (i = 0; name[i] && j < bufsz - 1; i++)
		buf[j++] = (name[i] == '\\' || name[i] == '/') ? '_' : name[i];
	buf[j] = 0;
}

/* Acquire (wait indefinitely, non-alertable) the create-or-open named
 * mutant `name`. Unlike the named-semaphore group above, this uses plain
 * O_CREAT (no O_EXCL): two processes both naming a brand-new lock for the
 * first time both legitimately need a valid, initialized lock back.
 *
 * First-touch initialization is a real, confirmed race if done naively
 * (check-then-plain-write of obj->max/futex/kind): two processes racing
 * the same fresh backing file could both start that write sequence, and
 * whichever one's re-initializing write landed second would silently
 * overwrite the other's already-in-progress lock acquisition, letting
 * both processes believe they held the lock at once. Confirmed via strace
 * against fork()+sem_open() as intermittent double-acquisition corruption.
 *
 * The fix: exactly one process performs the plain max/futex writes,
 * decided by an atomic CAS on `kind` (0 -> INITIALIZING). The CAS winner
 * writes max/futex then RELEASE-publishes kind=SEMAPHORE; every loser only
 * ever ACQUIRE-loads `kind`, synchronizing with that RELEASE before
 * touching max/futex, so no process ever writes those fields concurrently
 * or observes them half-written. */
int __plat_named_mutant_acquire(const char *name, __plat_handle_t *out)
{
	char path[160];
	struct ntlibc_linux_sync *obj;
	long fd, r;
	unsigned char expect;

	named_mutant_path(name, path, sizeof path);
	fd = raw_syscall(SYS_openat, AT_FDCWD_LX, (long)path, O_RDWR_LX | O_CREAT_LX, 0600, 0, 0);
	if (is_sys_error(fd)) { errno = (int)-fd; return -1; }
	raw_syscall(SYS_ftruncate, fd, (long)sizeof(struct ntlibc_linux_sync), 0, 0, 0, 0);
	r = raw_syscall(SYS_mmap, 0, (long)sizeof(struct ntlibc_linux_sync),
	                PROT_READ | PROT_WRITE, MAP_SHARED_LX, fd, 0);
	raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
	if (is_sys_error(r)) { errno = (int)-r; return -1; }
	/* Boxing, not dereference -- see map_named_sem()'s own comment
	 * above on the identical mmap(2)-return reinterpretation. */
	obj = unsafe_assume_valid_pointer((struct ntlibc_linux_sync *)r);

	expect = 0;
	if (__atomic_compare_exchange_n(&obj->kind, &expect, NTLIBC_LX_SYNC_INITIALIZING,
	                                0, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
		/* Provably the only process writing these two fields: the CAS
		 * above admits exactly one winner. */
		obj->max = 1;
		obj->futex = 1;
		__atomic_store_n(&obj->kind, NTLIBC_LX_SYNC_SEMAPHORE, __ATOMIC_RELEASE);
	} else {
		/* Either already published, or another process's initialization
		 * is still in flight -- spin until it publishes. Same reasoning
		 * as __plat_fast_lock() above: the winner's critical section is
		 * two plain stores, so this never spins long. */
		while (__atomic_load_n(&obj->kind, __ATOMIC_ACQUIRE) == NTLIBC_LX_SYNC_INITIALIZING)
			raw_syscall(SYS_sched_yield, 0L, 0L, 0L, 0L, 0L, 0L);
	}

	__plat_wait_one((__plat_handle_t)obj, 0, 0, 0);
	*out = (__plat_handle_t)obj;
	return 0;
}

void __plat_named_mutant_release(__plat_handle_t lock)
{
	__plat_semaphore_post(lock);
}

/* A REAL, CONFIRMED bug, the same class __plat_thread_close()'s own banner
 * documents for the boxed-pid domain but for a second, separate domain:
 * pthread_cond.c/pthread_mutex.c/pthread_rwlock.c/pthread_sync.c/
 * pthread_tsd.c/semaphore.c/mqueue.c used to release every semaphore/
 * event/named-semaphore handle this file hands out via plat_fd.h's generic
 * __plat_close(), which issues close(2) on `(int)((long)h - 1)`. That is
 * exactly right for an fd+1 handle, but every handle this file returns is
 * a raw `struct ntlibc_linux_sync *` -- an mmap(2)'d pointer (see this
 * file's own banner and src/internal/linux/sync.h), a completely
 * different representation that merely gets silently truncated to a
 * plausible-looking 32-bit "fd" by the same cast. Typically that close(2)
 * just fails EBADF (the truncated pointer essentially never names a real
 * open descriptor) and clobbers the caller's own errno right after an
 * otherwise-successful mutex/cond/rwlock/once/semaphore/mqueue teardown --
 * indistinguishable from unrelated errno corruption elsewhere -- and, on
 * top of that, close(2) never releases the mmap()'d page either way, so
 * every wrongly-__plat_close()'d handle also leaked a full page. Confirmed
 * unbounded under sustained load: pthread_cond.c's cond_wait() and
 * pthread_rwlock.c's rwlock_acquire() each allocate a fresh semaphore per
 * wait, not once per object lifetime, so a condvar-wait/signal loop or a
 * contended rwlock loop leaked a page per iteration.
 *
 * See plat_thread.h's own __plat_sync_close() banner for the full fix.
 * This backend's implementation is a real munmap(2): the exact inverse of
 * alloc_sync()/map_named_sem() above, which both hand back an
 * mmap(2)'d region sized to exactly one struct ntlibc_linux_sync (always
 * within a single page). munmap(2) unmaps every page overlapping
 * [h, h + length), so the exact length passed does not need to match the
 * original mmap(2) call's rounded-up page size -- only to name at least
 * one byte inside the same single page, which sizeof(struct
 * ntlibc_linux_sync) always does. */
int __plat_sync_close(__plat_handle_t h)
{
	long ret = raw_syscall(SYS_munmap, (long)h,
	                       (long)sizeof(struct ntlibc_linux_sync), 0, 0, 0, 0);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* A REAL, CONFIRMED bug, distinct from the TLS/CLONE_SETTLS one this file's
 * __plat_thread_spawn() banner documents: pthread.c used to release every
 * thread handle (join, detach, the error-unwind in pthread_create()) via
 * plat_fd.h's generic __plat_close(), which issues close(2) on
 * `(int)((long)h - 1)`. That is exactly right for an fd+1 handle, but a
 * THREAD handle here is a boxed pid+1 (see this file's own top banner) --
 * a different kernel namespace that merely shares the same small-integer
 * ENCODING. Confirmed via test/pthread-surface.c's
 * test_errno_thread_isolation(): closing a freshly wait4()-joined
 * thread's pid-as-if-it-were-an-fd returned a bogus EBADF, silently
 * clobbering the JOINING thread's own errno right after a successful
 * pthread_join() -- indistinguishable, before this fix, from a TLS
 * aliasing bug, and only unmasked once pthread_create()/pthread_join()
 * started actually running real threads. Worse than a wrong errno in
 * general: if a spawned thread's pid ever numerically equalled a real
 * open fd + 1, this would have closed that unrelated, live file
 * descriptor out from under the process.
 *
 * See plat_thread.h's own __plat_thread_close() banner for the full
 * fix. This backend's implementation is a real no-op: __plat_wait_one()
 * (this file's own wait4(2) join path) already reaps the exited
 * thread-group-leader process by the time any caller could reach this,
 * and there is no other Linux-side resource this boxed handle owns. */
int __plat_thread_close(__plat_handle_t h)
{
	(void)h;
	return 0;
}

/* ---- thread lifecycle, the remaining functions -----------------------
 * __plat_thread_resume() is the canonical implementation for both
 * plat_thread.h's and plat_process.h's identically-named declaration
 * (src/process/fork.c calls it too, with r.thread always
 * __PLAT_HANDLE_NULL on this backend -- see src/process/linux/
 * plat_process.c's own __plat_process_fork(); the lookup below simply
 * finds nothing for that handle and returns success). It lives here,
 * not in plat_process.c, because it needs __plat_thread_spawn()'s own
 * suspend_table above. */
int __plat_thread_resume(__plat_handle_t h)
{
	struct ntlibc_linux_sync *gate = suspend_table_take((int)((long)h - 1));
	if (gate) __plat_event_set((__plat_handle_t)gate);
	return 0;
}

#if defined(__aarch64__)
#define SYS_kill_lx    129
#define SYS_getpid_lx  172
#define SYS_exit_lx    93
#define SYS_write_lx   64
#define SYS_clock_gettime_lx 113
#elif defined(__x86_64__)
#define SYS_kill_lx    62
#define SYS_getpid_lx  39
#define SYS_exit_lx    60
#define SYS_write_lx   1
#define SYS_clock_gettime_lx 228
#elif defined(__i386__)
#define SYS_kill_lx    37
#define SYS_getpid_lx  20
#define SYS_exit_lx    1
#define SYS_write_lx   4
#define SYS_clock_gettime_lx 265
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif
#define LINUX_SIGSTOP  19

/* Plain kill(2), not tgkill(2): this backend's spawn() does not pass
 * CLONE_THREAD, so the spawned "thread" is its own thread-group leader --
 * its own separate pid, not a sibling in the caller's thread group. */
int __plat_thread_suspend(__plat_handle_t h)
{
	long tid = (long)h - 1;
	long r = raw_syscall(SYS_kill_lx, tid, (long)LINUX_SIGSTOP, 0, 0, 0, 0);
	if (is_sys_error(r)) { errno = (int)-r; return -1; }
	return 0;
}

/* NOT implemented for real: NT's QueueApcThread/redirect-via-CONTEXT-record
 * has no Linux equivalent built here yet (needs a dedicated real-time
 * signal with a kernel-installed handler). Both fail honestly rather than
 * silently doing nothing; PTHREAD_CANCEL_ASYNCHRONOUS is simply
 * unavailable on this platform, while deferred cancellation never calls
 * these at all. */
int __plat_thread_queue_apc(__plat_handle_t h, __plat_apc_fn fn, void *arg1, void *arg2)
{
	(void)h; (void)fn; (void)arg1; (void)arg2;
	errno = ENOSYS;
	return -1;
}

int __plat_thread_redirect_ip(__plat_handle_t h, void *target) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; thread handle and instruction target have distinct roles
{
	(void)h; (void)target;
	errno = ENOSYS;
	return -1;
}

/* No per-thread TEB-equivalent tracks stack bounds yet (missing
 * CLONE_SETTLS/real TCB, see banner). Honest failure rather than a
 * fabricated answer. */
int __plat_thread_stack_extent(__plat_handle_t h, void **base, size_t *size)
{
	(void)h; (void)base; (void)size;
	errno = ENOSYS;
	return -1;
}

/* Linux has no separate pseudo-handle concept like NT's NtCurrentThread():
 * gettid(2) is already durable, so the same tid+1 encoding answers both
 * roles. */
__plat_handle_t __plat_thread_current_pseudo(void)
{
	return __plat_thread_duplicate_self();
}

_Noreturn void __plat_thread_terminate_self(void)
{
	for (;;) raw_syscall(SYS_exit_lx, 0L, 0L, 0L, 0L, 0L, 0L);
}

/* The bypass-everything emergency abort __pthread_cancel_unsafe_enter()'s
 * documented regions use: a raw write(2) straight to fd 2, no stdio/
 * fd-table locks a suspended target thread might hold, then an immediate
 * unconditional exit. */
_Noreturn void __plat_cancel_unsafe_abort(const char *region)
{
	static const char msg1[] = "ntlibc: cancellation-unsafe abort in: ";
	static const char msg2[] = "\n";
	size_t len = 0;
	while (region[len]) len++;
	raw_syscall(SYS_write_lx, 2L, (long)msg1, (long)(sizeof msg1 - 1), 0, 0, 0);
	raw_syscall(SYS_write_lx, 2L, (long)region, (long)len, 0, 0, 0);
	raw_syscall(SYS_write_lx, 2L, (long)msg2, (long)(sizeof msg2 - 1), 0, 0, 0);
	for (;;) raw_syscall(SYS_exit_lx, 1L, 0L, 0L, 0L, 0L, 0L);
}

/* Linux has no APC-alertable-wait concept; a plain sched_yield(2) is the
 * honest equivalent since there is no APC queue to drain. */
void __plat_thread_alertable_yield(void)
{
	raw_syscall(SYS_sched_yield, 0L, 0L, 0L, 0L, 0L, 0L);
}

/* NT ticks: 100ns units since 1601-01-01. Linux's real clock_gettime(2)
 * gives seconds+nanoseconds since 1970-01-01; 11644473600 is the real,
 * well-known number of seconds between those two epochs (the same
 * constant every Windows-interop codebase uses for this conversion). */
long long __plat_query_system_time(void)
{
	struct linux_timespec ts = {0};
	long long secs_since_1601;
	long ret = raw_syscall(SYS_clock_gettime_lx, 0L /* CLOCK_REALTIME */, (long)&ts, 0, 0, 0, 0);
	if (is_sys_error(ret)) return 116444736000000000LL;
	secs_since_1601 = (long long)ts.tv_sec + 11644473600LL;
	return secs_since_1601 * 10000000LL + (long long)ts.tv_nsec / 100LL;
}

/* mqueue.c's positioned queue-file transfer via pread64(2)/pwrite64(2):
 * explicit offset, no side effect on the file position. */
#if defined(__aarch64__)
#define SYS_pread64_lx  67
#define SYS_pwrite64_lx 68
#elif defined(__x86_64__)
#define SYS_pread64_lx  17
#define SYS_pwrite64_lx 18
#elif defined(__i386__)
/* i386's pread64/pwrite64 take the 64-bit offset as TWO 32-bit halves (a
 * low/high register pair), a genuinely different argument shape, not
 * just a different number -- __plat_thread_file_io() below would need
 * to split `off` for i386 specifically, which it does not do. A real,
 * disclosed gap, not attempted here. */
#define SYS_pread64_lx  180
#define SYS_pwrite64_lx 181
#else
#error "plat_thread.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

ssize_t __plat_thread_file_io(__plat_handle_t h, void *buf, size_t count, // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; buffer extent and file offset have distinct roles
                              off_t off, int write_op)
{
	long fd = (long)h - 1;
	long r = write_op
		? raw_syscall(SYS_pwrite64_lx, fd, (long)buf, (long)count, (long)off, 0, 0)
		: raw_syscall(SYS_pread64_lx, fd, (long)buf, (long)count, (long)off, 0, 0);
	if (is_sys_error(r)) { errno = (int)-r; return -1; }
	return (ssize_t)r;
}

// NOLINTEND(misc-include-cleaner)
