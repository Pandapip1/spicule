/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * fork().
 *
 * Unlike execve, fork has no image to start from: it must give the child
 * a copy of *this* process's memory and resume inside fork() itself, not
 * at the entry point crt1.c uses for every other process. NT's only
 * primitive for that is ntdll's RtlCloneUserProcess:
 *
 *   - NtCreateProcessEx/NtCreateProcess make a thread-less process object
 *     sharing the caller's address space, but a subsequent
 *     NtCreateThreadEx into it fails with STATUS_PROCESS_IS_TERMINATING --
 *     there is no supported way to give such a process its first thread
 *     other than what RtlCloneUserProcess does internally.
 *
 *   - NtCreateUserProcess maps a *new* image into a *new* address space --
 *     that is exec's primitive (__spawn already uses its Rtl wrapper),
 *     not fork's.
 *
 *   - RtlCloneUserProcess itself is documented as unreliable under WOW64
 *     (measured on real Windows, M2libc's x86/windows/process.c): the
 *     cloned thread can resume past the 32-on-64 bring-up that programs
 *     the FS segment base, faulting on fs:0x18 (TEB access), or inherit
 *     an ntdll SRW lock only the WOW64 return path releases, deadlocking
 *     the child. Both are specific to the 32-on-64 transition, so only an
 *     i386 build running under WOW64 needs the fixup: fork() checks
 *     __is_wow64() and calls __wow64_fixup_clone() (arch/i386/src/
 *     wow64_fixup.c) on the clone's still-suspended handles before ever
 *     resuming it.
 *
 * RtlCloneUserProcess duplicates the whole address space at the same
 * virtual addresses and clones the calling thread's register state into a
 * new thread, so the clone's copy of this very call resumes with the same
 * stack and locals, returning STATUS_PROCESS_CLONED instead of
 * STATUS_SUCCESS -- fork()'s 0-vs-child-pid split, for free. It is also
 * why __fds (fd.c) and the heap (malloc.c) survive fork automatically:
 * they are just memory, and all of this process's memory makes the trip.
 *
 * What does NOT make the trip on its own is *handle* inheritance: NT
 * copies only OBJ_INHERIT handles into the clone. So every descriptor's
 * handle -- close-on-exec ones included -- is marked inheritable here
 * before cloning and restored after, in both processes. Marking *every*
 * descriptor matters: POSIX fork() hands the child every fd the parent
 * had, only dropping close-on-exec ones on an actual exec. Leaving
 * cloexec handles unmarked left the clone's fd table naming handles that
 * were never copied -- free handle numbers NT would hand straight back
 * out to the next thing that asked, such as an exec'ing child's own
 * RtlCreateUserProcess process handle. __fd_close_all_cloexec() (exec.c)
 * would then close that "descriptor", and the following waitpid failed
 * with STATUS_INVALID_HANDLE: execve() reporting EBADF for a program
 * that actually ran to completion (GNU make: "Bad file descriptor", exit
 * 127, for a compile whose object file was sitting right there).
 * Deterministic, not a race -- the same build loses the same files every
 * time.
 *
 * The close-on-exec handles are inheritable only for the length of the
 * clone call itself, so nothing leaks into a spawned program. The same
 * mark-around-the-clone treatment applies to __children's process
 * handles, for the same leak reason: __spawn's InheritHandles=TRUE
 * copies *every* inheritable handle, not just the fd table, so a
 * permanently-inheritable child handle would leak into every exec'd
 * program. As on every fork(), only the calling thread is cloned; a
 * multi-threaded caller's other threads simply do not exist in the
 * child, the same contract POSIX fork() has always had.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "libc.h"
#include "plat_fd.h"
#include "plat_process.h"
#include "plat_thread.h"

/* Set/clear OBJ_INHERIT on one open descriptor's handle in place:
 * NtDuplicateObject with the attribute asked for, then close the old
 * handle and keep the new one under the same fd number.
 * DUPLICATE_SAME_ATTRIBUTES is deliberately not used -- it would copy the
 * source's attributes instead of changing them, backwards from the point
 * here (same reason mark_children_inheritable avoids it). */
static void set_fd_inherit(int i, int inherit)
{
	__plat_handle_t dup;
	if (!__fds[i].h) return;
	if (__plat_dup(__fds[i].h, inherit, &dup) == 0) {
		__plat_close(__fds[i].h);
		__fds[i].h = dup;
		__mq_fd_replaced(i, dup);
	}
}

/* Mark every open descriptor's handle inheritable so
 * RtlCloneUserProcess's INHERIT_HANDLES flag carries it into the child --
 * close-on-exec descriptors included, since fork gives the child all of
 * them and only exec drops them (see this file's header comment). */
static void mark_fds_inheritable(void)
{
	int i;
	for (i = 0; i < FD_MAX; i++) set_fd_inherit(i, 1);
}

/* Undo that for the close-on-exec descriptors, once the clone has been
 * made.  Run in both processes, before either can reach an exec, so a
 * close-on-exec handle is never inheritable at the moment __spawn's
 * InheritHandles=TRUE would copy it into a new program. */
static void unmark_cloexec_fds(void)
{
	int i;
	for (i = 0; i < FD_MAX; i++)
		if (__fds[i].flags & O_CLOEXEC) set_fd_inherit(i, 0);
}

/* Set (inherit != 0) or clear the OBJ_INHERIT attribute on every tracked
 * child-process handle.  DUPLICATE_SAME_ATTRIBUTES is deliberately not
 * used: the attribute is being changed, not copied.  The table is
 * ordinary memory -- the static seed array or, once grown, a process-heap
 * allocation (children.c), both of which RtlCloneUserProcess duplicates
 * along with the rest of the address space -- so the new handle values,
 * and the __children pointer aiming at them, travel with the clone. */
static void mark_children_inheritable(int inherit)
{
	int i;
	for (i = 0; i < __child_cap; i++) {
		__plat_handle_t dup;
		if (!__children[i].pid || !__children[i].h) continue;
		if (__plat_dup(__children[i].h, inherit, &dup) == 0) {
			__plat_close(__children[i].h);
			__children[i].h = dup;
		}
	}
}

static pid_t fork_impl(int run_handlers)
{
	struct __plat_fork_result r;
	int rc;
	int pid;

	if (run_handlers) __pthread_atfork_prepare();
	mark_fds_inheritable();
	mark_children_inheritable(1);

	rc = __plat_process_fork(&r);

	if (rc == __PLAT_FORK_CHILD) {
		/* The child: this call is returning a second time, in a thread
		 * the kernel built by copying the one that called it. Almost
		 * nothing needs setting up -- it's all just memory, already
		 * here -- except the state POSIX says the child must *not*
		 * inherit, since the address-space copy doesn't know that
		 * distinction: stop the sibling handles in __children from
		 * travelling any further, and put close-on-exec descriptors
		 * back to non-inheritable now that they've arrived. */
		__pthread_reset_after_fork();
		mark_children_inheritable(0);
		unmark_cloexec_fds();
		/* ...except the reaped-children time accounting, which is
		 * memory and did make the trip, but shouldn't have: fork.html
		 * says the child's tms_cutime/tms_cstime "shall be set to 0",
		 * and nothing in the kernel holds this figure (see wait.c), so
		 * this call is the only thing that can reset it. */
		__rusage_children_reset();
		/* Same shape, same reason: fork.html also zeroes any pending
		 * alarm(). The deadline (sleep.c) is a static the address-space
		 * copy brought along; the timer handle behind it is not
		 * OBJ_INHERIT and so didn't, hence only the deadline needs
		 * forgetting, not cancelling. */
		__alarm_reset_after_fork();
		/* Memory locks and MCL_FUTURE are not inherited across fork().
		 * RtlCloneUserProcess copied mman.c's bookkeeping bytes, so make
		 * the child-side state match that kernel-level rule. */
		__mman_reset_after_fork();
		/* POSIX AIO operations are not inherited.  The native worker is a
		 * sibling thread and therefore did not survive RtlCloneUserProcess;
		 * forget its copied queue and stale event handle in the child. */
		__aio_reset_after_fork();
		/* The sibling entries that travelled with the clone carry the
		 * parent's job-control bookkeeping, which this process didn't
		 * cause. Left alone, the clone would report a stop it didn't
		 * cause through waitpid(WUNTRACED), or resume a sibling out
		 * from under the parent on its own exit. */
		__child_forget_stops();
		/* Same reason, one more member: sigdelivery.c's per-process
		 * listener pipe, delivery thread and mutex event. Only the
		 * calling thread is cloned, so the delivery thread the clone
		 * thinks it has doesn't exist here, and its pipe/mutex handle
		 * values name nothing live (or something NT has since recycled
		 * onto that slot) -- forget them and build fresh ones under
		 * this process's own pid. Left undone, the child would be
		 * permanently deaf to cross-process signals: nothing would
		 * ever retry this. */
		__sig_delivery_reinit_after_fork();
		if (run_handlers) __pthread_atfork_child();
		return 0;
	}

	mark_children_inheritable(0);
	unmark_cloexec_fds();
	if (rc < 0) {
		if (run_handlers) __pthread_atfork_parent();
		return -1;   /* errno already set by __plat_process_fork */
	}

	/* The parent.  The child exists, suspended; track it like any other
	 * child and let it run. */
	pid = r.pid;
	if (__child_add(pid, r.process, r.job) < 0) {
		/* The table grows on demand, so this only happens when it could
		 * not be grown -- the heap is exhausted.  Degrade rather than
		 * fail the fork: the child still runs, but it is unwaitable --
		 * waitpid() only ever consults the table (src/process/wait.c) --
		 * the same tradeoff __spawn makes. */
		__plat_close(r.process);
		if (r.job) __plat_close(r.job);
	}
	/* Still suspended: repair the WOW64-specific clone damage, if any,
	 * before the child runs a single instruction. Guarded to x86/x86_64
	 * (src/internal/{i386,x86_64}/wow64.c) so aarch64, which has neither
	 * symbol, never references them. */
#if defined(__i386__) || defined(__x86_64__)
	if (__is_wow64()) __wow64_fixup_clone(r.process, r.thread);
#endif
	__plat_thread_resume(r.thread);
	__plat_thread_close(r.thread);
	if (run_handlers) __pthread_atfork_parent();
	return pid;
}

pid_t fork(void)
{
	return fork_impl(1);
}

/* _Fork(): kept deliberately despite no test referencing it (so it will
 * keep surfacing on tools/lint-unreferenced.sh's list) -- POSIX.1-2024
 * specifies it (Austin Group Defects 62/1361/1383), so this is an
 * interface the project has early, not one it invented. Same reasoning
 * as posix_close().
 *
 * POSIX asks it be async-signal-safe and skip pthread_atfork() handlers;
 * neither distinguishes it here, since there is no libpthread and fork()
 * registers no handlers of its own -- revisit only if real threads
 * arrive. */
pid_t _Fork(void)
{
	return fork_impl(0);
}

// NOLINTEND(misc-include-cleaner)
