/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getrlimit()/setrlimit(): getrlimit() reports real numbers this library
 * actually enforces -- __fd_limit for RLIMIT_NOFILE (src/internal/fd.c's
 * live descriptor ceiling) and, for RLIMIT_NPROC/RLIMIT_CPU/RLIMIT_AS/
 * RLIMIT_DATA, whatever the last successful setrlimit() call recorded
 * (CHILD_CAP_LIMIT_/RLIM_INFINITY by default) -- and RLIM_INFINITY for
 * every other resource NT has no per-process cap for.
 *
 * RLIMIT_NOFILE is the one enforceable resource here that needs no NT
 * primitive at all, and it was long mis-recorded as needing one.  Its
 * clause -- "a number one greater than the maximum value that the system
 * may assign to a newly-created descriptor" (setrlimit.html) -- is about
 * descriptors, and descriptors on this platform are wholly spicule's own:
 * __fd_alloc() hands them out of the static __fds[] table in this
 * process's address space and already returns EMFILE when it runs out.
 * "The system" in that sentence is this library.  So setrlimit() lowers
 * __fd_limit, the bound __fd_alloc() loops to, and the limit is honoured
 * for real rather than accepted-and-ignored.  The soft limit has exactly
 * one copy -- __fd_limit itself -- so getrlimit() cannot drift from what
 * is enforced.  The hard limit may be lowered but never raised (no
 * appropriate privileges), and never past FD_MAX in any case: the table
 * is a fixed array, not something a limit can grow.
 *
 * setrlimit() additionally reflects onto NT for exactly the resources
 * include/sys/resource.h's own comment documents as having a real NT
 * enforcement primitive: RLIMIT_NPROC, RLIMIT_CPU, RLIMIT_AS, and
 * RLIMIT_DATA, via a
 * job object this process creates and assigns itself to on first use
 * (NtCreateJobObject/NtAssignProcessToJobObject, src/internal/nt.h) and
 * whose JobObjectExtendedLimitInformation this then updates
 * (NtSetInformationJobObject) -- ActiveProcessLimit for RLIMIT_NPROC,
 * PerProcessUserTimeLimit for RLIMIT_CPU, ProcessMemoryLimit for
 * RLIMIT_AS/RLIMIT_DATA (the same field for both, since NT does not
 * distinguish total address space from the data segment the way POSIX
 * does). The job-object call is best-effort: this process's own soft/
 * hard state is the source of truth getrlimit() reads back regardless of
 * whether the job object actually accepted the new limit, exactly the
 * way getrlimit() already reported FD_MAX/CHILD_CAP_LIMIT_ without ever
 * asking NT to confirm them.
 *
 * RLIMIT_FSIZE is stored and enforced too, but by spicule rather than by
 * NT: see the note beside fsize_cur below and the checks in the write
 * paths.  It needs no NT primitive for the same reason RLIMIT_NOFILE
 * does not -- the resource is bounded by this library's own code.
 *
 * For every other resource (RLIMIT_STACK, RLIMIT_CORE,
 * RLIMIT_RSS, RLIMIT_MEMLOCK), ON NT, there is no mechanism that reaches
 * the thing being capped after this process has already started
 * (NT fixes stack reservation at NtCreateThreadEx() time; there is no per-process max-file-size,
 * core-dump-size, RSS, or mlock-budget primitive at all -- see
 * include/sys/resource.h for the fuller per-resource accounting).
 * setrlimit() for one of these accepts a request only when it does not
 * actually ask for stricter enforcement than the fixed value already in
 * effect (raising, or repeating, the existing ceiling is a harmless
 * no-op); asking to genuinely lower it is rejected with EINVAL rather
 * than silently accepted and then not honored, which is exactly the
 * misrepresentation the header's previous undefined-ok comment warned
 * against.
 *
 * ON LINUX, all four of those are genuinely enforced by the kernel
 * (prlimit64(2) -- confirmed real for RLIMIT_STACK/CORE/MEMLOCK;
 * RLIMIT_RSS is accepted and stored but not acted on by the kernel
 * itself since 2.4.30/2.6.9, an honest caveat, not a reason to skip
 * wiring up the real syscall for it too -- see include/sys/resource.h's
 * setrlimit() comment), so setrlimit() for these four gets the exact
 * same soft/hard storage and "only privilege gates raising the hard
 * limit" treatment as RLIMIT_NPROC/CPU/AS/DATA above on that build,
 * reflected onto the kernel via src/misc/linux/plat_misc.c's
 * __plat_rlimit_apply_extra(). The two platforms' setrlimit() bodies for
 * these four therefore genuinely diverge (`#if defined(__linux__)`
 * below), because the two claims -- "there is no mechanism" and "the
 * kernel enforces this for real" -- cannot both be honoured by one code
 * path without one of them lying.
 *
 * getrusage() reports what NtQueryInformationProcess(ProcessTimes) can
 * answer -- ru_utime/ru_stime -- and leaves every other struct rusage
 * field zero, the same way many real getrusage() implementations do for
 * fields their platform has no counter for (Linux, for one, leaves most
 * of them zero too). RUSAGE_CHILDREN reads the running total
 * src/process/wait.c accumulates at every waitpid()/wait3()/wait4()
 * reap; RUSAGE_SELF and RUSAGE_THREAD both report this process's own
 * times, since this library has no per-thread accounting (the same
 * approximation src/time/clock_gettime.c's cputime_get() already makes
 * for CLOCK_THREAD_CPUTIME_ID).
 *
 * getpriority()/setpriority(): see include/sys/resource.h for the full
 * nice<->NT-base-priority mapping this uses and why it round-trips.
 * nice() (<unistd.h>) is here too, and is written in terms of those two
 * rather than beside them: one copy of the state, no way for the two
 * pages' arithmetic to disagree about this process's priority.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include "libc.h"
#include "plat_misc.h"
#include "plat_fd.h"

/* ---- getrlimit()/setrlimit() -------------------------------------------
 * Soft/hard state for the four resources setrlimit() actually accepts a
 * new value for. Everything else getrlimit() reports is a fixed constant
 * (FD_MAX, or RLIM_INFINITY) computed directly, not stored here. */
static rlim_t nproc_cur = CHILD_CAP_LIMIT_, nproc_max = CHILD_CAP_LIMIT_;
static rlim_t cpu_cur = RLIM_INFINITY, cpu_max = RLIM_INFINITY;
static rlim_t as_cur = RLIM_INFINITY, as_max = RLIM_INFINITY;
static rlim_t data_cur = RLIM_INFINITY, data_max = RLIM_INFINITY;
/* RLIMIT_FSIZE is stored and honoured like the four above, but WITHOUT a
 * job object: NT has no per-process maximum-file-size primitive, and
 * needs none.  The limit is about what THIS process may create, and
 * every path by which this process can extend a file goes through
 * spicule's own I/O -- there is no mmap in this library at all -- so the
 * enforcement point is our write paths, not the kernel's. */
static rlim_t fsize_cur = RLIM_INFINITY, fsize_max = RLIM_INFINITY;
#if defined(__linux__)
/* RLIMIT_STACK/CORE/RSS/MEMLOCK: on Linux (unlike NT -- see this file's
 * own banner and include/sys/resource.h's) these four are genuinely
 * enforced by the kernel via prlimit64(2), so they get the exact same
 * soft/hard storage treatment as RLIMIT_NPROC/CPU/AS/DATA above rather
 * than the NT build's own EINVAL-on-lowering fallback (setrlimit()'s
 * `default:` case below, kept unchanged for the NT build). */
static rlim_t stack_cur = RLIM_INFINITY, stack_max = RLIM_INFINITY;
static rlim_t core_cur = RLIM_INFINITY, core_max = RLIM_INFINITY;
static rlim_t rss_cur = RLIM_INFINITY, rss_max = RLIM_INFINITY;
static rlim_t memlock_cur = RLIM_INFINITY, memlock_max = RLIM_INFINITY;
#endif
/* RLIMIT_NOFILE's soft limit lives in __fd_limit (src/internal/fd.c), the
 * bound __fd_alloc() actually loops to, so that there is exactly one copy
 * of it and getrlimit() cannot drift from what is enforced.  Only the
 * hard limit needs storing here. */
static rlim_t nofile_max = FD_MAX;

/* ---- RLIMIT_FSIZE enforcement ------------------------------------------
 *
 * setrlimit.html: RLIMIT_FSIZE is "the maximum size of a file, in bytes,
 * that may be created by a process", and write.html's [EFBIG] is "An
 * attempt was made to write a file that exceeds the implementation-
 * defined maximum file size or the process' file size limit".
 *
 * NT has no per-process file-size quota and needs none.  The limit
 * governs what THIS process may create, and every path by which this
 * process can extend a file goes through spicule's own I/O -- write(),
 * pwrite(), writev(), ftruncate(), posix_fallocate(), and stdio, which
 * funnels into write().  There is no mmap in this library at all (no
 * <sys/mman.h>, no implementation), so that list is closed and
 * enforcement here is complete for this process, exactly as
 * RLIMIT_NOFILE's is.  A file extended by ANOTHER process is outside the
 * clause rather than a hole in this: the limit is per-process.
 *
 * SEMANTICS ARE MEASURED, NOT ASSUMED.  Taken from Linux/glibc with
 * SIGXFSZ ignored, limit 256:
 *     write(512) on an empty file        -> 256   (TRUNCATED, no error)
 *     write(200) at offset 200           -> 56    (truncated to the limit)
 *     write(512) with the file at 256    -> -1, EFBIG
 *     pwrite(100) at offset 1000         -> -1, EFBIG
 *     ftruncate(1024) / ftruncate(256)   -> -1 EFBIG / 0
 *     ftruncate(128)                     -> 0     (shrinking is fine)
 *     posix_fallocate(0, 1024)           -> EFBIG
 * So a write is CLAMPED when it starts below the limit and would cross
 * it, and fails with [EFBIG] only when not one byte may be written.
 * Operations that cannot partially succeed -- ftruncate, posix_fallocate
 * -- fail outright rather than clamping.
 *
 * A previous version of the fenced test expected write(512) on an empty
 * file to fail with EFBIG.  That is not what any implementation does,
 * and it is why the numbers above were measured before this was written.
 *
 * The measurements above were taken with SIGXFSZ ignored because the
 * clause has a second half, implemented by __fsize_exceeded() below:
 * "If a write or truncate operation would cause this limit to be
 * exceeded, SIGXFSZ shall be generated for the thread.  If the thread
 * is blocking, or the process is ignoring, SIGXFSZ, the write or
 * truncate operation shall fail with errno set to [EFBIG]"
 * (setrlimit.html).  The signal is not an alternative to the error:
 * a process that survives it still gets [EFBIG] back.
 */

/* The refusal, in one place so that the signal and the errno cannot
 * drift apart.  Returns -1 so a caller can `return __fsize_exceeded();`
 * whatever its own return type is.
 *
 * ORDER IS LOAD-BEARING, AND IT IS THE OTHER WAY ROUND FROM THE OBVIOUS
 * ONE.  __raise_internal() runs the handler inline on this thread and
 * returns only if the process is meant to carry on, so anything the
 * handler does -- a write(), a printf(), an open() -- can leave its own
 * value in errno.  Setting errno first and raising afterwards would let
 * a handler that merely counts the signal still hand its caller a
 * stale, wrong errno.  Assigning after the raise is what write() already
 * does for the SIGPIPE/[EPIPE] pair (src/unistd/write.c), and it is
 * correct for the same reason.
 *
 * If SIGXFSZ is neither caught nor ignored, __raise_internal() does not
 * return at all: setrlimit.html's default action for SIGXFSZ is
 * abnormal termination, and this library's default_action()
 * (src/signal/signal.c) gives it exactly that.
 *
 * ONLY THE PROCESS LIMIT COMES THROUGH HERE.  [EFBIG] has two other
 * sources in this tree and neither is this clause: the offset maximum
 * of an open file description (write.html, src/unistd/write.c) and a
 * volume's own maximum file size (posix_fallocate.html,
 * src/fcntl/fadvise.c).  Those are properties of the file, not limits
 * "of a process", so setrlimit.html's sentence does not reach them and
 * they must not generate a signal. */
int __fsize_exceeded(void)
{
	__sig_lock();
	__raise_internal(SIGXFSZ);
	__sig_unlock();
	errno = EFBIG;
	return -1;
}

/* Cheap predicate the write paths test before doing any work at all: with
 * no limit set -- the overwhelmingly common case -- nothing below runs
 * and the hot path is untouched. */
int __fsize_limited(void)
{
	return fsize_cur != RLIM_INFINITY;
}

/* The offset a write on this handle will start at.  `append` selects the
 * end of the file rather than the current position, matching what
 * NtWriteFile does for FILE_WRITE_TO_END_OF_FILE. */
/* out forwarded, unguarded, into the now-required
 * __plat_write_start_offset(); its one real call site below passes
 * &off, never NULL. */
static int fsize_start(__plat_handle_t h, int append, long long *out)
    __attribute__((nonnull(3)));
static int fsize_start(__plat_handle_t h, int append, long long *out)
{
	return __plat_write_start_offset(h, append, out);
}

/* How many of `count` bytes may be written on this handle.  Returns
 * `count` unchanged when no limit applies or the query cannot be
 * answered (a limit we cannot evaluate must not silently truncate a
 * caller's write), a smaller count when the write would cross the limit,
 * or __fsize_exceeded()'s -1 -- SIGXFSZ, then errno EFBIG -- when not
 * one byte may be written. */
long long __fsize_clamp(__plat_handle_t h, int append, size_t count) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long long off, room;

	if (!__fsize_limited()) return (long long)count;
	if (fsize_start(h, append, &off) < 0) return (long long)count;
	room = (long long)fsize_cur - off;
	if (room <= 0) return __fsize_exceeded();
	return (long long)count < room ? (long long)count : room;
}

/* How many bytes may still be written starting at `off`.  LLONG_MAX when
 * no limit applies, so a caller can compare against it unconditionally;
 * 0 or less means not one byte may be written there. */
long long __fsize_room_at(long long off)
{
	if (!__fsize_limited()) return 0x7fffffffffffffffLL;
	return (long long)fsize_cur - off;
}

/* For an operation that cannot partially succeed: may this process leave
 * the file `size` bytes long?  0 if yes, __fsize_exceeded()'s -1 --
 * SIGXFSZ, then errno EFBIG -- if not.  setrlimit.html's clause names
 * "a write or truncate operation", so ftruncate() and posix_fallocate()
 * generate the signal exactly as write() does. */
int __fsize_allow(long long size)
{
	if (!__fsize_limited()) return 0;
	if (size > (long long)fsize_cur) return __fsize_exceeded();
	return 0;
}

int getrlimit(int resource, struct rlimit *rl)
{
	if (!rl) { errno = EFAULT; return -1; }
	switch (resource) {
	case RLIMIT_NOFILE:
		/* Soft limit is the live ceiling __fd_alloc() enforces; hard
		 * limit is the table's own size, which no setrlimit() can
		 * raise past because the table is a fixed array. */
		rl->rlim_cur = (rlim_t)__fd_limit;
		rl->rlim_max = nofile_max;
		break;
	case RLIMIT_NPROC:
		rl->rlim_cur = nproc_cur; rl->rlim_max = nproc_max;
		break;
	case RLIMIT_CPU:
		rl->rlim_cur = cpu_cur; rl->rlim_max = cpu_max;
		break;
	case RLIMIT_AS:
		rl->rlim_cur = as_cur; rl->rlim_max = as_max;
		break;
	case RLIMIT_DATA:
		rl->rlim_cur = data_cur; rl->rlim_max = data_max;
		break;
	case RLIMIT_FSIZE:
		rl->rlim_cur = fsize_cur; rl->rlim_max = fsize_max;
		break;
#if defined(__linux__)
	case RLIMIT_STACK:
		rl->rlim_cur = stack_cur; rl->rlim_max = stack_max;
		break;
	case RLIMIT_CORE:
		rl->rlim_cur = core_cur; rl->rlim_max = core_max;
		break;
	case RLIMIT_RSS:
		rl->rlim_cur = rss_cur; rl->rlim_max = rss_max;
		break;
	case RLIMIT_MEMLOCK:
		rl->rlim_cur = memlock_cur; rl->rlim_max = memlock_max;
		break;
#else
	case RLIMIT_STACK: case RLIMIT_CORE: case RLIMIT_RSS:
	case RLIMIT_MEMLOCK:
		rl->rlim_cur = rl->rlim_max = RLIM_INFINITY;
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* Job object this process lazily creates and assigns itself to the first
 * time setrlimit() needs to reflect a limit onto NT. Best-effort: if job
 * objects are unavailable (or this NT-workalike's job-object support is a
 * stub, as Wine's NtQueryInformationJobObject is), the soft/hard state
 * above is still exactly what getrlimit() reports back, so the round
 * trip setrlimit() then getrlimit() promises stays intact either way. */
/* Push the current soft limits for the four enforceable resources onto
 * the lazily-created job object, best-effort (failure is not reported
 * to the caller -- see the comment above). */
static void apply_job_limits(void)
{
	__plat_job_apply_limits(nproc_cur, cpu_cur, as_cur, data_cur);
}

int setrlimit(int resource, const struct rlimit *rl)
{
	struct rlimit cur;

	if (!rl) { errno = EFAULT; return -1; }
	if (getrlimit(resource, &cur) != 0) return -1;  /* validates + EINVAL */

	/* "the new rlim_cur exceeds the new rlim_max" */
	if (rl->rlim_cur > rl->rlim_max) { errno = EINVAL; return -1; }

	switch (resource) {
	case RLIMIT_NOFILE:
		/* setrlimit.html: RLIMIT_NOFILE is "a number one greater than
		 * the maximum value that the system may assign to a
		 * newly-created descriptor".  Descriptors here are this
		 * library's own -- __fd_alloc() hands them out of the static
		 * __fds[] table -- so "the system" is spicule and the limit is
		 * enforceable without any NT primitive at all.  It is honoured
		 * for real: __fd_alloc() loops to __fd_limit and returns the
		 * EMFILE the clause requires past it.
		 *
		 * The hard limit can be lowered but never raised (no
		 * appropriate privileges -- src/unistd/ids.c's one always
		 * unprivileged user), and never past FD_MAX in any case, since
		 * the table is a fixed array rather than something a limit
		 * could grow. */
		if (rl->rlim_max > cur.rlim_max) { errno = EPERM; return -1; }
		nofile_max = rl->rlim_max;
		__fd_limit = rl->rlim_cur > (rlim_t)FD_MAX ? FD_MAX : (int)rl->rlim_cur;
		return 0;
	case RLIMIT_NPROC: case RLIMIT_CPU: case RLIMIT_AS: case RLIMIT_DATA:
		/* "Only a process with appropriate privileges can raise a
		 * hard limit" -- this library's one always-unprivileged
		 * user (src/unistd/ids.c) never has that. */
		if (rl->rlim_max > cur.rlim_max) { errno = EPERM; return -1; }
		switch (resource) { // NOLINT(bugprone-switch-missing-default-case) -- the enclosing switch admits exactly these four resource values
		case RLIMIT_NPROC: nproc_cur = rl->rlim_cur; nproc_max = rl->rlim_max; break;
		case RLIMIT_CPU:   cpu_cur   = rl->rlim_cur; cpu_max   = rl->rlim_max; break;
		case RLIMIT_AS:    as_cur    = rl->rlim_cur; as_max    = rl->rlim_max; break;
		case RLIMIT_DATA:  data_cur  = rl->rlim_cur; data_max  = rl->rlim_max; break;
		}
		apply_job_limits();
		return 0;
	case RLIMIT_FSIZE:
		/* Accepted for real, and stored.  This used to fall into the
		 * arm below and be REFUSED with [EINVAL] for any lowering --
		 * but setrlimit.html's [EINVAL] covers only "the value
		 * specified in resource is not valid" and "rlim_cur exceeds
		 * rlim_max", and lowering RLIMIT_FSIZE from RLIM_INFINITY is
		 * neither.  Refusing a legal call is a violation the caller
		 * cannot work around.
		 *
		 * FSIZE is split out from the arm below because it is not like
		 * the others: STACK/CORE/RSS/MEMLOCK have no mechanism that
		 * could reach the thing being capped, whereas the file size
		 * this process may create is bounded entirely by spicule's own
		 * write paths.  "Refuse rather than lie" belongs where it is
		 * true, and it is not true here. */
		if (rl->rlim_max > cur.rlim_max) { errno = EPERM; return -1; }
		fsize_cur = rl->rlim_cur;
		fsize_max = rl->rlim_max;
		return 0;
#if defined(__linux__)
	case RLIMIT_STACK: case RLIMIT_CORE: case RLIMIT_RSS: case RLIMIT_MEMLOCK:
		/* Real on Linux: prlimit64(2) genuinely enforces all four (see
		 * this file's own banner and include/sys/resource.h's setrlimit()
		 * comment for the honest RLIMIT_RSS caveat), so these get the
		 * same treatment as RLIMIT_NPROC/CPU/AS/DATA above rather than
		 * the NT build's "refuse rather than lie" no-op-or-EINVAL rule
		 * just below, which stays for the NT build precisely because it
		 * is NOT lying there -- there is really no mechanism to reflect
		 * a lowered value onto. */
		if (rl->rlim_max > cur.rlim_max) { errno = EPERM; return -1; }
		switch (resource) { // NOLINT(bugprone-switch-missing-default-case) -- the enclosing switch admits exactly these four resource values
		case RLIMIT_STACK:   stack_cur   = rl->rlim_cur; stack_max   = rl->rlim_max; break;
		case RLIMIT_CORE:    core_cur    = rl->rlim_cur; core_max    = rl->rlim_max; break;
		case RLIMIT_RSS:     rss_cur     = rl->rlim_cur; rss_max     = rl->rlim_max; break;
		case RLIMIT_MEMLOCK: memlock_cur = rl->rlim_cur; memlock_max = rl->rlim_max; break;
		}
		__plat_rlimit_apply_extra(stack_cur, core_cur, rss_cur, memlock_cur);
		return 0;
	default:
		errno = EINVAL;
		return -1;
	}
#else
	default:
		/* RLIMIT_STACK/CORE/RSS/MEMLOCK: no NT mechanism can actually
		 * move the fixed ceiling these already report (see the file
		 * banner comment). Accept the
		 * call only when it does not ask for anything stricter than
		 * what is already true -- a harmless no-op -- and refuse
		 * (EINVAL) a request that would require enforcement this
		 * library cannot provide, rather than silently lying about
		 * having applied it. */
		if (rl->rlim_cur < cur.rlim_cur || rl->rlim_max < cur.rlim_max) {
			errno = EINVAL;
			return -1;
		}
		return 0;
	}
#endif
}

int getrusage(int who, struct rusage *ru)
{
	unsigned long long user100ns, kernel100ns;

	if (!ru) { errno = EFAULT; return -1; }
	switch (who) {
	case RUSAGE_CHILDREN:
		__rusage_children(ru);
		return 0;
	case RUSAGE_SELF:
	case RUSAGE_THREAD:
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	memset(ru, 0, sizeof *ru);
	if (__plat_process_times_self(&user100ns, &kernel100ns) < 0) return -1;
	ru->ru_stime.tv_sec = (time_t)(kernel100ns / 10000000ULL);
	ru->ru_stime.tv_usec = (suseconds_t)((kernel100ns % 10000000ULL) / 10);
	ru->ru_utime.tv_sec = (time_t)(user100ns / 10000000ULL);
	ru->ru_utime.tv_usec = (suseconds_t)((user100ns % 10000000ULL) / 10);
	return 0;
}

/* ---- getpriority()/setpriority() ----------------------------------------
 * See include/sys/resource.h for the full writeup of why this maps nice
 * values onto ProcessPriorityClass (3 classes actually reachable from an
 * unprivileged caller) rather than the finer-grained ProcessBasePriority:
 * the latter is STATUS_NOT_IMPLEMENTED on the Wine build this project's
 * own CI runs against, confirmed directly --
 *
 *   NtSetInformationProcess(NtCurrentProcess(), ProcessBasePriority,
 *                            &bp, sizeof bp)
 *
 * returns STATUS_NOT_IMPLEMENTED (-> ENOSYS) on that Wine even though
 * NtQueryInformationProcess(ProcessBasicInformation) happily reports
 * BasePriority back -- support for *setting* it was only added to Wine
 * in commit b9dd7d114 ("ntdll: Implement ProcessBasePriority class in
 * NtSetInformationProcess."), first released in wine-10.7, well after
 * the wine-9.0 this project's own CI environment ships. */
/* This process's own nice value: the authoritative source getpriority()
 * reads back for PRIO_PROCESS on self, so that set-then-get is always
 * exact for this process regardless of where the mapping above is lossy
 * (see include/sys/resource.h). Starts at the POSIX default, 0. */
static int self_nice;

int getpriority(int which, id_t who) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int self;
	struct __child *c;
	__plat_handle_t h;
	int nice_value;

	switch (which) {
	case PRIO_PROCESS: self = (who == 0 || who == (id_t)getpid()); break;
	case PRIO_PGRP:     self = (who == 0 || who == (id_t)getpgrp()); break;
	case PRIO_USER:     self = (who == 0 || who == (id_t)geteuid()); break;
	default: errno = EINVAL; return -1;
	}

	if (self) return self_nice;

	/* Not self: spicule tracks no group/user directory, so only a
	 * foreign PRIO_PROCESS pid can possibly be found. */
	if (which != PRIO_PROCESS) { errno = ESRCH; return -1; }

	c = __child_find((int)who);
	if (c) {
		h = c->h;
	} else {
		if (__plat_process_open((int)who, &h) < 0) return -1;
	}
	{
		int r = __plat_priority_get(h, &nice_value);
		if (!c) __plat_close(h);
		if (r < 0) return -1;
	}
	return nice_value;
}

int setpriority(int which, id_t who, int value) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int self;
	struct __child *c;
	__plat_handle_t h;

	switch (which) {
	case PRIO_PROCESS: self = (who == 0 || who == (id_t)getpid()); break;
	case PRIO_PGRP:     self = (who == 0 || who == (id_t)getpgrp()); break;
	case PRIO_USER:     self = (who == 0 || who == (id_t)geteuid()); break;
	default: errno = EINVAL; return -1;
	}

	if (value < -NZERO) value = -NZERO;
	if (value > NZERO - 1) value = NZERO - 1;

	if (self) {
		/* "Only a process with appropriate privileges can lower its
		 * nice value" -- this library's one user is always
		 * unprivileged, so any value below the POSIX default (0) is
		 * always refused; anywhere in [0, NZERO-1], including back
		 * down to a value this process held a moment ago, is always
		 * allowed. */
		if (value < 0) { errno = EACCES; return -1; }
		if (__plat_priority_set_self(0, value) < 0) return -1;
		self_nice = value;
		return 0;
	}

	if (which != PRIO_PROCESS) { errno = ESRCH; return -1; }

	c = __child_find((int)who);
	if (c) return __plat_priority_set(c->h, 0, value);

	/* A process exists but this library did not spawn it: "the real
	 * [or] effective user ID of the executing process [does not]
	 * match the effective user ID of the process whose nice value is
	 * being changed" is the only way that can be true here, since
	 * spicule's one-user model has nothing else to check. */
	if (__plat_process_open((int)who, &h) < 0) return -1;
	__plat_close(h);
	errno = EPERM;
	return -1;
}

/* ---- nice() -------------------------------------------------------------
 *
 * nice.html DESCRIPTION: "The nice() function shall add the value of incr
 * to the nice value of the calling process.  A maximum nice value of
 * 2*{NZERO}-1 and a minimum nice value of 0 shall be imposed by the
 * system.  Requests for values above or below these limits shall result in
 * the nice value being set to the corresponding limit."  RETURN VALUE:
 * "Upon successful completion, nice() shall return the new nice value
 * -{NZERO}."
 *
 * It is getpriority() plus setpriority() and deliberately nothing else --
 * the same self_nice above, the same NtSetInformationProcess mirroring,
 * the same clamp -- so the two interfaces cannot end up disagreeing about
 * what this process's nice value is.  It was previously a `(void)incr;
 * return 0;` stub in src/unistd/ids.c, which could not have agreed with
 * anything.
 *
 * THE TWO PAGES COUNT FROM DIFFERENT ORIGINS, and mixing them up costs
 * exactly one {NZERO}.  nice()'s scale is [0, 2*{NZERO}-1] with the
 * default at {NZERO} (XBD <limits.h>: "{NZERO} Default process
 * priority"); getpriority()'s is that value less {NZERO}, so its default
 * is 0 -- which is the scale self_nice is already in.  The new value less
 * {NZERO} is therefore self_nice + incr, NOT self_nice + incr - {NZERO}.
 * Measured on glibc/Linux rather than reasoned about: from a default
 * process, nice(0)=0, nice(5)=5, a following nice(0)=5, nice(1000)=19,
 * and getpriority(PRIO_PROCESS, 0) agrees with each.
 *
 * [EPERM] "The incr argument is negative and the calling process does not
 * have appropriate privileges."  The privilege decision is THIS LIBRARY'S
 * and not NT's, which is a choice, not an oversight: NT does not refuse a
 * raise.  Probed under the Wine this project's suite runs on,
 * NtSetInformationProcess(NtCurrentProcess(), ProcessPriorityClass)
 * returned STATUS_SUCCESS for every class including HIGH and REALTIME,
 * and real NT gates only REALTIME (SeIncreaseBasePriorityPrivilege) --
 * so deriving the answer from what NT says would make [EPERM] unreachable
 * and let any process make itself more favourable than everything around
 * it.  spicule models one always-unprivileged user (src/unistd/ids.c),
 * the same premise setrlimit() refuses a hard-limit raise on, so a
 * negative incr is always refused here.  (The other route, the
 * finer-grained ProcessBasePriority class, is STATUS_NOT_IMPLEMENTED on
 * that Wine -- re-confirmed by the same probe -- which is why
 * setpriority() above uses ProcessPriorityClass and why this borrows it
 * rather than writing a second mapping.)
 *
 * That is stricter than setpriority() above, which refuses only a request
 * for a value below the POSIX default rather than any lowering, and the
 * difference belongs to the two pages rather than to this file:
 * nice.html's [EPERM] is stated on the SIGN OF incr, unconditionally,
 * while setpriority.html's [EACCES] is stated on the resulting value.
 * Linux refuses both (measured, unprivileged: setpriority(PRIO_PROCESS,
 * 0, 0) from nice value 5 is [EACCES] there); this library's
 * setpriority() deliberately permits a return to a value the process held
 * a moment ago, and that older choice is left where it was made.  The
 * state is one variable either way, so the two calls can differ about
 * what they will *do* and never about what the nice value *is*.
 *
 * APPLICATION USAGE: "As -1 is a permissible return value in a successful
 * situation, an application wishing to check for error situations should
 * set errno to 0, then call nice()".  So no successful path here may
 * touch errno -- neither getpriority() nor setpriority() sets it except
 * when failing, and nothing below adds to that. */
int nice(int incr)
{
	long long v;

	if (incr < 0) { errno = EPERM; return -1; }

	/* long long because `long` is 32 bits on both targets: incr near
	 * INT_MAX is a request "above the limit", which the DESCRIPTION
	 * says to clamp, not licence to overflow on the way there. */
	v = (long long)self_nice + incr;
	if (v > NZERO - 1) v = NZERO - 1;

	/* Below-the-limit needs no clamp: self_nice can never be negative
	 * (setpriority() refuses that) and incr is non-negative here. */
	if (setpriority(PRIO_PROCESS, 0, (int)v) != 0) return -1;
	return getpriority(PRIO_PROCESS, 0);
}

// NOLINTEND(misc-include-cleaner)
