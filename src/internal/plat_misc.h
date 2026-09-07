/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/misc/sched.c, times.c and resource.c's
 * POSIX-facing front doors call into instead of raw
 * Nt{OpenProcess,QueryInformationProcess,SetInformationProcess,Close,
 * YieldExecution,CreateJobObject,AssignProcessToJobObject,
 * SetInformationJobObject} calls.  See src/misc/nt/plat_misc.c for the
 * implementation these declare.
 *
 * Every function here takes POSIX-shaped arguments and returns a
 * POSIX-shaped result -- errno already set on failure, never a raw NT
 * status/struct for the front door to interpret.  Two functions make a
 * DIFFERENT errno decision than __errno_from_status()'s generic table
 * would for the exact same underlying failure, because two different
 * front-door call sites need two different answers to "a foreign
 * process could not be opened": sched.c's process_exists() (kill()-
 * adjacent: [EPERM] for a real access refusal, [ESRCH] for everything
 * else) versus resource.c's getpriority()/setpriority() (uniformly
 * [ESRCH], no distinction at all).  That decision is made here, with
 * the real NTSTATUS in hand, not reconstructed from errno afterward --
 * see __plat_process_open_checked() vs __plat_process_open() below.
 */
#ifndef _SPICULE_PLAT_MISC_H
#define _SPICULE_PLAT_MISC_H

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#if defined(__linux__)
#include <sched.h>
#include <time.h>
#endif
#include "plat_handle.h"

/* ---- src/misc/uname.c ---------------------------------------------------- */

/* uname(): fill every field of `u` (already checked non-NULL by the
 * front door, uname.html's only shall-fail clause) the way this backend
 * actually knows how -- NT's RtlGetVersion()/registry-nodename dance
 * (src/misc/nt/plat_misc.c), or Linux's own real uname(2) syscall
 * (src/misc/linux/plat_misc.c), which already answers every field
 * correctly in one call and needs no per-field NT-style reconstruction
 * at all. 0 on success, -1 with errno set on failure (this library's own
 * [EOVERFLOW] if a field NT computed does not fit `u`'s buffer; Linux's
 * real uname(2) cannot fail once `u` is known non-NULL). */
int __plat_uname(struct utsname *u);

/* sched_yield(): relinquish the processor.  No return value -- see
 * sched.c's own banner on why NtYieldExecution's "did I actually switch
 * away" answer is not a POSIX failure and sched_yield() checks nothing. */
void __plat_yield(void);

/* Whether the process referred to by `h` (a handle this library already
 * owns -- a known child, or one just opened via __plat_process_open_
 * checked() below) is still alive: sched.c's process_exists() reads
 * "alive" as "opens and queries fine, and its ProcessBasicInformation.
 * ExitStatus is still STATUS_PENDING". 1 if alive; 0 with errno set to
 * [ESRCH] otherwise -- every failure reason (the query itself failing,
 * or a real exit status) reports the same [ESRCH] uniformly here, so
 * there is no per-status decision being hidden by the uniform answer. */
int __plat_process_alive(__plat_handle_t h);

/* Open pid's process object for a query-only check (PROCESS_QUERY_
 * LIMITED_INFORMATION), the way sched.c's process_exists() needs:
 * [EPERM] iff the platform's own access check specifically refused
 * (STATUS_ACCESS_DENIED), [ESRCH] for every other failure (no such
 * pid). See this header's own banner for why that distinction cannot
 * wait until only errno is left to look at. out required: both
 * backends' shared static open_process() writes it unconditionally on
 * the success path with no NULL check, and this function's one real
 * call site (src/misc/sched.c) passes &process, never NULL. */
int __plat_process_open_checked(pid_t pid, __plat_handle_t *out)
    __attribute__((nonnull(2)));

/* Open pid's process object the same way, for resource.c's
 * getpriority()/setpriority(), which report [ESRCH] for every failure
 * uniformly -- no distinction to make, no status to keep in hand. out
 * required, same evidence as __plat_process_open_checked() above; both
 * real call sites (src/misc/resource.c) pass &h, never NULL. */
int __plat_process_open(pid_t pid, __plat_handle_t *out)
    __attribute__((nonnull(2)));

/* This process's own user/kernel CPU time, in 100ns units (NT's own
 * granularity for these fields, ProcessTimes' UserTime/KernelTime) --
 * times.c and resource.c's getrusage(RUSAGE_SELF|RUSAGE_THREAD) both
 * want exactly this and convert it their own way afterward, which is
 * why the conversion itself stays in the front door: it is this
 * library's own choice of tick size, nothing NT-specific. 0/-1(errno)
 * via return. Both outputs required: both backends write them
 * unconditionally on the success path with no NULL check, and both
 * real call sites (src/misc/resource.c, src/misc/times.c) pass
 * &user100ns/&kernel100ns, never NULL. */
int __plat_process_times_self(unsigned long long *user100ns, unsigned long long *kernel100ns)
    __attribute__((nonnull(1, 2)));

/* `h`'s base priority, converted to a nice value by this library's own
 * nice<->NT-base-priority mapping (include/sys/resource.h has the full
 * writeup and the round-trip argument) -- getpriority()'s half.
 * 0/-1(errno) via return, *nice_out set on success. nice_out required:
 * both backends write it unconditionally on the success path with no
 * NULL check, and the one real call site (src/misc/resource.c) passes
 * &nice_value, never NULL. */
int __plat_priority_get(__plat_handle_t h, int *nice_out)
    __attribute__((nonnull(2)));

/* Set `h`'s priority class, derived from `nice_value` by the same
 * mapping's other half (see include/sys/resource.h for why the finer-
 * grained ProcessBasePriority class is not used instead: STATUS_NOT_
 * IMPLEMENTED on the Wine this project's own CI runs against) --
 * setpriority()'s half.  `foreground` mirrors PROCESS_PRIORITY_CLASS's
 * own field; resource.c always passes 0 (see its own comment on why
 * NT's foreground-boost bit is never set by this library). 0/-1(errno)
 * via return. */
int __plat_priority_set(__plat_handle_t h, int foreground, int nice_value);

/* Set THIS process's own priority class the same way -- setpriority()'s
 * self case, which (unlike every other caller of __plat_priority_set())
 * has no handle of its own to hand in. */
int __plat_priority_set_self(int foreground, int nice_value);

/* The offset a write on `h` will start at: end-of-file when `append`,
 * else the descriptor's current position -- write.html's "starting
 * position" for resource.c's RLIMIT_FSIZE clamp.  Deliberately separate
 * from plat_fd.h's __plat_seek_query(), which this would otherwise
 * duplicate exactly: THAT call sets errno on failure (lseek()'s own
 * contract), and this one must NOT -- it is consulted on write()'s hot
 * path purely to decide whether a limit applies, a query that cannot be
 * answered is not itself an error any caller of this ever reports, and
 * __fsize_clamp()/fsize_start() (resource.c) just treat "cannot answer"
 * as "no limit applies" and carry on. Setting errno here would leave a
 * stray value behind a write() call that itself goes on to succeed.
 * 0/-1 via return (errno untouched either way); *out set only on 0.
 * out required: both backends write it unconditionally on the success
 * path with no NULL check, and the one real call site
 * (src/misc/resource.c's fsize_start(), itself now required the same
 * way -- forwarded straight through with no guard of its own) passes
 * &off, never NULL. */
int __plat_write_start_offset(__plat_handle_t h, int append, long long *out)
    __attribute__((nonnull(3)));

/* Best-effort push of the current NPROC/CPU/AS/DATA soft limits onto a
 * lazily-created job object this process assigns itself to the first
 * time it is needed.  See resource.c's own banner for why this is
 * entirely best-effort: failure here is never reported to the caller,
 * and getrlimit() never asks NT to confirm what was actually accepted.
 * RLIM_INFINITY in any argument means "no limit for that resource",
 * exactly like every other setrlimit() caller already sees it. */
void __plat_job_apply_limits(rlim_t nproc_cur, rlim_t cpu_cur, rlim_t as_cur, rlim_t data_cur);

#if defined(__linux__)
/* Everything below this line exists ONLY on the Linux build: real kernel
 * primitives that have no NT equivalent at all (not even a best-effort
 * one), so there is nothing for src/misc/nt/plat_misc.c to implement and
 * no reason to declare these where the NT build would see them. Each
 * front-door call site is itself guarded the same way (`#if defined
 * (__linux__)`), in src/misc/resource.c and src/misc/sched.c -- see
 * those files' own banners for why the guard has to live in the shared
 * front door and not just behind a seam, in each case.
 *
 * __plat_rlimit_apply_extra(): resource.c's setrlimit() reflects
 * RLIMIT_STACK/CORE/RSS/MEMLOCK onto the kernel for real here via
 * prlimit64(2), the same syscall __plat_job_apply_limits() above already
 * uses for NPROC/CPU/AS/DATA -- unlike NT, which has no per-process
 * mechanism that reaches any of these four after the process has
 * started (see include/sys/resource.h and resource.c's own banners),
 * Linux's setrlimit(2)/prlimit64(2) genuinely enforces all four (RSS is
 * the one exception worth flagging honestly: the kernel has accepted
 * and stored a RLIMIT_RSS value without ever acting on it since
 * 2.4.30/2.6.9 -- man 2 getrlimit says so outright -- so this is a real
 * syscall wired up faithfully, not a claim that RSS itself is
 * enforced). RLIM_INFINITY in any argument means "no limit for that
 * resource", exactly like __plat_job_apply_limits() above. */
void __plat_rlimit_apply_extra(rlim_t stack_cur, rlim_t core_cur, rlim_t rss_cur, rlim_t memlock_cur);

/* sched_setscheduler(2)/sched_getscheduler(2)/sched_setparam(2)/
 * sched_getparam(2)/sched_rr_get_interval(2): real Linux syscalls giving
 * genuine SCHED_FIFO/SCHED_RR enforcement, unlike NT, which (per
 * include/sched.h and src/misc/sched.c's own banners) has priorities and
 * a scheduler quantum but no process-visible POSIX FIFO/RR policy
 * distinction to enforce at all. `pid` is passed straight through with
 * no translation -- 0 already means "the calling process" on both the
 * POSIX front door and the raw syscall, so sched.c's own self/foreign
 * split collapses to nothing here. `policy` is never SCHED_SPORADIC
 * (include/sched.h's value 3): the real Linux kernel numbering at that
 * slot is SCHED_BATCH, an unrelated real policy (confirmed against this
 * host's own <bits/sched.h>: OTHER=0, FIFO=1, RR=2, BATCH=3, IDLE=5,
 * DEADLINE=6 -- no sporadic-server slot exists at all), so sched.c's own
 * front door keeps SCHED_SPORADIC on its bookkeeping-only path on every
 * platform and only ever calls these seams with OTHER/FIFO/RR. 0/-1
 * (errno) via return, matching every raw syscall in this header. */
int __plat_sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
int __plat_sched_getscheduler(pid_t pid);
int __plat_sched_setparam(pid_t pid, const struct sched_param *param);
int __plat_sched_getparam(pid_t pid, struct sched_param *param);
int __plat_sched_rr_get_interval(pid_t pid, struct timespec *interval);
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
