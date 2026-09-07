/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _SYS_RESOURCE_H
#define _SYS_RESOURCE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <sys/time.h>

#define __NEED_id_t
#include <bits/alltypes.h>

typedef unsigned long long rlim_t;

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

/* No trailing reserved padding: this reports what NT can actually tell us
 * (src/misc/resource.c) and nothing more. */
struct rusage {
	struct timeval ru_utime;
	struct timeval ru_stime;
	long ru_maxrss, ru_ixrss, ru_idrss, ru_isrss, ru_minflt, ru_majflt;
	long ru_nswap, ru_inblock, ru_oublock, ru_msgsnd, ru_msgrcv;
	long ru_nsignals, ru_nvcsw, ru_nivcsw;
};

int getrlimit (int, struct rlimit *);

/* setrlimit() on NT: RLIMIT_NPROC/CPU/AS/DATA have a real enforcement
 * primitive (a job object this process assigns itself to); every other
 * RLIMIT_* is tracked soft/hard in process state so getrlimit() reads back
 * exactly what was last set. RLIMIT_NOFILE/STACK/FSIZE/CORE/RSS/MEMLOCK
 * have no NT mechanism to shrink what they cap after process start, so
 * setrlimit() rejects a stricter request for these with EINVAL rather
 * than silently misrepresenting the ceiling.
 *
 * On Linux, setrlimit()/prlimit64(2) genuinely enforces STACK/CORE/RSS/
 * MEMLOCK too (RLIMIT_RSS is accepted and stored by the kernel but never
 * acted on, per its own man page), so a real lowering is accepted and
 * reflected onto the kernel for those four as well. */
int setrlimit (int, const struct rlimit *);
int getrusage (int, struct rusage *);

/* NZERO is the default nice value; the valid *returned* nice range is
 * [-NZERO, NZERO-1].
 *
 * This process's own nice value is tracked directly in process-local state
 * (the authoritative source getpriority() reads back on itself), and
 * mirrored best-effort onto NtSetInformationProcess(ProcessPriorityClass)
 * -- the coarser but more portable class, since the finer-grained
 * ProcessBasePriority is not implemented by every NT workalike this
 * project tests against. This maps 20 nice values onto 3 classes, badly
 * lossy on the NT-visible side, but getpriority() on one's own process
 * still reads back exactly what was last set. A *foreign* process's nice
 * value is instead derived from PROCESS_BASIC_INFORMATION.BasePriority,
 * best-effort and approximate (that field is not reliably populated for a
 * 32-bit process under WOW64 on at least the Wine build this project
 * tests against).
 *
 * PRIO_PGRP/PRIO_USER: spicule models a process group and user this process
 * is always the sole member of, so who==0, who==getpgrp(), or
 * who==geteuid() all behave exactly like PRIO_PROCESS on self; any other
 * who is ESRCH.
 *
 * nice() (<unistd.h>) is implemented in terms of these two but counts
 * from a different origin -- its scale is [0, 2*NZERO-1] rather than
 * this one's [-NZERO, NZERO-1] -- see src/misc/resource.c for the
 * EPERM/EACCES difference too. */
#define NZERO 20
#define PRIO_PROCESS 0
#define PRIO_PGRP 1
#define PRIO_USER 2
int getpriority (int, id_t);
int setpriority (int, id_t, int);

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)
#define RUSAGE_THREAD 1

#define RLIM_INFINITY (~0ULL)
#define RLIM_SAVED_CUR RLIM_INFINITY
#define RLIM_SAVED_MAX RLIM_INFINITY

#define RLIMIT_CPU     0
#define RLIMIT_FSIZE   1
#define RLIMIT_DATA    2
#define RLIMIT_STACK   3
#define RLIMIT_CORE    4
#define RLIMIT_RSS     5
#define RLIMIT_NPROC   6
#define RLIMIT_NOFILE  7
#define RLIMIT_MEMLOCK 8
#define RLIMIT_AS      9
#define RLIMIT_NLIMITS 16

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
