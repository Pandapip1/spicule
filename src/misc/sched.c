/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* NT exposes priority classes and a scheduler quantum, but not distinct
 * POSIX FIFO and round-robin process policies.  Keep the observable
 * policy/priority tuple here so applications can set it and read it back,
 * while include/unistd.h deliberately does not claim the stronger
 * _POSIX_PRIORITY_SCHEDULING option or hard realtime behavior.
 *
 * Foreign-process state is local to the caller.  This is enough to make
 * the process APIs coherent for self and children, including the common
 * set-then-get use, without pretending that another spicule process can
 * see a policy distinction the NT kernel itself does not store.
 *
 * sched_yield.html: "The sched_yield() function shall force the running
 * thread to relinquish the processor until it again becomes the head of
 * its thread list."  RETURN VALUE -- "shall return 0 if it completes
 * successfully, or ... -1 and set errno".  ERRORS -- "No errors are
 * defined."
 *
 * NtYieldExecution() is the NTDLL primitive, and takes no arguments.
 * It returns STATUS_SUCCESS when it actually switched away, and the
 * informational (non-error, high bit clear) STATUS_NO_YIELD_PERFORMED
 * 0x40000024 when there was no other runnable thread to switch to --
 * this is what kernel32's SwitchToThread() turns into a FALSE return.
 *
 * That second case is *not* a POSIX failure: the spec's only
 * requirement is that the caller relinquish the processor, and having
 * relinquished it to a scheduler that immediately handed it back
 * satisfies that. POSIX defines no errors here at all, so there is no
 * errno value that could describe it either. Hence the unconditional
 * 0: the return value is checked for nothing because there is nothing
 * NtYieldExecution can report that POSIX would call a failure.
 *
 * THAT WHOLE PICTURE IS NT-ONLY, and stays true of, and only checked
 * against, the NT build (`#else` below, unchanged). Linux's own
 * sched_setscheduler(2)/sched_getscheduler(2)/sched_setparam(2)/
 * sched_getparam(2)/sched_rr_get_interval(2) are real syscalls with
 * genuine SCHED_FIFO/SCHED_RR enforcement -- an unprivileged caller
 * asking for a realtime policy gets a real [EPERM] from the kernel
 * (CAP_SYS_NICE), not this file's own always-succeeds bookkeeping -- so
 * the Linux build (`#if defined(__linux__)` below) forwards
 * SCHED_OTHER/SCHED_FIFO/SCHED_RR straight to the kernel via the seams
 * in src/internal/plat_misc.h (src/misc/linux/plat_misc.c). ONE POLICY
 * IS THE EXCEPTION EVEN THERE: SCHED_SPORADIC (value 3 in this header)
 * has no Linux kernel equivalent at all -- the real kernel's own policy
 * numbering at slot 3 is SCHED_BATCH, a real, unrelated policy
 * (confirmed against a real host <bits/sched.h>: OTHER=0, FIFO=1, RR=2,
 * BATCH=3, IDLE=5, DEADLINE=6, no sporadic-server slot) -- so forwarding
 * policy 3 as-is would silently set SCHED_BATCH instead of failing or
 * degrading honestly. SCHED_SPORADIC therefore keeps this file's own
 * local bookkeeping (state_for()/set_state() below) on BOTH platforms;
 * only OTHER/FIFO/RR reach the real syscall on Linux. Local state is
 * still kept up to date after a successful real-kernel set too (see
 * sched_setscheduler()'s own comment below), purely so a later
 * SCHED_SPORADIC set-then-get for the same pid cannot appear to inherit
 * a stale recording from an earlier, unrelated real policy. */
#include <sched.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "libc.h"
#include "plat_misc.h"
#include "plat_fd.h"

#define SCHED_STATE_MAX 64
#define SCHED_PRIORITY_MAX 31

struct sched_state {
	pid_t pid;
	int policy;
	int priority;
};

static struct sched_state states[SCHED_STATE_MAX];
static int self_policy = SCHED_OTHER;
static int self_priority;

static int policy_valid(int policy) __attribute__((__pure__));
static int policy_valid(int policy)
{
	return policy == SCHED_OTHER || policy == SCHED_FIFO ||
	       policy == SCHED_RR || policy == SCHED_SPORADIC;
}

static int priority_min(int policy) __attribute__((__pure__));
static int priority_min(int policy)
{
	return policy == SCHED_OTHER ? 0 : 1;
}

static int priority_valid(int policy, int priority)
{
	return priority >= priority_min(policy) && priority <= SCHED_PRIORITY_MAX;
}

static int process_exists(pid_t pid)
{
	struct __child *child;
	__plat_handle_t process;
	int close_process = 0;
	int alive;

	if (pid == 0 || pid == getpid()) return 1;
	if (pid < 0) { errno = ESRCH; return 0; }
	child = __child_find((int)pid);
	if (child) process = child->h;
	else {
		if (__plat_process_open_checked(pid, &process) < 0) return 0;
		close_process = 1;
	}
	alive = __plat_process_alive(process);
	if (close_process) __plat_close(process);
	return alive;
}

static struct sched_state *state_for(pid_t pid, int create) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct sched_state *empty = 0;
	int i;

	if (pid == 0 || pid == getpid()) return 0;
	for (i = 0; i < SCHED_STATE_MAX; i++) {
		if (states[i].pid == pid) return &states[i];
		if (!states[i].pid && !empty) empty = &states[i];
	}
	if (create && empty) {
		empty->pid = pid;
		empty->policy = SCHED_OTHER;
		empty->priority = 0;
		return empty;
	}
	return 0;
}

/* -1 is never a real success value here (SCHED_PRIORITY_MAX is the
 * fixed constant 31; priority_min() only returns 0 or 1), so it is an
 * unambiguous "invalid policy" sentinel and the errno write can live
 * in a thin non-pure wrapper below. */
static int priority_max_or_neg1(int policy) __attribute__((__pure__));
static int priority_max_or_neg1(int policy)
{
	return policy_valid(policy) ? SCHED_PRIORITY_MAX : -1;
}

static int priority_min_or_neg1(int policy) __attribute__((__pure__));
static int priority_min_or_neg1(int policy)
{
	return policy_valid(policy) ? priority_min(policy) : -1;
}

int sched_get_priority_max(int policy)
{
	int r = priority_max_or_neg1(policy);
	if (r < 0) errno = EINVAL;
	return r;
}

int sched_get_priority_min(int policy)
{
	int r = priority_min_or_neg1(policy);
	if (r < 0) errno = EINVAL;
	return r;
}

#if defined(__linux__)
/* This pid's locally-recorded policy, if any -- SCHED_OTHER/self_policy's
 * own default for a pid this file has never seen -- used below only to
 * decide whether a SCHED_SPORADIC bookkeeping record should override
 * what the real kernel reports (see this file's own banner). Not a
 * general-purpose local cache: for anything other than SCHED_SPORADIC,
 * the real kernel is always asked, regardless of what is recorded here. */
static int local_policy_for(pid_t pid)
{
	struct sched_state *state;
	if (pid == 0 || pid == getpid()) return self_policy;
	state = state_for(pid, 0);
	return state ? state->policy : SCHED_OTHER;
}

int sched_getscheduler(pid_t pid)
{
	if (local_policy_for(pid) == SCHED_SPORADIC) return SCHED_SPORADIC;
	return __plat_sched_getscheduler(pid);
}

int sched_getparam(pid_t pid, struct sched_param *param)
{
	struct sched_state *state;
	if (!param) { errno = EINVAL; return -1; }
	if (local_policy_for(pid) == SCHED_SPORADIC) {
		if (pid == 0 || pid == getpid()) param->sched_priority = self_priority;
		else {
			state = state_for(pid, 0);
			param->sched_priority = state ? state->priority : 0;
		}
		return 0;
	}
	return __plat_sched_getparam(pid, param);
}
#else
int sched_getscheduler(pid_t pid)
{
	struct sched_state *state;
	if (!process_exists(pid)) return -1;
	if (pid == 0 || pid == getpid()) return self_policy;
	state = state_for(pid, 0);
	return state ? state->policy : SCHED_OTHER;
}

int sched_getparam(pid_t pid, struct sched_param *param)
{
	struct sched_state *state;
	if (!param) { errno = EINVAL; return -1; }
	if (!process_exists(pid)) return -1;
	if (pid == 0 || pid == getpid()) param->sched_priority = self_priority;
	else {
		state = state_for(pid, 0);
		param->sched_priority = state ? state->priority : 0;
	}
	return 0;
}
#endif

static int set_state(pid_t pid, int policy, int priority) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct sched_state *state;
	if (!process_exists(pid)) return -1;
	if (pid == 0 || pid == getpid()) {
		self_policy = policy;
		self_priority = priority;
		return 0;
	}
	state = state_for(pid, 1);
	if (!state) { errno = EAGAIN; return -1; }
	state->policy = policy;
	state->priority = priority;
	return 0;
}

#if defined(__linux__)
int sched_setparam(pid_t pid, const struct sched_param *param)
{
	int policy;
	if (!param) { errno = EINVAL; return -1; }
	policy = sched_getscheduler(pid);
	if (policy < 0) return -1;
	if (!priority_valid(policy, param->sched_priority)) {
		errno = EINVAL;
		return -1;
	}
	if (policy == SCHED_SPORADIC) return set_state(pid, policy, param->sched_priority);
	if (__plat_sched_setparam(pid, param) < 0) return -1;
	/* Keep local bookkeeping in step -- see this file's own banner. */
	set_state(pid, policy, param->sched_priority);
	return 0;
}

int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
	if (!policy_valid(policy) || !param ||
	    !priority_valid(policy, param->sched_priority)) {
		errno = EINVAL;
		return -1;
	}
	if (policy == SCHED_SPORADIC) return set_state(pid, policy, param->sched_priority);
	if (__plat_sched_setscheduler(pid, policy, param) < 0) return -1;
	/* Keep local bookkeeping in step -- see this file's own banner. */
	set_state(pid, policy, param->sched_priority);
	return 0;
}

int sched_rr_get_interval(pid_t pid, struct timespec *interval)
{
	if (!interval) { errno = EINVAL; return -1; }
	return __plat_sched_rr_get_interval(pid, interval);
}
#else
int sched_setparam(pid_t pid, const struct sched_param *param)
{
	int policy;
	if (!param) { errno = EINVAL; return -1; }
	policy = sched_getscheduler(pid);
	if (policy < 0) return -1;
	if (!priority_valid(policy, param->sched_priority)) {
		errno = EINVAL;
		return -1;
	}
	return set_state(pid, policy, param->sched_priority);
}

int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
	if (!policy_valid(policy) || !param ||
	    !priority_valid(policy, param->sched_priority)) {
		errno = EINVAL;
		return -1;
	}
	return set_state(pid, policy, param->sched_priority);
}

int sched_rr_get_interval(pid_t pid, struct timespec *interval)
{
	if (!interval) { errno = EINVAL; return -1; }
	if (!process_exists(pid)) return -1;
	interval->tv_sec = 0;
	interval->tv_nsec = 10000000L; /* the 10 ms NT scheduler tick */
	return 0;
}
#endif

int sched_yield(void)
{
	__plat_yield();
	return 0;
}

// NOLINTEND(misc-include-cleaner)
