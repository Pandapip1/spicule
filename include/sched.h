/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* <sched.h>: the process-scheduling interfaces are declared here, but
 * spicule does not claim the _POSIX_PRIORITY_SCHEDULING option -- NT has
 * priorities and a round-robin quantum, but no process-visible POSIX
 * FIFO/RR policy distinction and no hard realtime guarantee.
 * src/misc/sched.c keeps the observable policy/priority state and
 * validates process IDs while leaving that stronger option macro absent. */

#ifndef _SCHED_H
#define _SCHED_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_pid_t
#define __NEED_time_t
#define __NEED_struct_sched_param
#define __NEED_struct_timespec

#include <bits/alltypes.h>

#define SCHED_OTHER    0
#define SCHED_FIFO     1
#define SCHED_RR       2
#define SCHED_SPORADIC 3

int sched_get_priority_max(int);
int sched_get_priority_min(int);
int sched_getparam(pid_t, struct sched_param *);
int sched_getscheduler(pid_t);
int sched_rr_get_interval(pid_t, struct timespec *);
int sched_setparam(pid_t, const struct sched_param *);
int sched_setscheduler(pid_t, int, const struct sched_param *);
int sched_yield(void);

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
