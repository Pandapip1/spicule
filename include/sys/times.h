/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/times.h>: times() reuses the same NtQueryInformationProcess
 * (ProcessTimes) getrusage() already calls for tms_utime/tms_stime, and
 * the same running RUSAGE_CHILDREN total for tms_cutime/tms_cstime; see
 * src/misc/times.c for the unit conversion (100ns NT ticks to
 * sysconf(_SC_CLK_TCK) clock ticks). */
#ifndef _SYS_TIMES_H
#define _SYS_TIMES_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#define __NEED_clock_t
#include <bits/alltypes.h>

struct tms {
	clock_t tms_utime;
	clock_t tms_stime;
	clock_t tms_cutime;
	clock_t tms_cstime;
};

async_signal_safe
clock_t times(struct tms *);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
