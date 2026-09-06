/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_UTIME_H
#define	_UTIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#define __NEED_time_t

#include <bits/alltypes.h>

struct utimbuf {
	time_t actime;
	time_t modtime;
};

async_signal_safe
int utime (const char *, const struct utimbuf *);

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
