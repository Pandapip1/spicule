/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _ERRNO_H
#define _ERRNO_H

#include <features.h>
#include <bits/errno.h>
#include <ownership.h>

#ifdef __cplusplus
extern "C" {
#endif

/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline reads
 * this annotation to learn which thread-scoped fact a read of errno
 * requires proof of (some prior call or assignment on this path could have
 * set it) -- the family name lives here, not hardcoded in the checker. */
requires_thread_token(errno_grounds)
extern int *__errno_location(void);
#define errno (*__errno_location())

#ifdef _GNU_SOURCE
extern char *program_invocation_short_name, *program_invocation_name;
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
