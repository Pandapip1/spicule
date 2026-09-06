/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/utsname.h>: on NT, uname() fills sysname/release/version from
 * RtlGetVersion(), nodename from a registry lookup (falling back to
 * gethostname()), and machine from a compile-time arch check; on Linux,
 * a single uname(2) syscall answers all of them directly.
 */
#ifndef _SYS_UTSNAME_H
#define _SYS_UTSNAME_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

/* utsname.h.html gives no required size for these members; 256 is
 * comfortably above anything any field here can actually produce (the
 * longest -- nodename, via gethostname() -- is itself capped at
 * HOST_NAME_MAX+1 == 256, include/limits.h). */
struct utsname {
	char sysname[256];
	char nodename[256];
	char release[256];
	char version[256];
	char machine[256];
};

async_signal_safe
int uname(struct utsname *);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
