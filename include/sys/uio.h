/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/uio.h>: readv()/writev() are implemented as a loop over this
 * library's own read()/write(), since NT's scatter/gather primitives
 * (NtReadFileScatter/NtWriteFileGather) are page-granular and cannot
 * take an arbitrary struct iovec. See src/misc/uio.c for what that costs
 * against POSIX's atomicity requirement.
 */
#ifndef _SYS_UIO_H
#define _SYS_UIO_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#define __NEED_size_t
#define __NEED_ssize_t
#include <bits/alltypes.h>

struct iovec {
	void *iov_base;
	size_t iov_len;
};

io_operation
ssize_t readv(int, const struct iovec *, int);
io_operation
ssize_t writev(int, const struct iovec *, int);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
