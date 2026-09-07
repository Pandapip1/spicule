/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __vfs_resolve_at()/__vfs_open_dir() for Linux -- see src/internal/
 * nt/vfs_resolve.c's own banner for why this split exists: the overlay
 * that file implements compensates for NT having no real filesystem
 * rooted at / at all, which a real Linux process already has natively,
 * so the fallback is never needed here. Every path is native;
 * __vfs_resolve_at() always returns __VFS_NONE and __vfs_open_dir() is
 * consequently never reached, kept here only so the portable
 * src/internal/libc.h declaration has something to link against.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include "libc.h"

int __vfs_resolve_at(int dirfd, const char *path)
{
	(void)dirfd;
	if (!path) { errno = EFAULT; return -1; }
	if (!*path) { errno = ENOENT; return -1; }
	return __VFS_NONE;
}

int __vfs_open_dir(int kind, int cloexec, HANDLE *out) // NOLINT(bugprone-easily-swappable-parameters) -- fixed VFS contract; object kind and close-on-exec flag have distinct roles
{
	(void)kind; (void)cloexec; (void)out;
	errno = ENOTDIR;
	return -1;
}

// NOLINTEND(misc-include-cleaner)
