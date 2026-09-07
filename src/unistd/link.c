/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

/* Hard links are FileLinkInformation. Symbolic links need
 * SeCreateSymbolicLinkPrivilege or developer mode on Windows, so
 * symlink() reports EPERM when it can't; readlink() reads both NTFS
 * symlinks and junctions. Every NT-specific step lives in
 * src/unistd/nt/plat_unistd.c's __plat_link()/__plat_readlink()/
 * __plat_symlink(); these front doors are left with only the portable
 * AT_SYMLINK_FOLLOW flag linkat() forwards. */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include "libc.h"
#include "plat_unistd.h"

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
	/* link.html's "[EINVAL] The value of the flag argument is not
	 * valid" is a may-fail, unlike unlinkat()'s, so an unrecognised bit
	 * is left to mean "flag clear" rather than rejected -- only
	 * AT_SYMLINK_FOLLOW is read. */
	return __plat_link(olddirfd, oldpath, newdirfd, newpath, (flags & AT_SYMLINK_FOLLOW) != 0);
}

int link(const char *a, const char *b) { return linkat(AT_FDCWD, a, AT_FDCWD, b, 0); }

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsz)
{
	/* The vfs pre-check (reject a fixed-POSIX-namespace path before
	 * asking the backend) lives in __plat_readlink(), NT-only overlay
	 * machinery a backend without one (Linux) doesn't need. */
	return __plat_readlink(dirfd, path, buf, bufsz);
}

ssize_t readlink(const char *path, char *buf, size_t bufsz) { return readlinkat(AT_FDCWD, path, buf, bufsz); }

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
	return __plat_symlink(target, newdirfd, linkpath);
}

int symlink(const char *target, const char *linkpath) { return symlinkat(target, AT_FDCWD, linkpath); }

// NOLINTEND(misc-include-cleaner)
