/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * stat, from the information NT keeps.
 *
 * Permission and special bits come from WSL's $LXMOD NTFS extended
 * attribute when it exists, giving files created by spicule a persistent
 * POSIX mode without editing a Windows DACL. A file with no $LXMOD gets
 * a compatibility default: directories 0755, files 0644, a PE32/PE32+
 * image 0111 regardless of suffix, FILE_ATTRIBUTE_READONLY removing 0222.
 *
 * Pipes, consoles, character devices, and unclassifiable objects get a
 * synthetic st_dev/st_ino so the universal same-file idiom
 * (a.st_dev==b.st_dev && a.st_ino==b.st_ino) still holds. The NT-specific
 * details live in __plat_fstat()/__plat_fstatat() (src/stat/nt/plat_stat.c).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_stat.h"

int fstat(int fd, struct stat *st)
{
	struct __fd *f = __fd_get(fd);
	int result;
	if (!f) return -1;
	if (f->vfs && !f->vfs_native) return __vfs_stat(f->vfs, st);
	result = __plat_fstat(f->h, f->type, st);
	/* Wine does not retain the $LXMOD EA supplied to NtCreateFile.  A
	 * shm descriptor carries the mode read from its private namespace
	 * sidecar so fstat() can report the same persistent POSIX metadata. */
	if (result == 0 && f->shm_mode_valid)
		st->st_mode = (st->st_mode & S_IFMT) | (f->shm_mode & 07777);
	return result;
}

int fstatat(int dirfd, const char *path withtok(null_terminated), struct stat *st, int flags)
{
	if (!path) { errno = EFAULT; return -1; }
	/* /dev/stdin, /dev/stdout, /dev/stderr are fd-table lookups, portable
	 * across backends, so handled here rather than in __plat_fstatat();
	 * mirrors src/fcntl/open.c's own /dev/std* special case. */
	if (!strncmp(path, "/dev/", 5)) {
		int fd = -1;
		if (!strcmp(path, "/dev/stdin")) fd = 0;
		else if (!strcmp(path, "/dev/stdout")) fd = 1;
		else if (!strcmp(path, "/dev/stderr")) fd = 2;
		if (fd >= 0) return fstat(fd, st);
	}
	return __plat_fstatat(dirfd, path, flags, st);
}

int stat(const char *path withtok(null_terminated), struct stat *st) { return fstatat(AT_FDCWD, path, st, 0); }
int lstat(const char *path withtok(null_terminated), struct stat *st) { return fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW); }

// NOLINTEND(misc-include-cleaner)
