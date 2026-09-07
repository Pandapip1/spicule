/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The small pathname namespace POSIX requires independently of whatever
 * drive and directory launched the process.  It is deliberately a fallback
 * overlay: a native filesystem implementation that exposes rooted paths
 * wins, while names absent from its / and /dev receive the mandatory
 * objects below.
 *
 * /tmp is intentionally not here yet.  Its writable, per-process storage is
 * a separate backend; until that backend exists it is an absent root entry.
 *
 * Genuinely portable pieces only: __vfs_stat() (the synthetic objects'
 * own stat(2)-shaped answer, the same on every platform) and the cwd-
 * kind accessors. __vfs_resolve_at()/__vfs_open_dir() -- the overlay
 * decision itself, and NT-specific by construction (it exists to
 * compensate for NT having no real / or /dev at all) -- moved to
 * src/internal/$(PLATFORM)/vfs_resolve.c; see that pair's own banners
 * for why a future UEFI backend needs NT's real logic while Linux's
 * own version is a few lines returning "always native".
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "libc.h"

#define __VFS_STAT_DEV ((dev_t)0xffffffff00000003ULL) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

static int cwd_kind;

int __vfs_stat(int kind, struct stat *st)
{
	if (!st) { errno = EFAULT; return -1; }
	memset(st, 0, sizeof *st);
	st->st_dev = __VFS_STAT_DEV;
	st->st_ino = (ino_t)kind;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_blksize = 4096;
	if (kind == __VFS_ROOT || kind == __VFS_DEV) {
		st->st_mode = S_IFDIR | 0555;
		st->st_nlink = kind == __VFS_ROOT ? 3 : 2;
		return 0;
	}
	if (kind == __VFS_CONSOLE || kind == __VFS_NULL || kind == __VFS_TTY) {
		st->st_mode = S_IFCHR | 0666;
		st->st_nlink = 1;
		st->st_rdev = (dev_t)kind;
		return 0;
	}
	errno = ENOENT;
	return -1;
}

int __vfs_cwd_get(void) { return cwd_kind; }
void __vfs_cwd_set(int kind) { cwd_kind = kind; }

// NOLINTEND(misc-include-cleaner)
