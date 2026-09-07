/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_unistd.h"

int chdir(const char *path)
{
	int vfs;

	if (!path || !*path) { errno = ENOENT; return -1; }
	/* Path resolution (kind/native checks, ENOTDIR, {NAME_MAX} check)
	 * lives in __plat_chdir(), since __vfs_resolve_at() is NT-only
	 * overlay machinery no other backend needs (same split as open()'s
	 * front door). __vfs_cwd_set() stays here: it's portable process-wide
	 * cwd-kind bookkeeping, not a resolution step, and a backend with no
	 * overlay just reports __VFS_NONE, which is a harmless no-op. */
	if (__plat_chdir(path, &vfs) < 0) return -1;
	__vfs_cwd_set(vfs);
	return 0;
}

int fchdir(int fd)
{
	struct __fd *f = __fd_get(fd);
	char *p;
	int r;
	if (!f) return -1;
	if (f->type != __FD_DIR) { errno = ENOTDIR; return -1; }
	if (!f->vfs_native && f->vfs == __VFS_ROOT) return chdir("/");
	if (!f->vfs_native && f->vfs == __VFS_DEV) return chdir("/dev");
	p = __handle_path(f->h);
	if (!p) return -1;
	r = chdir(p);
	__free(p);
	return r;
}

// NOLINTEND(misc-include-cleaner)
