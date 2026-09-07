/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * open: the POSIX flags turned into NtCreateFile's.
 *
 * Every file is opened synchronous with all three share modes, matching
 * Unix semantics where one program can delete a file another has open.
 * A newly created file receives WSL's $LXMOD NTFS extended attribute;
 * FILE_ATTRIBUTE_READONLY mirrors the aggregate write bits for ordinary
 * Windows programs.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_fd.h"
#include "plat_fcntl.h"

int __open_handle(int dirfd, const char *path, int flags, unsigned mode,
                  __plat_handle_t *out, int *typeout, int *vfsout, int *vfsnativeout)
{
	*vfsout = __VFS_NONE;
	*vfsnativeout = 0;
	if (!path) { errno = EFAULT; return -1; }

	/* /dev/stdin, /dev/stdout, /dev/stderr and /dev/fd/N are the fd
	 * table -- genuinely portable POSIX-shaped logic (every backend's fd
	 * table works the same way), so this stays in the front door rather
	 * than moving into __plat_open() alongside the NT-specific VFS-
	 * overlay/path-resolution/$LXMOD machinery below it. */
	if (!strncmp(path, "/dev/", 5)) {
		int fd = -1;
		if (!strcmp(path, "/dev/stdin")) fd = 0;
		else if (!strcmp(path, "/dev/stdout")) fd = 1;
		else if (!strcmp(path, "/dev/stderr")) fd = 2;
		else if (!strncmp(path, "/dev/fd/", 8)) { fd = 0; { const char *q = path + 8; while (*q >= '0' && *q <= '9') fd = fd * 10 + *q++ - '0'; if (*q) fd = -1; } }
		if (fd >= 0) {
			struct __fd *f = __fd_get(fd);
			if (!f) return -1;
			if (__plat_dup(f->h, !(flags & O_CLOEXEC), out) < 0) return -1;
			*typeout = f->type;
			*vfsout = f->vfs; *vfsnativeout = f->vfs_native;
			return 0;
		}
	}

	return __plat_open(dirfd, path, flags, mode, out, typeout, vfsout, vfsnativeout);
}

int openat(int dirfd, const char *path, int flags, ...)
{
	mode_t mode = 0;
	__plat_handle_t h;
	int type, fd, vfs, vfs_native;

	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	if (__open_handle(dirfd, path, flags, mode, &h, &type, &vfs, &vfs_native) < 0) return -1;
	fd = __fd_install(h, flags & (O_APPEND | O_NONBLOCK | O_CLOEXEC | O_ACCMODE), type);
	if (fd < 0) { __plat_close(h); return -1; }
	__fds[fd].vfs = (unsigned char)vfs;
	__fds[fd].vfs_native = (unsigned char)vfs_native;
	return fd;
}

int open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return openat(AT_FDCWD, path, flags, mode);
}

int creat(const char *path, mode_t mode)
{
	return open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

// NOLINTEND(misc-include-cleaner)
