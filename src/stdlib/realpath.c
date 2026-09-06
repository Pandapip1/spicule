/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* realpath: open the file and ask the kernel what it is called.  A path
 * that does not exist cannot be canonicalised that way, so it is an
 * ENOENT like POSIX says.
 *
 * This front door is genuinely portable, not NT-only despite reading
 * that way at a glance: __vfs_resolve_at() (src/internal/vfs.c) and
 * __handle_path() (src/internal/{nt,linux}/handle_path.c) are both
 * real, correct, two-backend platform interfaces now -- the former
 * since the vfs.c/vfs_resolve.c split, the latter since the OPTS
 * shm_open/shm_unlink/mmap link gap traced fchmod()'s EACCES retry
 * (src/stat/chmod.c) to this exact function and got it a real Linux
 * body (readlinkat(2) on /proc/self/fd/N -- exactly the algorithm this
 * comment used to say a Linux backend "would need", before one existed).
 * __handle_path()'s Linux banner documents its own remaining honest
 * limitation (an unlinked-while-open descriptor's " (deleted)" suffix,
 * inherited from /proc/self/fd itself, not introduced here); nothing
 * else about this function is NT-specific any more, so it keeps calling
 * __vfs_resolve_at()/__handle_path() directly rather than being routed
 * through a dedicated __plat_realpath() of its own -- there is no
 * platform-specific behavior left here for such a seam to hide. */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "libc.h"
#include "ownership_stubs.h"

withtok(heap_allocated)
char *realpath(const char *__restrict path,
	char *__restrict resolved withtok(heap_allocated))
{
	int fd, saved;
	char *p, *q;
	size_t len;
	int vfs;

	if (!path) { errno = EINVAL; return 0; }
	if (!*path) { errno = ENOENT; return 0; }
	vfs = __vfs_resolve_at(AT_FDCWD, path);
	if (vfs < 0) return 0;
	if (vfs & __VFS_NATIVE) vfs = __VFS_NONE;
	if (vfs == __VFS_MISSING) { errno = ENOENT; return 0; }
	if (vfs != __VFS_NONE) {
		static const char *const names[] = { 0, "/", "/dev", "/dev/console", "/dev/null", "/dev/tty" };
		const char *name = names[vfs];
		size_t bytes;
		len = strlen(name);
		if (!__size_add_checked(len, 1, &bytes)) return 0;
		if (!resolved) {
			resolved = malloc(bytes);
			if (!resolved) return 0;
		}
		(void)snprintf(resolved, bytes, "%s", name);
		return resolved;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		/* a directory might refuse O_RDONLY; try it as one */
		if (errno == EISDIR || errno == EACCES) fd = open(path, O_RDONLY | O_DIRECTORY);
		if (fd < 0) return 0;
	}
	p = __handle_path(__fd_handle(fd));
	saved = errno;
	(void)close(fd);
	errno = saved;
	if (!p) return 0;
	for (q = p; *q; q++) if (*q == '\\') *q = '/';
	len = strlen(p);
	if (len > 3 && p[len-1] == '/') p[--len] = 0;
	if (!resolved) {
		size_t bytes;
		if (!__size_add_checked(len, 1, &bytes)) { __free(p); return 0; }
		resolved = malloc(bytes);
		if (!resolved) { __free(p); return 0; }
		memcpy(resolved, p, bytes);
		__free(p);
		return resolved;
	}
	if (len + 1 > PATH_MAX) { __free(p); errno = ENAMETOOLONG; return 0; }
	__ownership_writable_span(resolved, len + 1);
	memcpy(resolved, p, len + 1);
	__free(p);
	return resolved;
}

// NOLINTEND(misc-include-cleaner)
