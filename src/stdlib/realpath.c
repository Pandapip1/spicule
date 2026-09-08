/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* realpath: open the file and ask the kernel what it is called. A path
 * that does not exist cannot be canonicalised that way, so it is an
 * ENOENT like POSIX says.
 *
 * This front door is genuinely portable despite reading as NT-only at a
 * glance: __vfs_resolve_at() (src/internal/vfs.c) and __handle_path()
 * (src/internal/{nt,linux}/handle_path.c) are both real two-backend
 * platform interfaces -- the Linux side of __handle_path() reads
 * /proc/self/fd/N via readlinkat(2); its banner documents the one honest
 * limitation, an unlinked-while-open descriptor's " (deleted)" suffix,
 * inherited from /proc/self/fd itself. Nothing here is NT-specific, so it
 * calls __vfs_resolve_at()/__handle_path() directly rather than through a
 * dedicated __plat_realpath() -- there is no platform-specific behavior
 * left for such a seam to hide. */
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
		/* OPEN LINT FINDING (spicule.ValidPointer): vfs is one of
		 * libc.h's own small enum of values, all < the 6-entry names[]
		 * array, but the checker cannot correlate that enum's range with
		 * this array's extent. */
		const char *name = names[vfs];
		size_t bytes;
		unsafe_assume_string_terminated(name); /* a literal from names[] */
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
	unsafe_assume_string_terminated(p); /* __handle_path()'s own contract */
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
	unsafe_assume_writable_span(resolved, len + 1);
	memcpy(resolved, p, len + 1);
	__free(p);
	return resolved;
}

// NOLINTEND(misc-include-cleaner)
