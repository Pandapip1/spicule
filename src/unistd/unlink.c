/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * unlink and rmdir: open for DELETE and set the disposition.  POSIX
 * semantics (the name goes away at once even while other handles are
 * open) are asked for first, on Windows 10 1709 and later; older systems
 * answer STATUS_INVALID_PARAMETER and get the classic delete-on-close.
 */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "plat_unistd.h"

/* Checker gap (spicule.CapabilityToken/spicule.OwnershipType): strlen(path)
 * below needs path to carry null_terminated, which is concretely true
 * (every POSIX path argument is a C string) -- but stating it here via
 * withtok(null_terminated) cascades that same requirement up through
 * __unlink_at()/unlink()/rmdir()/unlinkat()'s own top-level analysis, and
 * from there into every caller of unlink()/rmdir() tree-wide (shm.c,
 * mqueue.c, semaphore.c, several src/util utilities), none of which
 * currently grant it either. That net-regresses the whole-tree lint far
 * more than it fixes here, so left open rather than propagated. */
static int final_component_is_dot(const char *path)
{
	size_t start, end, n;

	if (!path) return 0;
	end = strlen(path);
	while (end > 0 && (path[end-1] == '/' || path[end-1] == '\\')) end--;
	start = end;
	while (start > 0 && path[start-1] != '/' && path[start-1] != '\\') start--;
	n = end - start;
	return (n == 1 && path[start] == '.') ||
	       (n == 2 && path[start] == '.' && path[start+1] == '.');
}

int __unlink_at(int dirfd, const char *path, int isdir)
{
	if (isdir && final_component_is_dot(path)) { errno = EINVAL; return -1; }
	return __plat_unlink(dirfd, path, isdir);
}

int unlink(const char *path) { return __unlink_at(AT_FDCWD, path, 0); }
int rmdir(const char *path) { return __unlink_at(AT_FDCWD, path, 1); }

/* AT_REMOVEDIR is the only flag unlinkat() defines, and unlink.html's
 * "[EINVAL] (unlinkat() only) The value of the flag argument is not
 * valid" is a shall-fail: every other bit has to be refused rather than
 * masked off, or a caller who passes the wrong AT_* constant gets a
 * deletion instead of a diagnostic. */
int unlinkat(int dirfd, const char *path, int flags)
{
	if (flags & ~AT_REMOVEDIR) { errno = EINVAL; return -1; }
	return __unlink_at(dirfd, path, flags & AT_REMOVEDIR);
}
