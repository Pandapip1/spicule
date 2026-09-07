/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __vfs_resolve_at()/__vfs_open_dir() -- moved out of src/internal/vfs.c,
 * which keeps only the genuinely platform-generic pieces. The overlay
 * these two functions implement compensates for something specific to
 * NT -- no real filesystem rooted at / at all, so no real /dev, no real
 * /dev/null -- that a future UEFI backend will share but a real POSIX
 * platform like Linux does not: src/internal/linux/vfs_resolve.c's own
 * version is a few lines because a real Linux filesystem already IS the
 * thing this file exists to emulate.
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
#include "ownership_stubs.h"

static int issep(char c) __attribute__((pure));
static int issep(char c) { return c == '/' || c == '\\'; }

static int component(const char **pp, const char **start) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *p = *pp;
	int n;
	while (issep(*p)) p++;
	*start = p;
	while (*p && !issep(*p)) p++;
	n = (int)(p - *start);
	while (issep(*p)) p++;
	*pp = p;
	return n;
}

static int same(const char *s, int n, const char *word)
{
	int i;
	if (strlen(word) != (size_t)n) return 0;
	for (i = 0; i < n; i++)
		if (s[i] != word[i]) return 0;
	return 1;
}

static int native_fallback_status(NTSTATUS status)
{
	return status == STATUS_NO_SUCH_FILE || status == STATUS_NOT_FOUND ||
	       status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND ||
	       status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_SUPPORTED ||
	       status == STATUS_NOT_IMPLEMENTED;
}

int __vfs_resolve_at(int dirfd, const char *path)
{
	const char *p, *s;
	struct __fd *basefd = 0;
	struct __ntpath np;
	FILE_BASIC_INFORMATION bi;
	NTSTATUS status;
	size_t pathlen;
	int state, n, rooted = 0, trailing, can_probe = 0, custom_error = 0;
	int missing_parent = __VFS_NONE;
	int saved_errno;

	if (!path) { errno = EFAULT; return -1; }
	if (!*path) { errno = ENOENT; return -1; }
	/* Internal/native DOS device spellings stay outside the overlay. */
	if (!strcmp(path, "NUL") || !strcmp(path, "CON")) return __VFS_NONE;
	pathlen = strlen(path);
	trailing = pathlen > 1 && issep(path[pathlen - 1]);
	/* A drive prefix is always native, even when its tail uses '/'. */
	if (__nt_is_drive_letter((unsigned char)path[0]) && path[1] == ':')
		return __VFS_NONE;

	p = path;
	if (issep(*p)) {
		state = __VFS_ROOT;
		rooted = 1;
		can_probe = 1;
	} else if (dirfd != AT_FDCWD) {
		basefd = __fd_get(dirfd);
		if (!basefd) return -1;
		if (!basefd->vfs) return __VFS_NONE;
		state = basefd->vfs;
		rooted = 1;
		can_probe = basefd->vfs_native;
	} else if (__vfs_cwd_get()) {
		state = __VFS_KIND(__vfs_cwd_get());
		rooted = 1;
		can_probe = (__vfs_cwd_get() & __VFS_NATIVE) != 0;
	} else {
		return __VFS_NONE;
	}

	while ((n = component(&p, &s)) != 0) {
		if (state != __VFS_ROOT && state != __VFS_DEV) {
			custom_error = ENOTDIR;
			break;
		}
		if (same(s, n, ".")) continue;
		if (same(s, n, "..")) {
			if (state == __VFS_DEV) state = __VFS_ROOT;
			else if (state != __VFS_ROOT) { errno = ENOTDIR; return -1; }
			continue;
		}
		if (state == __VFS_ROOT) {
			if (same(s, n, "dev")) state = __VFS_DEV;
			else { missing_parent = state; state = __VFS_MISSING; break; }
		} else if (state == __VFS_DEV) {
			if (same(s, n, "console")) state = __VFS_CONSOLE;
			else if (same(s, n, "null")) state = __VFS_NULL;
			else if (same(s, n, "tty")) state = __VFS_TTY;
			else { missing_parent = state; state = __VFS_MISSING; break; }
		} else {
			errno = ENOTDIR;
			return -1;
		}
	}
	if (trailing && state != __VFS_ROOT && state != __VFS_DEV) {
		custom_error = ENOTDIR;
	}

	/* The overlay is a fallback, not a mount that hides native objects.
	 * Query the exact NT path first.  Absence and "this information class
	 * is unsupported" select the fallback; access and type failures remain
	 * native so the real operation can report them unchanged. */
	if (can_probe) {
		char *dir = 0, *joined = 0;
		saved_errno = errno;
		/* Wine's NtQueryAttributesFile does not resolve a relative name
		 * against RootDirectory even though NtCreateFile does.  Probe the
		 * equivalent absolute path for native overlay directory handles;
		 * the real operation still uses the pinned handle. */
		if (basefd && basefd->vfs_native) {
			size_t dl, pl = strlen(path), bytes;
			dir = __handle_path(basefd->h);
			if (!dir) return -1;
			dl = strlen(dir);
			if (!__size_add_checked(dl, pl, &bytes) ||
			    !__size_add_checked(bytes, 2, &bytes)) {
				__free(dir); errno = ENOMEM; return -1;
			}
			joined = __malloc(bytes);
			if (!joined) { __free(dir); errno = ENOMEM; return -1; }
			__ownership_writable_span(joined, dl);
			memcpy(joined, dir, dl);
			if (dl && !issep(joined[dl - 1])) joined[dl++] = '\\';
			__ownership_writable_span(joined + dl, pl + 1);
			memcpy(joined + dl, path, pl + 1);
			__free(dir);
			if (__ntpath_native(joined, &np, OBJ_CASE_INSENSITIVE) < 0) {
				__free(joined);
				return -1;
			}
			__free(joined);
		} else if (__ntpath_at_native(dirfd, path, &np, OBJ_CASE_INSENSITIVE) < 0) {
			return -1;
		}
		status = NtQueryAttributesFile(&np.oa, &bi);
		__ntpath_free(&np);
		if (!native_fallback_status(status))
			return state != __VFS_MISSING && !custom_error ? __VFS_NATIVE | state : __VFS_NONE;
		/* An unknown child of a native overlay directory remains native,
		 * including when it does not exist yet: create and mutation calls
		 * must still reach that filesystem.  Only the known mandatory names
		 * fall back object-by-object. */
		if (state == __VFS_MISSING) {
			if (basefd && basefd->vfs_native) return __VFS_NONE;
			if (missing_parent == __VFS_ROOT || missing_parent == __VFS_DEV) {
				const char *parent = missing_parent == __VFS_ROOT ? "/" : "/dev";
				if (__ntpath_native(parent, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;
				status = NtQueryAttributesFile(&np.oa, &bi);
				__ntpath_free(&np);
				if (!native_fallback_status(status)) return __VFS_NONE;
			}
		}
		errno = saved_errno;
	}
	if (custom_error) { errno = custom_error; return -1; }
	return rooted ? state : __VFS_NONE;
}

int __vfs_open_dir(int kind, int cloexec, HANDLE *out) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	if (kind != __VFS_ROOT && kind != __VFS_DEV) { errno = ENOTDIR; return -1; }
	InitializeObjectAttributes(&oa, 0, cloexec ? 0 : OBJ_INHERIT, 0, 0);
	st = NtCreateEvent(out, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

// NOLINTEND(misc-include-cleaner)
