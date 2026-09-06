/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * POSIX shared-memory objects, represented by ordinary backing files in a
 * private directory under the process temporary directory. Not a shortcut
 * around the VM implementation: src/mman/mman.c maps these through the same
 * NtCreateSection/NtMapViewOfSection path as any regular file, so the
 * descriptor has the object shape mmap()/ftruncate()/fstat()/close()/fork()
 * already understand.
 *
 * unlink() asks NT for POSIX deletion semantics first; Wine rejects that
 * disposition while a section view exists, so shm_unlink() falls back to
 * renaming the backing file out of the namespace -- the mapped object stays
 * alive while the original name becomes reusable immediately.
 *
 * Names without an initial slash and names with extra slashes are POSIX
 * implementation-defined; ntlibc accepts the former (Open POSIX Test Suite
 * compatibility) and rejects the latter. Component chars are restricted to
 * the portable filename set, which also avoids DOS device names/separators
 * getting a second interpretation.
 */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- strnlen(): bounded name and path validation
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include "libc.h"
#include "ownership_stubs.h"

static const char *shm_tmpdir(void)
{
	const char *dir = getenv("TMPDIR");
	if (!dir || !*dir) dir = getenv("TMP");
	if (!dir || !*dir) dir = getenv("TEMP");
	if (!dir || !*dir) dir = ".";
	return dir;
}

static int portable_name_char(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

withtok(heap_allocated)
static char *shm_path(const char *name)
{
	const char *dir;
	const char *component;
	const size_t prefix = sizeof "/ntlibc-shm/" - 1;
	size_t dirlen, maxdir, namelen, pathlen;
	char *path;
	size_t i;

	if (!name) { errno = EINVAL; return NULL; }
	namelen = strnlen(name, PATH_MAX);
	/* {PATH_MAX} includes the terminating null; {NAME_MAX} does not. */
	if (namelen >= PATH_MAX) { errno = ENAMETOOLONG; return NULL; }
	if (name[0] == '/') { component = name + 1; namelen--; }
	else component = name;
	if (namelen > NAME_MAX) { errno = ENAMETOOLONG; return NULL; }
	if (!namelen || (namelen == 1 && component[0] == '.') ||
	    (namelen == 2 && component[0] == '.' && component[1] == '.')) {
		errno = EINVAL;
		return NULL;
	}
	for (i = 0; i < namelen; i++)
		if (!portable_name_char((unsigned char)component[i])) {
			errno = EINVAL;
			return NULL;
		}

	if (namelen > (size_t)PATH_MAX - 1 - prefix) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	/* Bound the environment-derived directory scan by the exact room
	 * remaining after the fixed namespace and validated object name. */
	maxdir = (size_t)PATH_MAX - 1 - prefix - namelen;
	dir = shm_tmpdir();
	dirlen = strnlen(dir, maxdir + 1);
	if (dirlen > maxdir) { errno = ENAMETOOLONG; return NULL; }
	pathlen = dirlen + prefix + namelen + 1;
	path = malloc(pathlen);
	if (!path) return NULL;
	snprintf(path, pathlen, "%s/ntlibc-shm/%s", dir, component);
	return path;
}

/* path is never NULL here: both callers null-check their shm_path()/
 * shm_mode_path() result first. `slash` (strrchr(dir, '/')) is never NULL
 * either, since both callers only ever pass a path built by concatenating
 * "/ntlibc-shm(-mode)/" onto a directory -- but that's an invariant of the
 * callers, not something the nonnull attribute on `path` can state. */
static int ensure_namespace(const char *path) __attribute__((nonnull(1)));
static int ensure_namespace(const char *path)
{
	char *slash;
	char *dir = strdup(path);
	int saved;

	if (!dir) return -1;
	slash = strrchr(dir, '/');
	*slash = 0;
	if (mkdir(dir, 0777) < 0 && errno != EEXIST) {
		saved = errno;
		free(dir);
		errno = saved;
		return -1;
	}
	free(dir);
	return 0;
}

/* Sidecar file beside the data file, storing a four-byte POSIX mode. Real
 * NT would store this in the data file's $LXMOD EA, but stock Wine accepts
 * that EA in NtCreateFile and then drops it, so the sidecar is what makes
 * the mode survive close and reopen under Wine. */
withtok(heap_allocated)
static char *shm_mode_path(const char *path)
{
	const char *slash = strrchr(path, '/');
	size_t len = strlen(path);
	size_t prefix, bytes;
	char *modepath;

	if (!slash) { errno = EINVAL; return NULL; }
	prefix = (size_t)(slash - path);
	if (!__size_add_checked(len, sizeof "-mode", &bytes)) return NULL;
	modepath = malloc(bytes);
	if (!modepath) return NULL;
	__ownership_writable_span(modepath, prefix);
	__ownership_readable_span(path, prefix);
	memcpy(modepath, path, prefix);
	__ownership_writable_span(modepath + prefix, sizeof "-mode" - 1);
	memcpy(modepath + prefix, "-mode", sizeof "-mode" - 1);
	__ownership_writable_span(modepath + prefix + sizeof "-mode" - 1,
	                          len - prefix + 1);
	__ownership_readable_span(slash, len - prefix + 1);
	memcpy(modepath + prefix + sizeof "-mode" - 1, slash,
	       len - prefix + 1);
	return modepath;
}

static int shm_mode_write(const char *path, mode_t mode)
{
	char *modepath = shm_mode_path(path);
	unsigned char value[4];
	int fd, result = -1, saved;

	if (!modepath) return -1;
	if (ensure_namespace(modepath) < 0) { free(modepath); return -1; }
	value[0] = (unsigned char)mode;
	value[1] = (unsigned char)(mode >> 8);
	value[2] = (unsigned char)(mode >> 16);
	value[3] = (unsigned char)(mode >> 24);
	fd = open(modepath, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
	if (fd >= 0) {
		ssize_t written = write(fd, value, sizeof value);
		result = written == sizeof value ? 0 : -1;
		if (written >= 0 && result < 0) errno = EIO;
		saved = errno;
		(void)close(fd);
		errno = saved;
	}
	saved = errno;
	free(modepath);
	errno = saved;
	return result;
}

/* mode is never NULL: the one call site (shm_open()) always passes
 * &stored, the address of its own local. */
static int shm_mode_read(const char *path, mode_t *mode) __attribute__((nonnull(2)));
static int shm_mode_read(const char *path, mode_t *mode)
{
	char *modepath = shm_mode_path(path);
	unsigned char value[4];
	int fd, result = 0, saved;

	if (!modepath) return 0;
	fd = open(modepath, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (read(fd, value, sizeof value) == sizeof value) {
			*mode = (mode_t)((unsigned)value[0] | (unsigned)value[1] << 8 |
			                 (unsigned)value[2] << 16 | (unsigned)value[3] << 24);
			result = 1;
		}
		saved = errno;
		(void)close(fd);
		errno = saved;
	}
	saved = errno;
	free(modepath);
	errno = saved;
	return result;
}

static void shm_mode_unlink(const char *path)
{
	char *modepath = shm_mode_path(path);
	int saved = errno;
	if (modepath) {
		(void)unlink(modepath);
		free(modepath);
	}
	errno = saved;
}

int shm_open(const char *name, int oflag, mode_t mode)
{
	char *path;
	int fd, saved, created = 0, have_stored = 0;
	int access = oflag & O_ACCMODE;
	mode_t stored = 0;

	if ((oflag & ~(O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC)) ||
	    (access != O_RDONLY && access != O_RDWR)) {
		errno = EINVAL;
		return -1;
	}
	path = shm_path(name);
	if (!path) return -1;
	if (ensure_namespace(path) < 0) { free(path); return -1; }

	/* O_CREAT without O_EXCL must still distinguish new from existing --
	 * POSIX applies mode only to the former -- so try an atomic create
	 * first and fall back to opening the existing object. */
	if ((oflag & O_CREAT) && !(oflag & O_EXCL)) {
		fd = open(path, oflag | O_EXCL | O_CLOEXEC, mode);
		if (fd >= 0) created = 1;
		else if (errno == EEXIST)
			fd = open(path, (oflag & ~(O_CREAT | O_EXCL)) | O_CLOEXEC, mode);
	} else {
		fd = open(path, oflag | O_CLOEXEC, mode);
		created = fd >= 0 && (oflag & O_CREAT);
	}
	if (fd >= 0 && created) {
		stored = mode & ~__umask_get() & 07777;
		if (shm_mode_write(path, stored) < 0) {
			saved = errno;
			(void)close(fd);
			(void)unlink(path);
			free(path);
			errno = saved;
			return -1;
		}
		have_stored = 1;
	} else if (fd >= 0) {
		have_stored = shm_mode_read(path, &stored);
	}
	if (fd >= 0 && have_stored) {
		struct __fd *f = __fd_get(fd);
		if (f) {
			f->shm_mode = (unsigned short)stored;
			f->shm_mode_valid = 1;
		}
	}
	saved = errno;
	free(path);
	errno = saved;
	return fd;
}

static unsigned tombstone_serial;

/* Windows before POSIX disposition support, and Wine even when it accepts
 * the information class, cannot delete a file backing a live section.
 * Renaming satisfies shm_unlink()'s namespace contract instead: existing
 * mappings keep the same file object, and a later shm_open() of the
 * original name sees nothing. The tombstone's own unlink usually succeeds
 * immediately after; if not, the orphaned private name is harmless.
 *
 * PID+TID+serial make collisions non-routine; a collision with a
 * still-mapped tombstone just fails rename(), so the next serial is tried
 * rather than replacing a live object's last name. */
static int rename_mapped_away(const char *path)
{
	static const char stem[] = ".ntlibc-shm-deleted-";
	const char *slash = strrchr(path, '/');
	size_t dirlen = slash ? (size_t)(slash - path + 1) : 0;
	size_t size = dirlen + sizeof stem + 8 + 1 + 8 + 1 + 8;
	char *dead = malloc(size);
	int saved = errno;
	unsigned attempt;

	if (!dead) return -1;
	if (dirlen > INT_MAX) { free(dead); errno = ENAMETOOLONG; return -1; }
	for (attempt = 0; attempt < 32; attempt++) {
		unsigned serial = ++tombstone_serial;
		int n = snprintf(dead, size, "%.*s%s%08x-%08x-%08x",
		         (int)dirlen, path, stem, (unsigned)getpid(),
		         (unsigned)gettid(), serial);
		if (n < 0 || (size_t)n >= size) {
			int e = n < 0 ? errno : ENAMETOOLONG;
			free(dead);
			errno = e;
			return -1;
		}
		if (rename(path, dead) == 0) {
			/* A live section may block this cleanup unlink; the
			 * namespace operation already succeeded, so that isn't
			 * a shm_unlink() failure. */
			(void)unlink(dead);
			free(dead);
			errno = saved;
			return 0;
		}
	}
	saved = errno;
	free(dead);
	errno = saved;
	return -1;
}

int shm_unlink(const char *name)
{
	char *path = shm_path(name);
	int result, saved;

	if (!path) return -1;
	result = unlink(path);
	if (result < 0 && (errno == EACCES || errno == EBUSY))
		result = rename_mapped_away(path);
	if (result == 0) shm_mode_unlink(path);
	saved = errno;
	free(path);
	errno = saved;
	return result;
}
