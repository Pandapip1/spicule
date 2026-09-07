/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The real shape of DIR, private to this directory.  dirent.h only
 * forward-declares "struct __dirstream" so that programs carry it around
 * as an opaque pointer; here it is given a body.
 *
 * A DIR is backend-neutral: the directory HANDLE (via the fd table,
 * which is what makes dirfd() and fdopendir() free), a bufferful of the
 * backend's most recent raw answer (opaque bytes -- see
 * src/internal/plat_dirent.h; NT: NtQueryDirectoryFile's
 * FILE_ID_BOTH_DIR_INFORMATION records, Linux: getdents64(2)'s
 * linux_dirent64 records), and a cursor into it. Nothing here parses
 * those bytes itself; __dirstream_next() below decodes one record at a
 * time via __plat_dir_decode_one(), which is the only thing that knows
 * either backend's actual record shape.
 *
 * "." and ".." arrive as ordinary records straight from the backend on
 * both NT (confirmed against Wine/NT rather than assumed -- an earlier
 * version of this file synthesized them itself and ended up with each
 * doubled) and Linux (getdents64(2) always includes them); nothing here
 * treats them specially except that a fresh handle naturally starts
 * there.
 *
 * telldir()/seekdir() have no kernel-backed byte offset to report on
 * either backend: NT's cursor is opaque and internal to the handle, and
 * while a raw Linux fd offset from lseek(fd, 0, SEEK_CUR) DOES exist for
 * a real directory fd, using it here would be backend-specific and this
 * type is deliberately not. What is used instead is simply a count of
 * entries returned so far ("tell" below, and each dirent's d_off once it
 * has been returned).  seekdir() to a location behind where the stream
 * currently is rewinds and replays; a location ahead is reached by
 * discarding entries.  This is observably correct (seekdir(dp,
 * telldir(dp)) is a no-op, and seeking to a value obtained from an
 * earlier telldir() on the same DIR reproduces that position) but is
 * O(n) rather than O(1), and is not meaningful across different DIR
 * streams over the same directory the way a Linux fd offset can be.
 */
#ifndef _SPICULE_DIRENT_INTERNAL_H
#define _SPICULE_DIRENT_INTERNAL_H

#include <dirent.h>
#include "libc.h"
#include "plat_dirent.h"

/* One __plat_dir_read() call's worth of raw backend records.  Large
 * enough that most directories are read in one call. */
#define __DIRBUF_SIZE 32768

struct __dirstream {
	int fd;                 /* the __FD_DIR slot backing this stream */
	unsigned char *buf;     /* __DIRBUF_SIZE bytes of raw backend records */
	size_t bufpos;          /* byte offset in buf of the next unread record */
	size_t buflen;          /* bytes of buf holding real records; 0 = empty */
	int restart;            /* ask the backend to rewind on the next fill */
	int done;                /* the backend reported end-of-directory */
	long tell;                 /* entries returned so far; telldir()'s value */
	unsigned char vseen;       /* mandatory native-overlay entries observed */
	unsigned char vnext;       /* next missing mandatory entry to consider */
	struct dirent ent;          /* storage readdir() returns a pointer into */
};

/* dirent.h's DT_* are only visible under _GNU_SOURCE/_BSD_SOURCE, but the
 * type has to be computed unconditionally inside the library; these are
 * the same numeric values, duplicated so no feature-test macro is needed
 * just to implement readdir() itself. */
#define __DT_DIR 4
#define __DT_CHR 2
#define __DT_LNK 10
#define __DT_REG 8

static inline int __dirent_ascii_casecmp(const char *a, const char *b) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	for (;;) {
		unsigned char ac = (unsigned char)*a++, bc = (unsigned char)*b++;
		if (ac >= 'A' && ac <= 'Z') ac += 'a' - 'A';
		if (bc >= 'A' && bc <= 'Z') bc += 'a' - 'A';
		if (ac != bc || !ac) return ac - bc;
	}
}

static inline unsigned char __vfs_mandatory_count(int kind)
{
	return kind == __VFS_ROOT ? 1 : kind == __VFS_DEV ? 3 : 0;
}

static inline const char *__vfs_mandatory_name(int kind, int index)
{
	static const char *const root[] = { "dev" };
	static const char *const dev[] = { "console", "null", "tty" };
	return kind == __VFS_ROOT ? root[index] : dev[index];
}

static inline int __vfs_mandatory_kind(int kind, int index)
{
	return kind == __VFS_ROOT ? __VFS_DEV : __VFS_CONSOLE + index;
}

static inline unsigned __vfs_mandatory_seen(int kind, const char *name)
{
	int i, n = __vfs_mandatory_count(kind);
	for (i = 0; i < n; i++)
		if (!__dirent_ascii_casecmp(name, __vfs_mandatory_name(kind, i))) return 1u << i;
	return 0;
}

/* The next decoded record from dp's raw backend buffer, refilling via
 * __plat_dir_read() as needed and decoding via __plat_dir_decode_one()
 * (src/internal/plat_dirent.h). Fills *out and returns 1, or returns 0
 * at end-of-directory (dp->done is then true) or on error (errno set by
 * the backend). */
/* dp is the same required, non-optional DIR * handle as every public
 * function in this family (see include/dirent.h's own comment) -- every
 * caller in this tree (readdir.c's fill()) already holds one proven
 * nonnull by its own caller's contract, and this function dereferences
 * it unconditionally itself. out is likewise never optional: its one
 * caller always passes the address of a real local (`struct __dirent_raw
 * r; ... __dirstream_next(dp, &r)`), never NULL, and NULL would be
 * meaningless here anyway (there is no "discard the record" mode -- the
 * return value alone already says whether one was found). */
int __dirstream_next(DIR *dp, struct __dirent_raw *out)
    __attribute__((nonnull(1, 2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
