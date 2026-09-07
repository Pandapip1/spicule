/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-directory interface src/dirent/{readdir,getdents}.c's
 * POSIX-facing front doors call into instead of a raw
 * NtQueryDirectoryFile/getdents64(2) call.  See src/dirent/nt/
 * plat_dirent.c and src/dirent/linux/plat_dirent.c for the two
 * implementations this declares.
 *
 * This is the redesign this header's own banner used to say was out of
 * scope ("re-deriving a backend-neutral record shape here would be a
 * bigger redesign than this seam is scoped to make") -- now done, in
 * the smallest shape that unblocks a real Linux backend: __plat_dir_read()
 * itself is UNCHANGED (still hands back the backend's own raw bytes,
 * still hides only the syscall and its status handling -- see its own
 * comment below), and one new function, __plat_dir_decode_one(), is
 * added alongside it to decode a single record out of a buffer
 * __plat_dir_read() already filled into a POSIX-neutral shape
 * (`struct __dirent_raw`) that src/dirent/readdir.c's __dirstream_next()
 * and src/dirent/getdents.c's getdents() both now go through instead of
 * hardcoding FILE_ID_BOTH_DIR_INFORMATION themselves. The raw buffer
 * format `buf` holds between the two calls is still entirely the
 * backend's own business (NT: FILE_ID_BOTH_DIR_INFORMATION records
 * chained by NextEntryOffset; Linux: linux_dirent64 records chained by
 * d_reclen) -- nothing outside a backend's own plat_dirent.c ever looks
 * at those bytes directly anymore. */
#ifndef _SPICULE_PLAT_DIRENT_H
#define _SPICULE_PLAT_DIRENT_H

#include <stddef.h>
#include <sys/types.h>
#include "plat_handle.h"

/* Fill `buf` (`bufsize` bytes) with the next batch of raw directory
 * records from `h`'s own enumeration cursor.  `restart` asks the
 * backend to rewind to the first entry (rewinddir()'s effect) instead
 * of continuing from wherever the last call left off.  Returns the
 * number of bytes filled (> 0), 0 at end-of-directory, or -1 with
 * errno set. */
ssize_t __plat_dir_read(__plat_handle_t h, void *buf, size_t bufsize, int restart);

/* One directory entry, decoded out of a backend's own raw record shape
 * into a POSIX-neutral form every front door can read without knowing
 * which backend filled the buffer.  `type` is a DT_* value using the
 * same numeric convention dirent.h's own DT_* constants (and this
 * library's internal duplicates, src/dirent/dirent_internal.h's
 * __DT_*) use -- POSIX/glibc/Linux-kernel values, not anything
 * NT-specific; NT's backend computes it from FileAttributes, Linux's
 * backend already gets it as exactly this from the kernel and copies it
 * straight through (see that backend's own comment). `name` is always
 * NUL-terminated; 256 (NAME_MAX+1) is enough for every name either
 * backend can produce, matching struct dirent's own d_name[256]. */
struct __dirent_raw {
	ino_t ino;
	unsigned char type;
	char name[256];
};

/* Decodes the one record starting at byte offset *pos within `buf`
 * (`buflen` bytes, exactly as filled by a single __plat_dir_read()
 * call), filling *out and advancing *pos past the record on success
 * (returns 1).  Returns 0 if there is no record left at or past *pos in
 * this buffer -- end of what this fill produced, not end of the
 * directory -- meaning the caller should refill via another
 * __plat_dir_read() and resume decoding from *pos = 0 there.  No error
 * return: a buffer __plat_dir_read() itself already validated is
 * trusted the same way the rest of this backend already trusts
 * kernel-produced data (see e.g. src/dirent/nt/plat_dirent.c's own
 * comment on NtQueryDirectoryFile's guarantees). */
/* pos is required: both backends' own bodies (src/dirent/linux/
 * plat_dirent.c, src/dirent/nt/plat_dirent.c) dereference it
 * unconditionally, first statement (`if (*pos >= buflen) return 0;`).
 *
 * buf and out are now verified required too (the earlier, separate
 * pass this comment used to defer them to): once the `*pos >= buflen`
 * check passes, both backends unconditionally `memset(out, 0, sizeof
 * *out)` and then dereference a record pointer computed from `buf +
 * *pos` (`d->d_ino`/`fi->FileId`), with no further guard of either
 * pointer's own nullness. Both real call sites, in both callers, pass
 * an always-valid pointer: src/dirent/readdir.c's __dirstream_next()
 * passes dp->buf (checked once, for real, at allocation time --
 * src/dirent/opendir.c's alloc_dir(): `dp->buf = __malloc(...); if
 * (!dp->buf) { ...; return 0; }` -- so any DIR handle that ever
 * reaches a public call is one whose buf survived that check) and its
 * own out parameter (itself already required, nonnull(2) above);
 * src/dirent/getdents.c passes a fixed-size on-stack array (`unsigned
 * char buf[8192]`, whose address can never be NULL) and `&r`, a local
 * struct's address. */
int __plat_dir_decode_one(const void *buf, size_t buflen, size_t *pos, struct __dirent_raw *out)
    __attribute__((nonnull(1, 3, 4)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
