/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/stdio/misc.c's renameat() calls into,
 * instead of raw Nt{OpenFile,QueryInformationFile,SetInformationFile,
 * Close} calls.  See src/stdio/nt/plat_stdio.c for the NT
 * implementation, src/stdio/linux/plat_stdio.c for the Linux one.
 *
 * This used to be three functions taking `struct __ntpath *` directly
 * (an already-NT-resolved path), on the reasoning that "there is no
 * POSIX-shaped alternative to hand it as" -- the same reasoning
 * src/internal/plat_fcntl.h gave for open()'s __plat_create_file()
 * before that turned out to be wrong (see plat_fcntl.h's own updated
 * banner and commit ce4763c): a raw, unresolved path IS the POSIX-
 * shaped alternative, and each backend resolves it however it needs
 * to. __plat_rename() below takes the raw (olddirfd, old, newdirfd,
 * new) tuple src/stdio/misc.c's renameat() front door already has,
 * and the NT-specific resolution/attribute-query/rename-set sequence
 * (previously split across __plat_rename_open_old()/
 * __plat_query_new_attrs()/__plat_rename_set(), plus the front door's
 * own isdir_attrs()/ntpath_is_ancestor() helpers) moved into
 * src/stdio/nt/plat_stdio.c's own __plat_rename() body as one unit,
 * the same relocation shape as __plat_open().
 *
 * ntpath_is_ancestor()'s job -- refusing to rename a directory into
 * its own descendant -- has no portable form worth writing: Linux's
 * real renameat(2) already refuses this itself (EINVAL), so a Linux
 * backend needs no equivalent check at all, only the NT backend still
 * needs its own NT-path-buffer-comparing version (moved in unchanged).
 */
#ifndef _SPICULE_PLAT_STDIO_H
#define _SPICULE_PLAT_STDIO_H

/* Rename `old` (relative to `olddirfd`) to `new` (relative to
 * `newdirfd`) -- POSIX rename(2)/renameat(2) semantics exactly
 * (atomic, replaces an existing `new` subject to the same-type rules
 * rename.html's ERRORS describes: EISDIR/ENOTEMPTY/ENOTDIR when old/
 * new disagree on directory-ness, EXDEV across devices, EINVAL for a
 * dot/dot-dot final component or old being an ancestor of new).
 * 0/-1(errno). */
int __plat_rename(int olddirfd, const char *old, int newdirfd, const char *new);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
