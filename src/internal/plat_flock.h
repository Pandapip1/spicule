/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/file/flock.c's POSIX-facing front door
 * calls into instead of a raw NtLockFile/NtUnlockFile call.  See
 * src/file/nt/plat_flock.c for the implementation this declares.
 *
 * flock()'s own POSIX-conversion strategy -- always locking the whole
 * representable byte range rather than however many bytes the file is
 * today -- is this library's own choice of how to satisfy a whole-open-
 * file-description lock on a byte-range primitive, and stays in the
 * front door exactly like mman.c's reservation table (see plat_mem.h);
 * only the raw lock/unlock call and the Wine-specific IoStatusBlock
 * quirk it works around (see flock.c's own banner) live here.
 */
#ifndef _SPICULE_PLAT_FLOCK_H
#define _SPICULE_PLAT_FLOCK_H

#include "plat_handle.h"

/* Lock the entire representable byte range of `h`.  `nb` is LOCK_NB
 * (fail rather than block); `exclusive` selects LOCK_EX over LOCK_SH.
 * 0/-1(errno). */
int __plat_flock_lock(__plat_handle_t h, int nb, int exclusive);

/* Unlock the entire representable byte range of `h`.  0/-1(errno). */
int __plat_flock_unlock(__plat_handle_t h);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
