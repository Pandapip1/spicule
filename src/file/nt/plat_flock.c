/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_flock.h -- see that header
 * for the contract each function makes.  Everything here was, until
 * this file existed, inline inside src/file/flock.c's flock(); nothing
 * changed in substance, only location and the addition of a POSIX-
 * shaped return (0/-1 with errno set) in place of a raw NTSTATUS.
 *
 * IoStatusBlock on NtLockFile: try the real-NT-correct &io first, and
 * retry with NULL only if that specific call hard-fails
 * STATUS_NOT_IMPLEMENTED -- Wine's NtLockFile (dlls/ntdll/unix/file.c)
 * does exactly that whenever given a non-NULL IoStatusBlock
 * ("Unimplemented yet parameter"), confirmed against the environment
 * `make check` runs against. An earlier version of this file passed
 * NULL unconditionally to dodge that; see src/fcntl/nt/plat_fcntl.c's
 * __plat_lock_probe() for the windows-test failures on real Windows
 * that traded in for -- real NT requires an actual IoStatusBlock on
 * NtLockFile. NtUnlockFile has the opposite requirement (it
 * dereferences io_status unconditionally on every platform), so it
 * keeps &io below regardless.  See flock.c's own banner for the
 * fuller account of this and the other Wine landmines this file works
 * around.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "libc.h"
#include "plat_flock.h"

int __plat_flock_lock(__plat_handle_t h, int nb, int exclusive)
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER off = 0;
	LARGE_INTEGER len = 0x7fffffffffffffffLL;
	NTSTATUS st = NtLockFile(h, 0, 0, 0, &io, &off, &len, 0, nb ? 1 : 0, exclusive);
	if (st == STATUS_NOT_IMPLEMENTED)
		st = NtLockFile(h, 0, 0, 0, 0, &off, &len, 0, nb ? 1 : 0, exclusive);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_flock_unlock(__plat_handle_t h)
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER off = 0;
	LARGE_INTEGER len = 0x7fffffffffffffffLL;
	NTSTATUS st = NtUnlockFile(h, &io, &off, &len, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

// NOLINTEND(misc-include-cleaner)
