/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * flock(): see include/sys/file.h for the design writeup (including why
 * NT's shared byte-range lock space is mandatory rather than advisory).
 *
 * Always locks the whole file, byte 0 through LARGE_INTEGER's max
 * (0x7fffffffffffffff), not "however many bytes the file is today":
 * flock()'s open-file-description lock must still apply after the file
 * grows, and LockFile() explicitly supports locking beyond current EOF
 * for exactly this purpose.
 *
 * LOCK_SH<->LOCK_EX conversion has no atomic primitive on NT, so it's
 * unlock-then-relock. Two Wine bugs were found empirically (reproduced
 * with raw NtLockFile()/NtUnlockFile() calls, confirmed as Wine's and
 * not this file's): (1) NtUnlockFile() on a never-locked range wedges
 * the entire wineserver instead of returning STATUS_RANGE_NOT_LOCKED —
 * worked around by never unlocking unless lockstate[] confirms a lock
 * is actually held; (2) unlock-then-relock with the opposite exclusivity
 * on the same fd deadlocks the second NtLockFile() call, with no known
 * workaround (test/posix-termios.c avoids exercising an actual type
 * change for this reason). A third, non-deterministic issue — the same
 * lock/unlock pair sometimes returning STATUS_NOT_IMPLEMENTED from the
 * unlock under concurrent wine load — is why test/posix-termios.c
 * treats flock() failure as a note rather than a hard assertion.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/file.h>
#include <errno.h>
#include "libc.h"
#include "plat_flock.h"

static struct { __plat_handle_t h; unsigned char held; unsigned char exclusive; } lockstate[FD_MAX];

int flock(int fd, int op) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	int want_exclusive;

	if (!f) return -1;
	if (fd < 0 || fd >= FD_MAX) { errno = EBADF; return -1; }
	if (lockstate[fd].held && lockstate[fd].h != f->h) lockstate[fd].held = 0;

	switch (op & ~LOCK_NB) {
	case LOCK_SH:
	case LOCK_EX:
		want_exclusive = (op & ~LOCK_NB) == LOCK_EX;
		if (lockstate[fd].held && lockstate[fd].exclusive == want_exclusive) return 0;   /* already exactly this */
		if (lockstate[fd].held) {
			__plat_flock_unlock(f->h);
			lockstate[fd].held = 0;
		}
		if (__plat_flock_lock(f->h, op & LOCK_NB, want_exclusive) < 0) return -1;
		lockstate[fd].h = f->h;
		lockstate[fd].held = 1;
		lockstate[fd].exclusive = (unsigned char)want_exclusive;
		return 0;
	case LOCK_UN:
		if (lockstate[fd].held) {
			int r = __plat_flock_unlock(f->h);
			lockstate[fd].held = 0;
			if (r < 0) return -1;
		}
		/* Nothing held by this fd (never locked, or already
		 * unlocked): flock(2) DESCRIPTION does not document this as
		 * an error on any platform, so a plain success matches every
		 * other implementation's behaviour -- and avoids landmine
		 * (1) above entirely. */
		return 0;
	default:
		errno = EINVAL;
		return -1;
	}
}

// NOLINTEND(misc-include-cleaner)
