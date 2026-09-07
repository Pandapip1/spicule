/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getentropy(): fill a caller-given buffer with cryptographically strong
 * random bytes (BSD/glibc extension, not POSIX). NT has no entropy
 * source in ntdll; the real implementation needs bcrypt.dll's
 * BCryptGenRandom, so it's only real under SPICULE_USE_KERNEL32 (ENOSYS
 * otherwise) -- see src/unistd/nt/plat_unistd.c's __plat_getentropy().
 * Linux's is real unconditionally, via getrandom(2).
 *
 * getentropy(3): buflen > 256 is EIO. */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <errno.h>
#include "libc.h"
#include "plat_unistd.h"

int getentropy(void *buf, size_t buflen)
{
	if (buflen > 256) { errno = EIO; return -1; }
	return __plat_getentropy(buf, buflen);
}

// NOLINTEND(misc-include-cleaner)
