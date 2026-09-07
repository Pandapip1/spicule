/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * closedir mirrors close(): the fd table owns the HANDLE, this just
 * releases the fd slot through the usual path and then the DIR itself.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include "dirent_internal.h"

int closedir(DIR *dp consume(directory_stream_open))
{
	int r = close(dp->fd);
	__free(dp);
	return r;
}

// NOLINTEND(misc-include-cleaner)
