/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * telldir/seekdir: dp->tell is a plain count of entries returned, not a
 * kernel offset (see dirent_internal.h). Seeking backward rewinds and
 * replays; seeking forward just discards entries, like glibc when its
 * cached-offset trick doesn't apply. A location past the end of the
 * directory stops where readdir() does; telldir() then reports that.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "dirent_internal.h"

long telldir(DIR *dp)
{
	return dp->tell;
}

void seekdir(DIR *dp, long loc)
{
	unsigned long remaining;

	if (loc < 0) return;
	if (loc < dp->tell) rewinddir(dp);
	remaining = (unsigned long)loc - (unsigned long)dp->tell;
	while (remaining > 0 && dp->tell < loc) {
		remaining--;
		if (!readdir(dp)) break;
	}
}

// NOLINTEND(misc-include-cleaner)
