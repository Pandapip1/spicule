/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * fseek/ftell and friends.  The FILE's own idea of its position is the
 * fd's (or memory block's) position adjusted by whatever is sitting in
 * the buffer: subtract unread look-ahead bytes when reading, add
 * unwritten ones when writing.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include "stdio_impl.h"

int fseeko(FILE *f, off_t off, int whence)
{
	long long r;
	if (f->wpos && __fflush_locked(f) < 0) return -1;
	if (whence == SEEK_CUR) {
		size_t adjust = f->rend - f->rpos;
		if (adjust > SIZE_MAX - (size_t)f->nunget) {
			errno = EOVERFLOW;
			return -1;
		}
		adjust += (size_t)f->nunget;
		if (adjust > (size_t)LLONG_MAX || off < LLONG_MIN + (off_t)adjust) {
			errno = EOVERFLOW;
			return -1;
		}
		off -= (off_t)adjust;
	}
	/* Seek first, discard the buffered read-ahead only once it succeeds:
	 * on failure the offset must remain unchanged, and ftello() needs the
	 * unread buffer contents to reconstruct the logical position. */
	r = __file_seek(f, off, whence);
	if (r < 0) return -1;
	f->rpos = f->rend = 0;
	f->nunget = 0;
	f->nwunget = 0;
	f->eof = 0;
	return 0;
}

int fseek(FILE *f, long off, int whence) { return fseeko(f, (off_t)off, whence); }

off_t ftello(FILE *f)
{
	long long pos = __file_seek(f, 0, SEEK_CUR);
	size_t unread;
	if (pos < 0) return -1;
	/* The buffer is never both a read and a write buffer at once, so
	 * whichever of these is nonzero is the one that applies; on a "w+"
	 * or "r+" stream either may be, so test the buffer, not the mode. */
	unread = f->rend - f->rpos;
	if (unread > SIZE_MAX - (size_t)f->nunget) {
		errno = EOVERFLOW;
		return -1;
	}
	unread += (size_t)f->nunget;
	if (unread > (size_t)pos) {
		errno = EOVERFLOW;
		return -1;
	}
	pos -= (long long)unread;
	if (f->wpos > (size_t)(LLONG_MAX - pos)) {
		errno = EOVERFLOW;
		return -1;
	}
	pos += (long long)f->wpos;
	return (off_t)pos;
}

long ftell(FILE *f)
{
	off_t o = ftello(f);
	return (long)o;
}

void rewind(FILE *f)
{
	fseeko(f, 0, SEEK_SET);
	f->err = 0;
}

int fgetpos(FILE *__restrict f, fpos_t *__restrict pos)
{
	off_t o = ftello(f);
	if (o < 0) return -1;
	pos->__lldata = o;
	return 0;
}

int fsetpos(FILE *f, const fpos_t *pos)
{
	return fseeko(f, (off_t)pos->__lldata, SEEK_SET);
}

// NOLINTEND(misc-include-cleaner)
