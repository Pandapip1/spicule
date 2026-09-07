/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * df(1p): "The df utility shall write the amount of available space and
 * file slots for file systems on which the invoking user has appropriate
 * read access."
 *
 * All the real filesystem-space querying is statvfs()/fstatvfs()
 * (src/stat/statvfs.c, backed by NtQueryVolumeInformationFile -- see that
 * file's own banner for exactly which struct statvfs fields NT can
 * populate and which it cannot).  Nothing here reimplements any of that;
 * this file is purely command-line parsing, block-size arithmetic and
 * the report table.
 *
 * ---- OPTIONS implemented -----------------------------------------------
 *
 *  -k  "Write the information using a 1024-byte block ..." -- the one
 *      concrete unit df(1p) itself names.
 *
 * Without -k, df(1p)'s DESCRIPTION only ever says block counts are
 * written "in units of 512-byte blocks" *for -k's absence to be
 * contrasted against*; the base utility text does not fix a default unit
 * at all (unlike e.g. -k, which is explicit).  512 is picked here as the
 * default because it is the traditional, portable default block size
 * this project's own test.c/pathchk.c precedent of "state a real
 * ambiguity rather than hide it" calls for spelling out plainly: this is
 * a deliberate choice among conforming ones, not the one true unimplied
 * default.
 *
 * ---- file/directory operands --------------------------------------------
 *
 * "If a file operand is specified, ... the file system containing the
 * file shall be reported."  Implemented directly: statvfs(operand)
 * already reports the filesystem *containing* the given path whether
 * that path names a file, a directory, or anything else statvfs() will
 * resolve -- there is no need to special-case "operand is a directory"
 * vs. "operand is a file" the way du(1p) does, because statvfs() itself
 * already answers "which filesystem is this path on", not "how much
 * space does this path itself use".
 *
 * ---- the "no operands: report on all mounted file systems" case --------
 *
 * DESCRIPTION: "If no file operands are specified, ... shall write
 * information for all mounted file systems."  There is no NT-native
 * concept of "all mounted file systems" this tree can enumerate: POSIX's
 * own model (a single global namespace with a fixed source of mount
 * records, /etc/mtab or getmntent()) has no counterpart here, and
 * inventing one -- walking drive letters A: through Z: and probing each,
 * say -- would silently fabricate a filesystem list whose completeness
 * this code cannot actually vouch for (removable/disconnected drives,
 * UNC shares, subst'd drives...).  Rather than fake that list, the
 * no-operand case here is narrowed to the *one* filesystem this process
 * definitely has a real, unambiguous handle on without inventing
 * anything: the one containing the current working directory ("."),
 * exactly as if "." had been given as the sole operand.  This is a real,
 * disclosable gap against the standard's own "all mounted file systems"
 * text, stated here rather than hidden behind a plausible-looking table
 * with rows that were never actually verified to exist.
 *
 * ---- the "Filesystem" and "Mounted on" columns --------------------------
 *
 * POSIX's own suggested STDOUT format names a "Filesystem" column (the
 * special file / device the filesystem lives on) that has no equivalent
 * this tree can produce: NT reports a volume by serial number
 * (statvfs()'s own f_fsid, src/stat/statvfs.c), not a device pathname,
 * and there is no /dev-style block-device namespace to print instead.
 * The operand's own (resolved) path is printed in that column in its
 * place -- an honest "what did we query", not an invented device name --
 * and again under "Mounted on", since this platform has no separate
 * "device" vs. "mount point" pair the way POSIX's model does: the path
 * the caller gave *is* both, here.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include "util.h"

static int df_report(const char *path, unsigned long blocksize)
{
	struct statvfs vfs;
	uintmax_t total, avail, used, capacity_pct;

	if (statvfs(path, &vfs) != 0) {
		__util_diagf("df: %s: %s\n", path, strerror(errno));
		return -1;
	}

	/* f_frsize is the unit f_blocks/f_bfree/f_bavail are counted in
	 * (statvfs.html); convert to the caller's chosen report unit with
	 * ordinary integer block-count scaling rather than reporting bytes
	 * and dividing at print time, so a partial output block always
	 * rounds up like every other block-count report in this project
	 * (see du.c's identical reasoning). */
	total = (uintmax_t)vfs.f_blocks * vfs.f_frsize / blocksize;
	avail = (uintmax_t)vfs.f_bavail * vfs.f_frsize / blocksize;
	/* "Used" is total-minus-free (not total-minus-avail): free space a
	 * non-privileged process cannot use is still not *used* space. */
	used = (uintmax_t)(vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize / blocksize;

	/* Capacity: used / (used + avail) -- the traditional df definition,
	 * which is why it can exceed 100% when privileged-reserved space
	 * has been eaten into (used grows, avail does not, past the point
	 * where used+avail no longer equals total). */
	{
		uintmax_t denom = used + avail;
		capacity_pct = denom ? (used * 100 + denom - 1) / denom : 0;
	}

	printf("%-20s %10ju %10ju %10ju %8ju%% %s\n",
	       path, total, used, avail, capacity_pct, path);
	return 0;
}

int __util_df_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 1;
	unsigned long blocksize = 512;

	for (; i < argc; i++) {
		char *a = argv[i];
		/* a[0]: "pointer dereference is not proven nonnull" -- left
		 * open, same accepted class as the identical argv[i][0] access
		 * in src/util/du.c and friends (see that file's own comment). */
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-k")) { blocksize = 1024; continue; }
		__util_diagf("df: invalid option -- '%s'\n", a);
		return 1;
	}

	printf("%-20s %10s %10s %10s %9s %s\n",
	       "Filesystem", blocksize == 1024 ? "1024-blks" : "512-blocks",
	       "Used", "Available", "Capacity", "Mounted on");

	if (i >= argc) {
		/* No operands: see this file's header comment -- narrowed to
		 * the filesystem containing the current directory rather
		 * than a fabricated "all mounted file systems" list. */
		return df_report(".", blocksize) < 0 ? 1 : 0;
	}

	{
		int had_error = 0;
		for (; i < argc; i++)
			if (df_report(argv[i], blocksize) < 0) had_error = 1;
		return had_error ? 1 : 0;
	}
}
