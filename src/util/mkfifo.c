/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * mkfifo(1p): `mkfifo [-m mode] file...`
 *
 * OPTIONS:
 *  -m mode  "Set the file permission bits of the newly-created FIFO to
 *            the specified mode value.  The mode option-argument shall
 *            be the same as the mode operand defined for the chmod
 *            utility.  In the symbolic_mode strings, the op characters
 *            '+' and '-' shall be interpreted relative to an assumed
 *            initial mode of a=rw." -- note a=rw, not mkdir(1p)'s a=rwx:
 *            a FIFO is not executable by default.
 *
 * EXIT STATUS: "0 All the specified FIFO special files were created
 * successfully." ">0 An error occurred." -- diagnose-and-continue, same
 * shape as src/util/mkdir_util.c and src/util/rmdir.c.
 *
 * This tree's mkfifo() (src/stat/chmod.c) is a real ENOSYS stub: NT has
 * no native named-pipe object mapping onto POSIX FIFO semantics (unlike
 * NTFS reparse points for symlinks), so every operand fails with a real
 * "Function not implemented" rather than a fake success. -m's mode
 * string is still parsed and validated first, so a malformed argument
 * is reported as a usage error, not swallowed by mkfifo()'s ENOSYS.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include "libc.h"
#include "util.h"
#include "modeparse.h"

int __util_mkfifo_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, fail = 0;
	const char *mode_spec = 0;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

	i = 1;
	while (i < argc) {
		if (argv[i][0] != '-' || !argv[i][1]) break;
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-m")) {
			if (i + 1 >= argc) {
				__util_diagf("mkfifo: -m: option requires an argument\n");
				return 1;
			}
			mode_spec = argv[++i];
			i++;
			continue;
		}
		__util_diagf("mkfifo: %s: invalid option\n", argv[i]);
		return 1;
	}
	if (i >= argc) {
		__util_diagf("mkfifo: missing operand\n");
		return 1;
	}

	if (mode_spec) {
		/* "-m mode ... relative to an assumed initial mode of a=rw" */
		if (__util_parse_mode("mkfifo", mode_spec, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
		                      (mode_t)__umask_get(), &mode) < 0)
			return 1;
	}

	for (; i < argc; i++) {
		if (mkfifo(argv[i], mode) != 0) {
			__util_diagf("mkfifo: %s: %s\n", argv[i], strerror(errno));
			fail = 1;
		}
	}
	return fail;
}

// NOLINTEND(misc-include-cleaner)
