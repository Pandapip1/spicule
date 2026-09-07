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
 * no native named-pipe object that maps onto POSIX FIFO semantics the
 * way NTFS reparse points map onto symlinks, so every operand here fails
 * with a real "Function not implemented" diagnostic rather than a
 * silent, fake success -- exactly the "propagate the stub honestly"
 * requirement this utility exists to prove, not an oversight.  -m's
 * mode string is still parsed and validated before that call, so a
 * malformed -m argument is reported as such (a usage error) rather than
 * being swallowed by the ENOSYS from mkfifo() itself.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
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
#include "ownership_stubs.h" /* __ownership_pointer_nonnull(): restates argv[i]'s nonnull-ness where AggregateElementToken proves only its NUL-termination */

int __util_mkfifo_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, fail = 0;
	const char *mode_spec = 0;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

	i = 1;
	while (i < argc) {
		/* argv's own elements_withtok(null_terminated, argc) proves
		 * every element up to argc has a reachable NUL, but not that
		 * the element pointer itself is nonnull -- genuinely true
		 * (main()'s argv[0..argc-1] are never NULL), just not a fact
		 * an array-element read can carry across to ValidPointer. */
		__ownership_pointer_nonnull(argv[i]);
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
