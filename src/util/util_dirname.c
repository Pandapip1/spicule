/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named util_dirname.c, not dirname.c: same tcc-`ar` 15-byte member-name
 * collision with src/misc/dirname.c that src/util/util_basename.c's
 * header explains in full -- the util_ prefix is the whole fix, the
 * exported symbol is still __util_dirname_main().
 *
 * dirname(1p).  SYNOPSIS: "dirname string" -- exactly one operand, no
 * options.  STDOUT: "%s\n", <resulting string>.  The directory-portion
 * logic is dirname() (src/misc/dirname.c), which shares basename()'s
 * contract (src/util/util_basename.c's own comment): non-const `char *`,
 * mutated in place, argv[1] passed straight through since nothing here
 * reads it again.
 */
#include <stdio.h>
#include <libgen.h>
#include "util.h"

int __util_dirname_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	if (argc != 2) {
		__util_diagf("dirname: usage: dirname string\n");
		return 2;
	}
	if (fputs(dirname(argv[1]), stdout) < 0 || fputc('\n', stdout) == EOF) return 1;
	return fflush(stdout) == 0 ? 0 : 1;
}
