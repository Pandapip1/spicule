/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * readlink -- not an XCU mandatory utility, but part of this project's
 * POSIX-utilities filesystem tier: needed to resolve a symlink during
 * bootstrap without a real coreutils around. Implements the common case
 * every BSD/GNU readlink(1) agrees on: `readlink path...` prints each
 * path's raw symlink target, one per line, via readlink()
 * (src/unistd/link.c) -- no -f/-e/-m canonicalization, which is
 * realpath(1)'s job (src/util/realpath.c), not this one's.
 *
 * Multiple operands are each tried in turn rather than stopping at the
 * first failure (consistent with realpath's own choice). A path that is
 * not a symlink, or doesn't exist, fails the invocation (nonzero exit)
 * but doesn't stop remaining operands from being tried and printed.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include "util.h"

int __util_readlink_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, status = 0;

	if (argc < 2) {
		__util_diagf("readlink: missing operand\n");
		return 2;
	}

	for (i = 1; i < argc; i++) {
		char buf[PATH_MAX];
		ssize_t n = readlink(argv[i], buf, sizeof buf - 1);
		if (n < 0) {
			__util_diagf("readlink: %s: %s\n", argv[i], strerror(errno));
			status = 1;
			continue;
		}
		/* readlink() doesn't NUL-terminate: buf[n] is the first byte
		 * past what it wrote, in bounds since n <= "sizeof buf - 1"
		 * per readlink()'s own contract. Left open as an
		 * ntlibc.ValidPointer finding: no annotation exists for a
		 * return value bounded by a parameter (unlike, say,
		 * endptr_advances for strtol()) -- a vocabulary gap, not a
		 * bug. */
		buf[n] = 0;
		if (fputs(buf, stdout) < 0 || fputc('\n', stdout) == EOF) status = 1;
	}
	if (fflush(stdout) != 0) status = 1;
	return status;
}
