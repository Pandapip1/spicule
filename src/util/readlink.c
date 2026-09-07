/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * readlink -- not an XCU mandatory utility (POSIX.1-2017 has no
 * readlink(1p) page at all), but this project's own POSIX-utilities plan
 * folds it into the same filesystem tier as pwd/basename/dirname because
 * removing the bootstrap chain's dependency on external tools needs it
 * just as much as anything XCU does mandate: `readlink` is how a
 * bootstrap script resolves a symlink without a real coreutils around.
 * This implements the common case every BSD/GNU readlink(1) agrees on:
 * `readlink path...` prints each path's raw symlink target, one per
 * line, via the readlink() library call (src/unistd/link.c) -- no -f/-e/
 * -m canonicalization, which is realpath(1)'s job (src/util/realpath.c),
 * not this one's.
 *
 * Multiple operands are each processed in turn rather than stopping at
 * the first failure -- consistent with realpath's own choice (see that
 * file's comment) and with not silently discarding the operands after a
 * bad one.  A path that is not a symbolic link, or does not exist,
 * fails the whole invocation (nonzero exit) but does not stop the
 * remaining operands from being tried and printed.
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
		/* readlink() "shall not append a NUL character": buf[n] is the
		 * first byte past what it wrote, always in bounds since n is
		 * bounded by "sizeof buf - 1" above. Left open as an
		 * ntlibc.ValidPointer finding: that bound is readlink()'s own
		 * POSIX contract on its own third argument ("return value <=
		 * bufsiz"), and this vocabulary has no annotation for a
		 * return value bounded by a parameter (unlike, say,
		 * endptr_advances for strtol()'s different contract shape) --
		 * a real checker/vocabulary gap, not a bug here. */
		buf[n] = 0;
		if (fputs(buf, stdout) < 0 || fputc('\n', stdout) == EOF) status = 1;
	}
	if (fflush(stdout) != 0) status = 1;
	return status;
}
