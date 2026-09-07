/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * rmdir(1p): `rmdir [-p] dir...`
 *
 * OPTIONS -p: "Remove all directories in a pathname" -- after removing
 * `dir` itself, repeat with `dirname dir` (recursive by construction:
 * dirname of a multi-component path is itself a path -p can be
 * re-applied to). The standard doesn't say what happens when an
 * ancestor's rmdir() fails because it's not empty; every real
 * implementation treats that as the expected silent stop and reserves
 * the diagnostic for any other failure, which is the distinction
 * rmdir_ascend() implements below.
 *
 * EXIT STATUS: diagnose-and-continue loop, same shape as
 * src/util/mkdir_util.c.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <unistd.h>
#include "util.h"
#include "ownership_stubs.h"

/* Ascends from `dir` (already removed by the caller) via dirname(),
 * rmdir()-ing each ancestor until one is not empty (quiet stop), the
 * root is reached (dirname() stops shortening -- also a quiet stop), or
 * a real error occurs (diagnosed, nonzero return). */
static int rmdir_ascend(const char *dir)
{
	char buf[PATH_MAX];
	size_t n = strnlen(dir, sizeof buf);

	if (n >= sizeof buf) return 0; /* nothing sensible to ascend from */
	memcpy(buf, dir, n);
	buf[n] = 0;

	for (;;) {
		char prev[PATH_MAX];
		char *parent;
		size_t pn = strnlen(buf, sizeof buf);
		if (pn == sizeof buf) return 0;
		memcpy(prev, buf, pn + 1);
		/* pn+1 bytes through buf's own NUL (strnlen proved buf[pn]
		 * == 0, since pn == sizeof buf returned above already) --
		 * restated since include/libgen.h declares neither dirname()
		 * nor memcpy() as producing this token. */
		__ownership_string_terminated(prev);

		parent = dirname(buf); /* mutates buf in place; parent aliases it */
		/* dirname()'s POSIX contract guarantees null-termination, but
		 * include/libgen.h carries no withtok() for it -- restated
		 * here rather than annotate the header for other, unaudited
		 * callers. */
		__ownership_string_terminated(parent);
		if (!strcmp(parent, ".") || !strcmp(parent, prev)) return 0;

		if (rmdir(parent) != 0) {
			if (errno == ENOTEMPTY) return 0;
			__util_diagf("rmdir: %s: %s\n", parent, strerror(errno));
			return -1;
		}
		/* buf == parent already (dirname() mutated it in place);
		 * loop around to strip the next component. */
	}
}

int __util_rmdir_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, opt_p = 0, fail = 0;

	/* ntlibc.ValidPointer can't prove argv[i][0] nonnull here: the
	 * dereference is directly in the loop header, where the
	 * elements_withtok(null_terminated, argc) fact only reaches a
	 * checker-visible local, not a raw subscript. Left open: a known
	 * checker gap (argv[i] for i < argc is always live), not a bug, and
	 * tools/lint.sh's loopcond stage doesn't flag this condition shape
	 * -- restructuring just to dodge the checker has no other
	 * justification. */
	for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-p")) { opt_p = 1; continue; }
		__util_diagf("rmdir: %s: invalid option\n", argv[i]);
		return 1;
	}
	if (i >= argc) {
		__util_diagf("rmdir: missing operand\n");
		return 1;
	}

	for (; i < argc; i++) {
		if (rmdir(argv[i]) != 0) {
			__util_diagf("rmdir: %s: %s\n", argv[i], strerror(errno));
			fail = 1;
			continue;
		}
		if (opt_p && rmdir_ascend(argv[i]) < 0) fail = 1;
	}
	return fail;
}

// NOLINTEND(misc-include-cleaner)
