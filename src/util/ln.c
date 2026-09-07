/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ln(1p):
 *   ln [-fs] [-L|-P] source_file target_file
 *   ln [-fs] [-L|-P] source_file... target_dir
 *
 * OPTIONS:
 *  -f  "Force existing destination pathnames to be removed to allow the
 *       link."
 *  -s  "Create symbolic links instead of hard links.  If the -s option
 *       is specified, the -L and -P options shall be silently ignored."
 *
 * DESCRIPTION (no -f, destination exists): a diagnostic and continuing
 * to the remaining source files is exactly what link()/symlink() failing
 * EEXIST plus this file's usual diagnose-and-continue loop already
 * produce, so -f's absence needs no special-casing beyond "don't unlink
 * the target first".
 *
 * Second SYNOPSIS form applies when the final operand names an existing
 * directory -- every source_file is linked into it under its own
 * basename.
 *
 * ---- What is deliberately not implemented ------------------------------
 *
 * -L / -P: which of a symlink source's two identities (the link itself,
 * or the file it resolves to) a *hard* link should be made to. Not
 * implemented -- refused with a diagnostic, per this project's "refuse
 * rather than silently guess" rule -- because this tree's link()
 * (src/unistd/link.c) always hard-links the named entry as given with no
 * way to resolve through a symlink first; honoring -L would need new
 * plumbing in link() itself, out of scope here. The default (neither
 * flag given) already matches -P's behavior, the common case.
 */
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>
#include "util.h"
#include "ownership_stubs.h"

static int link_one(const char *src, const char *dst, int opt_s, int opt_f)
{
	if (opt_f) {
		struct stat st;
		/* lstat, not stat: an existing target that is itself a
		 * dangling symlink must still be removed to "allow the
		 * link", even though stat() on it would fail. */
		if (lstat(dst, &st) == 0) (void)unlink(dst);
	}
	if (opt_s) return symlink(src, dst);
	return link(src, dst);
}

int __util_ln_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, opt_s = 0, opt_f = 0, fail = 0;
	int nsrc, di;
	struct stat dst_st;
	int dir_form;

	/* OPEN LINT FINDING: ntlibc.ValidPointer can't prove argv[i][0]
	 * nonnull here -- the elements_withtok(null_terminated, argc) fact
	 * it uses elsewhere only reaches a local bound to argv[i] before
	 * dereference, not a raw subscript inside the loop header itself.
	 * Left open rather than restructured purely to dodge the checker
	 * (loopcond does not flag this condition shape). Known checker gap:
	 * argv[i] for i < argc is always live. */
	for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-L") || !strcmp(a, "-P")) {
			__util_diagf("ln: %s: not implemented -- see src/util/ln.c\n", a);
			return 1;
		}
		if (a[1] != 0 && strspn(a + 1, "fs") == strlen(a + 1)) {
			if (strchr(a, 'f')) opt_f = 1;
			if (strchr(a, 's')) opt_s = 1;
			continue;
		}
		__util_diagf("ln: %s: invalid option\n", a);
		return 1;
	}

	if (i >= argc) {
		__util_diagf("ln: missing operand\n");
		return 1;
	}
	nsrc = argc - i;
	if (nsrc < 2) {
		__util_diagf("ln: missing operand\n");
		return 1;
	}

	di = argc - 1; /* index of the final operand, the candidate target_dir */
	/* nsrc > 2 already forces the directory form; with exactly two
	 * operands, whether it's the dir form depends on the target. */
	dir_form = nsrc > 2;
	if (!dir_form && stat(argv[di], &dst_st) == 0 && S_ISDIR(dst_st.st_mode))
		dir_form = 1;

	if (!dir_form) {
		if (link_one(argv[i], argv[i + 1], opt_s, opt_f) != 0) {
			__util_diagf("ln: %s: %s\n", argv[i + 1], strerror(errno));
			return 1;
		}
		return 0;
	}

	for (; i < di; i++) {
		char base_copy[PATH_MAX];
		char target[PATH_MAX];
		char *base;
		size_t sn;
		int n;

		/* argv[i] is NUL-terminated per argv's own
		 * elements_withtok(null_terminated, argc) contract -- restated
		 * since that token doesn't survive a direct argv[i] read. */
		__ownership_string_terminated(argv[i]);
		sn = strlen(argv[i]);

		if (sn >= sizeof base_copy) {
			__util_diagf("ln: %s: %s\n", argv[i], strerror(ENAMETOOLONG));
			fail = 1;
			continue;
		}
		memcpy(base_copy, argv[i], sn + 1);
		base = basename(base_copy);
		n = snprintf(target, sizeof target, "%s/%s", argv[di], base);
		if (n < 0 || (size_t)n >= sizeof target) {
			__util_diagf("ln: %s: %s\n", argv[i], strerror(ENAMETOOLONG));
			fail = 1;
			continue;
		}
		if (link_one(argv[i], target, opt_s, opt_f) != 0) {
			__util_diagf("ln: %s: %s\n", target, strerror(errno));
			fail = 1;
		}
	}
	return fail;
}
