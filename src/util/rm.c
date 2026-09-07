/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * rm(1p): remove file hierarchies. Implements -f, -r/-R, multiple
 * operands, `--`.
 *
 * -r/-R walk the tree with nftw() (src/ftw/ftw.c) using FTW_DEPTH
 * (every descendant reported before its parent directory) and FTW_PHYS
 * (never follow a symlink into the tree -- rm(1p) requires removing the
 * link itself instead).
 *
 * -i (interactive confirmation) is deliberately unsupported and refused
 * loudly rather than silently no-op'd: no terminal-interaction layer
 * exists at this level yet, and a script or human relying on the prompt
 * would otherwise get silent, unconfirmed deletion (see src/sh/builtin.c's
 * bi_set() for the same reasoning).
 *
 * -f suppresses exactly what rm(1p) OPTIONS says and no more: the
 * confirmation prompt, and diagnostics/exit status for operands that do
 * not exist. It does NOT cover an existing directory operand without
 * -R/-r, a real removal failure, or "missing operand" (no operand at
 * all is a different case than an operand that doesn't exist). rm_one()
 * suppresses only ENOENT on the initial lstat() under -f;
 * __util_remove_tree()'s callback never consults `force`.
 *
 * names_dot_or_dotdot() refuses "." and ".." explicitly before touching
 * the filesystem, per rm(1p) DESCRIPTION -- without it, `rm -r .` would
 * walk into and empty out the process's own current directory.
 * Recognising "names the filesystem root" in general is not attempted:
 * roots here are drive letters/UNC shares, not one fixed string, and a
 * wrong heuristic is worse than none -- an actual root will fail its
 * own rmdir() (busy/access denied) and get diagnosed like any other
 * failure.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <ftw.h>
#include "util.h"
#include "ownership_stubs.h"

/* nftw()'s callback takes no user-data parameter, so the one thing it
 * needs across a whole walk (whether anything has failed so far) has to
 * live at file scope. Safe here: one synchronous nftw() call always
 * runs to completion before this could be read by anything else, and
 * this file never starts a second walk while one is in progress. */
static int rm_tree_failed;

static int rm_diag(const char *path, int error)
{
	__util_diagf("rm: cannot remove '%s': %s\n", path, strerror(error));
	rm_tree_failed = 1;
	return 0;
}

/* FTW_DEPTH reports every non-directory once, and every directory once
 * more as FTW_DP after all of its entries -- the two cases below are
 * the whole of "empty the tree, then remove it, leaves first". */
static int rm_walk_cb(const char *path, const struct stat *st, int type, struct FTW *ftwbuf)
{
	int saved_errno = errno;
	(void)st;
	(void)ftwbuf;
	switch (type) {
	case FTW_DP:
		if (rmdir(path) < 0) return rm_diag(path, errno);
		return 0;
	case FTW_DNR:
		__util_diagf("rm: cannot read directory '%s': %s\n", path, strerror(saved_errno));
		rm_tree_failed = 1;
		return 0;
	case FTW_NS:
		return rm_diag(path, saved_errno);
	default:
		/* FTW_F and FTW_SL (never followed, FTW_PHYS above) both go
		 * through unlink(): rm(1p) treats a non-directory, including
		 * a link, the same as a plain file. */
		if (unlink(path) < 0) return rm_diag(path, errno);
		return 0;
	}
}

/* Removes the whole tree rooted at `path`: rm -r's per-operand work,
 * and also src/util/mv.c's cross-filesystem fallback for a directory
 * source. Returns 0 if every entry was removed, -1 (diagnostics already
 * written) if any part of the tree could not be. */
int __util_remove_tree(const char *path)
{
	rm_tree_failed = 0;
	if (nftw(path, rm_walk_cb, 15, FTW_DEPTH | FTW_PHYS) < 0) {
		__util_diagf("rm: cannot remove '%s': %s\n", path, strerror(errno));
		return -1;
	}
	return rm_tree_failed ? -1 : 0;
}

static int names_dot_or_dotdot(const char *path withtok(null_terminated))
{
	size_t n = strlen(path);
	size_t start, len;

	while (n > 0 && (path[n - 1] == '/' || path[n - 1] == '\\')) n--;
	start = n;
	while (start > 0 && path[start - 1] != '/' && path[start - 1] != '\\') start--;
	len = n - start;
	return (len == 1 && path[start] == '.') ||
	       (len == 2 && path[start] == '.' && path[start + 1] == '.');
}

static int rm_one(const char *path withtok(null_terminated), int recursive, int force) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct stat lst;

	if (names_dot_or_dotdot(path)) {
		/* Not suppressed by -f: this is the standard's own outright
		 * refusal, not a missing-operand or already-gone case. */
		__util_diagf("rm: refusing to remove '.' or '..' (in '%s')\n", path);
		return -1;
	}

	if (lstat(path, &lst) < 0) {
		if (force && errno == ENOENT) return 0;
		__util_diagf("rm: cannot remove '%s': %s\n", path, strerror(errno));
		return -1;
	}

	if (S_ISDIR(lst.st_mode)) {
		if (!recursive) {
			/* Unconditional per rm(1p) -- not one of -f's two suppressions. */
			__util_diagf("rm: cannot remove '%s': Is a directory\n", path);
			return -1;
		}
		return __util_remove_tree(path);
	}

	if (unlink(path) < 0) {
		__util_diagf("rm: cannot remove '%s': %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int __util_rm_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int force = 0, recursive = 0;
	int i = 1;
	int had_error = 0;

	for (; i < argc; i++) {
		char *a = argv[i];
		char *p;

		/* a is one of argv's own elements; restate the null-terminated
		 * guarantee since the checker can't trace a plain local back
		 * to argv on its own (same as cp.c's identical loop). */
		__ownership_string_terminated(a);

		if (a[0] != '-' || a[1] == 0) break;   /* not an option; a bare "-" is an operand */
		if (!strcmp(a, "--")) { i++; break; }

		for (p = a + 1; *p; p++) {
			if (*p == 'f') { force = 1; continue; }
			if (*p == 'r' || *p == 'R') { recursive = 1; continue; }
			if (*p == 'i') {
				/* Refuse loudly rather than silently deleting
				 * without ever having prompted -- see this
				 * file's header. */
				__util_diagf("rm: -i: interactive confirmation is not "
				                "supported by this build; refusing rather "
				                "than deleting without prompting\n");
				return 2;
			}
			__util_diagf("rm: invalid option -- '%c'\n", *p);
			return 2;
		}
	}

	if (i >= argc) {
		__util_diagf("rm: missing operand\n");
		return 2;
	}

	for (; i < argc; i++) {
		/* Restate the null-terminated contract on argv[i]: it does not
		 * survive the direct argv[i] read this checker can trace on
		 * its own. */
		__ownership_string_terminated(argv[i]);
		if (rm_one(argv[i], recursive, force) < 0) had_error = 1;
	}

	return had_error ? 1 : 0;
}

// NOLINTEND(misc-include-cleaner)
