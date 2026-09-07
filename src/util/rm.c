/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * rm(1p): "The rm utility shall remove the directory entry specified by
 * each file argument."
 *
 * Implements: -f, -r/-R (XCU rm(1p) OPTIONS: "Remove file hierarchies"),
 * multiple operands, `--` to end option parsing.  `-R`/`-r` walk the
 * tree with nftw() (src/ftw/ftw.c, a real, already-tested recursion
 * driver over opendir()/readdir()/lstat() -- there is no need to write
 * a second one here), FTW_DEPTH so every descendant is removed before
 * its parent directory and FTW_PHYS so a symbolic link inside the tree
 * is never followed -- rm(1p): "The rm utility shall not traverse
 * directories by following symbolic links into other parts of the
 * hierarchy, but shall remove the links themselves."
 *
 * Deliberately out of scope, refused loudly rather than silently
 * ignored or silently treated as a no-op: `-i` (interactive
 * confirmation).  No real terminal-interaction story exists at this
 * layer yet -- see src/sh/builtin.c's bi_set() comment for the same
 * "refuse unsupported options" reasoning applied there.  A silently
 * accepted `-i` that never actually prompted would be strictly worse
 * than refusing it: a script or a human relying on the prompt would get
 * silent, unconfirmed deletion instead.
 *
 * What -f suppresses, read literally off rm(1p) OPTIONS, and no more:
 * "Do not prompt for confirmation. Do not write diagnostic messages or
 * modify the exit status in the case of no file operands, or in the
 * case of operands that do not exist."  That is the whole list -- it
 * does not cover a file operand that names an existing directory
 * without -R/-r (DESCRIPTION's directory clause is unconditional, not
 * gated on -f), and it does not cover a real removal failure
 * (permission denied, a non-empty directory rmdir() refuses, etc.).
 * rm_one() below suppresses exactly ENOENT on the initial lstat() under
 * -f and nothing else; __util_remove_tree()'s callback never consults
 * `force` at all, on purpose.
 *
 * "Missing operand" (no file argument at all) is reported and counted
 * as an error even under -f: -f's suppression list is about operands
 * that do not exist, not about there being no operand to begin with.
 *
 * rm(1p) DESCRIPTION: "It is an error to attempt to remove the files
 * dot or dot-dot, or a file with a name that names the root directory
 * alone."  names_dot_or_dotdot() below refuses the first two,
 * explicitly, before ever touching the filesystem, because a directory
 * operand of "." with -r would otherwise walk into (and empty out) the
 * process's own current directory -- exactly the "single easiest place
 * in this whole POSIX-utilities effort to write something that deletes
 * the wrong thing" the task that produced this file called out by name.
 * Recognising "a path that names the filesystem root" in general is not
 * attempted: this platform's roots are drive letters and UNC shares
 * rather than one fixed string, and a heuristic that gets that wrong is
 * worse than not trying -- a real attempt to rmdir() an actual root
 * will fail on its own (busy/access denied) and be diagnosed like any
 * other removal failure.
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

/* nftw()'s callback takes no user-data parameter -- a well-known wart of
 * the historical ftw()/nftw() interface, inherited as-is from POSIX
 * (see src/ftw/ftw.c's own header) -- so the one thing __remove_cb()
 * needs across a whole walk (whether anything in it has failed so far)
 * has to live at file scope.  Safe here: __util_remove_tree() runs one
 * synchronous nftw() call to completion (nftw() never returns to its
 * caller mid-walk) before this state could be read by anything else,
 * and nothing in this single-threaded, one-utility-invocation-per-
 * process file ever starts a second walk while one is in progress. */
static int rm_tree_failed;

static int rm_diag(const char *path, int error)
{
	__util_diagf("rm: cannot remove '%s': %s\n", path, strerror(error));
	rm_tree_failed = 1;
	return 0;
}

/* FTW_DEPTH means every non-directory is reported once, and every
 * directory is reported exactly once more, as FTW_DP, after all of its
 * entries -- so the two cases below are the whole of "make the tree
 * empty, then remove it, from the leaves up". */
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
		/* FTW_F (regular file) and FTW_SL (symbolic link, not
		 * followed -- FTW_PHYS below): both go through unlink(),
		 * which is rm(1p)'s own "if the current file is not a
		 * directory, rm shall perform actions equivalent to the
		 * unlink() function" for a link exactly as for a file. */
		if (unlink(path) < 0) return rm_diag(path, errno);
		return 0;
	}
}

/* Removes the whole tree rooted at `path`: rm -r's per-operand work,
 * and also src/util/mv.c's cross-filesystem fallback for a directory
 * source.  Returns 0 if every entry was removed, -1 (with diagnostics
 * already written to stderr) if any part of the tree could not be. */
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
			/* rm(1p): "the rm utility shall write a diagnostic
			 * message to standard error, do nothing more with
			 * file" -- unconditional, not one of -f's two
			 * suppressions. */
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

		/* a is one of argv's own elements; restate the argv-wide
		 * null-terminated guarantee here, the same way
		 * src/util/cp.c's identical loop shape already does -- a
		 * plain local like `a` is not something the checker can trace
		 * back to argv on its own. The raw a[0] read just below stays
		 * open regardless (same as cp.c's own identical loop). */
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
		/* argv[i] is genuinely null-terminated by this function's own
		 * elements_withtok(null_terminated, argc) contract on argv --
		 * restated here since that token does not survive the direct
		 * argv[i] read this checker can trace on its own. */
		__ownership_string_terminated(argv[i]);
		if (rm_one(argv[i], recursive, force) < 0) had_error = 1;
	}

	return had_error ? 1 : 0;
}

// NOLINTEND(misc-include-cleaner)
