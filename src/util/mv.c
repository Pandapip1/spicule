/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * mv(1p). Two SYNOPSIS forms are implemented:
 *   mv [-f] source target
 *   mv [-f] source... target_dir
 *
 * Mechanism: try rename() first -- atomic, and already gives mv(1p)'s
 * "existing dest_file unlinked first"/"existing empty dest dir replaced"
 * behavior for free, since that comes from the platform's own rename
 * semantics (src/stdio/misc.c's rename()). Only on EXDEV (different
 * volumes -- src/stdio/misc.c's renameat() maps this from NT's
 * STATUS_NOT_SAME_DEVICE) does this fall back to copy-then-remove,
 * reusing src/util/cp.c's copy and src/util/rm.c's tree removal. Any
 * other rename() failure is a diagnostic and nonzero exit, no fallback:
 * guessing that some other errno also means "try copying" risks doing
 * something different from what the user asked for.
 *
 * target_dir form: same "target/basename(source)" construction as
 * cp(1p), via the same __util_join_basename() (src/util/cp.c).
 *
 * Deliberately out of scope, refused loudly rather than silently
 * ignored -- same reasoning as src/util/rm.c and src/util/cp.c:
 *   -i  interactive overwrite confirmation.
 * -f is accepted but a genuine no-op: mv(1p)'s -f means "do not
 * prompt", and this build never prompts (no -i), so there's nothing
 * left for -f to change.
 *
 * The EXDEV fallback does not move a symbolic link across volumes:
 * doing so correctly means recreating the link (readlink()+symlink()),
 * not copying file contents, and copying the link's referent instead
 * would silently change what the moved entry means -- refused with a
 * diagnostic, same policy as a symlink found inside a cp -R tree.
 * Within one volume this doesn't apply: rename() moves a symlink
 * correctly and is always tried first.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "util.h"
#include "ownership_stubs.h"

static int mv_one(const char *src withtok(null_terminated), const char *dst withtok(null_terminated))
{
	struct stat sst;

	if (rename(src, dst) == 0) return 0;
	if (errno != EXDEV) {
		__util_diagf("mv: cannot move '%s' to '%s': %s\n", src, dst, strerror(errno));
		return -1;
	}

	/* Cross-volume: rename() cannot do this atomically, so copy the
	 * source and then remove it -- see this file's header. */
	if (lstat(src, &sst) < 0) {
		__util_diagf("mv: cannot stat '%s': %s\n", src, strerror(errno));
		return -1;
	}

	if (S_ISLNK(sst.st_mode)) {
		__util_diagf("mv: '%s': moving a symbolic link across filesystems "
		                "is not supported by this build (see src/util/mv.c)\n", src);
		return -1;
	}

	if (S_ISDIR(sst.st_mode)) {
		if (__util_copy_tree(src, dst, 0) < 0) return -1;
		if (__util_remove_tree(src) < 0) {
			__util_diagf("mv: '%s' was copied to '%s' but the original could "
			                "not be fully removed -- manual cleanup is needed\n",
			                src, dst);
			return -1;
		}
		return 0;
	}

	if (__util_copy_regular_file(src, dst, 0) < 0) return -1;
	if (unlink(src) < 0) {
		__util_diagf("mv: '%s' was copied to '%s' but the original could not "
		                "be removed: %s\n", src, dst, strerror(errno));
		return -1;
	}
	return 0;
}

int __util_mv_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	size_t i = 1;
	size_t nargs = argc > 0 ? (size_t)argc : 0;
	size_t noperands;
	int had_error = 0;
	const char *target;
	struct stat tst;
	int target_is_dir;

	for (; i < nargs; i++) {
		char *a = argv[i];
		char *p;

		/* a is argv[i], i < nargs <= argc; restated since a plain local
		 * isn't traceable back to argv on its own (same as
		 * src/util/cp.c's identical loop). The raw a[0] read below
		 * stays open: __ownership_pointer_nonnull() instead was tried
		 * and reverted -- it reopened the strcmp() finding below and
		 * broke the unrelated target = argv[nargs - 1] read further
		 * down. */
		__ownership_string_terminated(a);

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }

		for (p = a + 1; *p; p++) {
			if (*p == 'f') continue;   /* genuine no-op -- see header */
			if (*p == 'i') {
				__util_diagf("mv: -i: interactive confirmation is not "
				                "supported by this build; refusing rather "
				                "than moving without prompting\n");
				return 2;
			}
			__util_diagf("mv: invalid option -- '%c'\n", *p);
			return 2;
		}
	}

	noperands = i < nargs ? nargs - i : 0;
	if (noperands < 2) {
		__util_diagf("mv: missing %s\n",
			noperands == 0 ? "operand" : "destination operand");
		return 2;
	}

	target = argv[nargs - 1];
	/* Restated for the same reason as `a` above (`nargs`, not `argc`). */
	__ownership_string_terminated(target);
	target_is_dir = stat(target, &tst) == 0 && S_ISDIR(tst.st_mode);

	if (noperands > 2 && !target_is_dir) {
		__util_diagf("mv: target '%s' is not a directory\n", target);
		return 2;
	}

	for (; i < nargs - 1; i++) {
		const char *src = argv[i];

		/* Same restatement as above (`nargs` loop bound). */
		__ownership_string_terminated(src);

		if (target_is_dir) {
			char *dst = __util_join_basename(target, src);
			if (!dst) {
				__util_diagf("mv: %s: %s\n", src, strerror(ENOMEM));
				had_error = 1;
				continue;
			}
			/* Left open: dst's null_terminated token from
			 * __util_join_basename()'s dual return doesn't survive to
			 * this call -- same open finding as cp.c's identical
			 * cp_one(src, dst, ...) call. */
			if (mv_one(src, dst) < 0) had_error = 1;
			free(dst);
		} else {
			if (mv_one(src, target) < 0) had_error = 1;
		}
	}

	return had_error ? 1 : 0;
}
