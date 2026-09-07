/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * mv(1p). Two SYNOPSIS forms are implemented:
 *   mv [-f] source target
 *   mv [-f] source... target_dir
 *
 * mv(1p)'s DESCRIPTION describes the effect ("rename" when possible),
 * not a mechanism, so the mechanism here is: try rename() first --
 * atomic, and POSIX's own preferred primitive whenever it applies (it
 * already carries all of mv(1p)'s "existing dest_file is unlinked
 * first"/"existing empty dest directory is replaced" behaviour, because
 * that behaviour comes from the platform's rename semantics, which
 * src/stdio/misc.c's rename() documents).  Only when rename() fails
 * specifically because the two paths are on different volumes --
 * reported as EXDEV; src/stdio/misc.c's renameat() sets exactly that
 * errno from NT's STATUS_NOT_SAME_DEVICE, so this is a real, observed
 * mapping, not a guess -- does this fall back to a copy of the source
 * followed by removing it, reusing src/util/cp.c's file/tree copy and
 * src/util/rm.c's tree removal rather than duplicating either.  Any
 * other rename() failure is a real diagnostic and a nonzero exit, with
 * no fallback attempted: guessing that some other errno also means
 * "try copying instead" risks silently doing something very different
 * from what the user asked for.
 *
 * target_dir form: identical "target/basename(source)" construction as
 * cp(1p)'s, via the same __util_join_basename() (src/util/cp.c).
 *
 * Deliberately out of scope, refused loudly rather than silently
 * ignored -- same reasoning as src/util/rm.c's and src/util/cp.c's:
 *   -i  interactive overwrite confirmation.
 * `-f` is accepted, but is a genuine no-op here rather than a silently
 * *different* no-op: mv(1p)'s -f means "do not prompt", and this build
 * never prompts (no -i), so there is nothing left for -f to change --
 * unlike a refused option, accepting -f does not misrepresent what the
 * utility does.
 *
 * The EXDEV fallback does not attempt to move a symbolic link across
 * volumes: doing so correctly means recreating the link itself
 * (readlink() + symlink()) rather than copying file *contents*, which
 * is not implemented here, and copying the link's *referent* instead
 * would silently change what the moved entry means. Refused with a
 * diagnostic instead -- the same policy src/util/cp.c applies to a
 * symlink found inside a -R tree, for the same reason. Within one
 * volume this limitation does not apply at all: rename() moves a
 * symbolic link correctly and is always tried first.
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

		/* a is one of argv's own elements (i < nargs <= argc);
		 * restate the argv-wide null-terminated guarantee here, the
		 * same way src/util/cp.c's identical loop shape already does
		 * -- a plain local like `a` is not something the checker can
		 * trace back to argv on its own. The raw a[0] read just below
		 * stays open (same as cp.c's own identical loop): closing it
		 * needs __ownership_pointer_nonnull() instead, which was
		 * tried and reverted -- it reopened the strcmp() finding below
		 * and broke the unrelated target = argv[nargs - 1] read
		 * further down. */
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
	/* Restated for the same reason as `a` above: the loop bound this
	 * function uses is `nargs`, not `argc`. */
	__ownership_string_terminated(target);
	target_is_dir = stat(target, &tst) == 0 && S_ISDIR(tst.st_mode);

	if (noperands > 2 && !target_is_dir) {
		__util_diagf("mv: target '%s' is not a directory\n", target);
		return 2;
	}

	for (; i < nargs - 1; i++) {
		const char *src = argv[i];

		/* Same restatement as above, again because of the `nargs`
		 * loop bound. */
		__ownership_string_terminated(src);

		if (target_is_dir) {
			char *dst = __util_join_basename(target, src);
			if (!dst) {
				__util_diagf("mv: %s: %s\n", src, strerror(ENOMEM));
				had_error = 1;
				continue;
			}
			/* Left open: dst's null_terminated token from
			 * __util_join_basename()'s dual (heap_allocated +
			 * null_terminated) return does not survive to this call
			 * -- the same open finding src/util/cp.c's byte-for-byte
			 * identical cp_one(src, dst, ...) call has. */
			if (mv_one(src, dst) < 0) had_error = 1;
			free(dst);
		} else {
			if (mv_one(src, target) < 0) had_error = 1;
		}
	}

	return had_error ? 1 : 0;
}
