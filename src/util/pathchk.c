/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * pathchk(1p).  SYNOPSIS: "pathchk [-p] [-P] pathname...".  Default mode
 * (no options), quoted in full because it is the whole of what this
 * file implements: "the pathchk utility shall check each component of
 * each pathname operand based on the underlying file system.  A
 * diagnostic shall be written for each pathname operand that:
 *   - Is longer than {PATH_MAX} bytes
 *   - Contains any component longer than {NAME_MAX} bytes in its
 *     containing directory
 *   - Contains any component in a directory that is not searchable
 *   - Contains any byte sequence that is not valid in its containing
 *     directory"
 * STDOUT: "Not used."  EXIT STATUS: "0 All pathname operands passed all
 * of the checks. >0 An error occurred."
 *
 * -p and -P are refused rather than silently ignored: -p checks against
 * the compile-time {_POSIX_NAME_MAX}/{_POSIX_PATH_MAX} floor instead of
 * this filesystem's real limits, and -P additionally forbids a leading
 * '-' or an empty pathname -- both are real, different check sets this
 * file does not implement, and pretending `pathchk -p x` ran the -p
 * checks when it silently ran the default ones would be exactly the
 * undiagnosable wrongness src/sh/builtin.c's bi_set() comment (and
 * test/sh-design.md's refusal list) already refuse elsewhere in this
 * project.
 *
 * {NAME_MAX}/{PATH_MAX} come from pathconf() (src/unistd/sysconf.c),
 * which is what "based on the underlying file system" means, rather
 * than the <limits.h> compile-time constants -p uses -- they happen to
 * answer with those same constants today (this library has only one
 * filesystem backend), but going through pathconf() is what stays
 * correct if that ever stops being true.
 *
 * "[A] byte sequence that is not valid in its containing directory" has
 * no single POSIX answer -- validity is a property of the filesystem, and
 * this library has exactly one backend (NTFS/NT).  What is checked is
 * NTFS's own reserved set: the ASCII control bytes 0x00-0x1F and the six
 * characters '<', '>', ':', '"', '|', '?', '*' that NT's own filesystems
 * refuse in a component -- a stated, deliberately NT-specific reading of
 * a rule that is filesystem-defined by design, not a portable one.
 *
 * "Nonexistent path prefixes shall not be treated as an error" (the same
 * DESCRIPTION paragraph) is why the search-permission check below stops,
 * rather than errors, the moment a prefix does not exist: there is
 * nothing left to check permissions of.
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include "util.h"
#include "ownership_stubs.h" /* __ownership_pointer_nonnull(): restates argv[i]'s nonnull-ness where AggregateElementToken proves only its NUL-termination */

#define ISSEP(c) ((c) == '/' || (c) == '\\')

static int byte_is_invalid(char c)
{
	if ((unsigned char)c < 0x20) return 1;
	return strchr("<>:\"|?*", c) != 0;
}

/* Returns 0 if `path` passed every default-mode check, nonzero (with at
 * least one diagnostic already written to stderr) otherwise. */
static int check_one(const char *path withtok(null_terminated))
{
	long name_max = pathconf(path, _PC_NAME_MAX);
	long path_max = pathconf(path, _PC_PATH_MAX);
	size_t len = strlen(path);
	size_t dstart = 0;
	char prefix[PATH_MAX + 1];
	size_t plen = 0;
	const char *start, *p;
	int err = 0;

	if (name_max < 0) name_max = NAME_MAX;
	if (path_max < 0) path_max = PATH_MAX;

	if (len > (size_t)path_max) {
		__util_diagf("pathchk: %s: pathname longer than %ld bytes\n", path, path_max);
		err = 1;
	}

	/* A drive prefix ("C:") is not a pathname component in the sense
	 * the rest of this loop checks -- no NAME_MAX limit, no directory
	 * of its own to search -- the same carve-out src/misc/basename.c
	 * and src/misc/dirname.c make for the same two bytes. */
	if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
	    path[1] == ':') {
		dstart = 2;
		prefix[0] = path[0];
		prefix[1] = ':';
		prefix[2] = 0;
		plen = 2;
	} else {
		prefix[0] = 0;
	}

	start = path + dstart;
	/* *start/*start (below, and inside the ISSEP() run and the post-run
	 * recheck): "dereference extent is not proven sufficient" --
	 * genuinely safe (path carries withtok(null_terminated), and start
	 * only ever advances to a position already read as non-NUL), but
	 * ntlibc.ValidPointer's extent proof runs entirely off RegionStore's
	 * dynamic-extent tracking, which null_terminated (a pure reachable-
	 * NUL fact, see string_tokens.h) never populates -- a data-dependent
	 * pointer walk over a borrowed, unsized char* has no annotation in
	 * this tree that closes it. Left open. */
	while (*start) {
		size_t clen;

		/* Collapse a run of separators into one '/' in the prefix
		 * being accumulated -- what matters for the checks below is
		 * which directory a component is *in*, not which separator
		 * spelling or how many of them the operand used to say so. */
		while (ISSEP(*start)) {
			if (plen < sizeof prefix - 1) prefix[plen++] = '/';
			start++;
		}
		if (!*start) break;

		clen = strcspn(start, "/\\");
		p = start + clen;

		if (clen > (size_t)name_max) {
			__util_diagf("pathchk: %s: component \"%.*s\" longer than %ld bytes\n",
				path, (int)clen, start, name_max);
			err = 1;
		}
		{
			size_t k;
			for (k = 0; k < clen; k++) {
				if (byte_is_invalid(start[k])) {
					__util_diagf("pathchk: %s: component \"%.*s\" contains a "
					                "byte not valid in its containing directory\n",
						path, (int)clen, start);
					err = 1;
					break;
				}
			}
		}

		/* Search permission on the directory this component is *in* --
		 * i.e. the prefix accumulated from every component before this
		 * one, checked only if that prefix names something that
		 * exists at all (see this file's header on nonexistent
		 * prefixes). */
		if (plen > 0) {
			prefix[plen] = 0;
			if (access(prefix, F_OK) == 0 && access(prefix, X_OK) != 0) {
				__util_diagf("pathchk: %s: %s: directory not searchable\n", path, prefix);
				err = 1;
			}
		}

		if (plen + clen < sizeof prefix) {
			if (snprintf(prefix + plen, sizeof prefix - plen, "%.*s",
			    (int)clen, start) != (int)clen)
				return 1;
			plen += clen;
		}
		start = p;
	}

	return err;
}

int __util_pathchk_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, status = 0;

	for (i = 1; i < argc; i++) {
		/* argv's own elements_withtok(null_terminated, argc) proves
		 * every element up to argc has a reachable NUL, but not that
		 * the element pointer itself is nonnull -- genuinely true
		 * (main()'s argv[0..argc-1] are never NULL), just not a fact
		 * an array-element read can carry across to ValidPointer. */
		__ownership_pointer_nonnull(argv[i]);
		/* A lone "-" is a conventional pathname (often "read from
		 * stdin" elsewhere), not an option -- getopt(3) draws the same
		 * line. */
		if (argv[i][0] != '-' || !strcmp(argv[i], "-")) break;
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "-P")) {
			__util_diagf("pathchk: %s: not implemented -- only the default "
			                "(no-option) pathchk(1p) check set is\n", argv[i]);
			return 2;
		}
		__util_diagf("pathchk: %s: unsupported option\n", argv[i]);
		return 2;
	}

	if (i >= argc) {
		__util_diagf("pathchk: missing pathname operand\n");
		return 2;
	}

	for (; i < argc; i++) {
		__ownership_string_terminated(argv[i]); /* AggregateElementToken's null_terminated grant from argv's own elements_withtok doesn't survive across the check_one() call boundary */
		if (check_one(argv[i])) status = 1;
	}

	return status;
}
