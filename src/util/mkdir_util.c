/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named mkdir_util.c, not mkdir.c like src/internal/util.h's own
 * "src/util/<name>.c" convention would suggest: this tree already has a
 * src/stat/mkdir.c (the mkdir() library function itself), and `ar`'s
 * member names are truncated basenames with no directory component
 * (tools/linkcheck.sh's own comment), so two different objects both
 * named mkdir.o would silently shadow each other inside lib/libc.a.
 * chmod_util.c has the identical reason (src/stat/chmod.c already
 * exists); every other utility in this tier has no such collision and
 * keeps the plain name.
 *
 * mkdir(1p): `mkdir [-p] [-m mode] dir...`
 *
 * OPTIONS:
 *  -m mode  "Set the file permission bits of the newly-created directory
 *            to the specified mode value.  The mode option-argument
 *            shall be the same as the mode operand defined for the
 *            chmod utility.  In the symbolic_mode strings, the op
 *            characters '+' and '-' shall be interpreted relative to an
 *            assumed initial mode of a=rwx; '+' shall add permissions to
 *            the default mode, '-' shall delete permissions from the
 *            default mode."
 *  -p       "Create any missing intermediate pathname components."
 *
 * EXIT STATUS: "0 All the specified directories were created
 * successfully, or the -p option was specified and all the specified
 * directories either already existed or were created successfully."
 * ">0 An error occurred."  -- implemented as the diagnose-and-continue
 * loop this project uses throughout (see src/util/test.c and
 * src/sh/builtin.c for the same shape): one bad operand does not stop
 * the rest from being tried.
 *
 * ---- The umask interaction mkdir() itself does not let this utility
 * fully honour ------------------------------------------------------
 *
 * This tree's mkdir() (src/stat/mkdir.c -> __plat_mkdir(),
 * src/stat/nt/plat_stat.c) unconditionally does
 * `mode = mode & ~__umask_get() & 07777` before creating the directory,
 * with no way for a caller to ask for the exact bits it computed to be
 * used verbatim.  That is the right default when no -m is given (mkdir
 * (1p) says exactly that: the default mode is 0777 "as modified by
 * umask"), but chmod(1p)'s who-omitted umask rule (see modeparse.h) only
 * excuses masking permission bits whose who was left implicit -- an
 * explicit `-m u+x` should not have its 'x' bit stripped just because it
 * falls inside the umask, and yet mkdir()'s NT backend strips it anyway,
 * unconditionally, after this file has already computed the exact
 * intended mode.  Fixing that would mean reaching into __plat_mkdir()
 * (or adding a mode-bypass parameter to it) purely for this utility's
 * sake, which is out of scope here -- this is a real, tracked gap in
 * mkdir() itself, stated rather than hidden, not something to route
 * around by duplicating __plat_mkdir()'s directory-creation logic in
 * src/util/.
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
#include <sys/stat.h>
#include "libc.h"
#include "util.h"
#include "modeparse.h"
#include "ownership_stubs.h" /* __ownership_string_terminated(): dirname() (libgen.h) has no ownership annotations of its own, but always returns either "." or a NUL it just wrote into its argument -- see src/misc/dirname.c */

/* Creates `path`, and with -p, any missing intermediate components too.
 * `leaf_mode` is applied only to `path` itself -- an intermediate
 * component created along the way gets the same default (0777, as
 * modified by umask via mkdir() itself) that a plain `mkdir` with no -m
 * would use, since neither mkdir(1p) nor mkfifo(1p) says what an
 * automatically-created ancestor's mode should be. Returns 0 on success
 * (including "already existed as a directory" under has_p), -1 with
 * errno set otherwise. `path` is always null-terminated: both call sites
 * (the initial __util_mkdir_main call and the recursive dirname() call
 * below) pass a buffer that genuinely has a reachable NUL. */
// NOLINTNEXTLINE(misc-no-recursion) -- parent creation recurses on a strictly shorter path prefix
static int mkdir_p(char *path withtok(null_terminated), mode_t leaf_mode, int is_leaf, int has_p)
{
	struct stat st;

	if (mkdir(path, is_leaf ? leaf_mode : 0777) == 0) return 0;

	if (errno == EEXIST) {
		if (!has_p && is_leaf) return -1; /* plain mkdir: EEXIST is a real error */
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
		errno = ENOTDIR;
		return -1;
	}
	if (errno == ENOENT && has_p) {
		char parent[PATH_MAX];
		char *p;
		size_t n = strlen(path);
		if (n >= sizeof parent) { errno = ENAMETOOLONG; return -1; }
		memcpy(parent, path, n + 1);
		p = dirname(parent);
		__ownership_string_terminated(p);
		if (!strcmp(p, path)) return -1; /* dirname made no progress: true root, ENOENT stands */
		/* "." means the parent is just the current directory, which
		 * always exists -- nothing to create, go straight to retrying
		 * `path` itself.  Otherwise the parent is a real path that
		 * needs the same treatment, recursively. */
		if (strcmp(p, ".") && mkdir_p(p, 0, 0, has_p) < 0) return -1; // NOLINT(bugprone-suspicious-string-compare) -- nonzero intentionally means the parent is not the current-directory sentinel
		if (mkdir(path, is_leaf ? leaf_mode : 0777) == 0) return 0;
		if (errno == EEXIST && stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
		return -1;
	}
	return -1;
}

int __util_mkdir_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, opt_p = 0, fail = 0;
	const char *mode_spec = 0;
	mode_t leaf_mode = 0777;

	i = 1;
	while (i < argc) {
		/* argv's own elements_withtok(null_terminated, argc) proves
		 * every element up to argc has a reachable NUL, but not that
		 * the element pointer itself is nonnull -- genuinely true
		 * (main()'s argv[0..argc-1] are never NULL), just not a fact
		 * an array-element read can carry across to ValidPointer. */
		__ownership_pointer_nonnull(argv[i]);
		if (argv[i][0] != '-' || !argv[i][1]) break;
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-p")) { opt_p = 1; i++; continue; }
		if (!strcmp(argv[i], "-m")) {
			if (i + 1 >= argc) {
				__util_diagf("mkdir: -m: option requires an argument\n");
				return 1;
			}
			mode_spec = argv[++i];
			i++;
			continue;
		}
		__util_diagf("mkdir: %s: invalid option\n", argv[i]);
		return 1;
	}
	if (i >= argc) {
		__util_diagf("mkdir: missing operand\n");
		return 1;
	}

	if (mode_spec) {
		/* "-m mode ... relative to an assumed initial mode of a=rwx" */
		if (__util_parse_mode("mkdir", mode_spec, S_IRWXU | S_IRWXG | S_IRWXO,
		                      (mode_t)__umask_get(), &leaf_mode) < 0)
			return 1;
	}

	for (; i < argc; i++) {
		char path[PATH_MAX];
		size_t n;
		__ownership_string_terminated(argv[i]); /* AggregateElementToken's null_terminated grant from argv's own elements_withtok doesn't survive into this second loop */
		n = strlen(argv[i]);
		if (n >= sizeof path) {
			__util_diagf("mkdir: %s: %s\n", argv[i], strerror(ENAMETOOLONG));
			fail = 1;
			continue;
		}
		memcpy(path, argv[i], n + 1);
		__ownership_string_terminated(path); /* memcpy just copied argv[i]'s own NUL (n + 1 bytes) into path */
		if (mkdir_p(path, leaf_mode, 1, opt_p) < 0) {
			int saved = errno;
			__util_diagf("mkdir: %s: %s\n", argv[i], strerror(saved));
			fail = 1;
		}
	}
	return fail;
}

// NOLINTEND(misc-include-cleaner)
