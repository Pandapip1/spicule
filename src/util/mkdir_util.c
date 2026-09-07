/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named mkdir_util.c, not mkdir.c: src/stat/mkdir.c already holds the
 * mkdir() library function, and `ar` member names are truncated
 * basenames with no directory component, so two mkdir.o's would shadow
 * each other in lib/libc.a. chmod_util.c has the same reason.
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
 * ">0 An error occurred."  -- diagnose-and-continue, same shape as
 * src/util/test.c and src/sh/builtin.c.
 *
 * Known gap: this tree's mkdir() (src/stat/mkdir.c -> __plat_mkdir())
 * always applies `mode & ~umask()`, even for an explicit -m bit whose
 * who was given explicitly -- which chmod(1p)'s umask rule (see
 * modeparse.h) says should NOT be masked. Fixing that means reaching
 * into __plat_mkdir() itself; out of scope for this utility.
 */

/* This translation unit implements spicule's freestanding -nostdinc
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
#include "ownership_stubs.h" /* __ownership_string_terminated(): dirname() has no ownership annotations of its own, but always returns "." or a NUL it just wrote into its argument -- see src/misc/dirname.c */

/* Creates `path`, and with -p, any missing intermediate components too.
 * `leaf_mode` applies only to `path` itself; an intermediate gets the
 * default 0777-as-modified-by-umask, since neither mkdir(1p) nor
 * mkfifo(1p) specifies an automatically-created ancestor's mode. Returns
 * 0 on success (including "already existed as a directory" under
 * has_p), -1 with errno set otherwise. `path` is always null-terminated:
 * both call sites pass a buffer with a reachable NUL. */
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
		/* "." is the current directory, which always exists; anything
		 * else needs the same treatment, recursively. */
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
		/* elements_withtok(null_terminated, argc) proves NUL-termination
		 * but not nonnull-ness of argv[i] itself (true in practice, but
		 * not provable from an array-element read). */
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
		__ownership_string_terminated(argv[i]); /* elements_withtok's grant doesn't survive into this second loop */
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
