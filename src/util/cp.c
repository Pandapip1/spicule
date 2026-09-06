/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * cp(1p). Three SYNOPSIS forms are implemented:
 *   cp [-f] source_file target_file
 *   cp [-f] source_file... target_dir
 *   cp -R [-f] source_file... target
 *
 * Single-file form: "cp shall copy the contents of source_file (or, if
 * source_file is a file of type symbolic link, the contents of the file
 * referenced by source_file) to the destination path named by
 * target_file" -- so the source operand is looked up with stat(), not
 * lstat(): a symlink source is followed and its *referent's* bytes
 * become a new, ordinary file at the destination.  That is deliberately
 * different from -R's behaviour on a symlink found *inside* a tree
 * (see below).
 *
 * target_dir form ("source_file... target", target an existing
 * directory): each destination path is "the concatenation of target, a
 * single <slash> character if target did not end in a <slash>, and the
 * last component of source_file" -- __util_join_basename() (shared with
 * src/util/mv.c's identical construction).
 *
 * -R form: recursive tree copy via nftw() (src/ftw/ftw.c), FTW_PHYS so
 * a symbolic link inside the tree is reported as itself (FTW_SL) and
 * not followed, and *without* FTW_DEPTH so a directory is reported
 * before its contents -- required here, since the destination directory
 * has to exist before anything can be written into it.
 *
 * Deliberately out of scope, and refused loudly rather than silently
 * ignored (same "refuse unsupported options" reasoning as
 * src/sh/builtin.c's bi_set(), and src/util/rm.c's -i):
 *   -i  interactive overwrite confirmation -- no terminal-interaction
 *       story exists at this layer yet.
 *   -p  preserve mode/ownership/timestamps -- not implemented; every
 *       file this utility creates gets the platform's ordinary default
 *       create mode (0666, masked by umask -- see open()'s own umask
 *       handling), and every directory it creates gets 0777 likewise,
 *       regardless of the source's actual mode.  A silent partial -p
 *       (say, timestamps but not owner) would be a worse lie than an
 *       outright refusal.
 *   -H/-L/-P  control which symbolic links named *on the command line*
 *       (as opposed to inside a recursively-copied tree) are followed;
 *       not implemented, refused rather than guessed at.
 *
 * A symbolic link encountered *inside* a -R tree (as opposed to as a
 * top-level operand) is refused per-entry with a diagnostic rather than
 * silently skipped or silently dereferenced: cp(1p)'s exact behaviour
 * there depends on -H/-L/-P, none of which this build implements, and
 * guessing which one to emulate is exactly the "never guess when an
 * operation's real effect is ambiguous" case this project's utilities
 * keep refusing instead of getting quietly wrong.  Likewise FIFOs,
 * device nodes and sockets encountered in a tree: cp(1p) allows
 * recreating them "as implementation-defined", which this build declines
 * to attempt at all rather than inventing a policy the standard leaves
 * unspecified.
 *
 * cp(1p): "If source_file references the same file as dest_file, cp may
 * write a diagnostic message ... and shall do nothing more with
 * source_file."  This build takes that option: opening the destination
 * for writing before finishing the read would truncate the source out
 * from under itself if the two names refer to one file (st_dev/st_ino
 * match), so it is refused up front rather than risked.
 *
 * __util_copy_tree()'s path_is_under_or_same() also refuses copying a
 * directory into its own subtree (`cp -R foo foo/sub`) -- see that
 * function's own comment for the unbounded-growth hazard it closes and
 * the real limits of a purely textual check.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
#include "util.h"
#include "ownership_stubs.h"

/* ==== single regular file: open/read/write loop ======================== */

/* Copies one regular file's bytes from `src` to `dst` (creating or
 * truncating `dst`).  Shared by the single-file form, by -R's per-file
 * tree-walk callback below, and by src/util/mv.c's cross-filesystem
 * fallback. `force` is -f's cp(1p) meaning: "If a file descriptor for
 * dest_file cannot be obtained ... attempt to unlink dest_file and
 * proceed" -- retried once, on the destination *open* failing, not on
 * any later error. */
int __util_copy_regular_file(const char *src, const char *dst, int force)
{
	int in, out;
	char buf[65536];
	ssize_t n;

	in = open(src, O_RDONLY);
	if (in < 0) {
		__util_diagf("cp: cannot open '%s' for reading: %s\n", src, strerror(errno));
		return -1;
	}

	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (out < 0 && force) {
		unlink(dst);
		out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	}
	if (out < 0) {
		__util_diagf("cp: cannot create '%s': %s\n", dst, strerror(errno));
		(void)close(in);
		return -1;
	}

	while ((n = read(in, buf, sizeof buf)) > 0) {
		if ((size_t)n > sizeof buf) { errno = EIO; n = -1; break; }
		__ownership_readable_span(buf, (size_t)n);
		size_t off = 0;
		while (off < (size_t)n) {
			ssize_t w = write(out, buf + off, (size_t)n - off);
			if (w <= 0 || (size_t)w > (size_t)n - off) {
				if (w >= 0) errno = EIO;
				__util_diagf("cp: error writing to '%s': %s\n", dst, strerror(errno));
				(void)close(in);
				(void)close(out);
				return -1;
			}
			off += (size_t)w;
		}
	}
	if (n < 0) {
		__util_diagf("cp: error reading '%s': %s\n", src, strerror(errno));
		(void)close(in);
		(void)close(out);
		return -1;
	}
	(void)close(in);
	if (close(out) < 0) {
		__util_diagf("cp: error closing '%s': %s\n", dst, strerror(errno));
		return -1;
	}
	return 0;
}

/* ==== -R: a whole directory tree ======================================== */

/* See src/util/rm.c's header for why this state is file-scope rather
 * than threaded through nftw()'s callback: the same argument applies
 * here verbatim (one synchronous nftw() call per __util_copy_tree(),
 * nothing re-entrant). */
static const char *cpt_src_root;
static size_t cpt_src_root_len;
static const char *cpt_dst_root;
static int cpt_force;
static int cpt_tree_failed;

/* `srcpath` is always cpt_src_root itself, or cpt_src_root followed by
 * "/" and more path -- nftw() builds every path it reports by
 * appending "/name" to its parent, starting from the root it was
 * given, so this is guaranteed rather than merely assumed.  Returns a
 * freshly malloc'd string, or NULL (errno ENOMEM) on allocation
 * failure. */
withtok(heap_allocated)
static char *cpt_dst_path(const char *srcpath withtok(null_terminated))
{
	const char *rel = srcpath + cpt_src_root_len;
	size_t dstlen, rellen, bytes;
	char *out;
	int n;

	/* cpt_dst_root is set exactly once, from __util_copy_tree()'s own
	 * null_terminated `dst` parameter, before nftw() (and therefore this
	 * callback chain) ever runs -- see this file's file-scope-state
	 * comment above. rel is a suffix of srcpath, so it reaches exactly
	 * the same trailing NUL byte srcpath's own null_terminated contract
	 * already guarantees. Neither fact is visible to the checker across
	 * a static-global boundary or through pointer-offset arithmetic, so
	 * both are restated here the same way src/util/find.c's argv-derived
	 * locals restate theirs. */
	__ownership_string_terminated(cpt_dst_root);
	__ownership_string_terminated(rel);
	dstlen = strlen(cpt_dst_root);

	while (*rel == '/' || *rel == '\\') rel++;
	if (!*rel) return strdup(cpt_dst_root);

	rellen = strlen(rel);
	if (!__util_size_add(dstlen, rellen, &bytes) ||
	    !__util_size_add(bytes, 2, &bytes)) { errno = ENOMEM; return NULL; }
	out = malloc(bytes);
	if (!out) { errno = ENOMEM; return NULL; }
	n = snprintf(out, bytes, "%s/%s", cpt_dst_root, rel);
	if (n < 0 || (size_t)n >= bytes) {
		free(out);
		if (n >= 0) errno = EOVERFLOW;
		return NULL;
	}
	return out;
}

static int cpt_cb(const char *path, const struct stat *st, int type, struct FTW *ftwbuf)
{
	int saved_errno = errno;
	char *dstpath;

	(void)ftwbuf;
	dstpath = cpt_dst_path(path);
	if (!dstpath) {
		__util_diagf("cp: %s: %s\n", path, strerror(ENOMEM));
		cpt_tree_failed = 1;
		return 0;
	}

	switch (type) {
	case FTW_D: {
		struct stat existing;
		if (mkdir(dstpath, 0777) < 0 &&
		    !(errno == EEXIST && stat(dstpath, &existing) == 0 && S_ISDIR(existing.st_mode))) {
			__util_diagf("cp: cannot create directory '%s': %s\n", dstpath, strerror(errno));
			cpt_tree_failed = 1;
		}
		break;
	}
	case FTW_F:
		if (__util_copy_regular_file(path, dstpath, cpt_force) < 0) cpt_tree_failed = 1;
		break;
	case FTW_SL:
		/* See this file's header: which of -H/-L/-P to emulate for
		 * a link found mid-tree is genuinely ambiguous, and none of
		 * the three is implemented, so this is refused rather than
		 * guessed. */
		__util_diagf("cp: '%s': copying a symbolic link inside a directory "
		                "tree is not supported by this build\n", path);
		cpt_tree_failed = 1;
		break;
	case FTW_DNR:
		__util_diagf("cp: cannot read directory '%s': %s\n", path, strerror(saved_errno));
		cpt_tree_failed = 1;
		break;
	case FTW_NS:
		__util_diagf("cp: cannot stat '%s': %s\n", path, strerror(saved_errno));
		cpt_tree_failed = 1;
		break;
	default:
		/* FTW_DP never occurs: __util_copy_tree() does not pass
		 * FTW_DEPTH, so directories are reported once, pre-order,
		 * as FTW_D above. Anything else nftw() might one day report
		 * is a file type this build has no policy for -- see this
		 * file's header on FIFOs/devices/sockets. */
		__util_diagf("cp: '%s': not a regular file, directory or symbolic "
		                "link -- not supported by this build\n", path);
		cpt_tree_failed = 1;
		break;
	}

	(void)st;
	free(dstpath);
	return 0;
}

/* A best-effort, purely textual guard against the classic "copy a
 * directory into its own subtree" hazard: `cp -R foo foo/sub` (or
 * `cp -R foo foo` itself). Without it, nftw() creating a *destination*
 * entry underneath the very tree it is still reading the *source* from
 * risks that entry becoming visible to a not-yet-consumed readdir() on
 * an ancestor still open in the walk -- POSIX leaves "is an entry added
 * during a readdir() scan of its directory returned by a later
 * readdir() on that scan" unspecified, so this can, platform-dependently,
 * make the walk re-descend into what it just created and grow without
 * bound until the disk fills. This does not resolve symlinks, "..", or
 * two differently-spelled paths that name the same place -- only a
 * literal (case-insensitive, since NT pathnames are) prefix compare of
 * the two operands exactly as given. That is a real, stated gap, not a
 * silent guarantee: it catches the direct and by far the most likely
 * accidental case rather than every disguised one. */
static int path_is_under_or_same(const char *child, const char *parent withtok(null_terminated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t plen = strlen(parent);
	size_t i;

	for (i = 0; i < plen; i++) {
		char a = child[i], b = parent[i];
		if (a >= 'A' && a <= 'Z') a += 32;
		if (b >= 'A' && b <= 'Z') b += 32;
		if (a == '\\') a = '/';
		if (b == '\\') b = '/';
		if (a != b) return 0;
	}
	return child[plen] == 0 || child[plen] == '/' || child[plen] == '\\';
}

/* Recursively copies the tree rooted at `src` to `dst` (which becomes
 * the copy's own root -- callers that need "into an existing directory"
 * semantics build that destination with __util_join_basename() first,
 * exactly as __util_cp_main() and src/util/mv.c do).  Returns 0 if
 * every entry was copied, -1 (diagnostics already written) otherwise. */
int __util_copy_tree(const char *src withtok(null_terminated), const char *dst withtok(null_terminated), int force)
{
	if (path_is_under_or_same(dst, src)) {
		__util_diagf("cp: cannot copy '%s' into itself, '%s'\n", src, dst);
		return -1;
	}

	cpt_src_root = src;
	cpt_src_root_len = strlen(src);
	cpt_dst_root = dst;
	cpt_force = force;
	cpt_tree_failed = 0;

	if (nftw(src, cpt_cb, 15, FTW_PHYS) < 0) {
		__util_diagf("cp: cannot copy '%s': %s\n", src, strerror(errno));
		return -1;
	}
	return cpt_tree_failed ? -1 : 0;
}

/* ==== "target/basename(source)", shared with src/util/mv.c ============= */

withtok(heap_allocated) withtok(null_terminated) __attribute__((nonnull(1, 2)))
char *__util_join_basename(const char *dir withtok(null_terminated), const char *src withtok(null_terminated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char *srccopy = strdup(src);
	char *base, *out;
	size_t dirlen, need;
	int need_slash, n;

	if (!srccopy) return NULL;
	base = basename(srccopy);   /* libgen.h; may write into srccopy */
	/* basename() returns a pointer either into srccopy itself (already
	 * established null_terminated by strdup()'s own return contract) or
	 * to its own internal static string -- either way a real C string;
	 * not visible to the checker since libgen.h's basename() is an
	 * opaque external declaration with no ownership contract of its
	 * own. */
	__ownership_string_terminated(base);
	dirlen = strlen(dir);
	need_slash = dirlen > 0 && dir[dirlen - 1] != '/' && dir[dirlen - 1] != '\\';

	need = dirlen + (need_slash ? 1 : 0) + strlen(base) + 1;
	out = malloc(need);
	if (out) {
		n = snprintf(out, need, need_slash ? "%s/%s" : "%s%s", dir, base);
		if (n < 0 || (size_t)n >= need) {
			free(out);
			out = NULL;
			if (n >= 0) errno = EOVERFLOW;
		} else {
			/* snprintf() is deliberately not itself annotated to grant
			 * null_terminated (see include/stdio.h's own comment on why
			 * its buffer argument isn't marked at all), but a successful,
			 * non-truncated call like this one always NUL-terminates --
			 * restate that fact the same way src/util/pax.c's namebuf
			 * does after its own snprintf() success check. */
			__ownership_string_terminated(out);
		}
	}
	free(srccopy);
	return out;
}

/* ==== dispatch: one operand ============================================= */

static int cp_one(const char *src withtok(null_terminated), const char *dst withtok(null_terminated), int recursive, int force) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct stat sst, dst_st;

	if (stat(src, &sst) < 0) {
		__util_diagf("cp: cannot stat '%s': %s\n", src, strerror(errno));
		return -1;
	}

	if (stat(dst, &dst_st) == 0 && dst_st.st_dev == sst.st_dev && dst_st.st_ino == sst.st_ino) {
		__util_diagf("cp: '%s' and '%s' are the same file\n", src, dst);
		return -1;
	}

	if (S_ISDIR(sst.st_mode)) {
		if (!recursive) {
			__util_diagf("cp: -R not specified; omitting directory '%s'\n", src);
			return -1;
		}
		return __util_copy_tree(src, dst, force);
	}
	return __util_copy_regular_file(src, dst, force);
}

int __util_cp_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int recursive = 0, force = 0;
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

		/* a is one of argv's own elements (i < nargs <= argc); restate
		 * the argv-wide null-terminated guarantee here, the same way
		 * src/util/find.c/test.c restate theirs right after a copy out
		 * of an elements_withtok(null_terminated, argc)-carrying array
		 * -- a plain local like `a` reused across loop iterations is
		 * not something the checker can see through automatically. */
		__ownership_string_terminated(a);

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }

		for (p = a + 1; *p; p++) {
			if (*p == 'r' || *p == 'R') { recursive = 1; continue; }
			if (*p == 'f') { force = 1; continue; }
			if (*p == 'i' || *p == 'p' || *p == 'H' || *p == 'L' || *p == 'P') {
				__util_diagf("cp: -%c: not supported by this build; "
				                "refusing rather than silently ignoring it "
				                "(see src/util/cp.c)\n", *p);
				return 2;
			}
			__util_diagf("cp: invalid option -- '%c'\n", *p);
			return 2;
		}
	}

	noperands = i < nargs ? nargs - i : 0;
	if (noperands < 2) {
		__util_diagf("cp: missing %s\n",
			noperands == 0 ? "operand" : "destination operand");
		return 2;
	}

	target = argv[nargs - 1];
	/* Also an argv element (nargs - 1 < nargs <= argc); restated for the
	 * same reason `a` above is -- it later crosses into
	 * __util_join_basename()'s and cp_one()'s own null_terminated
	 * parameters. */
	__ownership_string_terminated(target);
	target_is_dir = stat(target, &tst) == 0 && S_ISDIR(tst.st_mode);

	if (noperands > 2 && !target_is_dir) {
		/* cp(1p) OPERANDS: "It shall be an error if ... target does
		 * not name a directory" once more than one source_file is
		 * given. */
		__util_diagf("cp: target '%s' is not a directory\n", target);
		return 2;
	}

	for (; i < nargs - 1; i++) {
		const char *src = argv[i];

		/* Same argv-element restatement as `a`/`target` above: src
		 * crosses into __util_join_basename()'s and cp_one()'s own
		 * null_terminated parameters below. */
		__ownership_string_terminated(src);

		if (target_is_dir) {
			char *dst = __util_join_basename(target, src);
			if (!dst) {
				__util_diagf("cp: %s: %s\n", src, strerror(ENOMEM));
				had_error = 1;
				continue;
			}
			if (cp_one(src, dst, recursive, force) < 0) had_error = 1;
			free(dst);
		} else {
			if (cp_one(src, target, recursive, force) < 0) had_error = 1;
		}
	}

	return had_error ? 1 : 0;
}
