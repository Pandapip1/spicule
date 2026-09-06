/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ftw()/nftw(): a recursion driver over opendir/readdir (src/dirent/)
 * and stat/lstat (src/stat/) -- nothing here is NT-specific.
 *
 * nopenfd: naively opening one DIR per level and recursing would hold
 * as many directory streams open at once as the walk is deep, with no
 * bound at all.  Instead, every currently-open ancestor DIR is kept on
 * an LRU list (struct walkstate's lru_head/lru_tail); opening one more
 * than nopenfd allows closes the least-recently-used ancestor first,
 * remembering its position with telldir().  When the walk returns to
 * that ancestor to keep reading its entries, it is reopened with
 * opendir() and replayed back to that position with seekdir() --
 * exactly the classic historical ftw() trick (also used by 4.4BSD and
 * glibc's implementations) for honouring nopenfd without limiting how
 * deep the tree may go.
 *
 * FTW_MOUNT / st_dev: src/stat/stat.c sets st_dev from
 * FILE_FS_VOLUME_INFORMATION's VolumeSerialNumber, a real, distinct
 * value per NTFS volume -- so "same file system as path" has a real,
 * working test here (root_dev, captured from the first stat() of the
 * walk's own root, compared against every subsequent entry). This is
 * not N/A on this platform.
 *
 * Directories that would be descendants of themselves: with FTW_PHYS
 * clear the walk follows links, so a link back up the tree makes a
 * directory its own descendant and the recursion never terminates.
 * nftw.html requires that case be cut off, so every directory the
 * recursion has entered keeps its (st_dev, st_ino) on a stack threaded
 * through walk()'s own `anc` parameter, and a directory whose pair is
 * already on it is not descended into.  The pair is the identity
 * stat.html specifies ("st_ino together with st_dev uniquely identify
 * the file"), and both halves are real here -- st_dev is the volume
 * serial number FTW_MOUNT above already relies on, and st_ino is
 * FileInternalInformation's IndexNumber (src/stat/stat.c).  Only the
 * path is remembered, not every directory ever seen: the requirement is
 * "descendant of itself", so two different links to one directory in
 * unrelated branches are both walked, as they must be.
 *
 * FTW_CHDIR: built directly on chdir() (src/unistd/chdir.c).  Every
 * pathname the recursion carries is relative to the walk's *original*
 * cwd -- each recursive call appends "/name" to its parent's path, and
 * that is also the pathname the callback must be handed -- so once the
 * walk has chdir'd into a directory, none of those names mean what they
 * did any more.  resolve() therefore rewrites every one of them against
 * the cwd captured before the first chdir(), and it is used for *all*
 * of the walk's filesystem access (chdir, lstat, stat, opendir), not
 * just the chdir; see its comment.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <ftw.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include "libc.h"
#include "ownership_stubs.h"

struct level {
	struct level *lru_prev, *lru_next;	/* only meaningful while dp != NULL */
	DIR *dp;
	long pos;		/* telldir() position, valid while dp == NULL and pos != 0 */
	char *path;
};

/* One entry per directory the recursion is currently inside, innermost
 * first.  Each frame lives on the walk() invocation that pushed it and
 * is passed down as an argument rather than parked in struct walkstate,
 * so the chain is exactly as deep as the recursion, unwinds with it, and
 * needs no cleanup on any error return -- and no pointer to a stack
 * frame ever outlives the call that owns it. */
struct ancestor {
	const struct ancestor *up;
	dev_t dev;
	ino_t ino;
};

struct walkstate {
	int nopenfd;
	int open_count;
	int flags;
	int legacy;		/* ftw(): never report FTW_SL/FTW_SLN/FTW_DP */
	int have_root_dev;
	dev_t root_dev;
	char *cwd0;		/* FTW_CHDIR only: process cwd when the walk started */
	int cwd_moved;		/* FTW_CHDIR only: a descendant chdir'd away from this level */
	int (*fn3)(const char *, const struct stat *, int);
	int (*fn4)(const char *, const struct stat *, int, struct FTW *);
};

/* Rewrite one of the walk's accumulated pathnames into something the
 * filesystem can still be asked about after FTW_CHDIR has moved the
 * process. Every such pathname is relative to the cwd the walk started
 * in (walk() appends "/name" to its parent's path), so once the process
 * has chdir'd into "tailtree", asking about "tailtree/f1" resolves to
 * "tailtree/tailtree/f1" -- lstat() fails, the entry is reported FTW_NS,
 * and a directory mis-typed that way is never descended into. Resolving
 * against the cwd captured once, before the walk's first chdir(), fixes
 * that no matter how deep the recursion has gone or how many directories
 * it has already entered.
 *
 * cwd0 is non-NULL only for an FTW_CHDIR walk, so this is a no-op (and
 * allocates nothing) for every other walk. Absolute-path test is the one
 * __ntpath_at() (src/internal/path.c) uses: a leading slash/backslash,
 * or an "X:" drive letter.
 *
 * Returns the pathname to use, or NULL with errno set on allocation
 * failure. *tmp gets the allocation the caller must free, or NULL when
 * the returned pointer is `path` itself. */
static const char *resolve(struct walkstate *ws, const char *path, char **tmp)
{
	const char *cwd = ws->cwd0;
	int absolute = path[0] == '/' || path[0] == '\\' ||
		(((path[0] | 0x20) >= 'a' && (path[0] | 0x20) <= 'z') && path[1] == ':');
	size_t l0, l1, total;
	char *restrict full;

	*tmp = NULL;
	if (absolute || !cwd) return path;

	l0 = strlen(cwd);
	l1 = strlen(path);
	if (!__size_add_checked(l0, 1, &total) ||
	    !__size_add_checked(total, l1, &total) ||
	    !__size_add_checked(total, 1, &total)) { errno = ENOMEM; return NULL; }
	full = malloc(total);
	if (!full) { errno = ENOMEM; return NULL; }
	snprintf(full, total, "%s/%s", cwd, path);
	*tmp = full;
	return full;
}

/* FTW_CHDIR: "change the current working directory to each directory as
 * it reports files in that directory" (nftw.html). */
static int enter_dir(struct walkstate *ws, const char *path)
{
	char *tmp;
	const char *p = resolve(ws, path, &tmp);
	int r;

	if (!p) return -1;
	r = chdir(p);
	free(tmp);
	return r;
}

/* Head/tail are tracked via two file-scope pointers threaded through the
 * recursion by argument rather than true globals, so a nested/recursive
 * call from within a callback (unusual, but not forbidden) cannot
 * corrupt an in-progress outer walk's bookkeeping. */
struct lru {
	struct level *head, *tail;
};

static void lru_unlink(struct lru *lru, struct level *lv)
{
	if (lv->lru_prev) lv->lru_prev->lru_next = lv->lru_next; else if (lru->head == lv) lru->head = lv->lru_next;
	if (lv->lru_next) lv->lru_next->lru_prev = lv->lru_prev; else if (lru->tail == lv) lru->tail = lv->lru_prev;
	lv->lru_prev = lv->lru_next = NULL;
}

static void lru_push_tail(struct lru *lru, struct level *lv)
{
	lv->lru_prev = lru->tail;
	lv->lru_next = NULL;
	if (lru->tail) lru->tail->lru_next = lv; else lru->head = lv;
	lru->tail = lv;
}

static int close_one(struct walkstate *ws, struct lru *lru, struct level *lv)
{
	lv->pos = telldir(lv->dp);
	(void)closedir(lv->dp);
	lv->dp = NULL;
	lru_unlink(lru, lv);
	if (ws->open_count <= 0) {
		errno = EOVERFLOW;
		return -1;
	}
	ws->open_count--;
	return 0;
}

/* Reopen lv if it is currently closed, evicting the LRU ancestor first
 * if that would exceed nopenfd.  Returns 0 on success, -1 with errno
 * set (from opendir()) on failure. */
static int level_open(struct walkstate *ws, struct lru *lru, struct level *lv)
{
	char *tmp;
	const char *p;

	if (lv->dp) return 0;
	if (ws->nopenfd >= 1 && ws->open_count >= ws->nopenfd && lru->head) {
		if (close_one(ws, lru, lru->head) < 0) return -1;
	}
	if (ws->open_count < 0 || ws->open_count >= INT_MAX) {
		errno = EMFILE;
		return -1;
	}
	/* lv->path is an accumulated walk path, so an FTW_CHDIR walk has to
	 * resolve it too -- this reopen happens *after* the process has
	 * chdir'd into a descendant. */
	p = resolve(ws, lv->path, &tmp);
	if (!p) return -1;
	lv->dp = opendir(p);
	free(tmp);
	if (!lv->dp) return -1;
	if (lv->pos) seekdir(lv->dp, lv->pos);
	ws->open_count = (int)((unsigned)ws->open_count + 1U);
	lru_push_tail(lru, lv);
	return 0;
}

static int base_offset(const char *path)
{
	const char *slash = strrchr(path, '/');
	size_t offset;

	if (!slash) return 0;
	offset = strlen(path) - strlen(slash + 1);
	if (offset > INT_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	return (int)offset;
}

static int report(struct walkstate *ws, const char *path, const struct stat *st, int type, int level) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct FTW f;
	int saved_errno, r;

	if (ws->legacy && (type == FTW_SLN || type == FTW_SL || type == FTW_DP))
		type = (type == FTW_SL) ? FTW_NS : (type == FTW_SLN ? FTW_NS : FTW_D);

	if (ws->fn3) return ws->fn3(path, st, type);
	f.base = base_offset(path);
	if (f.base < 0) return -1;
	f.level = level;
	saved_errno = errno;
	r = ws->fn4(path, st, type, &f);
	if (r == -1 && errno == saved_errno) errno = EACCES;
	return r;
}

static int mount_skip(struct walkstate *ws, const struct stat *st)
{
	if (!(ws->flags & FTW_MOUNT)) return 0;
	if (!ws->have_root_dev) { ws->root_dev = st->st_dev; ws->have_root_dev = 1; return 0; }
	return st->st_dev != ws->root_dev;
}

/* Is `st` one of the directories the recursion is already inside -- i.e.
 * would descending into it make it a descendant of itself?
 *
 * Only asked when FTW_PHYS is clear, which is the only case nftw.html
 * imposes the requirement for and the only case that can produce the
 * cycle: with FTW_PHYS set, a link is reported (FTW_SL) rather than
 * followed, so the walk never leaves the one directory hierarchy it was
 * given.  Leaving FTW_PHYS alone is also what keeps it usable as the
 * escape hatch a caller reaches for when it wants the links themselves. */
static int is_own_ancestor(const struct ancestor *anc, const struct stat *st)
{
	const struct ancestor *a;

	for (a = anc; a; a = a->up)
		if (a->ino == st->st_ino && a->dev == st->st_dev) return 1;
	return 0;
}

// NOLINTNEXTLINE(misc-no-recursion) -- the directory walk mirrors the filesystem hierarchy and is path-depth bounded
static int walk(struct walkstate *ws, struct lru *lru, const char *path, int level, int is_root, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
		const struct ancestor *anc)
{
	struct stat lst, st, zero;
	const struct stat *rst;
	const char *fs;
	char *fstmp;
	int type, r;

	/* Everything below asks the filesystem about `fs` and tells the
	 * callback about `path`: the two differ only for an FTW_CHDIR walk,
	 * which has moved the process out from under `path`. */
	fs = resolve(ws, path, &fstmp);
	if (!fs) return -1;

	if (lstat(fs, &lst) < 0) {
		int e = errno;
		free(fstmp);
		errno = e;
		/* ftw.html ERRORS: "[ENOENT] A component of path does not name
		 * an existing file or path is an empty string" -- for the
		 * walk's own root this is ftw()/nftw() itself failing (-1,
		 * errno left as lstat() set it), not something routed through
		 * the callback as FTW_NS. A descendant discovered by readdir()
		 * that later turns out unstatable (e.g. removed mid-walk) is
		 * exactly what FTW_NS is for, so only the root is special. */
		if (is_root) return -1;
		if (e != EACCES) return -1;
		memset(&zero, 0, sizeof zero);
		return report(ws, path, &zero, FTW_NS, level);
	}

	if (ws->flags & FTW_PHYS) {
		rst = &lst;
		type = S_ISLNK(lst.st_mode) ? FTW_SL : S_ISDIR(lst.st_mode) ? FTW_D : FTW_F;
	} else if (stat(fs, &st) < 0) {
		int e = errno;
		free(fstmp);
		if (S_ISLNK(lst.st_mode)) return report(ws, path, &lst, FTW_SLN, level);
		if (e != EACCES) { errno = e; return -1; }
		errno = e;
		return report(ws, path, &lst, FTW_NS, level);
	} else {
		rst = &st;
		type = S_ISDIR(st.st_mode) ? FTW_D : FTW_F;
	}
	free(fstmp);

	if (mount_skip(ws, rst)) return 0;

	if (type != FTW_D) return report(ws, path, rst, type, level);

	/* nftw.html, both halves: "If FTW_PHYS is clear and FTW_DEPTH is
	 * set, nftw() shall follow links instead of reporting them, but
	 * shall not report any directory that would be a descendant of
	 * itself.  If FTW_PHYS is clear and FTW_DEPTH is clear, nftw()
	 * shall follow links instead of reporting them, but shall not
	 * report the contents of any directory that would be a descendant
	 * of itself."  The two differ in what survives: with FTW_DEPTH
	 * clear the directory is still reported (as FTW_D, which is where
	 * it would have been reported anyway, before its contents), and
	 * only the descent is dropped; with FTW_DEPTH set the only report
	 * it would ever get is the FTW_DP that comes *after* its contents,
	 * and that one the clause forbids outright. */
	if (!(ws->flags & FTW_PHYS) && is_own_ancestor(anc, rst))
		return (ws->flags & FTW_DEPTH) ? 0 : report(ws, path, rst, FTW_D, level);

	/* Directory: FTW_DEPTH reports it last (FTW_DP), after every entry;
	 * otherwise report it first, as FTW_D, before descending. */
	if (!(ws->flags & FTW_DEPTH)) {
		r = report(ws, path, rst, FTW_D, level);
		if (r) return r;
	}

	{
		struct level lv;
		struct ancestor here;
		struct dirent *de;
		size_t plen = strlen(path);
		int had_trailing_slash = plen > 0 && path[plen - 1] == '/';

		lv.lru_prev = lv.lru_next = NULL;
		lv.dp = NULL;
		lv.pos = 0;
		lv.path = strdup(path);
		if (!lv.path) { errno = ENOMEM; return -1; }

		if (level_open(ws, lru, &lv) < 0) {
			int e = errno;
			free(lv.path);
			if (e != EACCES) { errno = e; return -1; }
			errno = e;
			return report(ws, path, rst, FTW_DNR, level);
		}

		/* On the path from here down, so is_own_ancestor() can see it.
		 * Pushed only once the descent is really going to happen: a
		 * directory reported FTW_DNR is never entered, and one left on
		 * the chain after that would make a *sibling* of the same
		 * inode look like a cycle. */
		here.dev = rst->st_dev;
		here.ino = rst->st_ino;
		here.up = anc;

		if (ws->flags & FTW_CHDIR) { enter_dir(ws, path); ws->cwd_moved = 0; }

		r = 0;
		while ((de = readdir(lv.dp)) != NULL) {
			const char *name = de->d_name;
			char *restrict child;
			size_t clen, namelen, off, separator;

			/* readdir() returns a fixed struct dirent.  Validate its name
			 * within that physical member before traversing or copying it. */
			namelen = strnlen(de->d_name, sizeof de->d_name);
			if (namelen == sizeof de->d_name) { r = -1; errno = EIO; break; }
			if ((namelen == 1 && de->d_name[0] == '.') ||
			    (namelen == 2 && de->d_name[0] == '.' &&
			     de->d_name[1] == '.')) continue;

			separator = had_trailing_slash ? 0 : 1;
			if (plen > (size_t)-1 - separator) {
				r = -1; errno = ENOMEM; break;
			}
			off = plen + separator;
			if (namelen > (size_t)-1 - off) {
				r = -1; errno = ENOMEM; break;
			}
			clen = off + namelen;
			if (clen == (size_t)-1) { r = -1; errno = ENOMEM; break; }
			clen++;
			child = malloc(clen);
			if (!child) { r = -1; errno = ENOMEM; break; }
			snprintf(child, clen, "%s%s%s", path,
			    separator ? "/" : "", name);

			/* level_open() may have closed lv.dp to make room for a
			 * descendant's own directory; reopen (and replay via
			 * seekdir()) right before the next readdir() needs it. */
			r = walk(ws, lru, child, level + 1, 0, &here);
			free(child);
			if (r) break;

			/* "as it reports files in that directory": a child that
			 * was itself a directory left the process standing in it,
			 * so come back here before reporting the next sibling --
			 * otherwise the whole point of FTW_CHDIR, that fn can use
			 * path+base as-is, holds only until the first descent. */
			if (ws->cwd_moved) { enter_dir(ws, path); ws->cwd_moved = 0; }

			if (level_open(ws, lru, &lv) < 0) { r = -1; break; }
		}

		/* Tell the level above that the cwd is no longer its own. */
		if (ws->flags & FTW_CHDIR) ws->cwd_moved = 1;

		if (lv.dp && close_one(ws, lru, &lv) < 0 && !r) r = -1;
		free(lv.path);
		if (r) return r;
	}

	if (ws->flags & FTW_DEPTH)
		return report(ws, path, rst, FTW_DP, level);
	return 0;
}

int ftw(const char *path, int (*fn)(const char *, const struct stat *, int), int nopenfd)
{
	struct walkstate ws;
	struct lru lru;

	if (!path || !*path) { errno = ENOENT; return -1; }

	memset(&ws, 0, sizeof ws);
	ws.nopenfd = nopenfd;
	ws.fn3 = fn;
	ws.legacy = 1;
	lru.head = lru.tail = NULL;

	return walk(&ws, &lru, path, 0, 1, NULL);
}

int nftw(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *),
	 int nopenfd, int flags) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct walkstate ws;
	struct lru lru;

	if (!path || !*path) { errno = ENOENT; return -1; }

	memset(&ws, 0, sizeof ws);
	ws.nopenfd = nopenfd;
	ws.flags = flags;
	ws.fn4 = fn;
	lru.head = lru.tail = NULL;

	if (flags & FTW_CHDIR) {
		/* getcwd()'s own required "grow the buffer until it fits"
		 * loop (getcwd.html: no fixed size may be assumed) rather
		 * than a single fixed-size guess. */
		size_t cap = 256;
		for (;;) {
			char *buf = malloc(cap);
			if (!buf) break;
			if (getcwd(buf, cap)) { ws.cwd0 = buf; break; }
			free(buf);
			if (errno != ERANGE) break;
			{
				size_t next;
				if (!__array_next_capacity(cap, cap, 1, 256, 1, &next)) {
					errno = ENOMEM;
					break;
				}
				cap = next;
			}
		}
		if (!ws.cwd0) return -1;
	}

	{
		int r = walk(&ws, &lru, path, 0, 1, NULL);
		int saved = errno;

		/* FTW_CHDIR may leave walk() in any directory it visited, but the
		 * caller's working directory must be restored before nftw() returns.
		 * A restoration failure becomes the result only when the walk itself
		 * succeeded; otherwise retain the original failure and its errno. */
		if (ws.cwd0 && chdir(ws.cwd0) < 0) {
			if (r != 0) errno = saved;
			else r = -1;
		} else if (r != 0) {
			errno = saved;
		}
		free(ws.cwd0);
		return r;
	}
}

// NOLINTEND(misc-include-cleaner)
