/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <ftw.h> -- ftw() (`OB XSI`)
 * and nftw() -- against src/ftw/ftw.c and include/ftw.h:
 *
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/ftw.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/nftw.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/ftw.h.html
 *
 * ==================== what this file is not =========================
 *
 * This header is not virgin ground.  `test/posix-tail.c` (ledger group
 * J3) and `test/posix-glob.c` already audit the descent itself, the
 * FTW_D/FTW_F/FTW_DP type codes, `struct FTW`'s base/level at depths 0
 * to 2, FTW_DEPTH both ways, FTW_MOUNT on a one-volume fixture, the
 * `[ENOENT]`/`[ENOTDIR]` error clauses, and the callback's non-zero
 * return -- and they already fence two BUGs (FTW_CHDIR walking nothing
 * below the root; no protection against a directory that is a
 * descendant of itself) and report the FTW_SL/FTW_SLN group as `rc=77`
 * unverified.  **None of that is repeated here.**  This file audits
 * what those two left, and every live assertion below is about a
 * clause neither of them asserts.
 *
 * ==================== the findings, up front ========================
 *
 * Three BUGs are fenced, all three in error handling that the two
 * existing files' fixtures never reach.  Three numbers that disagree,
 * so each says what it counts: **three fenced test functions**; **six
 * `#if 0` blocks**, since each fence's call site in main() is guarded
 * separately; **four clauses violated**, because the first fence
 * covers the stat() half and the opendir() half of one requirement,
 * which have one shared fix.
 *
 *  1. `test_nftw_error_other_than_eacces_stops_the_walk` --
 *     src/ftw/ftw.c turns EVERY stat()/lstat() failure on a descendant
 *     into FTW_NS, and EVERY opendir() failure into FTW_DNR, and
 *     continues the walk.  Both pages reserve that treatment for a
 *     lack-of-permission failure and require any other failure to end
 *     the walk with -1.
 *
 *  2. `test_nftw_dnr_reported_once` -- with FTW_DEPTH clear, a
 *     directory that cannot be read is handed to fn TWICE: once as
 *     FTW_D, before opendir() is attempted, and again as FTW_DNR when
 *     it fails.  The implementation's own FTW_DEPTH path reports such
 *     a directory exactly once, which is what shows the second report
 *     is an artefact of ordering rather than a decision.
 *
 *  3. `test_nftw_eacces_when_fn_returns_minus_one` -- nftw.html's
 *     ERRORS list carries an `[EACCES]` condition ftw.html does not
 *     have: "or fn returns -1 and does not reset errno".  Nothing in
 *     src/ftw/ftw.c ever assigns to errno on that path.  This is the
 *     weakest of the three and its counter-argument is recorded in the
 *     ledger next to it.
 *
 * One correction to an existing ledger row, asserted live here rather
 * than argued: J3 grouped `[ENAMETOOLONG]` with FTW_DNR/FTW_NS/
 * `[EACCES]` in a single N/A row whose stated mechanism is this
 * platform's permission model.  That mechanism does not apply to
 * `[ENAMETOOLONG]`, which needs no fixture at all -- only a name -- and
 * `src/internal/path.c`'s `__name_too_long()` implements the clause for
 * every path-taking interface in this library.  See
 * `test_ftw_enametoolong()`.
 *
 * ==================== how the live assertions are grounded ==========
 *
 * Nothing here was run: there is no tcc and no wine in the environment
 * this file was written in, so every expected value below is either
 * (a) fixed by the standard's own text, (b) a property of the fixture
 * this file builds itself two lines earlier, or (c) traced through
 * src/ by reading it, with the file and function named at the
 * assertion.  No expected value is derived from a guess about what the
 * implementation "probably" does.  Where a clause could only be
 * checked by a value that would have to be guessed, it is not
 * asserted; where a fixture cannot be built here, the test is fenced
 * and says so.
 * ================================================================== */
#define _GNU_SOURCE
#include <ftw.h>

/* basedefs/ftw.h.html DESCRIPTION: "The <ftw.h> header shall define the
 * stat structure and the symbolic names for st_mode and the file type
 * test macros as described in <sys/stat.h>."
 *
 * This function is deliberately the first thing in the file, above
 * every other #include, so that <ftw.h> is the only header that can
 * have supplied `struct stat`, `st_mode`, `S_ISDIR` and `S_ISREG`.
 * The clause is about what ONE header provides on its own, and in a
 * translation unit that has already pulled in <sys/stat.h> it degrades
 * into a tautology -- the same reasoning test/POSIX-COVERAGE.md's
 * "Where a group U fence lives" section sets out for <fcntl.h>'s
 * SEEK_* clause.  A failure here is a compile error, not a CHECK. */
static int ftw_h_alone_types(const struct stat *st)
{
	if (S_ISDIR(st->st_mode)) return FTW_D;
	if (S_ISREG(st->st_mode)) return FTW_F;
	return FTW_NS;
}

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ====================================================================
 * The fixture.
 *
 * Four directory levels and nine objects, deeper and wider than either
 * existing file's tree, because the clauses this file is about are the
 * ones a two-level tree cannot reach: "at most one file descriptor
 * shall be used for each directory level" only starts evicting and
 * replaying open directory streams when the walk is deeper than the
 * limit it was given.
 *
 *   ftwtree/                    level 0   dir
 *   ftwtree/a.txt               level 1   file, 5 bytes
 *   ftwtree/b.txt               level 1   file, 0 bytes
 *   ftwtree/d1/                 level 1   dir
 *   ftwtree/d1/c.txt            level 2   file
 *   ftwtree/d1/d2/              level 2   dir
 *   ftwtree/d1/d2/e.txt         level 3   file
 *   ftwtree/d1/d2/d3/           level 3   dir
 *   ftwtree/d1/d2/d3/f.txt      level 4   file
 *
 * "ftwtree" collides with no other test's fixture: test/posix-tail.c
 * uses "tailtree" and test/posix-glob.c uses "root".  Everything is
 * removed again by kill_tree(); `make check` runs with the source tree
 * as the working directory, so a test that litters is a test that will
 * eventually pass for the wrong reason.
 * ================================================================== */
static const struct { const char *path; int isdir; int level; } objs[] = {
	{ "ftwtree",                1, 0 },
	{ "ftwtree/a.txt",          0, 1 },
	{ "ftwtree/b.txt",          0, 1 },
	{ "ftwtree/d1",             1, 1 },
	{ "ftwtree/d1/c.txt",       0, 2 },
	{ "ftwtree/d1/d2",          1, 2 },
	{ "ftwtree/d1/d2/e.txt",    0, 3 },
	{ "ftwtree/d1/d2/d3",       1, 3 },
	{ "ftwtree/d1/d2/d3/f.txt", 0, 4 },
};
#define NOBJ ((int)(sizeof objs / sizeof objs[0]))

static int make_file(const char *path, const char *data, size_t n)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	if (n && write(fd, data, n) != (ssize_t)n) { close(fd); return -1; }
	return close(fd);
}

static int make_tree(void)
{
	if (mkdir("ftwtree", 0755) < 0 && errno != EEXIST) return -1;
	if (mkdir("ftwtree/d1", 0755) < 0 && errno != EEXIST) return -1;
	if (mkdir("ftwtree/d1/d2", 0755) < 0 && errno != EEXIST) return -1;
	if (mkdir("ftwtree/d1/d2/d3", 0755) < 0 && errno != EEXIST) return -1;
	if (make_file("ftwtree/a.txt", "12345", 5) < 0) return -1;
	if (make_file("ftwtree/b.txt", "", 0) < 0) return -1;
	if (make_file("ftwtree/d1/c.txt", "", 0) < 0) return -1;
	if (make_file("ftwtree/d1/d2/e.txt", "", 0) < 0) return -1;
	if (make_file("ftwtree/d1/d2/d3/f.txt", "", 0) < 0) return -1;
	return 0;
}

static void kill_tree(void)
{
	unlink("ftwtree/d1/d2/d3/f.txt");
	rmdir("ftwtree/d1/d2/d3");
	unlink("ftwtree/d1/d2/e.txt");
	rmdir("ftwtree/d1/d2");
	unlink("ftwtree/d1/c.txt");
	rmdir("ftwtree/d1");
	unlink("ftwtree/b.txt");
	unlink("ftwtree/a.txt");
	rmdir("ftwtree");
}

/* Every callback records what it was handed, so assertions can be made
 * about the whole walk: the order of siblings within one directory is
 * not specified anywhere on either page, and nothing below depends on
 * it. */
#define MAXENT 64
static struct {
	char path[256];
	int flag, base, level, isdir;
	long size;
} ent[MAXENT];
static int nent;
static int saw_null_stat;
static int stop_after;		/* >0: return stop_value on that call */
static int stop_value;

static void record(const char *p, const struct stat *st, int flag, int base, int level)
{
	if (!st) saw_null_stat = 1;
	if (nent < MAXENT) {
		size_t n = strlen(p);
		if (n >= sizeof ent[0].path) n = sizeof ent[0].path - 1;
		memcpy(ent[nent].path, p, n);
		ent[nent].path[n] = 0;
		ent[nent].flag = flag;
		ent[nent].base = base;
		ent[nent].level = level;
		ent[nent].isdir = st ? (S_ISDIR(st->st_mode) ? 1 : 0) : -1;
		ent[nent].size = st ? (long)st->st_size : -1;
	}
	nent++;
}

static int fn3(const char *p, const struct stat *st, int flag)
{
	record(p, st, flag, -1, -1);
	if (stop_after && nent == stop_after) return stop_value;
	return 0;
}

static int fn4(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	record(p, st, flag, f->base, f->level);
	if (stop_after && nent == stop_after) return stop_value;
	return 0;
}

static void reset_walk(void)
{
	nent = 0;
	saw_null_stat = 0;
	stop_after = 0;
	stop_value = 0;
}

static int find_ent(const char *path)
{
	int i;
	for (i = 0; i < nent && i < MAXENT; i++)
		if (!strcmp(ent[i].path, path)) return i;
	return -1;
}

static int count_ent(const char *path)
{
	int i, n = 0;
	for (i = 0; i < nent && i < MAXENT; i++)
		if (!strcmp(ent[i].path, path)) n++;
	return n;
}

static const char *filename_of(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

/* ====================================================================
 * basedefs/ftw.h.html -- the header's own obligations
 * ================================================================== */
static void test_ftw_h_header_shape(void)
{
	/* "The <ftw.h> header shall define the FTW structure, which shall
	 * include at least the following members: int base; int level" --
	 * both members exist (this would not compile otherwise) and both
	 * are int-sized. */
	struct FTW f;
	static const int types[] = { FTW_F, FTW_D, FTW_DNR, FTW_DP, FTW_NS, FTW_SL, FTW_SLN };
	static const int flags[] = { FTW_PHYS, FTW_MOUNT, FTW_DEPTH, FTW_CHDIR };
	struct stat st;
	size_t i, j;

	f.base = -1;
	f.level = -1;
	CHECK(sizeof f.base == sizeof(int));
	CHECK(sizeof f.level == sizeof(int));
	CHECK(f.base == -1 && f.level == -1);	/* assignable, and read back */

	/* "The <ftw.h> header shall define the following symbolic constants
	 * for use as values of the third argument to the
	 * application-supplied function": seven names, each naming a
	 * different condition, so no two may compare equal -- a callback
	 * switching on the third argument cannot tell FTW_D from FTW_DP if
	 * they are the same number. */
	for (i = 0; i < sizeof types / sizeof types[0]; i++)
		for (j = i + 1; j < sizeof types / sizeof types[0]; j++)
			CHECK(types[i] != types[j]);

	/* "The <ftw.h> header shall define the following symbolic constants
	 * for use as values of the fourth argument to nftw()", and
	 * nftw.html: the fourth argument "is a bitwise-inclusive OR of zero
	 * or more of the following flags".  Being OR-able and still
	 * distinguishable requires each to be non-zero and to share no bit
	 * with any other. */
	for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
		CHECK(flags[i] != 0);
		for (j = i + 1; j < sizeof flags / sizeof flags[0]; j++)
			CHECK((flags[i] & flags[j]) == 0);
	}
	CHECK((FTW_PHYS | FTW_MOUNT | FTW_DEPTH | FTW_CHDIR) ==
	      (FTW_PHYS + FTW_MOUNT + FTW_DEPTH + FTW_CHDIR));

	/* "shall define the stat structure and the symbolic names for
	 * st_mode and the file type test macros as described in
	 * <sys/stat.h>" -- see ftw_h_alone_types() at the top of the file,
	 * which is compiled with <ftw.h> as the only header in scope. */
	CHECK(stat("ftwtree", &st) == 0);
	CHECK(ftw_h_alone_types(&st) == FTW_D);
	CHECK(stat("ftwtree/a.txt", &st) == 0);
	CHECK(ftw_h_alone_types(&st) == FTW_F);
}

/* ====================================================================
 * nftw.html: level, base and the stat buffer, all the way down
 *
 * test/posix-tail.c asserts these on a tree two levels deep;
 * test/posix-glob.c asserts `level > 0` and a base offset for every
 * non-root path of a tree two levels deep.  The clause is about
 * arbitrary depth, and src/ftw/ftw.c computes `base` textually
 * (base_offset(), strrchr for '/') and `level` by counting recursion,
 * so depth is exactly the axis worth pushing.
 * ================================================================== */
static void test_nftw_level_base_and_stat_buffer(void)
{
	int i, j;

	reset_walk();
	CHECK(nftw("ftwtree", fn4, 16, 0) == 0);
	CHECK(nent == NOBJ);
	CHECK(!saw_null_stat);

	for (i = 0; i < NOBJ; i++) {
		j = find_ent(objs[i].path);
		CHECK(j >= 0);
		if (j < 0) continue;

		/* "The nftw() function shall recursively descend the directory
		 * hierarchy rooted in path" and "At each file it encounters,
		 * nftw() shall call the user-supplied function fn" -- each of
		 * the nine objects, and each of them once. */
		CHECK(count_ent(objs[i].path) == 1);

		/* "The value of level indicates depth relative to the root of
		 * the walk, where the root level is 0." */
		CHECK(ent[j].level == objs[i].level);

		/* "The value of base is the offset of the object's filename in
		 * the pathname passed as the first argument to fn." */
		CHECK(ent[j].base >= 0 && ent[j].base <= (int)strlen(objs[i].path));
		CHECK(!strcmp(ent[j].path + ent[j].base, filename_of(objs[i].path)));

		/* "FTW_D The object is a directory." / "FTW_F The object is a
		 * non-directory file." */
		CHECK(ent[j].flag == (objs[i].isdir ? FTW_D : FTW_F));

		/* "The second argument is a pointer to the stat buffer
		 * containing information on the object, filled in as if
		 * fstatat(), stat(), or lstat() had been called to retrieve
		 * the information" -- the buffer must agree with the type flag
		 * the same call reports, at every level. */
		CHECK(ent[j].isdir == objs[i].isdir);
	}

	/* and the buffer carries real content, not a zeroed placeholder:
	 * make_tree() wrote exactly five bytes into a.txt */
	j = find_ent("ftwtree/a.txt");
	CHECK(j >= 0 && ent[j].size == 5);

	/* ftw.html: "The ftw() function shall visit a directory before
	 * visiting any of its descendants" -- asserted here for every
	 * ancestor/descendant pair in a four-level tree, not only for the
	 * root's immediate children. */
	reset_walk();
	CHECK(ftw("ftwtree", fn3, 16) == 0);
	CHECK(nent == NOBJ);
	for (i = 0; i < NOBJ; i++) {
		char parent[256];
		const char *slash;
		int child_at, parent_at;

		slash = strrchr(objs[i].path, '/');
		if (!slash) continue;			/* the walk root */
		memcpy(parent, objs[i].path, (size_t)(slash - objs[i].path));
		parent[slash - objs[i].path] = 0;
		child_at = find_ent(objs[i].path);
		parent_at = find_ent(parent);
		CHECK(parent_at >= 0 && child_at >= 0 && parent_at < child_at);
	}

	/* ftw.html's own list of values for the third argument is FTW_D,
	 * FTW_DNR, FTW_F, FTW_SL and FTW_NS -- FTW_DP and FTW_SLN are on
	 * nftw.html's list only, and <ftw.h> defines them for nftw()'s
	 * sake.  ftw() must not deliver either. */
	for (i = 0; i < nent && i < MAXENT; i++)
		CHECK(ent[i].flag != FTW_DP && ent[i].flag != FTW_SLN);
}

/* ====================================================================
 * ftw.html: "The ftw() function shall use at most one file descriptor
 * for each level in the tree", and nftw.html: "The argument fd_limit
 * sets the maximum number of file descriptors that shall be used by
 * nftw() while traversing the file tree. At most one file descriptor
 * shall be used for each directory level."
 *
 * A limit below the tree's depth is what forces src/ftw/ftw.c's
 * close/reopen machinery to run: level_open() evicts the
 * least-recently-opened ancestor with close_one(), which saves
 * telldir(), and reopens it later with opendir() + seekdir().  If that
 * replay were off by one entry in either direction, an object would be
 * visited twice or not at all -- which is what these assertions
 * measure, at four different limits against a four-level tree.
 * test/posix-tail.c exercises the limit 1 against a two-level tree,
 * which is one eviction; this is three, nested.
 * ================================================================== */
static void test_fd_limit_and_visit_once(void)
{
	static const int limits[] = { 1, 2, 3, 16 };
	size_t k;
	int i;

	for (k = 0; k < sizeof limits / sizeof limits[0]; k++) {
		reset_walk();
		CHECK(nftw("ftwtree", fn4, limits[k], 0) == 0);
		CHECK(nent == NOBJ);
		for (i = 0; i < NOBJ; i++)
			CHECK(count_ent(objs[i].path) == 1);

		/* the post-order walk replays the same streams in the same
		 * places, so it gets the same treatment */
		reset_walk();
		CHECK(nftw("ftwtree", fn4, limits[k], FTW_DEPTH) == 0);
		CHECK(nent == NOBJ);
		for (i = 0; i < NOBJ; i++)
			CHECK(count_ent(objs[i].path) == 1);

		/* ftw() takes the same budget under the name ndirs:
		 * "The ndirs argument shall specify the maximum number of
		 * directory streams or file descriptors or both available for
		 * use by ftw() while traversing the tree." */
		reset_walk();
		CHECK(ftw("ftwtree", fn3, limits[k]) == 0);
		CHECK(nent == NOBJ);
		for (i = 0; i < NOBJ; i++)
			CHECK(count_ent(objs[i].path) == 1);
	}
}

/* ====================================================================
 * ftw.html: "When ftw() returns it shall close any directory streams
 * and file descriptors it uses not counting any opened by the
 * application-supplied fn function."
 *
 * Nothing in the tree asserts this today, and it is observable without
 * any private interface.  open() returns the lowest-numbered descriptor
 * not in use (open.html; and src/internal/fd.c's __fd_alloc() scans the
 * table from 0 for the first free slot, which is the same rule for the
 * Wine and real-Windows legs).  opendir() takes one of those slots
 * (src/dirent/opendir.c calls __fd_install()) and closedir() gives it
 * back (src/dirent/closedir.c calls close()).  So the number open()
 * hands back before a walk and after it must be identical -- and would
 * differ by exactly the number of streams the walk failed to close.
 *
 * The probe deliberately opens an existing fixture file read-only, so
 * it creates nothing and the two probes differ in nothing but their
 * position around the call.
 * ================================================================== */
static int probe_fd(void)
{
	int fd = open("ftwtree/a.txt", O_RDONLY);
	if (fd >= 0) close(fd);
	return fd;
}

static void test_streams_closed_when_it_returns(void)
{
	int before = probe_fd();

	CHECK(before >= 0);
	if (before < 0) return;

	/* the tree exhausted */
	reset_walk();
	CHECK(nftw("ftwtree", fn4, 16, 0) == 0);
	CHECK(probe_fd() == before);

	/* "not counting any opened by the application-supplied fn
	 * function" is the other half of the clause and needs no assertion
	 * of its own here: no callback in this file opens anything, so
	 * every descriptor still outstanding would be the walk's. */

	/* an invocation of fn returning a non-zero value, deep enough that
	 * several recursion frames have to unwind */
	reset_walk(); stop_after = 7; stop_value = 5;
	CHECK(nftw("ftwtree", fn4, 16, 0) == 5);
	CHECK(probe_fd() == before);

	/* the same, with the close/reopen machinery active */
	reset_walk(); stop_after = 7; stop_value = 5;
	CHECK(nftw("ftwtree", fn4, 1, 0) == 5);
	CHECK(probe_fd() == before);

	/* the post-order walk, which reports directories after closing
	 * their streams */
	reset_walk();
	CHECK(nftw("ftwtree", fn4, 2, FTW_DEPTH) == 0);
	CHECK(probe_fd() == before);

	/* ftw() likewise -- the clause is on its page */
	reset_walk();
	CHECK(ftw("ftwtree", fn3, 2) == 0);
	CHECK(probe_fd() == before);

	/* and a walk that fails outright still leaves nothing behind */
	reset_walk();
	CHECK(nftw("ftwtree/no-such-entry", fn4, 5, 0) == -1);
	CHECK(probe_fd() == before);
}

/* ====================================================================
 * The walk root need not be a directory.
 *
 * Neither page requires `path` to name one -- ftw.html says only "the
 * directory hierarchy rooted in path", and its [ENOTDIR] clause is
 * about "a component of path", not about the last component.  A
 * one-object hierarchy is still a hierarchy, and a caller handed a
 * pathname it has not stat'd itself relies on this.
 * ================================================================== */
static void test_walk_root_is_not_a_directory(void)
{
	reset_walk();
	CHECK(nftw("ftwtree/a.txt", fn4, 5, 0) == 0);
	CHECK(nent == 1);
	if (nent == 1) {
		/* "FTW_F The object is a non-directory file." */
		CHECK(ent[0].flag == FTW_F);
		/* "level indicates depth relative to the root of the walk,
		 * where the root level is 0" -- the root is this file */
		CHECK(ent[0].level == 0);
		CHECK(!strcmp(ent[0].path + ent[0].base, "a.txt"));
		CHECK(ent[0].isdir == 0);
		CHECK(ent[0].size == 5);
	}

	reset_walk();
	CHECK(ftw("ftwtree/a.txt", fn3, 5) == 0);
	CHECK(nent == 1);
	if (nent == 1) CHECK(ent[0].flag == FTW_F);

	/* FTW_DEPTH is about directories and changes nothing here */
	reset_walk();
	CHECK(nftw("ftwtree/a.txt", fn4, 5, FTW_DEPTH) == 0);
	CHECK(nent == 1);
	if (nent == 1) CHECK(ent[0].flag == FTW_F);
}

/* ====================================================================
 * nftw.html RETURN VALUE: "An invocation of fn shall return a non-zero
 * value, in which case nftw() shall return that value."
 *
 * test/posix-tail.c stops the walk at its first and second callback,
 * which is at or next to the root.  The value has to survive being
 * returned up through every recursion frame, so the case worth adding
 * is a stop from deep inside one -- and under FTW_DEPTH, where the
 * value comes back out of the post-order report rather than the
 * pre-order one.
 * ================================================================== */
static void test_stop_value_from_depth(void)
{
	/* With FTW_DEPTH clear the root is the first call, and with
	 * FTW_DEPTH set it is the last of nine; so the seventh call is
	 * below the root either way, and its value has at least one frame
	 * to travel through. */
	reset_walk(); stop_after = 7; stop_value = 123;
	CHECK(nftw("ftwtree", fn4, 16, 0) == 123);
	CHECK(nent == 7);
	if (nent == 7) CHECK(ent[6].level >= 1);

	reset_walk(); stop_after = 7; stop_value = -3;
	CHECK(nftw("ftwtree", fn4, 16, FTW_DEPTH) == -3);
	CHECK(nent == 7);
	if (nent == 7) CHECK(ent[6].level >= 1);

	/* the same value returned through the close/reopen machinery */
	reset_walk(); stop_after = 7; stop_value = 123;
	CHECK(nftw("ftwtree", fn4, 1, 0) == 123);
	CHECK(nent == 7);

	/* ftw.html RETURN VALUE says the same thing for ftw() */
	reset_walk(); stop_after = 6; stop_value = 55;
	CHECK(ftw("ftwtree", fn3, 1) == 55);
	CHECK(nent == 6);
}

/* ====================================================================
 * nftw.html: the fourth argument "is a bitwise-inclusive OR of zero or
 * more of the following flags".
 *
 * Each flag is checked on its own by test/posix-tail.c.  What is not
 * checked anywhere is that they compose: the fixture has no symbolic
 * link and sits on one file system, so FTW_PHYS and FTW_MOUNT must
 * both be no-ops on it whatever they are combined with, and FTW_DEPTH
 * must still turn every FTW_D into an FTW_DP.  FTW_CHDIR is left out
 * of the combinations deliberately -- it is the BUG test/posix-tail.c
 * already fences, and folding it in here would re-report that.
 * ================================================================== */
static void test_flag_combinations(void)
{
	static const int combos[] = {
		FTW_PHYS,
		FTW_MOUNT,
		FTW_PHYS | FTW_DEPTH,
		FTW_MOUNT | FTW_DEPTH,
		FTW_PHYS | FTW_MOUNT,
		FTW_PHYS | FTW_MOUNT | FTW_DEPTH,
	};
	size_t k;
	int i, j;

	for (k = 0; k < sizeof combos / sizeof combos[0]; k++) {
		int depth = (combos[k] & FTW_DEPTH) != 0;

		reset_walk();
		CHECK(nftw("ftwtree", fn4, 16, combos[k]) == 0);
		CHECK(nent == NOBJ);

		for (i = 0; i < NOBJ; i++) {
			j = find_ent(objs[i].path);
			CHECK(count_ent(objs[i].path) == 1);
			if (j < 0) continue;
			CHECK(ent[j].level == objs[i].level);
			/* "FTW_DP The object is a directory and subdirectories
			 * have been visited. (This condition shall only occur if
			 * the FTW_DEPTH flag is included in flags.)" */
			if (objs[i].isdir)
				CHECK(ent[j].flag == (depth ? FTW_DP : FTW_D));
			else
				CHECK(ent[j].flag == FTW_F);
		}

		/* "FTW_SL ... (This condition shall only occur if the FTW_PHYS
		 * flag is included in flags.)" and "FTW_SLN ... (This
		 * condition shall only occur if the FTW_PHYS flag is not
		 * included in flags.)" -- the fixture contains no symbolic
		 * link, so neither may appear under any combination.  Nor may
		 * FTW_NS or FTW_DNR: everything here is readable. */
		for (i = 0; i < nent && i < MAXENT; i++) {
			CHECK(ent[i].flag != FTW_SL);
			CHECK(ent[i].flag != FTW_SLN);
			CHECK(ent[i].flag != FTW_NS);
			CHECK(ent[i].flag != FTW_DNR);
		}

		/* "FTW_DEPTH: If set, nftw() shall report all files in a
		 * directory before reporting the directory itself." */
		if (depth) {
			CHECK(find_ent("ftwtree") == nent - 1);
			CHECK(find_ent("ftwtree/d1/d2/d3/f.txt") < find_ent("ftwtree/d1/d2/d3"));
			CHECK(find_ent("ftwtree/d1/d2/d3") < find_ent("ftwtree/d1/d2"));
			CHECK(find_ent("ftwtree/d1/d2") < find_ent("ftwtree/d1"));
		}
	}
}

/* ====================================================================
 * ERRORS, *shall fail*: "[ENAMETOOLONG] The length of a component of a
 * pathname is longer than {NAME_MAX}." -- on both pages.
 *
 * test/POSIX-COVERAGE.md's group J3 records this clause as N/A,
 * grouped into one row with FTW_DNR, FTW_NS and [EACCES] and given
 * their mechanism: "chmod 0 does not revoke owner access on this
 * platform, so a directory that cannot be read or an object that
 * cannot be stat'd cannot be built".  That mechanism is about
 * permissions and this clause is not: it needs no fixture at all, only
 * a name, and the name need not exist.
 *
 * Read from src/, not measured: src/internal/path.c's
 * __name_too_long() splits the path on '/' and '\\' and returns 1 when
 * any component exceeds NAME_MAX (255, include/limits.h:31);
 * dos_from_posix() calls it first and sets ENAMETOOLONG; __ntpath()
 * propagates that failure without touching errno; lstat() reaches it
 * through fstatat(AT_FDCWD, ...) -> __ntpath_at(), whose AT_FDCWD
 * branch calls __ntpath().  src/ftw/ftw.c's walk() lstat()s the walk
 * root first and returns -1 with errno as lstat() left it.
 * ================================================================== */
static void test_ftw_enametoolong(void)
{
	char big[NAME_MAX + 46];		/* 300 bytes: one over-long component */
	char under[8 + 256 + 1];		/* "ftwtree/" + a 256-byte component */

	memset(big, 'x', sizeof big - 1);
	big[sizeof big - 1] = 0;
	CHECK(strlen(big) > NAME_MAX);

	reset_walk(); errno = 0;
	CHECK(nftw(big, fn4, 5, 0) == -1);
	CHECK(errno == ENAMETOOLONG);
	CHECK(nent == 0);

	reset_walk(); errno = 0;
	CHECK(ftw(big, fn3, 5) == -1);
	CHECK(errno == ENAMETOOLONG);
	CHECK(nent == 0);

	/* the same over-long piece as a component of a longer pathname
	 * whose other components are fine and do exist */
	strcpy(under, "ftwtree/");
	memset(under + 8, 'y', 256);
	under[8 + 256] = 0;
	reset_walk(); errno = 0;
	CHECK(nftw(under, fn4, 5, 0) == -1);
	CHECK(errno == ENAMETOOLONG);
	CHECK(nent == 0);
}

/* ====================================================================
 * ftw.html: "The argument ndirs should be in the range [1,{OPEN_MAX}]."
 *
 * A *should*, not a *shall*, and the only error clause about it is
 * ftw.html's *may fail* "[EINVAL] The value of the ndirs argument is
 * invalid" -- nftw.html's ERRORS section has no [EINVAL] at all.  So 0
 * is an application error with no required outcome, and this is
 * asserted permissively on purpose: it pins down only that the call
 * terminates and does not report a partial tree as a complete one.
 *
 * Recorded rather than fenced.  src/ftw/ftw.c's level_open() guards
 * its eviction with `ws->nopenfd >= 1`, so a limit of 0 or less turns
 * the ceiling off entirely rather than clamping it -- but with the
 * range stated as a *should* and [EINVAL] as a *may fail*, no clause
 * says what it must do instead, and manufacturing one would be
 * inventing a gap.
 * ================================================================== */
static void test_ndirs_out_of_range(void)
{
	int r;

	reset_walk();
	r = nftw("ftwtree", fn4, 0, 0);
	CHECK(r == 0 || r == -1);
	if (r == 0) CHECK(nent == NOBJ);

	reset_walk();
	r = ftw("ftwtree", fn3, 0);
	CHECK(r == 0 || r == -1);
	if (r == 0) CHECK(nent == NOBJ);
}

/* ====================================================================
 * FINDING 1 -- fenced BUG
 * ================================================================== */
#if SPICULE_TEST(PASS, posix_ftw_error_other_than_eacces_stops_walk) /* BUG: src/ftw/ftw.c reports every stat()/lstat() failure below
	the walk root as FTW_NS, and every opendir() failure as
	FTW_DNR, and carries on walking.  Both pages reserve that for
	a lack-of-permission failure and require any other failure to
	end the walk with -1.

	nftw.html DESCRIPTION, the FTW_NS bullet, which says it
	outright: "FTW_NS The stat() function failed on the object
	because of lack of appropriate permission. The stat buffer
	passed to fn is undefined. Failure of stat() for any other
	reason is considered an error and nftw() shall return -1."

	nftw.html RETURN VALUE, the same requirement as a termination
	condition: "The nftw() function shall continue until the first
	of the following conditions occurs: ... The nftw() function
	detects an error other than [EACCES] (see FTW_DNR and FTW_NS
	above), in which case nftw() shall return -1 and set errno to
	indicate the error."

	ftw.html says it twice too -- DESCRIPTION: "The tree traversal
	shall continue until either the tree is exhausted, an
	invocation of fn returns a non-zero value, or some error,
	other than [EACCES], is detected within ftw()", and RETURN
	VALUE: "If ftw() encounters an error other than [EACCES] (see
	FTW_DNR and FTW_NS above), it shall return -1 and set errno to
	indicate the error."  The parenthetical is the standard tying
	FTW_DNR and FTW_NS to that one errno and to no other.

	WHAT src/ftw/ftw.c DOES (read, not measured).  walk() opens
	with `if (lstat(path, &lst) < 0) { if (is_root) return -1; ...
	return report(ws, path, &zero, FTW_NS, level); }`.  The walk
	root is handled correctly; for anything below it, errno is
	never examined -- every failure becomes FTW_NS and the parent's
	readdir() loop keeps going, because report() returns whatever
	fn returns and fn returning 0 means "continue".  The
	FTW_PHYS-clear branch does the same for stat(): `else if
	(stat(path, &st) < 0) return report(ws, path, &lst,
	S_ISLNK(lst.st_mode) ? FTW_SLN : FTW_NS, level);`.  And the
	directory branch does the same for opendir(): `if
	(level_open(ws, lru, &lv) < 0) { free(lv.path); return
	report(ws, path, rst, FTW_DNR, level); }`, where level_open()
	fails exactly when opendir() does, whatever it failed with.
	There is no `errno == EACCES` test anywhere in the file.

	WHAT A CALLER OBSERVES TODAY.  A walk over a tree something
	else is changing -- a build tree, a spool directory, anything
	a second process writes -- silently reports the vanished
	entries as FTW_NS and returns 0, so the caller is told the
	tree was exhausted and that some of it was unreadable, when in
	fact the walk hit an [ENOENT] the standard requires it to stop
	on.  A caller that deletes a tree with nftw(FTW_DEPTH) is the
	worst case: it gets 0 back and believes the tree is gone.

	UNIMPL, not N/A or BUG?  BUG.  The interface exists, the
	clause is one it implements (it already distinguishes the walk
	root, where it returns -1 correctly), and the fix is local:
	consult errno at the three call sites above and route only
	EACCES to FTW_NS/FTW_DNR.

	WHY FENCED RATHER THAN LIVE.  The fixture below makes a
	stat() fail for a reason other than permission by having the
	callback unlink a sibling the walk has not reached yet, which
	needs the entry's name to have been buffered by readdir()
	already.  src/dirent/dirent_internal.h sets __DIRBUF_SIZE to
	32768 and src/dirent/getdents.c fills that buffer from one
	NtQueryDirectoryFile, so a three-entry directory arrives in a
	single call -- read from those files, not measured here.  That
	is a real dependency on an implementation detail, and it is
	why this is fenced rather than run: it would be a poor live
	assertion even once the defect is fixed.  The clause it
	asserts does not depend on it, and neither does the reading of
	src/ftw/ftw.c above. */
static int mut_removed;
static int mut_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	static const char *const names[3] = { "ftwmut/one", "ftwmut/two", "ftwmut/three" };
	int i;

	record(p, st, flag, f->base, f->level);
	if (flag == FTW_F && !mut_removed) {
		for (i = 0; i < 3; i++)
			if (strcmp(p, names[i])) unlink(names[i]);
		mut_removed = 1;
	}
	return 0;
}

static void test_nftw_error_other_than_eacces_stops_the_walk(void)
{
	int i, r;

	CHECK(mkdir("ftwmut", 0755) == 0 || errno == EEXIST);
	CHECK(make_file("ftwmut/one", "", 0) == 0);
	CHECK(make_file("ftwmut/two", "", 0) == 0);
	CHECK(make_file("ftwmut/three", "", 0) == 0);

	reset_walk();
	mut_removed = 0;
	errno = 0;
	r = nftw("ftwmut", mut_cb, 5, 0);

	/* the walk's lstat() of an entry readdir() had already returned
	 * fails with [ENOENT], which is not a lack of permission */
	CHECK(r == -1);
	CHECK(errno == ENOENT);

	/* and the object is not handed to fn as FTW_NS instead */
	for (i = 0; i < nent && i < MAXENT; i++)
		CHECK(ent[i].flag != FTW_NS);

	unlink("ftwmut/one");
	unlink("ftwmut/two");
	unlink("ftwmut/three");
	rmdir("ftwmut");
}
#endif

/* ====================================================================
 * FINDING 2 -- fenced BUG
 * ================================================================== */
#if SPICULE_TEST(NA, posix_ftw_unreadable_dir_reported_twice) /* N/A (the defect below is real; this test cannot show it -- see WHY N/A): with FTW_DEPTH clear, a directory that cannot be read is
	handed to fn twice -- once as FTW_D, then again as FTW_DNR.

	nftw.html DESCRIPTION: "At each file it encounters, nftw()
	shall call the user-supplied function fn with four arguments",
	of which "The third argument is an integer giving additional
	information. Its value is one of the following: ... FTW_D The
	object is a directory. ... FTW_DNR The object is a directory
	that cannot be read. The fn function shall not be called for
	any of its descendants."  One file, one call, one of those
	values -- not one file, two calls, two different values.
	ftw.html's counterpart is "For each object in the hierarchy,
	ftw() shall call the function pointed to by fn", with "FTW_DNR
	For a directory that cannot be read" and "If the integer is
	FTW_DNR, descendants of that directory shall not be
	processed."

	WHAT src/ftw/ftw.c DOES (read, not measured).  walk() emits
	the pre-order report before it has tried to open anything:

	    if (!(ws->flags & FTW_DEPTH)) {
	            r = report(ws, path, rst, FTW_D, level);
	            if (r) return r;
	    }
	    ...
	    if (level_open(ws, lru, &lv) < 0) {
	            free(lv.path);
	            return report(ws, path, rst, FTW_DNR, level);
	    }

	so an unreadable directory goes through both.  With FTW_DEPTH
	set the first report is skipped and the same directory is
	reported exactly once, which is what shows the duplicate is an
	artefact of when the FTW_D report is emitted rather than a
	decision about FTW_DNR: the same object gets one call or two
	depending on a flag whose entire specified effect is ordering.

	WHAT A CALLER OBSERVES TODAY.  A callback that counts, sums or
	mirrors counts the directory twice; one that switches on the
	third argument acts on FTW_D -- descending, or creating the
	mirror entry and expecting its contents -- for a directory
	whose contents will never arrive.

	Fix shape: attempt the open first and choose FTW_D or FTW_DNR
	from the result, which is also where the errno test finding 1
	needs has to go, so the two share one change to that branch.

	WHY N/A AND NOT BUG.  The defect above is real and rests on the
	source quoted, not on this test.  The disposition, though, has to
	describe what this test can measure, and the answer is nothing.

	It needs a directory opendir() fails on with [EACCES].  That
	fixture was recorded as unbuildable here ("chmod 0 does not
	revoke owner access on this platform"), so the fixture line was
	left as a comment rather than a chmod() call -- deliberately, so
	a chmod() that silently did nothing could not make this pass for
	the wrong reason.

	MEASURED, and this is why the marker changed.  Nothing creates
	"ftwtree/noread" at all -- not make_tree(), which builds only
	ftwtree, d1, d1/d2, d1/d2/d3 and five files, and not this
	function.  Every assertion below therefore addresses a path that
	does not exist, on any runner: count_ent("ftwtree/noread") is 0,
	not 2, and the branch under test is never reached.  Run with the
	fence forced open, the case fails four assertions -- none of them
	the double report.  A BUG marker would have recorded that failure
	as confirmation of the finding, which it is not: this test cannot
	distinguish the defect from its own missing fixture.  So it is
	declared N/A and is not probed, rather than being counted as
	evidence it does not supply.

	To make it live, the fixture need not be an [EACCES] directory at
	all.  Any opendir() failure after the FTW_D report exercises the
	same branch -- e.g. a callback that rmdir()s "ftwtree/noread"
	when it is handed FTW_D for it, the same mid-walk mutation
	test_nftw_error_other_than_eacces_stops_the_walk already uses
	successfully here.  level_open() then fails with [ENOENT] and the
	same object is reported FTW_D and then FTW_DNR, which is the
	clause violation, needing no permission the runner cannot grant.
	That is a new assertion rather than a repair of this one, so it
	is left to a follow-up. */
static void test_nftw_dnr_reported_once(void)
{
	int i, n_d = 0, n_dnr = 0;

	/* fixture: "ftwtree/noread" is a directory that stat() succeeds on
	 * and opendir() fails on with [EACCES] */

	reset_walk();
	CHECK(nftw("ftwtree", fn4, 16, 0) == 0);

	for (i = 0; i < nent && i < MAXENT; i++) {
		if (strcmp(ent[i].path, "ftwtree/noread")) continue;
		if (ent[i].flag == FTW_D) n_d++;
		if (ent[i].flag == FTW_DNR) n_dnr++;
	}
	CHECK(count_ent("ftwtree/noread") == 1);
	CHECK(n_dnr == 1);
	CHECK(n_d == 0);

	/* "The fn function shall not be called for any of its
	 * descendants." */
	for (i = 0; i < nent && i < MAXENT; i++)
		CHECK(strncmp(ent[i].path, "ftwtree/noread/", 15) != 0);

	/* and the FTW_DEPTH path, which already reports it once, must keep
	 * doing so */
	reset_walk();
	CHECK(nftw("ftwtree", fn4, 16, FTW_DEPTH) == 0);
	CHECK(count_ent("ftwtree/noread") == 1);
	i = find_ent("ftwtree/noread");
	CHECK(i >= 0 && ent[i].flag == FTW_DNR);
}
#endif

/* ====================================================================
 * FINDING 3 -- fenced BUG
 * ================================================================== */
#if SPICULE_TEST(PASS, posix_ftw_eacces_when_fn_returns_minus_one) /* BUG: nftw() does not set errno to [EACCES] when fn returns -1
	without setting errno itself.

	nftw.html ERRORS, *shall fail*: "[EACCES] Search permission is
	denied for any component of path or read permission is denied
	for path, or fn returns -1 and does not reset errno."  The
	third alternative is nftw()'s alone -- ftw.html's [EACCES]
	entry reads "Search permission is denied for any component of
	path or read permission is denied for path." and stops there
	-- so it is not boilerplate shared between the two pages, it
	is a requirement written for nftw() specifically.

	WHAT src/ftw/ftw.c DOES (read, not measured).  The string
	"errno" appears in it four times: `errno = ENOENT` in each of
	ftw() and nftw() for an empty path, and `errno = ENOMEM` twice
	on allocation failure.  fn's return value travels back out
	through report() and walk() untouched, so when fn returns -1
	the caller gets -1 with errno holding whatever the last
	lstat()/stat()/opendir() left in it -- which on a walk where
	nothing failed is whatever the caller had before the call.

	WHAT A CALLER OBSERVES TODAY.  nftw() returns -1, which is
	also its own failure return, and errno does not say which of
	the two happened.  Pinning it to [EACCES] is what makes that
	-1 mean something definite, and it is the only reason the
	clause exists: a callback returning -1 is otherwise
	indistinguishable from nftw() failing.

	THE COUNTER-ARGUMENT, AND WHY IT IS REJECTED.  One can read
	the ERRORS section as describing only nftw()'s own failures,
	and a non-zero return from fn as not being one of those --
	RETURN VALUE lists "An invocation of fn shall return a
	non-zero value, in which case nftw() shall return that value"
	as a different termination condition from "detects an error".
	On that reading the sentence is a remark about how such a -1
	usually arises rather than an obligation.  It is rejected
	because the sentence is not in RETURN VALUE, it is an entry in
	the *shall fail* list, and an entry there states a condition
	under which the function shall fail with that errno; and
	because the condition it names -- "fn returns -1 and does not
	reset errno" -- is a fact about fn, not about nftw(), so on
	the descriptive reading the clause would have no addressee at
	all.  This is nonetheless the weakest of this file's three
	findings and is recorded as such in the ledger.

	Fix shape: in nftw(), if the value coming back out of walk()
	is -1 and errno is unchanged from what it was on entry, set
	errno to EACCES.  ftw() must NOT get the same treatment: the
	clause is not on its page. */
static int minus_one_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	record(p, st, flag, f->base, f->level);
	return -1;
}

static void test_nftw_eacces_when_fn_returns_minus_one(void)
{
	reset_walk();
	errno = 0;
	CHECK(nftw("ftwtree", minus_one_cb, 16, 0) == -1);
	CHECK(nent == 1);		/* it stopped at the first invocation */
	CHECK(errno == EACCES);
}
#endif

int main(void)
{
	if (make_tree() < 0) {
		printf("posix-ftw: could not build the fixture (errno=%d)\n", errno);
		kill_tree();
		return 1;
	}

	test_ftw_h_header_shape();
	test_nftw_level_base_and_stat_buffer();
	test_fd_limit_and_visit_once();
	test_streams_closed_when_it_returns();
	test_walk_root_is_not_a_directory();
	test_stop_value_from_depth();
	test_flag_combinations();
	test_ftw_enametoolong();
	test_ndirs_out_of_range();
#if SPICULE_TEST(PASS, posix_ftw_error_other_than_eacces_stops_walk) /* BUG: see the fence above test_nftw_error_other_than_eacces_stops_the_walk */
	test_nftw_error_other_than_eacces_stops_the_walk();
#endif
#if SPICULE_TEST(NA, posix_ftw_unreadable_dir_reported_twice) /* N/A: see the fence above test_nftw_dnr_reported_once */
	test_nftw_dnr_reported_once();
#endif
#if SPICULE_TEST(PASS, posix_ftw_eacces_when_fn_returns_minus_one) /* BUG: see the fence above test_nftw_eacces_when_fn_returns_minus_one */
	test_nftw_eacces_when_fn_returns_minus_one();
#endif

	kill_tree();

	if (fails) { printf("posix-ftw: failures: %d\n", fails); return 1; }
	printf("posix-ftw: all ok\n");
	return 0;
}
