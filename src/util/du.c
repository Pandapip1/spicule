/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * du(1p): "The du utility shall write the sizes of the file space
 * allocated to, and the size of the file space allocated to any files
 * contained in, the directory."  Recursion is nftw() (src/ftw/ftw.c, a
 * real, already-tested recursion driver -- see src/util/rm.c's identical
 * reasoning for not writing a second one here), walked FTW_PHYS (a
 * symbolic link is counted for its own small allocation, never followed
 * -- du(1p) DESCRIPTION does not ask for link targets to be counted, and
 * following them could double-count a target reachable two ways, or
 * recurse forever through a cycle) and FTW_DEPTH (every directory's own
 * report -- FTW_DP -- comes after all of its descendants', which is
 * exactly the order needed to accumulate a directory's total from its
 * children before printing it).
 *
 * ---- what a "block" is here ---------------------------------------------
 *
 * st_blocks (src/stat/nt/plat_stat.c's __file_allocation_blocks(),
 * `AllocationSize / 512` rounded up) is real, disk-allocation-derived
 * data on this platform -- NOT left zero the way statvfs()'s f_files/
 * f_ffree/f_favail are (see src/stat/statvfs.c's own banner for that
 * different, genuinely-empty case).  So du sums st_blocks, already in
 * 512-byte units by POSIX convention, rather than st_size: "disk usage"
 * is what this utility reports, not "apparent size", and an allocated-
 * but-sparse or rounded-up-to-a-cluster file is supposed to show the
 * larger, real number.
 *
 * ---- OPTIONS implemented -------------------------------------------------
 *
 *  -a  "Write counts for all files, not just directories." -- without
 *      it, only directories (and a plain-file operand named directly,
 *      see below) get a line.
 *  -s  "Instead of the default output, write only the grand total for
 *      each of the specified files." -- implemented as "print only the
 *      report for the operand's own top-level entry (FTW level 0)",
 *      which is exactly the grand total, whether that operand is a file
 *      or a directory.
 *  -k  Non-POSIX, common extension: report in 1024-byte blocks instead
 *      of the default 512-byte blocks (du(1p) itself only ever mentions
 *      512-byte blocks, so that is this utility's unqualified default).
 *
 *  -r  du(1p) OPTIONS: historically "generate messages about files that
 *      cannot be read", and the standard's own RATIONALE notes this was
 *      once unconditional, real, portable behaviour on some systems and
 *      a documented no-op on others -- so there is no single "the"
 *      behaviour to silently pick.  Resolved here the same way rm(1p)'s
 *      -f is read literally rather than guessed at (see rm.c's header):
 *      -r *adds* a diagnostic on an inaccessible entry that this
 *      implementation would otherwise skip quietly.  Without -r, an
 *      entry nftw() reports FTW_NS/FTW_DNR is skipped with no message
 *      (the portable, modern default many implementations settled on);
 *      with -r, the same entry gets a "du: cannot access ..." line on
 *      stderr before being skipped.  Either way it still counts toward a
 *      nonzero exit status: a silently-skipped entry is not the same as
 *      a successfully-measured one, message or no message.
 *
 * EXIT STATUS: du(1p) "0 ... >0 An error occurred." -- diagnose-or-not
 * per -r above, but never silently claim success over an entry that
 * could not actually be measured.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ftw.h>
#include <sys/stat.h>
#include "util.h"

/* One accumulator per nesting level currently open, indexed by struct
 * FTW's own `level` -- see this file's header on why a level-indexed
 * array is enough: nftw()'s FTW_DEPTH post-order walk never has two
 * directories at the same level "open" (accumulating) at once, so a
 * slot is always safe to reuse the moment its owning directory's FTW_DP
 * has been folded into its parent's slot. 4096 is far beyond any real
 * pathname's component count this platform's own PATH_MAX (used
 * elsewhere in this tier, e.g. src/util/mkdir_util.c) could reach. */
#define DU_MAXLEVEL 4096
static uintmax_t level_sum[DU_MAXLEVEL]; /* 512-byte units, always */
static int du_all, du_summary, du_rflag, du_had_error;
static unsigned long du_blocksize;

static uintmax_t to_units(uintmax_t blocks512)
{
	return du_blocksize == 1024 ? (blocks512 + 1) / 2 : blocks512;
}

static void print_line(uintmax_t blocks512, const char *path)
{
	printf("%ju\t%s\n", to_units(blocks512), path);
}

/* ftwbuf->level below (and, once that dereference is reached, st->st_blocks
 * in the FTW_F/FTW_SL/FTW_DP cases) is flagged "pointer dereference is not
 * proven nonnull" by tools/lint.sh ownership: left open, same accepted
 * class as src/util/rm.c/cp.c's own nftw() callbacks would be if they
 * dereferenced either parameter at all (they cast both to (void) instead,
 * see rm_walk_cb()/cpt_cb()). Unlike those two, this really is true and
 * provable in principle -- src/ftw/ftw.c's report() always calls this
 * callback as `ws->fn4(path, st, type, &f)` with a real, non-null `st` and
 * `&f` (report()'s own stack-local struct FTW) on every call -- but
 * stating it with __attribute__((nonnull(2, 4))) here was tried and
 * reverted: it does silence this pair, but it also lets
 * ntlibc.OwnershipChecker's exploration reach past this function's first
 * statement into the FTW_DP case below, where it cannot prove
 * level_sum[lvl]'s lower bound (lvl is never actually negative -- FTW's
 * `level` is a plain recursion-depth counter src/ftw/ftw.c's walk() only
 * ever increments from 0 -- but nothing in ownership.h's vocabulary states
 * a scalar struct field's numeric range the way extent_at_least/
 * element_extent state a pointer's byte/element extent), a net regression
 * from 2 findings to 3. Verified with a direct clang --analyze run scoped
 * to this file before keeping or reverting either change. */
static int du_cb(const char *path, const struct stat *st, int type, struct FTW *ftwbuf)
{
	int lvl = ftwbuf->level;

	switch (type) {
	case FTW_NS:
		if (du_rflag) __util_diagf("du: cannot access '%s'\n", path);
		du_had_error = 1;
		return 0;
	case FTW_DNR:
		if (du_rflag) __util_diagf("du: cannot read directory '%s'\n", path);
		du_had_error = 1;
		return 0;
	case FTW_F:
	case FTW_SL: {
		uintmax_t blocks = (uintmax_t)st->st_blocks;
		if (lvl > 0 && lvl - 1 < DU_MAXLEVEL) level_sum[lvl - 1] += blocks;
		/* The operand itself (level 0) is always reported, whether or
		 * not it is a directory -- see this file's header on -a. */
		if (lvl == 0 || (!du_summary && du_all))
			print_line(blocks, path);
		return 0;
	}
	case FTW_DP: {
		uintmax_t total = (lvl < DU_MAXLEVEL) ? level_sum[lvl] : 0;
		total += (uintmax_t)st->st_blocks; /* the directory entry's own allocation, if any */
		if (lvl < DU_MAXLEVEL) level_sum[lvl] = 0;
		if (lvl > 0 && lvl - 1 < DU_MAXLEVEL) level_sum[lvl - 1] += total;
		/* -s: only the grand total (level 0) is printed; otherwise
		 * every directory's own cumulative total is. */
		if (!du_summary || lvl == 0) print_line(total, path);
		return 0;
	}
	default:
		return 0;
	}
}

static int du_one(const char *path)
{
	memset(level_sum, 0, sizeof level_sum);
	if (nftw(path, du_cb, 15, FTW_PHYS | FTW_DEPTH) < 0) {
		__util_diagf("du: %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int __util_du_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 1;

	du_all = du_summary = du_rflag = du_had_error = 0;
	du_blocksize = 512;

	for (; i < argc; i++) {
		char *a = argv[i];
		char *p;
		/* a[0]: "pointer dereference is not proven nonnull" -- left
		 * open, same accepted class as the identical argv[i][0] access
		 * in src/util/rm.c, cp.c, mv.c, df.c, uuencode.c, and
		 * uudecode.c's own option loops. argv's own
		 * elements_withtok(null_terminated, argc) above proves every
		 * element up to argc has a reachable NUL, but include/
		 * string_tokens.h's null_terminated token is defined purely as
		 * that reachability fact (see its own comment) -- it carries no
		 * companion "and the pointer itself is not NULL" qualifier, so
		 * ntlibc.OwnershipChecker's AggregateElementToken machinery has
		 * nothing to hand ntlibc.ValidPointer here. No annotation in
		 * ownership.h currently closes this. */
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		for (p = a + 1; *p; p++) {
			if (*p == 'a') { du_all = 1; continue; }
			if (*p == 's') { du_summary = 1; continue; }
			if (*p == 'r') { du_rflag = 1; continue; }
			if (*p == 'k') { du_blocksize = 1024; continue; }
			__util_diagf("du: invalid option -- '%c'\n", *p);
			return 1;
		}
	}

	if (i >= argc) {
		if (du_one(".") < 0) du_had_error = 1;
		return du_had_error ? 1 : 0;
	}

	for (; i < argc; i++)
		if (du_one(argv[i]) < 0) du_had_error = 1;

	return du_had_error ? 1 : 0;
}
