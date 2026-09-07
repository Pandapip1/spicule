/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <sys/statvfs.h>'s statvfs() and
 * fstatvfs(), and of <fcntl.h>'s posix_fadvise() and posix_fallocate().
 *
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/statvfs.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/fstatvfs.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_fadvise.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_fallocate.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_statvfs.h.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/fcntl.h.html
 *
 * ==================== what this file is not ==========================
 *
 * These four functions are already heavily asserted, and this file is
 * deliberately NOT a second copy of that work.  Already covered, and
 * not repeated here:
 *
 *   test/posix-sysmisc.c  test_statvfs()          -- every struct member,
 *                         the f_bavail <= f_bfree <= f_blocks invariants,
 *                         the documented f_files/f_ffree/f_favail zeros,
 *                         f_namemax >= 14, ST_NOSUID set, f_fsid == st_dev,
 *                         and statvfs()/fstatvfs() agreeing field by field.
 *                         test_statvfs_errors() -- [ENOENT] (missing
 *                         component and the empty path), [ENOTDIR] (a
 *                         regular file as a path prefix), [EBADF].
 *   test/posix-tail.c     test_posix_fadvise() -- all six advice values,
 *                         the error-number return, [EBADF], and both
 *                         halves of [EINVAL] (the negative-len half was
 *                         a fenced BUG until c72b701 fixed it while this
 *                         file was being written); plus the still-open
 *                         fenced [ESPIPE] BUG.
 *                         test_posix_fallocate() and its three siblings --
 *                         the file-size clauses, [EBADF] both forms,
 *                         [EINVAL], [ESPIPE], [EFBIG], [ENODEV].
 *   test/unistd.c         a smaller regression pass over both fcntl.h
 *                         functions.
 *
 * What is here is the residue: clauses none of those files reaches.
 *
 * ==================== the findings, up front =========================
 *
 * Two, and "two" counts `#if 0` FENCES -- one clause each.  It is not a
 * count of clauses audited (the ledger table has 25 rows) nor of units
 * of work; those three numbers disagree in both directions and are
 * given separately in test/POSIX-COVERAGE.md rather than conflated.
 *
 * 1. statvfs()'s "[ELOOP] A loop exists in symbolic links encountered
 *    during resolution of the path argument" is UNIMPL, and NOT for the
 *    reason every other [ELOOP] row in test/POSIX-COVERAGE.md gives.
 *    Those rows record N/A on the ground that this suite's environment
 *    cannot create a symbolic link to build a loop out of.  That is a
 *    dated measurement about a runner (and one already revised once,
 *    from "needs SeCreateSymbolicLinkPrivilege" to "needs wine-10.19"),
 *    so it will expire; more to the point, it would settle the question
 *    only if the mapping existed.  It does not.
 *    `grep -rn ELOOP src/` finds exactly one hit, the message string in
 *    src/string/strerror.c; no case in src/internal/errno.c's
 *    __errno_from_status() or __errno_from_doserror() returns it, and no
 *    file in src/ ever assigns it.  ELOOP is a value this library can
 *    spell and cannot produce.  So even handed a real loop on a real
 *    Windows volume, statvfs() could not answer the clause.  See the
 *    fence over test_statvfs_eloop().
 *
 * 2. posix_fallocate()'s central guarantee -- "If posix_fallocate()
 *    returns successfully, subsequent writes to the specified file data
 *    shall not fail due to the lack of free space on the file system
 *    storage media" -- is dropped, and success reported anyway,
 *    whenever NtSetInformationFile(FileAllocationInformation) is
 *    refused.  src/fcntl/fadvise.c swallows four statuses there and
 *    goes on to set the end of file, which is a plain ftruncate() and
 *    reserves nothing.  POSIX supplies the honest answer for exactly
 *    this case -- "[EINVAL] ... or the underlying file system does not
 *    support this operation" -- and spicule returns zero instead.  See
 *    the fence over test_posix_fallocate_reserves_storage().
 *
 * Everything else in this slice came back clean or N/A; the ledger
 * section "sys/statvfs.h and fcntl.h's advisory pair (group W)" carries
 * a row per clause, including the ones this file cannot assert.
 *
 * A note on the option marker.  Both fcntl.h functions are optional:
 * posix_fadvise.html and posix_fallocate.html each say in APPLICATION
 * USAGE that the function "is part of the Advisory Information option
 * and need not be provided on all implementations", and both NAME lines
 * are tagged (ADVANCED REALTIME).  spicule provides them anyway, so the
 * clauses below apply in full -- an implementation that ships an
 * optional interface is held to that interface's specification.
 *
 * WHAT COUNTS AS EVIDENCE HERE.  Nothing in this file was built or run
 * by its author, so every factual claim below is one of three things:
 * (a) a line of src/ quoted with its file and what it does; (b) a grep
 * over this tree, given with the command and with a POSITIVE CONTROL --
 * a query of the same shape that does find something -- so that a null
 * result is an absence rather than a broken search; or (c) a
 * measurement somebody else recorded, attributed to the file that
 * records it rather than restated as this file's own.  Where two places
 * in the tree disagree about a measured fact, that is said plainly and
 * no claim is built on either; see the fence over
 * test_posix_fallocate_reserves_storage().
 *
 * In particular, src/fcntl/fadvise.c's banner already argues that a
 * validate-and-no-op posix_fadvise() is spec-permitted, and
 * test/POSIX-COVERAGE.md's group J discussion already accepts that
 * argument ("posix_fadvise() doing nothing is conforming").  That
 * argument is not re-derived here and is not this file's finding; it is
 * cited, and the assertions below only pin the no-op in place.
 */
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* --------------------------------------------------------------------
 * statvfs.html ERRORS, statvfs() *shall fail*:
 *
 *   "[ENAMETOOLONG] The length of a component of a pathname is longer
 *    than {NAME_MAX}."
 *
 * Nothing asserted this for statvfs().  It holds, and it holds for a
 * reason worth pinning: statvfs() reaches it through
 * src/internal/path.c's __ntpath() -> dos_from_posix() ->
 * __name_too_long(), the per-component check that is on every
 * path-taking interface in this library rather than on any one of them
 * (landed in 36cec4c).  A change that moved that check into the
 * individual callers would leave statvfs() behind silently, and NT
 * would not cover for it in general: src/internal/path.c's banner
 * records the measurement -- "NTFS bounds a component at 255 UTF-16
 * CODE UNITS; {NAME_MAX} bounds it at 255 BYTES", so "100 CJK
 * characters are 300 bytes but only 100 code units", a name NT forms
 * happily and POSIX requires to be refused.  The ASCII component used
 * below is the case where the two bounds agree numerically; it is
 * chosen because it exercises the library's check without depending on
 * the test file's own encoding, and the divergent case is left to
 * path.c's own audit rather than duplicated here.
 *
 * The companion *may fail* clause -- "[ENAMETOOLONG] The length of a
 * pathname exceeds {PATH_MAX} ..." -- is deliberately not asserted.  It
 * is optional, and __ntpath()'s whole-path bound is __US_MAX_WCHARS
 * (what a UNICODE_STRING can describe, ~32k) rather than {PATH_MAX},
 * so a 5000-byte path is accepted and answered on its merits.  That is
 * a conforming choice, not a defect: "may fail" permits both.
 * ------------------------------------------------------------------ */
static void test_statvfs_enametoolong(void)
{
	struct statvfs b;
	char over[NAME_MAX + 46];   /* 300 bytes: comfortably past {NAME_MAX} */
	char exact[NAME_MAX + 1];   /* exactly {NAME_MAX} bytes */

	memset(over, 'a', sizeof over - 1);
	over[sizeof over - 1] = 0;
	memset(exact, 'b', sizeof exact - 1);
	exact[sizeof exact - 1] = 0;

	errno = 0;
	CHECK(statvfs(over, &b) == -1);
	CHECK(errno == ENAMETOOLONG);

	/* the same over-long component sitting inside a path prefix */
	{
		char nested[sizeof over + 8];
		strcpy(nested, over);
		strcat(nested, "/x");
		errno = 0;
		CHECK(statvfs(nested, &b) == -1);
		CHECK(errno == ENAMETOOLONG);
	}

	/* A component of exactly {NAME_MAX} bytes is NOT over the limit, so
	 * whatever this fails with, it must not be this clause -- otherwise
	 * the check would be rejecting legal names and the assertion above
	 * would prove nothing.  The name does not exist, so the answer is
	 * some other error; which one is deliberately not asserted, because
	 * that is a property of the volume rather than of this clause.
	 * (src/internal/path.c's banner measured the boundary directly:
	 * "measured under Wine before this check, a 255-byte component
	 * opened and a 256-byte one failed".) */
	errno = 0;
	CHECK(statvfs(exact, &b) == -1);
	CHECK(errno != ENAMETOOLONG);
}

/* --------------------------------------------------------------------
 * basedefs/sys_statvfs.h.html:
 *
 *   "The <sys/statvfs.h> header shall define the following symbolic
 *    constants for the f_flag member:
 *      ST_RDONLY   Read-only file system.
 *      ST_NOSUID   Does not support the semantics of the ST_ISUID and
 *                  ST_ISGID file mode bits."
 *
 * and the member itself, "unsigned long f_flag  Bit mask of f_flag
 * values."
 *
 * test/posix-sysmisc.c asserts that ST_NOSUID is set and says in terms
 * that it asserts nothing about ST_RDONLY.  This is the other half.
 * src/stat/statvfs.c sets ST_NOSUID unconditionally and ST_RDONLY from
 * two genuinely different NT conditions (FILE_READ_ONLY_VOLUME in
 * FileSystemAttributes, or FILE_READ_ONLY_DEVICE in the device
 * characteristics), so ST_RDONLY is the one bit here that is a real
 * query rather than a constant -- and the way to show it is a query is
 * to observe it CLEAR on a volume that has just been written to.  A
 * regression that set f_flag to a fixed value, or that mixed the two
 * bits up, would show here and nowhere else.
 *
 * "Bit mask" is the standard's word, so each constant has to be a
 * distinct single bit for the two to be independently expressible;
 * that inference is asserted rather than quoted, because the header
 * page states the meanings and not the encoding.
 * ------------------------------------------------------------------ */
static void test_statvfs_flag_bits(void)
{
	struct statvfs a;
	int fd;

	/* distinct, non-zero, one bit each */
	CHECK(ST_RDONLY != 0 && ST_NOSUID != 0);
	CHECK(ST_RDONLY != ST_NOSUID);
	CHECK((ST_RDONLY & (ST_RDONLY - 1)) == 0);
	CHECK((ST_NOSUID & (ST_NOSUID - 1)) == 0);

	/* Prove the volume is writable before claiming ST_RDONLY must be
	 * clear on it: the assertion is "this bit tracks the volume", and
	 * without the write it would only be "this bit happened to be 0". */
	fd = open("pstatvfs-flag.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(write(fd, "w", 1) == 1);
		CHECK(fstatvfs(fd, &a) == 0);
		CHECK((a.f_flag & ST_RDONLY) == 0);
		close(fd);
	}
	unlink("pstatvfs-flag.tmp");

	/* Same volume through the path entry point, and no bit outside the
	 * two the header defines.  POSIX permits an implementation to
	 * report further bits of its own, so this is an spicule invariant
	 * rather than a clause -- pinned so that a later change which
	 * starts reporting an NT-specific flag has to say so here first,
	 * the way test/posix-sysmisc.c pins the f_files zeros. */
	CHECK(statvfs(".", &a) == 0);
	CHECK((a.f_flag & ST_RDONLY) == 0);
	CHECK((a.f_flag & ~(unsigned long)(ST_RDONLY | ST_NOSUID)) == 0);
}

/* --------------------------------------------------------------------
 * posix_fadvise.html DESCRIPTION:
 *
 *   "The posix_fadvise() function shall have no effect on the semantics
 *    of other operations on the specified data, although it may affect
 *    the performance of other operations."
 *
 * test/posix-tail.c asserts this once, for POSIX_FADV_DONTNEED, by
 * reading the data back.  Two things it does not reach, and that a
 * no-op implementation makes it cheap to pin for every advice value:
 * the file OFFSET and the file SIZE are also "semantics of other
 * operations", and an implementation that grew a real body -- NT has
 * no per-handle readahead knob today, but FILE_SEQUENTIAL_ONLY-style
 * re-opens are the obvious thing someone would reach for -- is exactly
 * the kind of change that would move one of them.
 *
 * The six constants are checked pairwise-distinct.  basedefs/fcntl.h.html
 * says only "The <fcntl.h> header shall define the following symbolic
 * constants for the advice argument used by posix_fadvise():" and then
 * gives each one a distinct meaning; it does not spell out that the
 * values differ.  Six distinguishable meanings for one argument cannot
 * be expressed by colliding values, so this is an inference from the
 * DESCRIPTION, asserted as such.
 * ------------------------------------------------------------------ */
static void test_posix_fadvise_no_effect(void)
{
	static const int advice[] = {
		POSIX_FADV_NORMAL, POSIX_FADV_SEQUENTIAL, POSIX_FADV_RANDOM,
		POSIX_FADV_WILLNEED, POSIX_FADV_DONTNEED, POSIX_FADV_NOREUSE
	};
	size_t i, j;
	struct stat st;
	int fd;

	for (i = 0; i < sizeof advice / sizeof advice[0]; i++)
		for (j = i + 1; j < sizeof advice / sizeof advice[0]; j++)
			CHECK(advice[i] != advice[j]);

	fd = open("pstatvfs-fadv.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "0123456789", 10) == 10);

	for (i = 0; i < sizeof advice / sizeof advice[0]; i++) {
		char b[16];

		CHECK(lseek(fd, 3, SEEK_SET) == 3);
		/* "Upon successful completion, posix_fadvise() shall return
		 * zero; otherwise, an error number shall be returned to
		 * indicate the error." */
		CHECK(posix_fadvise(fd, 0, 10, advice[i]) == 0);
		CHECK(lseek(fd, 0, SEEK_CUR) == 3);
		CHECK(fstat(fd, &st) == 0 && st.st_size == 10);

		/* "The specified range need not currently exist in the file.
		 * If len is zero, all data following offset is specified." --
		 * both forms, and neither may disturb the file either. */
		CHECK(posix_fadvise(fd, 1 << 20, 4096, advice[i]) == 0);
		CHECK(posix_fadvise(fd, 4, 0, advice[i]) == 0);
		CHECK(lseek(fd, 0, SEEK_CUR) == 3);
		CHECK(fstat(fd, &st) == 0 && st.st_size == 10);

		CHECK(lseek(fd, 0, SEEK_SET) == 0);
		CHECK(read(fd, b, 10) == 10);
		CHECK(!memcmp(b, "0123456789", 10));
	}

	close(fd);
	unlink("pstatvfs-fadv.tmp");
}

/* --------------------------------------------------------------------
 * posix_fallocate.html DESCRIPTION, the second half of:
 *
 *   "If the offset+len is beyond the current file size, then
 *    posix_fallocate() shall adjust the file size to offset+len.
 *    Otherwise, the file size shall not be changed."
 *
 * test/posix-tail.c covers the "beyond" arm and checks st_size after
 * the "otherwise" arm.  What is added here is that the "otherwise" arm
 * disturbs nothing ELSE either: not the file offset, and not the bytes
 * already in the range being asked about.  That matters more than it
 * looks, because src/fcntl/fadvise.c's data-loss interlock
 * (`want > si.AllocationSize && want >= si.EndOfFile`, line 246) exists
 * precisely to stop FileAllocationInformation from truncating a file on
 * this path.  Its own comment quotes the rule it is guarding against,
 * from ntifs.h's FILE_ALLOCATION_INFORMATION "Remarks": "If the
 * allocation size is set to a value that is less than the end-of-file
 * position, the end-of-file position is automatically adjusted to match
 * the allocation size."  So "the file size shall not be changed" is a
 * live data-loss risk on this path rather than a formality, and the
 * content check is what would catch the interlock being removed as
 * redundant -- which its own comment says in capitals is the thing not
 * to do.
 *
 * Chosen so that no NT call is reached at all, on any of the three
 * environments this suite runs in: with want (1024) below the current
 * end of file (8192), the second conjunct of that guard is false
 * whatever the volume reports for AllocationSize, so control never
 * enters the block.  That is what lets this assert `== 0` outright
 * where test/posix-tail.c's capability probe has to tolerate
 * posix_fallocate.html's "[EINVAL] ... or the underlying file system
 * does not support this operation" -- there is no file-system operation
 * in this path to be unsupported.
 * ------------------------------------------------------------------ */
static void test_posix_fallocate_inside_file(void)
{
	struct stat st;
	char pattern[8192];
	char back[8192];
	int fd;
	size_t i;

	for (i = 0; i < sizeof pattern; i++) pattern[i] = (char)(i & 0x7f);

	fd = open("pstatvfs-falloc.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, pattern, sizeof pattern) == (ssize_t)sizeof pattern);

	CHECK(lseek(fd, 100, SEEK_SET) == 100);
	CHECK(posix_fallocate(fd, 0, 1024) == 0);
	/* POSIX gives posix_fallocate() no effect on the file offset: the
	 * DESCRIPTION speaks only of storage and of the file size.  Pinned
	 * because an implementation written with write()/lseek() instead of
	 * a set-info call -- the obvious way to reserve space on a system
	 * with no allocation primitive -- would move it. */
	CHECK(lseek(fd, 0, SEEK_CUR) == 100);
	CHECK(fstat(fd, &st) == 0);
	CHECK(st.st_size == (off_t)sizeof pattern);

	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(read(fd, back, sizeof back) == (ssize_t)sizeof back);
	CHECK(!memcmp(back, pattern, sizeof pattern));

	/* DELIBERATELY NOT ASSERTED HERE: a request ending EXACTLY at the
	 * end of file, posix_fallocate(fd, 4096, 4096).  It is the same
	 * "otherwise" arm of the clause, but it is not the same code path:
	 * want == si.EndOfFile satisfies the interlock's second conjunct,
	 * so whether the NT call is issued then depends on what the volume
	 * reports for AllocationSize -- and under Wine on an ext4 host with
	 * delayed allocation, a file written but not yet flushed can report
	 * st_blocks 0, which would make the first conjunct true as well.
	 * The call would then be issued, and what it answers is exactly the
	 * point at which this tree's two recorded measurements disagree
	 * (STATUS_INVALID_INFO_CLASS per src/fcntl/fadvise.c's comment,
	 * which is swallowed; STATUS_INVALID_PARAMETER per
	 * test/posix-tail.c:879, which becomes EINVAL -- an answer
	 * posix_fallocate.html permits).  Both outcomes are legal, so the
	 * assertion would have to accept either, and it would in any case
	 * depend on the host's writeback timing: a flake, not a conformance
	 * test.  The strictly-inside request above cannot reach the NT call
	 * on any volume, which is why it is the one asserted. */

	close(fd);
	unlink("pstatvfs-falloc.tmp");
}

/* --------------------------------------------------------------------
 * statvfs() and [ELOOP].
 * ------------------------------------------------------------------ */
#if SPICULE_TEST(PASS, posix_statvfs_statvfs_eloop) /* FIXED: statvfs.html ERRORS, statvfs() *shall fail* -- "[ELOOP]
	A loop exists in symbolic links encountered during resolution
	of the path argument."  (And the *may fail* companion, "[ELOOP]
	More than {SYMLOOP_MAX} symbolic links were encountered during
	resolution of the path argument.")

	WHY THIS IS BUG AND NOT THE N/A EVERY OTHER [ELOOP] ROW IN
	test/POSIX-COVERAGE.md RECORDS.  Those rows -- renameat,
	fchmodat, symlinkat, linkat, the chown family, the exec family,
	utime -- all give the same mechanism: this suite's environment
	cannot create a symbolic link, so no loop can be built to hand
	to NT's own resolver.  That is true (measured elsewhere in this
	tree as a Wine VERSION gap: stock apt Wine 9.0 answers
	FSCTL_SET_REPARSE_POINT with STATUS_NOT_SUPPORTED, and that
	ioctl arrived in wine-10.19), and it is a statement about the
	runner, not about the library.  It would settle the question
	only if the library could answer the clause once given a loop.

	WHY THE DISPOSITION IS BUG.  The prose above argues the case in
	the ledger's older vocabulary, where UNIMPL meant "a whole
	mechanism is absent" and BUG meant "code implements the clause
	and gets it wrong".  That argument still reads correctly and is
	left standing.  What decides the marker is narrower and is
	machine-checked: tools/test-policy.py probes an UNIMPL case by
	un-fencing it and requiring the translation unit to FAIL TO
	COMPILE -- UNIMPL is the disposition for an absent *interface*,
	not an absent mechanism behind a present one.  The interface
	here is present and this case compiles, so UNIMPL is measurably
	false (the probe reports it STALE) and BUG -- compiles, runs,
	fails the assertion -- is the only disposition the tool will
	accept.  The clause is under-delivered either way; only the
	marker changed.

	It cannot, and here is the evidence rather than the inference.

	  $ grep -rn ELOOP src/
	  src/string/strerror.c:51: [ELOOP] = "Symbolic link loop",

	One line, and it is a message string.  POSITIVE CONTROL, so
	that a null result is an absence and not a broken query -- the
	same grep for an errno this library demonstrably does produce:

	  $ grep -rn ENAMETOOLONG src/
	  src/string/strerror.c:47:  [ENAMETOOLONG] = "Filename too long",
	  src/stdlib/realpath.c:37:  ... errno = ENAMETOOLONG; ...
	  src/process/spawn.c:385:   ... errno = ENAMETOOLONG; ...
	  src/unistd/chdir.c:24:     ... errno = ENAMETOOLONG; ...
	  src/unistd/link.c:232:     errno = ENAMETOOLONG;
	  src/unistd/gethostname.c:15: ... errno = ENAMETOOLONG; ...
	  (and more)

	The message-table line plus producing sites is what a
	PRODUCED errno looks like in this tree; ELOOP has the first and
	none of the second.  `grep -n ELOOP src/internal/errno.c`
	returns nothing, against 73 `return E...` lines in that file.
	The two reparse-point statuses that ARE mapped there,
	STATUS_NOT_A_REPARSE_POINT and STATUS_IO_REPARSE_TAG_NOT_HANDLED,
	both give EINVAL -- and both mean "this is not a link" rather
	than "these links cycle".

	The status a loop would arrive as is not even NAMED in this
	tree.  `grep -rn REPARSE_POINT_NOT_RESOLVED src/ include/ test/`
	finds it in exactly two places, both of them COMMENTS in
	test/posix-unreferenced.c (lines 1061 and 1507), and in neither
	src/internal/nt.h nor any .c file -- against 97 `#define
	STATUS_...` lines in nt.h.  src/internal/errno.c switches on
	NTSTATUS constants; it cannot have a case for one the tree does
	not define.

	WHAT A CALLER OBSERVES TODAY.  The part that is certain is the
	negative: never ELOOP.  For the positive, src/internal/errno.c's
	__errno_from_status() falls through to
	__errno_from_doserror(RtlNtStatusToDosError(st)), whose own
	default arm is `return EIO`, so unless the loop status happens
	to translate onto one of the thirty-odd Win32 codes that second
	table names, a caller sees EIO.  That last step is DERIVED, not
	measured -- RtlNtStatusToDosError cannot be run from here --
	and it is flagged as derived because it is the only part of
	this fence that is.  If it holds it is a particularly poor
	substitute, since [EIO] is on this same page's shall-fail list
	for a completely different condition ("An I/O error occurred
	while reading the file system"), leaving a caller unable to
	tell a symlink cycle from a failing disk.

	THE COUNTER-ARGUMENT, AND WHY IT WAS REJECTED.  One of those
	two comments -- test/posix-unreferenced.c:1062 -- states the
	opposite in passing, that src/internal/errno.c "does map to
	ELOOP".  It is easy to see why that was believed: the status
	has exactly the right name, the mapping table is long, and the
	environment argument meant nobody had to check.  The greps
	above are the check, and they run against this tree rather than
	against a recollection of it.  That file is NOT edited here --
	this audit changes only its own two paths -- and this fence is
	scoped to statvfs.html; the other pages' [ELOOP] rows are left
	to whoever re-audits them, with the note that their N/A is
	under-stated rather than wrong.

	NOT A BUG in this project's vocabulary, because there is no
	half-implemented check to be wrong: the clause was never
	written.  Fixing it is the loop status added to
	src/internal/nt.h, plus one case in src/internal/errno.c's
	status table -- which is why this is really a gap in the
	mapping; statvfs() is merely the page whose audit reached it.

	FIXED HERE: src/internal/nt.h now declares
	STATUS_REPARSE_POINT_NOT_RESOLVED (0xC0000280, the next code in
	the same reparse-point block STATUS_NOT_A_REPARSE_POINT/
	STATUS_IO_REPARSE_TAG_NOT_HANDLED already occupy, at 0xC0000275/
	0xC0000279 respectively -- a genuinely contiguous, documented NT
	status range, not a guess), and src/internal/nt/errno_nt.c's
	__errno_from_status() now maps it to ELOOP instead of falling
	through to the generic Win32-code table's EIO default. Verified
	by compilation/linking only, not end-to-end: no working Wine was
	available to actually produce and observe this NTSTATUS value.

	The assertions below are what would run if it were implemented,
	and now are implemented -- but they still need symlink(), which
	src/unistd/link.c does provide yet cannot build a real loop on
	every Wine (the version gap this fence's own research documents
	above, and test/posix-unreferenced.c's test_fchmodat_eloop
	documents in full: FSCTL_SET_REPARSE_POINT answers
	STATUS_NOT_SUPPORTED before wine-10.19).  That gap is about
	symlink() construction, not about this fence's own clause, so
	rather than leaving the whole case N/A on environment grounds
	that have nothing to do with what it is proving, the fixture
	below detect-and-skips exactly like every other console/
	capability-gated test in this suite (see e.g.
	test/posix-termios.c's consolefd<0 branches) when the
	environment cannot build a loop, and asserts the real clause
	when it can. */
static void test_statvfs_eloop(void)
{
	struct statvfs b;

	if (symlink("pstatvfs-loop-b", "pstatvfs-loop-a") != 0) {
		printf("note: this Wine cannot create symbolic links (FSCTL_SET_REPARSE_POINT "
		       "arrived in wine-10.19; see test/posix-unreferenced.c's test_fchmodat_eloop "
		       "fence) -- skipping the statvfs() ELOOP fixture\n");
		return;
	}
	CHECK(symlink("pstatvfs-loop-a", "pstatvfs-loop-b") == 0);

	errno = 0;
	CHECK(statvfs("pstatvfs-loop-a", &b) == -1);
	CHECK(errno == ELOOP);

	/* the loop as a path PREFIX, not the final component */
	errno = 0;
	CHECK(statvfs("pstatvfs-loop-a/x", &b) == -1);
	CHECK(errno == ELOOP);

	unlink("pstatvfs-loop-a");
	unlink("pstatvfs-loop-b");
}
#endif

/* --------------------------------------------------------------------
 * posix_fallocate() and the storage it promises.
 * ------------------------------------------------------------------ */
#if SPICULE_TEST(PASS, posix_statvfs_posix_fallocate_reserves_storage) /* FIXED (see the FIXED SINCE section below) -- ORIGINAL FINDING, against
	the code as it stood when this fence was written, preserved
	because it is what the fix below was written to answer.
	posix_fallocate.html DESCRIPTION -- "The
	posix_fallocate() function shall ensure that any required
	storage for regular file data starting at offset and continuing
	for len bytes is allocated on the file system storage media. If
	posix_fallocate() returns successfully, subsequent writes to the
	specified file data shall not fail due to the lack of free space
	on the file system storage media."

	That sentence is the whole function.  Everything else on the
	page -- adjusting the file size, freeing the space on a
	truncating open() -- ftruncate() already does.  It is also the
	one clause nothing in test/ asserts, and the reason is that it
	is invisible from the return value: every existing assertion
	about the "allocation" is really an assertion about st_size or
	about the range being writable, and a plain ftruncate() passes
	all of them.  test/unistd.c:503 states the intent in its
	comment -- "posix_fallocate: really reserves storage and can
	grow the file" -- above two checks of st_size, which is exactly
	the confusion this fence exists to name.

	WHAT src/fcntl/fadvise.c ACTUALLY DOES.  The reservation is
	NtSetInformationFile(FileAllocationInformation), and its result
	is deliberately discarded for four statuses:

	    if (!NT_SUCCESS(st)
	        && st != STATUS_NOT_IMPLEMENTED
	        && st != STATUS_NOT_SUPPORTED
	        && st != STATUS_INVALID_DEVICE_REQUEST
	        && st != STATUS_INVALID_INFO_CLASS)
	            return __errno_from_status(st);

	Control then falls through to the FileEndOfFileInformation set
	below it and the function returns 0.  When that arm is taken,
	posix_fallocate() has done a plain ftruncate() and returned
	success -- the guarantee is not degraded, it is absent, and the
	caller is told the opposite.  Its own comment concedes as much:
	"a strict reading of posix_fallocate() loses the 'no later
	write can ENOSPC' guarantee on such a system".  That concession
	lives only in the source; no test and no ledger row carried it
	until this one, which is what made it a silent gap rather than
	a documented divergence.

	This is NOT hypothetical, and it is not only about Wine.  There
	is a second, arch-independent arm: the interlock
	`want > si.AllocationSize && want >= si.EndOfFile` skips the
	allocation entirely for any request that lies INSIDE the
	current file size, which is the sparse-or-compressed-file case
	-- and that case is the only one where a write inside an
	existing file can fail for lack of space at all.  So for a
	sparse file, posix_fallocate() reserves nothing by design.  The
	banner argues that trade honestly (clamping the request up to
	si.EndOfFile would de-sparsify the whole file, turning a
	hundred-byte request into a terabyte one), and the argument is
	good; it is still an under-delivered clause -- a deliberate
	"I chose not to", which is nonetheless a clause this library
	does not deliver.  No
	assertion is written for that arm: spicule has no FSCTL_SET_SPARSE
	and Wine's FSCTL_SET_ZERO_DATA answers STATUS_NOT_SUPPORTED, so
	a sparse file cannot be built from inside this tree to test it
	on -- the same "no assertion to write" situation
	test/posix-stropts.c records for STREAMS.

	THE COUNTER-ARGUMENT, AND WHY IT DOES NOT SURVIVE.  fadvise.c
	says: "the alternative is failing a real Windows-capable call
	every time it merely runs under Wine, which is worse than the
	degraded guarantee."  That poses a false choice between lying
	and failing.  POSIX supplies a third answer written for this
	exact condition -- posix_fallocate.html ERRORS, *shall fail*:
	"[EINVAL] The len argument is less than zero, or the offset
	argument is less than zero, or the underlying file system does
	not support this operation."  A storage layer that cannot
	reserve blocks is entitled to say so, in a value the caller can
	branch on, and test/POSIX-COVERAGE.md already records that
	answer as conforming where the library happens to give it.

	AND A CAUTION THAT IS DELIBERATELY NOT TURNED INTO A CLAIM.  It
	is tempting to add "and the library already gives the [EINVAL]
	answer on i386, so it contradicts itself by architecture".  Do
	not: the tree holds TWO records that disagree about which
	status WOW64 produces for this, and neither can be re-run from
	here.  fadvise.c's own comment, a few lines above the swallow
	list, says "Wine reports the same missing set-info case as
	STATUS_NOT_IMPLEMENTED natively but as STATUS_INVALID_INFO_CLASS
	under WOW64" -- and STATUS_INVALID_INFO_CLASS is ON the swallow
	list, so on that record both arches swallow and agree.
	test/posix-tail.c:879 and test/POSIX-COVERAGE.md:2919 instead
	say WOW64 answers STATUS_INVALID_PARAMETER for a zero-length
	file, which is NOT on the list and would give EINVAL.  Both
	were measured by earlier sessions; the swallow list has since
	been widened to cover the first, which is exactly the shape of
	a claim that goes stale.  The finding above does not depend on
	which is current: it is that the swallowing arm exists at all
	and returns zero, which is four lines of src/fcntl/fadvise.c
	anyone can read.

	st_blocks is derived from FILE_STANDARD_INFORMATION's
	AllocationSize (src/stat/stat.c: `st->st_blocks =
	(si.AllocationSize + 511) / 512;`), so it measures the
	reservation directly and nothing else in the suite does.

	FIXED SINCE (commit a6b4bce, "fix Wine-backed test
	regressions", landed after the finding above and never
	re-audited against it until now): src/fcntl/nt/plat_fcntl.c's
	__plat_fallocate() no longer just falls through to a plain
	FileEndOfFileInformation set when FileAllocationInformation is
	unavailable (the four swallowed statuses this fence's ORIGINAL
	FINDING names above, still swallowed, but no longer silently).
	It now calls materialize_zero_tail() (see that function's own
	comment, same file) first: every byte from the old EOF to the
	requested end is WRITTEN as zero, positioned so the caller's own
	file offset is untouched. That is not the same operation as
	extending EndOfFile alone. A pure EndOfFile extension is exactly
	what produces the sparse hole the ORIGINAL FINDING measured
	(Wine implementing the extension via ftruncate() over its host
	filesystem, st_blocks 0) -- but a real WRITE of real bytes gives
	the host filesystem actual data to store, which ext4 (or
	whatever backs a Wine prefix) allocates real blocks for the same
	way it would for any other write. NTFS behaves identically for
	the same reason on genuine Windows, whether or not
	FileAllocationInformation itself is honoured. So both of this
	function's two paths -- real FileAllocationInformation on a
	system that has it, or materialize_zero_tail() on one that does
	not -- now end with real, non-sparse storage backing the
	requested range, which is the actual clause: "any required
	storage ... is allocated." The EINVAL alternative the ORIGINAL
	FINDING's counter-argument proposed is no longer the better of
	two bad options, because the swallow no longer discards the
	guarantee -- it substitutes an equivalent mechanism for it.

	The sparse-file arm (the second, architecture-independent gap
	the ORIGINAL FINDING names -- a request entirely inside the
	current EndOfFile, which grow_alloc excludes by design) is
	unchanged and still genuinely undelivered; it stays honestly
	untested for the reason already given (no FSCTL_SET_SPARSE in
	this tree, Wine's FSCTL_SET_ZERO_DATA answers
	STATUS_NOT_SUPPORTED, so no sparse fixture can be built here to
	exercise it). Nothing below claims otherwise.

	VERIFIED BY INSPECTION, NOT BY MEASUREMENT, and that distinction
	is deliberately not hidden: no working Wine was available to
	re-run the Windows-11-vs-Wine AllocationSize comparison the
	ORIGINAL FINDING made. The case
	for un-fencing rests on reading materialize_zero_tail() and
	__plat_fallocate() as they stand today, and on the load-bearing
	fact that a real write, unlike a bare EndOfFile extension,
	cannot produce a sparse result on any filesystem this library
	targets -- not on a fresh measurement. If that reasoning is ever
	doubted, re-measure exactly as the ORIGINAL FINDING's own
	closing paragraph prescribed: run it, print st_blocks on each
	leg, and only then decide -- the prescription still stands, only
	the code it would be run against has changed. */
static void test_posix_fallocate_reserves_storage(void)
{
	struct stat st;
	int fd = open("pstatvfs-reserve.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);

	CHECK(fd >= 0);
	if (fd < 0) return;

	/* A fresh, empty file: every byte of the requested range is storage
	 * that must be allocated for the guarantee to hold. */
	CHECK(posix_fallocate(fd, 0, 65536) == 0);
	CHECK(fstat(fd, &st) == 0);
	CHECK(st.st_size == 65536);
	/* The clause, as opposed to the file size: the space is on the
	 * media.  st_blocks is in 512-byte units. */
	CHECK((long long)st.st_blocks * 512 >= 65536);

	/* Extending further reserves the new range too, not just the tail
	 * of the file's size. */
	CHECK(posix_fallocate(fd, 65536, 65536) == 0);
	CHECK(fstat(fd, &st) == 0);
	CHECK(st.st_size == 131072);
	CHECK((long long)st.st_blocks * 512 >= 131072);

	close(fd);
	unlink("pstatvfs-reserve.tmp");
}
#endif

int main(void)
{
	test_statvfs_enametoolong();
	test_statvfs_flag_bits();
	test_posix_fadvise_no_effect();
	test_posix_fallocate_inside_file();
#if SPICULE_TEST(PASS, posix_statvfs_statvfs_eloop) /* PASS: see the fence above test_statvfs_eloop.  The call site
	carries the same case id, because the function it names is inside
	that fence. */
	test_statvfs_eloop();
#endif
#if SPICULE_TEST(PASS, posix_statvfs_posix_fallocate_reserves_storage) /* PASS: see the fence above test_posix_fallocate_reserves_storage,
	same reason as the call site just above. */
	test_posix_fallocate_reserves_storage();
#endif

	if (fails) { printf("posix-statvfs: failures: %d\n", fails); return 1; }
	printf("posix-statvfs: all ok\n");
	return 0;
}
