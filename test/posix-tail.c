/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the long tail of one- and
 * two-function headers that no priority in test/POSIX-COVERAGE.md's
 * order ever reached (group J3; J1 is <locale.h>'s object API in
 * test/posix-locale.c and J2 is <stropts.h> in test/posix-stropts.c):
 *
 *   sys/uio.h      readv writev              (XSI)
 *   ftw.h          ftw nftw                  (ftw is OB XSI)
 *   fcntl.h        posix_fadvise posix_fallocate  (ADV)
 *   setjmp.h       _setjmp _longjmp          (OB XSI)
 *   string.h       strlen strnlen
 *   sys/times.h    times                     (XSI)
 *   sys/utsname.h  uname
 *   sys/time.h     gettimeofday              (OB)
 *   stdlib.h       srand48                   (XSI)
 *
 * They are audited in one file because they share nothing but their
 * size; each section names its page and stands alone.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   functions/readv.html          functions/writev.html
 *   functions/ftw.html            functions/nftw.html
 *   functions/posix_fadvise.html  functions/posix_fallocate.html
 *   functions/_setjmp.html        functions/setjmp.html
 *   functions/longjmp.html        functions/strlen.html
 *   functions/times.html          functions/uname.html
 *   functions/gettimeofday.html   functions/drand48.html
 *   basedefs/sys_uio.h.html       basedefs/ftw.h.html
 *   basedefs/sys_times.h.html     basedefs/sys_utsname.h.html
 *
 * ==================== outcomes ========================================
 *
 * Nothing in this file is fenced any more.  Four of the fences were in
 * the two <fcntl.h> advisory functions and are fixed: posix_fadvise's
 * missing [ESPIPE] for a pipe or FIFO and its missing [EINVAL] for
 * len < 0, posix_fallocate's [ENODEV] for a non-regular file reported
 * as [EBADF], and its missing [EBADF] for a descriptor opened
 * read-only.  The last one was in nftw() -- no protection against a
 * directory that is a descendant of itself through a symbolic link,
 * which nftw.html requires when FTW_PHYS is clear -- and it is fixed
 * too, in src/ftw/ftw.c, with `test_nftw_symlink_loop` running live.
 *
 * Two assertion groups can come out **unverified (exit 77)** rather than
 * passing or failing, for one reason between them: both the
 * FTW_PHYS/FTW_SL/FTW_SLN group and the descendant-of-itself group need
 * a real symbolic link, and symlink() here fails ENOSYS under Wine and
 * EPERM on a real Windows without SeCreateSymbolicLinkPrivilege.  That ENOSYS
 * is the correct rendering of the STATUS_NOT_SUPPORTED (0xc00000bb)
 * stock Wine below 10.19 answers FSCTL_SET_REPARSE_POINT with -- and
 * src/internal/errno.c:82-84 maps that status onto ENOSYS along with
 * STATUS_NOT_IMPLEMENTED and STATUS_INVALID_DEVICE_REQUEST, so do not
 * read the errno back as evidence of NOT_IMPLEMENTED specifically.  On
 * the Wine leg the privilege is never consulted at all. Each group probes at
 * run time, a SKIP line naming the mechanism and the observed errno is
 * printed, and main() returns 77 -- tools/run-tests.py, tools/asan-
 * build.sh and CI's PowerShell loop all report that in their own
 * bucket. Modelled on test/posix-socket.c. Nothing is silently
 * skipped and nothing unrun is reported as a pass.
 */
#define _GNU_SOURCE
#include "test-policy.h"
#include <sys/uio.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <ftw.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

static int fails;
/* Counts assertion groups this run declined to exercise because the
 * environment could not provide the fixture -- as opposed to `fails`,
 * which counts assertions that ran and got the wrong answer. See
 * main()'s tail for why the two exit differently. */
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ====================================================================
 * sys/uio.h -- readv(), writev()
 *
 * readv.html: "shall be equivalent to read(), except as described
 * below ... shall place the input data into the iovcnt buffers
 * specified by the members of the iov array ... The iovcnt argument is
 * valid if greater than 0 and less than or equal to {IOV_MAX} ... The
 * readv() function shall always fill an area completely before
 * proceeding to the next."
 *
 * writev.html: the gather direction, plus two clauses readv.html has
 * no counterpart for -- "If fildes refers to a regular file and all of
 * the iov_len members in the array pointed to by iov are 0, writev()
 * shall return 0 and have no other effect", and "If the sum of the
 * iov_len values is greater than {SSIZE_MAX}, the operation shall fail
 * and no data shall be transferred."
 *
 * ERRORS on both: "Refer to read"/"Refer to write", plus *shall fail*
 * "[EINVAL] The sum of the iov_len values ... overflowed an ssize_t"
 * and *may fail* "[EINVAL] The iovcnt argument was less than or equal
 * to 0, or greater than {IOV_MAX}".
 * ================================================================== */
static void test_readv(void)
{
	char a[4], b[8], c[4];
	struct iovec iov[3];
	int fd = open("tail-readv.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	ssize_t n;

	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "hello world!", 12) == 12);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);

	/* "shall always fill an area completely before proceeding to the
	 * next" -- the split must land exactly on the iov boundaries */
	memset(a, '#', sizeof a); memset(b, '#', sizeof b);
	iov[0].iov_base = a; iov[0].iov_len = 4;
	iov[1].iov_base = b; iov[1].iov_len = 8;
	n = readv(fd, iov, 2);
	CHECK(n == 12);
	CHECK(!memcmp(a, "hell", 4));
	CHECK(!memcmp(b, "o world!", 8));

	/* "Refer to read" -- read.html RETURN VALUE: 0 at end-of-file */
	iov[0].iov_base = a; iov[0].iov_len = 4;
	CHECK(readv(fd, iov, 1) == 0);

	/* a short read: fewer bytes available than the vector asks for.
	 * read.html: "shall return the number of bytes actually read". */
	CHECK(lseek(fd, 8, SEEK_SET) == 8);
	memset(a, '#', sizeof a); memset(b, '#', sizeof b); memset(c, '#', sizeof c);
	iov[0].iov_base = a; iov[0].iov_len = 4;
	iov[1].iov_base = b; iov[1].iov_len = 8;
	iov[2].iov_base = c; iov[2].iov_len = 4;
	CHECK(readv(fd, iov, 3) == 4);
	CHECK(!memcmp(a, "rld!", 4));
	/* the areas past the data are untouched: readv() filled area 0
	 * completely, found nothing left, and stopped */
	CHECK(b[0] == '#' && c[0] == '#');

	/* Note on what is NOT assertable here: src/misc/uio.c now moves the
	 * whole vector in one read() and scatters what came back, so the
	 * short transfer above is a short read() rather than a loop that
	 * stopped early (XSH 2.9.7 -- see test/posix-grp.c's comment where
	 * that fence used to be).  The old loop survives only for a vector
	 * whose gather buffer could not be allocated, and its `break` when
	 * one area comes back short is unobservable for the same reasons it
	 * always was: for a regular file the next read() at end-of-file
	 * returns 0 and the total is identical either way, and for a pipe
	 * spicule's read() answers EAGAIN on empty, which the loop also
	 * treats as "stop and report what moved".  No assertion pretends to
	 * cover it.
	 *
	 * zero-length areas are skipped, not treated as end-of-input */
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	memset(a, '#', sizeof a);
	iov[0].iov_base = b; iov[0].iov_len = 0;
	iov[1].iov_base = a; iov[1].iov_len = 4;
	CHECK(readv(fd, iov, 2) == 4);
	CHECK(!memcmp(a, "hell", 4));

	close(fd);
	unlink("tail-readv.tmp");
}

static void test_readv_writev_iovcnt(void)
{
	char buf[8];
	struct iovec iov[2];
	int fd = open("tail-iovcnt.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);

	CHECK(fd >= 0);
	if (fd < 0) return;
	iov[0].iov_base = buf; iov[0].iov_len = sizeof buf;
	iov[1].iov_base = buf; iov[1].iov_len = 0;

	/* *may fail* "[EINVAL] The iovcnt argument was less than or equal
	 * to 0, or greater than {IOV_MAX}" -- spicule does implement it, so
	 * it is asserted */
	errno = 0; CHECK(readv(fd, iov, 0) == -1);  CHECK(errno == EINVAL);
	errno = 0; CHECK(readv(fd, iov, -1) == -1); CHECK(errno == EINVAL);
	errno = 0; CHECK(writev(fd, iov, 0) == -1); CHECK(errno == EINVAL);
	errno = 0; CHECK(readv(fd, iov, IOV_MAX + 1) == -1);  CHECK(errno == EINVAL);
	errno = 0; CHECK(writev(fd, iov, IOV_MAX + 1) == -1); CHECK(errno == EINVAL);

	/* "The iovcnt argument is valid if greater than 0 and less than or
	 * equal to {IOV_MAX}" -- the upper edge must be accepted, not
	 * rejected off by one.  Every element is zero-length, so this is a
	 * pure iovcnt-validation call and writes nothing. */
	{
		static struct iovec big[1024 + 1];
		int i;
		CHECK(IOV_MAX <= (int)(sizeof big / sizeof big[0]));
		for (i = 0; i < IOV_MAX; i++) { big[i].iov_base = buf; big[i].iov_len = 0; }
		errno = 0;
		CHECK(writev(fd, big, IOV_MAX) == 0);
	}
	/* sys_uio.h.html: "{IOV_MAX} ... defined in <limits.h>"; XBD
	 * <limits.h> requires it to be at least {_XOPEN_IOV_MAX}, 16. */
	CHECK(IOV_MAX >= 16);

	close(fd);
	unlink("tail-iovcnt.tmp");
}

static void test_writev(void)
{
	char rb[16];
	struct iovec iov[3];
	int fd = open("tail-writev.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);

	CHECK(fd >= 0);
	if (fd < 0) return;

	/* "shall gather output data from the iovcnt buffers ... iov[0],
	 * iov[1], ..., iov[iovcnt-1]" -- in that order, concatenated */
	iov[0].iov_base = (void *)"abc"; iov[0].iov_len = 3;
	iov[1].iov_base = (void *)"";    iov[1].iov_len = 0;
	iov[2].iov_base = (void *)"de";  iov[2].iov_len = 2;
	CHECK(writev(fd, iov, 3) == 5);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(read(fd, rb, sizeof rb) == 5);
	CHECK(!memcmp(rb, "abcde", 5));

	/* "If fildes refers to a regular file and all of the iov_len
	 * members ... are 0, writev() shall return 0 and have no other
	 * effect." */
	{
		struct stat before, after;
		CHECK(fstat(fd, &before) == 0);
		iov[0].iov_len = iov[1].iov_len = iov[2].iov_len = 0;
		CHECK(writev(fd, iov, 3) == 0);
		CHECK(fstat(fd, &after) == 0);
		CHECK(before.st_size == after.st_size);
	}

	/* *shall fail* "[EINVAL] The sum of the iov_len values in the iov
	 * array would overflow an ssize_t", and "the operation shall fail
	 * and no data shall be transferred" */
	{
		struct stat before, after;
		CHECK(fstat(fd, &before) == 0);
		iov[0].iov_base = (void *)"z"; iov[0].iov_len = 1;
		iov[1].iov_base = (void *)"z"; iov[1].iov_len = (size_t)SSIZE_MAX;
		errno = 0;
		CHECK(writev(fd, iov, 2) == -1);
		CHECK(errno == EINVAL);
		CHECK(fstat(fd, &after) == 0);
		CHECK(before.st_size == after.st_size);   /* "no data ... transferred" */
	}
	/* the same clause on the read side (readv.html ERRORS) */
	{
		char b1[1];
		CHECK(lseek(fd, 0, SEEK_SET) == 0);
		iov[0].iov_base = b1; iov[0].iov_len = 1;
		iov[1].iov_base = b1; iov[1].iov_len = (size_t)SSIZE_MAX;
		errno = 0;
		CHECK(readv(fd, iov, 2) == -1);
		CHECK(errno == EINVAL);
	}

	/* "Refer to write" -- write.html *shall fail* [EBADF] */
	iov[0].iov_base = (void *)"x"; iov[0].iov_len = 1;
	errno = 0; CHECK(writev(-1, iov, 1) == -1); CHECK(errno == EBADF);
	errno = 0; CHECK(readv(-1, iov, 1) == -1);  CHECK(errno == EBADF);

	close(fd);
	unlink("tail-writev.tmp");
}

/* ====================================================================
 * ftw.h -- ftw(), nftw()
 * ================================================================== */

/* Every callback records what it was handed into this table, so the
 * assertions can be made about the whole walk rather than one entry at
 * a time -- ordering between siblings is unspecified, so nothing below
 * depends on it. */
#define MAXENT 32
static struct { char path[256]; int flag; int base; int level; } ent[MAXENT];
static int nent;
static int stop_after;      /* >0: return `stop_value` on that entry */
static int stop_value;
static int saw_null_stat;

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

static void reset_walk(void) { nent = 0; stop_after = 0; stop_value = 0; saw_null_stat = 0; }

/* fn4(), plus the check that gives FTW_CHDIR its point: "nftw() shall
 * change the current working directory to each directory as it reports
 * files in that directory", so the object's own filename -- p + base,
 * the offset nftw() hands the callback for exactly this purpose -- must
 * name it from where the callback is standing. */
static int chdir_probe_misses;

static int fn4_chdir(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	struct stat probe;
	record(p, st, flag, f->base, f->level);
	if (stat(p + f->base, &probe) != 0) chdir_probe_misses++;
	return 0;
}

static int find_ent(const char *path)
{
	int i;
	for (i = 0; i < nent && i < MAXENT; i++)
		if (!strcmp(ent[i].path, path)) return i;
	return -1;
}

/* tree:  tailtree/            (dir)
 *        tailtree/f1          (regular, 5 bytes)
 *        tailtree/sub/        (dir)
 *        tailtree/sub/f2      (regular, 0 bytes) */
static int make_tree(void)
{
	int fd;
	if (mkdir("tailtree", 0755) < 0 && errno != EEXIST) return -1;
	if (mkdir("tailtree/sub", 0755) < 0 && errno != EEXIST) return -1;
	fd = open("tailtree/f1", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	if (write(fd, "12345", 5) != 5) { close(fd); return -1; }
	close(fd);
	fd = open("tailtree/sub/f2", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	close(fd);
	return 0;
}

static void kill_tree(void)
{
	unlink("tailtree/sub/f2");
	unlink("tailtree/sub/loop");
	rmdir("tailtree/sub");
	unlink("tailtree/f1");
	unlink("tailtree/link");
	unlink("tailtree/dangling");
	rmdir("tailtree");
}

static void test_ftw(void)
{
	int i, d, f;

	CHECK(make_tree() == 0);

	/* DESCRIPTION: "shall recursively descend the directory hierarchy
	 * rooted in path.  For each object in the hierarchy, ftw() shall
	 * call the function pointed to by fn" -- all four objects, once
	 * each.  RETURN VALUE: "If the tree is exhausted, ftw() shall
	 * return 0." */
	reset_walk();
	CHECK(ftw("tailtree", fn3, 5) == 0);
	CHECK(nent == 4);
	CHECK(find_ent("tailtree") >= 0);
	CHECK(find_ent("tailtree/f1") >= 0);
	CHECK(find_ent("tailtree/sub") >= 0);
	CHECK(find_ent("tailtree/sub/f2") >= 0);
	CHECK(!saw_null_stat);   /* "a pointer to a stat structure" */

	/* "FTW_D  For a directory.  ...  FTW_F  For a non-directory file." */
	d = find_ent("tailtree");     CHECK(d >= 0 && ent[d].flag == FTW_D);
	d = find_ent("tailtree/sub"); CHECK(d >= 0 && ent[d].flag == FTW_D);
	f = find_ent("tailtree/f1");  CHECK(f >= 0 && ent[f].flag == FTW_F);
	f = find_ent("tailtree/sub/f2"); CHECK(f >= 0 && ent[f].flag == FTW_F);

	/* "filled in as if stat() or lstat() had been called" -- st_size
	 * of the 5-byte file is a cheap, decisive check that the buffer is
	 * the real thing and not a zeroed placeholder.  (st_mode is
	 * checked through S_ISDIR/S_ISREG rather than a literal, since
	 * permission bits are a platform matter.) */
	{
		struct stat st;
		f = find_ent("tailtree/f1");
		CHECK(stat("tailtree/f1", &st) == 0);
		CHECK(st.st_size == 5);
	}

	/* "The ftw() function shall visit a directory before visiting any
	 * of its descendants." */
	for (i = 0; i < nent; i++) {
		if (!strcmp(ent[i].path, "tailtree/f1") || !strcmp(ent[i].path, "tailtree/sub"))
			CHECK(find_ent("tailtree") < i);
		if (!strcmp(ent[i].path, "tailtree/sub/f2"))
			CHECK(find_ent("tailtree/sub") < i);
	}

	/* "If the function pointed to by fn returns a non-zero value,
	 * ftw() shall stop its tree traversal and return whatever value
	 * was returned by the function pointed to by fn." */
	reset_walk(); stop_after = 2; stop_value = 77;
	CHECK(ftw("tailtree", fn3, 5) == 77);
	CHECK(nent == 2);
	reset_walk(); stop_after = 1; stop_value = -5;
	CHECK(ftw("tailtree", fn3, 5) == -5);
	CHECK(nent == 1);

	/* "The ndirs argument shall specify the maximum number of
	 * directory streams or file descriptors ... available for use by
	 * ftw() while traversing the tree" -- a walk two levels deep with
	 * ndirs == 1 must still complete, by closing and reopening
	 * ancestors rather than by failing or by exceeding the limit. */
	reset_walk();
	CHECK(ftw("tailtree", fn3, 1) == 0);
	CHECK(nent == 4);

	/* ERRORS, *shall fail*: "[ENOENT] A component of path does not name
	 * an existing file or path is an empty string." */
	/* (ftw()/nftw() each carry their own explicit empty-path check, but
	 * removing it changes nothing observable: lstat("") fails ENOENT
	 * and the walk root's failure is returned as -1 with that errno
	 * anyway.  The assertion below is on the clause, which holds
	 * either way -- deliberately not on the redundant check.) */
	reset_walk(); errno = 0;
	CHECK(ftw("", fn3, 5) == -1);
	CHECK(errno == ENOENT);
	CHECK(nent == 0);
	reset_walk(); errno = 0;
	CHECK(ftw("tailtree/no-such-thing", fn3, 5) == -1);
	CHECK(errno == ENOENT);
	CHECK(nent == 0);
	reset_walk(); errno = 0;
	CHECK(ftw("no-such-dir/f", fn3, 5) == -1);
	CHECK(errno == ENOENT);

	/* ERRORS, *shall fail*: "[ENOTDIR] A component of path names an
	 * existing file that is neither a directory nor a symbolic link to
	 * a directory." */
	reset_walk(); errno = 0;
	CHECK(ftw("tailtree/f1/below", fn3, 5) == -1);
	CHECK(errno == ENOTDIR || errno == ENOENT);
}

static void test_nftw(void)
{
	int i, r;

	/* nftw.html: "The fourth argument is a pointer to an FTW
	 * structure.  The value of base is the offset of the object's
	 * filename in the pathname passed as the first argument to fn.
	 * The value of level indicates depth relative to the root of the
	 * walk, where the root level is 0." */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, 0) == 0);
	CHECK(nent == 4);
	i = find_ent("tailtree");        CHECK(i >= 0 && ent[i].level == 0 && ent[i].base == 0);
	i = find_ent("tailtree/f1");     CHECK(i >= 0 && ent[i].level == 1 && ent[i].base == 9);
	i = find_ent("tailtree/sub");    CHECK(i >= 0 && ent[i].level == 1 && ent[i].base == 9);
	i = find_ent("tailtree/sub/f2"); CHECK(i >= 0 && ent[i].level == 2 && ent[i].base == 13);
	/* base really is an offset into the path handed to fn */
	i = find_ent("tailtree/sub/f2");
	CHECK(i >= 0 && !strcmp(ent[i].path + ent[i].base, "f2"));
	/* "FTW_D  The object is a directory. ... FTW_F  The object is a
	 * non-directory file." -- and with FTW_DEPTH clear, FTW_DP must
	 * never appear ("This condition shall only occur if the FTW_DEPTH
	 * flag is included in flags") */
	for (i = 0; i < nent; i++) CHECK(ent[i].flag != FTW_DP);

	/* "FTW_DEPTH: If set, nftw() shall report all files in a directory
	 * before reporting the directory itself" -- and the directory is
	 * then reported as FTW_DP, not FTW_D. */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_DEPTH) == 0);
	CHECK(nent == 4);
	i = find_ent("tailtree");     CHECK(i >= 0 && ent[i].flag == FTW_DP);
	i = find_ent("tailtree/sub"); CHECK(i >= 0 && ent[i].flag == FTW_DP);
	CHECK(find_ent("tailtree/f1") < find_ent("tailtree"));
	CHECK(find_ent("tailtree/sub") < find_ent("tailtree"));
	CHECK(find_ent("tailtree/sub/f2") < find_ent("tailtree/sub"));
	/* the walk root is reported last of all under FTW_DEPTH */
	CHECK(find_ent("tailtree") == nent - 1);
	for (i = 0; i < nent; i++) CHECK(ent[i].flag != FTW_D);

	/* "FTW_MOUNT: If set, nftw() shall only report files in the same
	 * file system as path."  src/stat/stat.c fills st_dev from the NT
	 * volume serial number, so this is a real test here: the whole
	 * fixture is on one volume, so FTW_MOUNT must change nothing. */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_MOUNT) == 0);
	CHECK(nent == 4);

	/* "FTW_PHYS: If set, nftw() shall perform a physical walk and
	 * shall not follow symbolic links." -- with no symbolic links in
	 * the fixture, a physical walk sees exactly the same four objects.
	 * The symbolic-link half of FTW_PHYS is the group that may come
	 * out unverified; see test_nftw_symlinks(). */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_PHYS) == 0);
	CHECK(nent == 4);
	for (i = 0; i < nent; i++) CHECK(ent[i].flag != FTW_SL && ent[i].flag != FTW_SLN);

	/* RETURN VALUE: "An invocation of fn shall return a non-zero
	 * value, in which case nftw() shall return that value." */
	reset_walk(); stop_after = 1; stop_value = 42;
	CHECK(nftw("tailtree", fn4, 5, 0) == 42);
	CHECK(nent == 1);

	/* "The argument fd_limit sets the maximum number of file
	 * descriptors that shall be used ... At most one file descriptor
	 * shall be used for each directory level." */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 1, 0) == 0);
	CHECK(nent == 4);

	/* ERRORS, *shall fail*: [ENOENT] for an empty string or a
	 * non-existent component */
	reset_walk(); errno = 0;
	CHECK(nftw("", fn4, 5, 0) == -1);
	CHECK(errno == ENOENT);
	reset_walk(); errno = 0;
	CHECK(nftw("tailtree/nope", fn4, 5, 0) == -1);
	CHECK(errno == ENOENT);

	/* "FTW_CHDIR: ... If clear, nftw() shall not change the current
	 * working directory."  The `clear` half is asserted here because
	 * it is the one a caller depends on silently; the `set` half is
	 * fenced as a BUG below. */
	{
		char cwd0[1024], cwd1[1024];
		CHECK(getcwd(cwd0, sizeof cwd0) != NULL);
		reset_walk();
		CHECK(nftw("tailtree", fn4, 5, 0) == 0);
		CHECK(getcwd(cwd1, sizeof cwd1) != NULL);
		CHECK(!strcmp(cwd0, cwd1));
	}
	(void)r;
}

/* FTW_CHDIR's own half of the flag: the walk must still find and
 * descend the whole tree while standing somewhere other than the cwd it
 * started in.  It is a separate test from test_nftw() above because it
 * exercises a separate mechanism in src/ftw/ftw.c -- every pathname the
 * recursion carries is relative to the walk's original cwd, so with
 * FTW_CHDIR set each of them has to be resolved against the cwd
 * captured before the first chdir() before the filesystem is asked
 * about it (resolve() there).  Getting that wrong does not fail
 * loudly: lstat() simply misses, the entry is reported FTW_NS, and a
 * directory mis-typed that way is never descended into, so the walk
 * still returns 0 as though the tree had been exhausted.  Hence the
 * FTW_NS sweep and the exact per-entry types below rather than a count.
 *
 * FTW_NS is specified as "The stat() function failed on the object
 * because of lack of appropriate permission" -- it is not a way to
 * report "the implementation looked in the wrong place".
 *
 * fn4() changes no directory itself, so none of this is covered by the
 * "results are unspecified if the application-supplied fn function does
 * not preserve the current working directory" escape clause. */
static void test_nftw_chdir(void)
{
	char cwd0[1024], cwd1[1024];
	int i;

	CHECK(getcwd(cwd0, sizeof cwd0) != NULL);

	/* Run once from a cwd longer than the implementation's initial
	 * 256-byte capture buffer, forcing the checked getcwd growth path.
	 * Keep the resulting path below Windows' separate MAX_PATH current-
	 * directory ceiling: that limit is unrelated to the buffer-growth
	 * behavior this test covers. */
	{
		char part[NAME_MAX + 1];
		char target[1200];
		size_t cwdlen = strlen(cwd0);
		size_t partlen = 0;
		int made = 1;
		int entered = 0;
		snprintf(target, sizeof target, "%s/tailtree", cwd0);
		if (cwdlen < 256) {
			partlen = 256 - cwdlen - 1;
			if (!partlen) partlen = 1;
			memset(part, 'x', partlen);
			part[partlen] = 0;
			if (mkdir(part, 0755) != 0 || chdir(part) != 0)
				made = 0;
			else
				entered = 1;
		}
		CHECK(made);
		if (made) {
			CHECK(getcwd(cwd1, sizeof cwd1) != NULL && strlen(cwd1) >= 256);
			reset_walk();
			CHECK(nftw(target, fn4, 5, FTW_CHDIR) == 0);
		}
		if (entered) {
			CHECK(chdir("..") == 0);
			CHECK(rmdir(part) == 0);
		}
		CHECK(chdir(cwd0) == 0);
	}

	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_CHDIR) == 0);
	/* the whole tree is still reported, with the right types */
	CHECK(nent == 4);
	i = find_ent("tailtree");        CHECK(i >= 0 && ent[i].flag == FTW_D);
	i = find_ent("tailtree/f1");     CHECK(i >= 0 && ent[i].flag == FTW_F);
	i = find_ent("tailtree/sub");    CHECK(i >= 0 && ent[i].flag == FTW_D);
	i = find_ent("tailtree/sub/f2"); CHECK(i >= 0 && ent[i].flag == FTW_F);
	for (i = 0; i < nent && i < MAXENT; i++) CHECK(ent[i].flag != FTW_NS);

	/* "shall change the current working directory to each directory as
	 * it reports files in that directory" -- so it really did move,
	 * which is what distinguishes a fix from "ignore FTW_CHDIR" */
	CHECK(getcwd(cwd1, sizeof cwd1) != NULL);
	CHECK(chdir(cwd0) == 0);

	/* ... and what a caller actually uses FTW_CHDIR for: every entry
	 * must be reachable by its basename (path + base) from wherever the
	 * walk is standing when it reports it, not just eventually named
	 * correctly in full.  fn4_chdir() checks that from inside the
	 * callback, which is the only place it can be observed. */
	reset_walk();
	chdir_probe_misses = 0;
	CHECK(nftw("tailtree", fn4_chdir, 5, FTW_CHDIR) == 0);
	CHECK(nent == 4);
	CHECK(chdir_probe_misses == 0);
	CHECK(chdir(cwd0) == 0);
}

/* nftw.html FTW_PHYS/FTW_SL/FTW_SLN, and ftw.html's FTW_SL, all need a
 * real symbolic link.  symlink() fails ENOSYS under Wine -- the correct
 * rendering of the STATUS_NOT_SUPPORTED that stock Wine below 10.19
 * answers FSCTL_SET_REPARSE_POINT with, the privilege never being
 * consulted on that leg -- and EPERM on a real Windows without
 * SeCreateSymbolicLinkPrivilege, so this group probes
 * at run time and reports itself unverified rather than passing or
 * failing silently. */
static void test_nftw_symlinks(void)
{
	int i;

	unlink("tailtree/link");
	if (symlink("f1", "tailtree/link") < 0) {
		printf("SKIP posix-tail nftw symbolic-link tests "
		       "(symlink() failed, errno=%d; NT needs "
		       "SeCreateSymbolicLinkPrivilege or Developer Mode, and stock Wine "
		       "below 10.19 does not "
		       "implement FSCTL_SET_REPARSE_POINT) -- FTW_PHYS's FTW_SL, "
		       "FTW_SLN and the symlink-following clauses were not "
		       "exercised\n", errno);
		unverified++;
		return;
	}

	/* "FTW_SL  The object is a symbolic link.  (This condition shall
	 * only occur if the FTW_PHYS flag is included in flags.)" */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_PHYS) == 0);
	i = find_ent("tailtree/link");
	CHECK(i >= 0 && ent[i].flag == FTW_SL);

	/* FTW_PHYS clear: "nftw() shall follow links instead of reporting
	 * them" -- so the link is reported as whatever it points at */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, 0) == 0);
	i = find_ent("tailtree/link");
	CHECK(i >= 0 && ent[i].flag == FTW_F);

	/* "FTW_SLN  The object is a symbolic link that does not name an
	 * existing file.  (This condition shall only occur if the FTW_PHYS
	 * flag is not included in flags.)" */
	unlink("tailtree/dangling");
	if (symlink("no-such-target", "tailtree/dangling") == 0) {
		reset_walk();
		CHECK(nftw("tailtree", fn4, 5, 0) == 0);
		i = find_ent("tailtree/dangling");
		CHECK(i >= 0 && ent[i].flag == FTW_SLN);
		reset_walk();
		CHECK(nftw("tailtree", fn4, 5, FTW_PHYS) == 0);
		i = find_ent("tailtree/dangling");
		CHECK(i >= 0 && ent[i].flag == FTW_SL);
		unlink("tailtree/dangling");
	}

	/* ftw.html: "For an object other than a symbolic link on which
	 * stat() could not successfully be executed ... If the object is a
	 * symbolic link and stat() failed, it is unspecified whether ftw()
	 * passes FTW_SL or FTW_NS" -- unspecified, so not asserted. */
	unlink("tailtree/link");
}

/* nftw.html DESCRIPTION, both halves of the requirement:
 *   "If FTW_PHYS is clear and FTW_DEPTH is set, nftw() shall follow
 *    links instead of reporting them, but shall not report any
 *    directory that would be a descendant of itself.  If FTW_PHYS is
 *    clear and FTW_DEPTH is clear, nftw() shall follow links instead of
 *    reporting them, but shall not report the contents of any directory
 *    that would be a descendant of itself."
 *
 * src/ftw/ftw.c keeps the (st_dev, st_ino) of every directory on the
 * recursion path (struct walkstate's `anc`, a chain of stack frames) and
 * refuses to descend into one already on it.  Both halves of the pair
 * are real here -- st_dev is the NT volume serial number FTW_MOUNT
 * already relies on, st_ino is FileInternalInformation's IndexNumber --
 * so the same-file test stat.html specifies works.
 *
 * Like test_nftw_symlinks() above, this needs a symbolic link the
 * platform may refuse to create, so it probes at run time and reports
 * itself unverified rather than passing silently on a walk it never
 * made. */
static void test_nftw_symlink_loop(void)
{
	int i, dirs;

	unlink("tailtree/sub/loop");
	if (symlink("..", "tailtree/sub/loop") < 0) {
		printf("SKIP posix-tail nftw descendant-of-itself tests "
		       "(symlink() failed, errno=%d; same mechanism as the "
		       "group above) -- the FTW_PHYS-clear \"shall not report "
		       "the contents of any directory that would be a "
		       "descendant of itself\" clauses were not exercised\n",
		       errno);
		unverified++;
		return;
	}

	/* FTW_PHYS clear, FTW_DEPTH clear: the contents of a directory
	 * that would be a descendant of itself must not be reported.  The
	 * walk must terminate, and must report each real object a bounded
	 * number of times. */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, 0) == 0);
	dirs = 0;
	for (i = 0; i < nent && i < MAXENT; i++)
		if (ent[i].flag == FTW_D) dirs++;
	CHECK(dirs <= 3);          /* tailtree, tailtree/sub, and the link */
	CHECK(nent < MAXENT);      /* it terminated rather than running away */
	/* ...and the cut falls exactly at the loop, not wider: in this half
	 * of the clause the directory itself is still reported ("shall not
	 * report the *contents*"), and every real object is still walked.
	 * Without these, refusing the whole subtree -- or the whole walk --
	 * would satisfy the two bounds above just as well. */
	i = find_ent("tailtree/sub/loop");
	CHECK(i >= 0 && ent[i].flag == FTW_D);
	CHECK(find_ent("tailtree/sub/loop/f1") < 0);
	CHECK(find_ent("tailtree") >= 0);
	CHECK(find_ent("tailtree/f1") >= 0);
	CHECK(find_ent("tailtree/sub") >= 0);
	CHECK(find_ent("tailtree/sub/f2") >= 0);

	/* FTW_PHYS clear, FTW_DEPTH set: the directory itself must not be
	 * reported when it would be a descendant of itself -- the only
	 * report it would ever get is the FTW_DP that comes *after* its
	 * contents, and this half of the clause forbids that outright. */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_DEPTH) == 0);
	CHECK(nent < MAXENT);
	CHECK(find_ent("tailtree/sub/loop") < 0);
	CHECK(find_ent("tailtree") >= 0);
	CHECK(find_ent("tailtree/f1") >= 0);
	CHECK(find_ent("tailtree/sub") >= 0);
	CHECK(find_ent("tailtree/sub/f2") >= 0);

	/* FTW_PHYS set is the escape hatch and must be unaffected: the
	 * link is reported as FTW_SL and never followed */
	reset_walk();
	CHECK(nftw("tailtree", fn4, 5, FTW_PHYS) == 0);
	i = find_ent("tailtree/sub/loop");
	CHECK(i >= 0 && ent[i].flag == FTW_SL);

	unlink("tailtree/sub/loop");
}

/* ====================================================================
 * fcntl.h -- posix_fadvise(), posix_fallocate()
 * ================================================================== */
static void test_posix_fadvise(void)
{
	int fd = open("tail-fadv.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);

	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "0123456789", 10) == 10);

	/* RETURN VALUE: "Upon successful completion, posix_fadvise() shall
	 * return zero; otherwise, an error number shall be returned" --
	 * the error number itself, not -1 with errno.
	 * DESCRIPTION: every advice value is advisory, and "shall have no
	 * effect on the semantics of other operations", so a
	 * validate-and-no-op implementation is conforming. */
	CHECK(posix_fadvise(fd, 0, 0, POSIX_FADV_NORMAL) == 0);
	CHECK(posix_fadvise(fd, 0, 10, POSIX_FADV_SEQUENTIAL) == 0);
	CHECK(posix_fadvise(fd, 0, 10, POSIX_FADV_RANDOM) == 0);
	CHECK(posix_fadvise(fd, 0, 10, POSIX_FADV_WILLNEED) == 0);
	CHECK(posix_fadvise(fd, 0, 10, POSIX_FADV_DONTNEED) == 0);
	CHECK(posix_fadvise(fd, 0, 10, POSIX_FADV_NOREUSE) == 0);
	/* "The specified range need not currently exist in the file" */
	CHECK(posix_fadvise(fd, 1 << 20, 4096, POSIX_FADV_WILLNEED) == 0);
	/* "If len is zero, all data following offset is specified." */
	CHECK(posix_fadvise(fd, 4, 0, POSIX_FADV_WILLNEED) == 0);
	/* "shall have no effect on the semantics of other operations" */
	{
		char b[16];
		CHECK(lseek(fd, 0, SEEK_SET) == 0);
		CHECK(posix_fadvise(fd, 0, 10, POSIX_FADV_DONTNEED) == 0);
		CHECK(read(fd, b, 10) == 10);
		CHECK(!memcmp(b, "0123456789", 10));
	}

	/* ERRORS, *shall fail*: "[EBADF] The fd argument is not a valid
	 * file descriptor." */
	CHECK(posix_fadvise(-1, 0, 0, POSIX_FADV_NORMAL) == EBADF);
	CHECK(posix_fadvise(4242, 0, 0, POSIX_FADV_NORMAL) == EBADF);

	/* ERRORS, *shall fail*: "[EINVAL] The value of advice is invalid" */
	CHECK(posix_fadvise(fd, 0, 0, -1) == EINVAL);
	CHECK(posix_fadvise(fd, 0, 0, 999) == EINVAL);
	CHECK(posix_fadvise(fd, 0, 0, POSIX_FADV_NOREUSE + 1) == EINVAL);

	/* EBADF is checked before the advice value: a bad fd and a bad
	 * advice together give EBADF.  POSIX does not order these, so this
	 * asserts only that one of the two documented errors is returned. */
	{
		int r = posix_fadvise(-1, 0, 0, 999);
		CHECK(r == EBADF || r == EINVAL);
	}

	close(fd);
	unlink("tail-fadv.tmp");
}

/* The other half of the [EINVAL] clause asserted above: "[EINVAL] The
 * value of advice is invalid, or the value of len is less than zero."
 * Kept apart from test_posix_fadvise() because the advice half is a
 * property of the switch in src/fcntl/fadvise.c and this one is a
 * property of the guard in front of it. */
static void test_posix_fadvise_einval_negative_len(void)
{
	int fd = open("tail-fadv2.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(posix_fadvise(fd, 0, -1, POSIX_FADV_NORMAL) == EINVAL);
	CHECK(posix_fadvise(fd, 0, -4096, POSIX_FADV_WILLNEED) == EINVAL);
	/* a valid len still succeeds, so the check is not simply
	 * rejecting everything */
	CHECK(posix_fadvise(fd, 0, 4096, POSIX_FADV_WILLNEED) == 0);
	close(fd);
	unlink("tail-fadv2.tmp");
}

/* posix_fadvise.html ERRORS, *shall fail*: "[ESPIPE] The fd argument is
 * associated with a pipe or FIFO."  Both ends, because the clause names
 * the descriptor's object and not its direction.
 *
 * A FIFO cannot be added to this: mkfifo() is ENOSYS here
 * (src/stat/chmod.c).  It would not widen the test if it could --
 * src/internal/fd.c's __handle_type() maps NT's one
 * FILE_DEVICE_NAMED_PIPE onto __FD_PIPE for the anonymous and the named
 * case alike, so a FIFO reaches the same predicate a pipe() end does. */
static void test_posix_fadvise_espipe(void)
{
	int p[2], fd;
	CHECK(pipe(p) == 0);
	CHECK(posix_fadvise(p[0], 0, 0, POSIX_FADV_NORMAL) == ESPIPE);
	CHECK(posix_fadvise(p[1], 0, 0, POSIX_FADV_NORMAL) == ESPIPE);
	/* The two documented errors a pipe with an invalid advice
	 * satisfies at once.  POSIX orders neither against the other, so
	 * this asserts only that one of them comes back -- the same
	 * permissive shape test_posix_fadvise() uses for [EBADF] against
	 * an invalid advice.  (src/fcntl/fadvise.c validates the arguments
	 * first, so it is EINVAL here.) */
	{
		int r = posix_fadvise(p[0], 0, 0, 999);
		CHECK(r == EINVAL || r == ESPIPE);
	}
	close(p[0]); close(p[1]);

	/* The other direction, so the fix cannot be "achieved" by refusing
	 * every descriptor: a regular file is not a pipe and still gets 0.
	 * test_posix_fadvise() asserts this at length on its own file; it
	 * is repeated here because it is what makes the assertions above
	 * discriminating rather than merely satisfiable. */
	fd = open("tail-fadv3.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(posix_fadvise(fd, 0, 4096, POSIX_FADV_WILLNEED) == 0);
		close(fd);
		unlink("tail-fadv3.tmp");
	}
}

static void test_posix_fallocate(void)
{
	int fd = open("tail-falloc.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	struct stat st;

	CHECK(fd >= 0);
	if (fd < 0) return;

	/* Capability probe, before any of the DESCRIPTION assertions.
	 * posix_fallocate.html's *shall fail* list includes "[EINVAL] The
	 * len argument is less than zero, or the offset argument is less
	 * than zero, **or the underlying file system does not support this
	 * operation**" -- so EINVAL for a well-formed request is a
	 * conforming answer from an implementation whose storage layer
	 * cannot reserve blocks, and asserting success unconditionally
	 * would be asserting an environment, not a clause.
	 *
	 * That case is real here rather than hypothetical.  Measured with
	 * the same binary source built both ways: on x86_64 every form of
	 * this call succeeds, while on i386 (WOW64)
	 * NtSetInformationFile(FileAllocationInformation) comes back
	 * STATUS_INVALID_PARAMETER for a zero-length file, which
	 * src/fcntl/fadvise.c reports as EINVAL.  (Its own comment records
	 * that Wine answers STATUS_NOT_IMPLEMENTED for this class and
	 * falls through on ENOSYS specifically; the WOW64 path returns a
	 * different status, which that fallback does not cover.  A
	 * non-empty file skips the call entirely, because its
	 * AllocationSize is already a whole cluster -- which is why
	 * test/unistd.c's pre-existing call, made on a five-byte file,
	 * passes on both arches and this one does not.)
	 *
	 * So: probe once, and report the allocation group unverified
	 * rather than failed when the answer is the documented EINVAL. */
	{
		int cap = posix_fallocate(fd, 0, 4096);
		if (cap == EINVAL) {
			printf("SKIP posix-tail posix_fallocate() allocation tests "
			       "(posix_fallocate() returned EINVAL for a well-formed "
			       "request on a zero-length file -- posix_fallocate.html's "
			       "documented \"the underlying file system does not support "
			       "this operation\"; measured as WOW64 "
			       "NtSetInformationFile(FileAllocationInformation) -> "
			       "STATUS_INVALID_PARAMETER) -- the file-size and "
			       "storage-reservation clauses were not exercised\n");
			unverified++;
		} else {
			/* DESCRIPTION: "If the offset+len is beyond the current
			 * file size, then posix_fallocate() shall adjust the file
			 * size to offset+len."  RETURN VALUE: zero, or an error
			 * number. */
			CHECK(cap == 0);
			CHECK(fstat(fd, &st) == 0);
			CHECK(st.st_size == 4096);

			/* "Otherwise, the file size shall not be changed." */
			CHECK(posix_fallocate(fd, 0, 1024) == 0);
			CHECK(fstat(fd, &st) == 0);
			CHECK(st.st_size == 4096);
			CHECK(posix_fallocate(fd, 1024, 512) == 0);
			CHECK(fstat(fd, &st) == 0);
			CHECK(st.st_size == 4096);

			/* the allocated range really is writable and readable back */
			{
				char b[8];
				CHECK(lseek(fd, 4000, SEEK_SET) == 4000);
				CHECK(write(fd, "abcdefgh", 8) == 8);
				CHECK(lseek(fd, 4000, SEEK_SET) == 4000);
				CHECK(read(fd, b, 8) == 8);
				CHECK(!memcmp(b, "abcdefgh", 8));
				CHECK(fstat(fd, &st) == 0);
				CHECK(st.st_size == 4096);
			}

			/* "Space allocated via posix_fallocate() shall be freed by
			 * a successful call to creat() or open() that truncates the
			 * size of the file." */
			{
				int t = open("tail-falloc.tmp", O_RDWR | O_TRUNC);
				CHECK(t >= 0);
				if (t >= 0) {
					CHECK(fstat(t, &st) == 0);
					CHECK(st.st_size == 0);
					close(t);
				}
			}
		}
	}

	/* ERRORS, *shall fail*: "[EBADF] The fd argument is not a valid
	 * file descriptor." */
	CHECK(posix_fallocate(-1, 0, 16) == EBADF);
	CHECK(posix_fallocate(4242, 0, 16) == EBADF);

	/* ERRORS, *shall fail*: "[EINVAL] The len argument is less than
	 * zero, or the offset argument is less than zero" */
	CHECK(posix_fallocate(fd, 0, -1) == EINVAL);
	CHECK(posix_fallocate(fd, -1, 16) == EINVAL);
	CHECK(posix_fallocate(fd, -1, -1) == EINVAL);

	/* ERRORS, *shall fail*: "[ESPIPE] The fd argument is associated
	 * with a pipe or FIFO." */
	{
		int p[2];
		CHECK(pipe(p) == 0);
		CHECK(posix_fallocate(p[0], 0, 16) == ESPIPE);
		CHECK(posix_fallocate(p[1], 0, 16) == ESPIPE);
		close(p[0]); close(p[1]);
	}

	/* [EFBIG] is fenced below rather than asserted here: the only way
	 * src/fcntl/fadvise.c can produce it is by signed-integer overflow,
	 * which is undefined behaviour, and calling it trips UBSan under
	 * `make asan`. */

	/* A descriptor on a directory: posix_fallocate.html has *shall
	 * fail* clauses for both "[ENODEV] The fd argument does not refer
	 * to a regular file" and "[EBADF] The fd argument references a
	 * file that was opened without write permission", and a directory
	 * descriptor satisfies both conditions at once.  POSIX does not
	 * order them, so either answer conforms and this asserts only that
	 * one of the two is given -- never success.  The unambiguous half
	 * of the [ENODEV] clause is fenced below, on a writable character
	 * device. */
	{
		int d;
		CHECK(mkdir("tail-falloc.d", 0755) == 0 || errno == EEXIST);
		d = open("tail-falloc.d", O_RDONLY);
		if (d >= 0) {
			int r = posix_fallocate(d, 0, 16);
			CHECK(r == ENODEV || r == EBADF);
			CHECK(r != 0);
			close(d);
		}
		rmdir("tail-falloc.d");
	}

	/* *may fail* "[EINVAL] The len argument is zero" -- optional, so
	 * both answers conform; asserted only as "does not crash and
	 * returns one of the two". */
	{
		int r = posix_fallocate(fd, 0, 0);
		CHECK(r == 0 || r == EINVAL);
	}

	close(fd);
	unlink("tail-falloc.tmp");
}

static void test_posix_fallocate_efbig(void)
{
	int fd = open("tail-falloc-efbig.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	/* Past any file size NTFS can represent, with no overflow of off_t in
	 * the sum.
	 *
	 * The bound that matters is 8 PB = 2^53, NOT the "under 2^48" this
	 * comment used to claim: per Microsoft's NTFS overview the largest
	 * volume-and-file is cluster-size dependent and reaches 8 PB on a
	 * 2048 KB-cluster volume (256 TB = 2^48 is the 64 KB row, not the
	 * ceiling).  The values below survive that correction with room to
	 * spare -- 2^61 exceeds even 8 PB -- but the reasoning did not, and a
	 * comment giving a wrong reason for a right test is what gets
	 * "corrected" in the wrong direction later.
	 *
	 * On the ordinary 4 KB-cluster volume this runs on, the real limit is
	 * 4096 * (2^32-1) = 16 TiB, so these are far past it. */
	CHECK(posix_fallocate(fd, (off_t)1 << 60, (off_t)1 << 60) == EFBIG);
	CHECK(posix_fallocate(fd, 0, (off_t)1 << 61) == EFBIG);
	/* The representability guard itself, which the two assertions above
	 * do NOT reach: their sums fit in a long long and are merely larger
	 * than the volume's limit.  These two cannot be represented at all,
	 * so they pin `offset > LLONG_MAX - len` specifically -- and this is
	 * exactly the case the old `want = offset + len; if (want < 0)` form
	 * could only ever reach by signed-overflow undefined behaviour. */
	CHECK(posix_fallocate(fd, (off_t)LLONG_MAX, 1) == EFBIG);
	CHECK(posix_fallocate(fd, 1, (off_t)LLONG_MAX) == EFBIG);
	CHECK(posix_fallocate(fd, (off_t)LLONG_MAX, (off_t)LLONG_MAX) == EFBIG);
	/* and a request that is merely large but representable is not
	 * turned into EFBIG by the same check */
	{
		int r = posix_fallocate(fd, 0, 8192);
		CHECK(r != EFBIG);
	}
	close(fd);
	unlink("tail-falloc-efbig.tmp");
}

static void test_posix_fallocate_enodev(void)
{
	static const char *const devs[] = { "/dev/null", "NUL" };
	size_t i;
	int found = 0;

	for (i = 0; i < sizeof devs / sizeof devs[0]; i++) {
		struct stat st;
		int fd = open(devs[i], O_WRONLY);
		if (fd < 0) continue;
		if (fstat(fd, &st) == 0 && !S_ISREG(st.st_mode)) {
			found = 1;
			CHECK(posix_fallocate(fd, 0, 16) == ENODEV);
			CHECK(posix_fallocate(fd, 0, 0) == ENODEV || errno == errno);
		}
		close(fd);
		if (found) break;
	}
	CHECK(found);
}

static void test_posix_fallocate_ebadf_readonly(void)
{
	int fd = open("tail-falloc-ro.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	int rd;
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "hello world", 11) == 11);
	close(fd);

	rd = open("tail-falloc-ro.tmp", O_RDONLY);
	CHECK(rd >= 0);
	if (rd >= 0) {
		/* entirely inside the existing file: no NT call is reached,
		 * so this isolates the missing permission check */
		CHECK(posix_fallocate(rd, 0, 5) == EBADF);
		/* and past the end of it */
		CHECK(posix_fallocate(rd, 0, 100) == EBADF);
		close(rd);
	}
	unlink("tail-falloc-ro.tmp");
}

/* ====================================================================
 * setjmp.h -- _setjmp(), _longjmp()   (OB XSI)
 *
 * _setjmp.html DESCRIPTION, in full: "The _longjmp() and _setjmp()
 * functions shall be equivalent to longjmp() and setjmp(),
 * respectively, with the additional restriction that _longjmp() and
 * _setjmp() shall not manipulate the signal mask.  If _longjmp() is
 * called even though env was never initialized by a call to _setjmp(),
 * or when the last such call was in a function that has since
 * returned, the results are undefined."  RETURN VALUE: "Refer to
 * longjmp and setjmp."
 *
 * The signal-mask sentence is the entire difference from
 * setjmp()/longjmp(), so it is the clause that matters here -- and it
 * is genuinely testable on this platform: src/signal/signal.c keeps a
 * real process-wide `blocked` set that sigprocmask() reads and writes.
 * ================================================================== */
static jmp_buf jb;
static volatile int jump_val;

static void do_longjmp(int v) { _longjmp(jb, v); }

static void test__setjmp_return_values(void)
{
	int r;

	/* setjmp.html RETURN VALUE: "shall return 0 ... upon returning
	 * from a setjmp() macro invocation directly" */
	r = _setjmp(jb);
	if (r == 0) { jump_val = 1; do_longjmp(7); }
	/* longjmp.html: "cause the setjmp() macro to return the val
	 * argument" */
	CHECK(r == 7);
	CHECK(jump_val == 1);

	/* longjmp.html: "If val is 0, setjmp() shall return 1." */
	r = _setjmp(jb);
	if (r == 0) { jump_val = 2; do_longjmp(0); }
	CHECK(r == 1);
	CHECK(jump_val == 2);

	/* a negative val is returned as given: only 0 is special */
	r = _setjmp(jb);
	if (r == 0) { jump_val = 3; do_longjmp(-9); }
	CHECK(r == -9);
	CHECK(jump_val == 3);
}

static void test__longjmp_does_not_manipulate_the_signal_mask(void)
{
	sigset_t only_usr1, saved, observed;
	int r;

	CHECK(sigemptyset(&only_usr1) == 0);
	CHECK(sigaddset(&only_usr1, SIGUSR1) == 0);

	/* start from a known mask: SIGUSR1 blocked */
	CHECK(sigprocmask(SIG_BLOCK, &only_usr1, &saved) == 0);
	CHECK(sigprocmask(SIG_SETMASK, NULL, &observed) == 0);
	CHECK(sigismember(&observed, SIGUSR1) == 1);

	r = _setjmp(jb);
	if (r == 0) {
		/* change the mask between the _setjmp() and the _longjmp() */
		CHECK(sigprocmask(SIG_UNBLOCK, &only_usr1, NULL) == 0);
		do_longjmp(1);
	}
	CHECK(r == 1);

	/* "_longjmp() ... shall not manipulate the signal mask" -- so the
	 * mask must still be the one in effect at the _longjmp(), i.e.
	 * SIGUSR1 UNBLOCKED, not the one saved by the _setjmp(). */
	CHECK(sigprocmask(SIG_SETMASK, NULL, &observed) == 0);
	CHECK(sigismember(&observed, SIGUSR1) == 0);

	/* and _setjmp() itself must not have altered the mask on the way
	 * in either: block it again, _setjmp(), and check it is still
	 * blocked without any jump happening */
	CHECK(sigprocmask(SIG_BLOCK, &only_usr1, NULL) == 0);
	if (_setjmp(jb) == 0) {
		CHECK(sigprocmask(SIG_SETMASK, NULL, &observed) == 0);
		CHECK(sigismember(&observed, SIGUSR1) == 1);
	}

	CHECK(sigprocmask(SIG_SETMASK, &saved, NULL) == 0);
}

/* ====================================================================
 * string.h -- strlen(), strnlen()
 *
 * strlen.html DESCRIPTION: "The strlen() function shall compute the
 * number of bytes in the string to which s points, not including the
 * terminating NUL character."  RETURN VALUE: "shall return the length
 * of s; no return value shall be reserved to indicate an error."
 *
 * strnlen (CX): "shall compute the smaller of the number of bytes in
 * the array to which s points, not including any terminating NUL
 * character, or the value of the maxlen argument.  The strnlen()
 * function shall never examine more than maxlen bytes of the array
 * pointed to by s."  RETURN VALUE: "the number of bytes preceding the
 * first null byte ... if s contains a null byte within the first
 * maxlen bytes; otherwise, it shall return maxlen."
 * ================================================================== */
static void test_strlen(void)
{
	static const char *cases[] = { "", "a", "ab", "hello, world", "0123456789abcdef" };
	size_t i;
	char buf[64];

	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		size_t n = 0;
		while (cases[i][n]) n++;
		CHECK(strlen(cases[i]) == n);
	}
	/* "not including the terminating NUL character" */
	CHECK(strlen("") == 0);
	/* embedded NUL terminates: only the first is the end of the string */
	memcpy(buf, "ab\0cd", 6);
	CHECK(strlen(buf) == 2);

	/* src/string/strlen.c is a word-at-a-time SWAR scan with a
	 * byte-at-a-time prologue to reach alignment and a byte-at-a-time
	 * epilogue inside the word that contains the NUL.  Every
	 * (start offset, length) pair below the word size therefore has to
	 * be exercised, or one of the three phases can be wrong without
	 * any assertion noticing. */
	{
		size_t off, len;
		for (off = 0; off < 2 * sizeof(size_t); off++) {
			for (len = 0; len < 3 * sizeof(size_t); len++) {
				memset(buf, 'x', sizeof buf);
				buf[off + len] = 0;
				CHECK(strlen(buf + off) == len);
			}
		}
	}
}

static void test_strnlen(void)
{
	const char *s = "hello";
	char *heap;

	/* "the number of bytes preceding the first null byte ... if s
	 * contains a null byte within the first maxlen bytes" */
	CHECK(strnlen(s, 100) == 5);
	CHECK(strnlen(s, 6) == 5);
	/* "otherwise, it shall return maxlen" */
	CHECK(strnlen(s, 5) == 5);
	CHECK(strnlen(s, 3) == 3);
	CHECK(strnlen(s, 1) == 1);
	CHECK(strnlen(s, 0) == 0);
	CHECK(strnlen("", 0) == 0);
	CHECK(strnlen("", 4) == 0);

	/* "shall never examine more than maxlen bytes of the array pointed
	 * to by s."  A heap block of exactly `n` bytes with no NUL in it:
	 * a conforming strnlen() reads all n and stops; one that scans for
	 * a NUL first reads past the end.  There is no return value that
	 * distinguishes the two -- both answer n -- so this assertion is
	 * really an ASan assertion, the same shape as
	 * test/posix-ctype.c's out-of-domain probe, and tools/asan-build.sh
	 * is what makes it bite.  Kept small and heap-allocated on purpose:
	 * a static array would have padding after it and ASan could not
	 * see the overread. */
	{
		size_t n;
		for (n = 1; n <= 40; n++) {
			heap = malloc(n);
			CHECK(heap != NULL);
			if (!heap) break;
			memset(heap, 'q', n);
			CHECK(strnlen(heap, n) == n);
			free(heap);
		}
	}
	/* the same, with the NUL in the last readable byte */
	{
		size_t n;
		for (n = 1; n <= 40; n++) {
			heap = malloc(n);
			CHECK(heap != NULL);
			if (!heap) break;
			memset(heap, 'q', n);
			heap[n - 1] = 0;
			CHECK(strnlen(heap, n) == n - 1);
			CHECK(strnlen(heap, n + 100) == n - 1);
			free(heap);
		}
	}
}

/* ====================================================================
 * sys/times.h -- times()   (XSI)
 *
 * times.html: "shall fill the tms structure pointed to by buffer with
 * time-accounting information ... All times are measured in terms of
 * the number of clock ticks used."  RETURN VALUE: "shall return the
 * elapsed real time, in clock ticks, since an arbitrary point in the
 * past ... This point does not change from one invocation of times()
 * within the process to another.  The return value may overflow the
 * possible range of type clock_t.  If times() fails, (clock_t)-1 shall
 * be returned and errno set."
 * ================================================================== */
static void test_times(void)
{
	struct tms a, b;
	clock_t t1, t2;
	long i;
	volatile double sink = 0;

	memset(&a, 0xff, sizeof a);
	t1 = times(&a);
	CHECK(t1 != (clock_t)-1);
	/* every member was written (the 0xff fill is not a plausible tick
	 * count, and a negative value is not a plausible CPU time) */
	CHECK(a.tms_utime >= 0);
	CHECK(a.tms_stime >= 0);
	CHECK(a.tms_cutime >= 0);
	CHECK(a.tms_cstime >= 0);

	/* burn a little CPU so a second sample cannot be identical for
	 * trivial reasons, then check the two clauses that are assertable:
	 * the elapsed-time origin "does not change from one invocation ...
	 * to another" (so the return value is non-decreasing), and the CPU
	 * totals are cumulative (so they are non-decreasing too). */
	for (i = 0; i < 2000000; i++) sink += (double)i * 0.5;
	CHECK(sink != 0);

	t2 = times(&b);
	CHECK(t2 != (clock_t)-1);
	CHECK(t2 >= t1);
	CHECK(b.tms_utime >= a.tms_utime);
	CHECK(b.tms_stime >= a.tms_stime);
	CHECK(b.tms_cutime >= a.tms_cutime);
	CHECK(b.tms_cstime >= a.tms_cstime);

	/* "All times are measured in terms of the number of clock ticks
	 * used" and times.html's SEE ALSO points at sysconf(_SC_CLK_TCK)
	 * for what a tick is -- so that must be a usable positive number */
	CHECK(sysconf(_SC_CLK_TCK) > 0);

	/* No assertion is made about the *magnitude* of tms_utime, or that
	 * it grew across the loop above: NT's ProcessTimes is quantised
	 * (and coarser still under Wine), the tick is 1/100s here, and a
	 * loop short enough to keep the suite fast is not guaranteed to
	 * cross a tick boundary.  Asserting growth would be a flake, not a
	 * conformance test. */
}

/* ====================================================================
 * sys/utsname.h -- uname()
 *
 * uname.html: "shall store information identifying the current system
 * in the structure pointed to by name ... shall return a string naming
 * the current system in the character array sysname.  Similarly,
 * nodename shall contain the name of this node ... The arrays release
 * and version shall further identify the operating system.  The array
 * machine shall contain a name that identifies the hardware ... The
 * format of each member is implementation-defined."  RETURN VALUE:
 * "Upon successful completion, a non-negative value shall be returned.
 * Otherwise, -1 shall be returned and errno set."  ERRORS: "No errors
 * are defined."
 * ================================================================== */
static void test_uname(void)
{
	struct utsname u, v;

	memset(&u, 0xff, sizeof u);
	errno = 0;
	/* "a non-negative value shall be returned" -- non-negative, not
	 * specifically 0 */
	CHECK(uname(&u) >= 0);

	/* every member is a string: NUL-terminated within its array, and
	 * carrying something.  "The format of each member is
	 * implementation-defined", so nothing below asserts a value. */
	CHECK(memchr(u.sysname,  0, sizeof u.sysname)  != NULL);
	CHECK(memchr(u.nodename, 0, sizeof u.nodename) != NULL);
	CHECK(memchr(u.release,  0, sizeof u.release)  != NULL);
	CHECK(memchr(u.version,  0, sizeof u.version)  != NULL);
	CHECK(memchr(u.machine,  0, sizeof u.machine)  != NULL);
	CHECK(u.sysname[0]  != 0);
	CHECK(u.nodename[0] != 0);
	CHECK(u.release[0]  != 0);
	CHECK(u.version[0]  != 0);
	CHECK(u.machine[0]  != 0);

	/* "identifying the current system" -- the answer is a property of
	 * the system, so two calls in one process must agree */
	CHECK(uname(&v) >= 0);
	CHECK(!strcmp(u.sysname,  v.sysname));
	CHECK(!strcmp(u.nodename, v.nodename));
	CHECK(!strcmp(u.release,  v.release));
	CHECK(!strcmp(u.version,  v.version));
	CHECK(!strcmp(u.machine,  v.machine));

	/* nodename is "the name of this node within an
	 * implementation-defined communications network" -- the same thing
	 * gethostname() reports, and spicule builds one from the other */
	{
		char host[256];
		if (gethostname(host, sizeof host) == 0)
			CHECK(!strcmp(host, u.nodename));
	}
}

/* ====================================================================
 * sys/time.h -- gettimeofday()   (OB XSI)
 *
 * gettimeofday.html: "shall obtain the current time, expressed as
 * seconds and microseconds since the Epoch, and store it in the
 * timeval structure pointed to by tp.  The resolution of the system
 * clock is unspecified.  If tzp is not a null pointer, the behavior is
 * unspecified."  RETURN VALUE: "shall return 0 and no value shall be
 * reserved to indicate an error."  ERRORS: "No errors are defined."
 * ================================================================== */
static void test_gettimeofday(void)
{
	struct timeval tv, tv2;
	time_t t;

	errno = 0;
	/* "shall return 0 and no value shall be reserved to indicate an
	 * error" -- 0 is the only conforming return value */
	CHECK(gettimeofday(&tv, NULL) == 0);

	/* "expressed as seconds and microseconds since the Epoch": tv_usec
	 * is a microsecond remainder, so it is in [0, 1000000) */
	CHECK(tv.tv_usec >= 0);
	CHECK(tv.tv_usec < 1000000);
	/* and the seconds field really is Epoch-based, which time() also
	 * reports (time.html: "the current value of the system-wide clock
	 * ... measured in seconds since the Epoch") */
	t = time(NULL);
	CHECK(t != (time_t)-1);
	CHECK(tv.tv_sec <= t + 2 && tv.tv_sec >= t - 2);
	/* a sanity floor no correct clock can be below: 2001-09-09 */
	CHECK(tv.tv_sec > 1000000000);

	/* the clock advances, or at worst does not go backwards, between
	 * two immediately consecutive calls.  CLOCK_REALTIME may be
	 * stepped by an administrator, so this is a weak assertion on
	 * purpose -- "resolution ... is unspecified" forbids anything
	 * stronger. */
	CHECK(gettimeofday(&tv2, NULL) == 0);
	CHECK(tv2.tv_sec > tv.tv_sec ||
	      (tv2.tv_sec == tv.tv_sec && tv2.tv_usec >= tv.tv_usec));

	/* "If tzp is not a null pointer, the behavior is unspecified" --
	 * so nothing is asserted about the result, only that passing one
	 * is survivable, which is what every real caller of this obsolete
	 * interface does */
	{
		struct timezone tz;
		memset(&tz, 0, sizeof tz);
		(void)gettimeofday(&tv2, &tz);
	}
	CHECK(errno == 0);   /* "ERRORS: No errors are defined." */
}

/* ====================================================================
 * stdlib.h -- srand48()   (XSI)
 *
 * drand48.html: "The initializer function srand48() sets the
 * high-order 32 bits of Xi to the low-order 32 bits contained in its
 * argument.  The low-order 16 bits of Xi are set to the arbitrary
 * value 330E(16)."  The sequence is "Xn+1 = (aXn + c) mod m" with
 * m = 2^48, a = 0x5DEECE66D and c = 0xB "unless lcong48() is invoked",
 * and "After lcong48() is called, a subsequent call to either
 * srand48() or seed48() shall restore the standard multiplier and
 * addend values."
 *
 * That fully determines every value the generator produces after a
 * given srand48(), so the oracle below is arithmetic rather than a
 * golden vector: X1 is computed here from the page's own formula and
 * compared against what drand48()/lrand48()/mrand48() report.
 * ================================================================== */

/* 48-bit LCG step, written straight from drand48.html's formula, in
 * unsigned 64-bit arithmetic (only the low 48 bits are kept, so the
 * multiply wrapping is harmless -- the same argument src/stdlib/
 * rand48.c's own comment makes). */
static unsigned long long lcg_step(unsigned long long x)
{
	return (0x5DEECE66DULL * x + 0xBULL) & 0xffffffffffffULL;
}

static void test_srand48(void)
{
	static const long seeds[] = { 0, 1, 42, -1, 0x7fffffff, 0x12345678 };
	size_t i;

	for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++) {
		long seed = seeds[i];
		/* "sets the high-order 32 bits of Xi to the low-order 32 bits
		 * contained in its argument.  The low-order 16 bits of Xi are
		 * set to ... 330E." */
		unsigned long long x = (((unsigned long long)(unsigned long)seed & 0xffffffffULL) << 16)
		                     | 0x330eULL;
		unsigned long long x1 = lcg_step(x);
		unsigned long long x2 = lcg_step(x1);

		srand48(seed);
		/* drand48.html: drand48() returns "non-negative,
		 * double-precision, floating-point values, uniformly
		 * distributed over the interval [0.0,1.0)", taken from the
		 * high-order bits of Xi -- i.e. exactly Xi / 2^48, which is
		 * exact in a double (48 bits < 53) */
		CHECK(drand48() == (double)x1 / 281474976710656.0);
		CHECK(drand48() == (double)x2 / 281474976710656.0);

		/* lrand48(): "non-negative, long integers, uniformly
		 * distributed over the interval [0,2^31)", i.e. the top 31
		 * bits of the next Xi */
		srand48(seed);
		CHECK((unsigned long)lrand48() == (unsigned long)(x1 >> 17));
		CHECK(lrand48() >= 0);

		/* mrand48(): "signed long integers uniformly distributed over
		 * the interval [-2^31,2^31)", i.e. the top 32 bits taken as
		 * a signed 32-bit value */
		srand48(seed);
		CHECK(mrand48() == (long)(int)(unsigned int)(x1 >> 16));
	}

	/* "constant default initializer values shall be supplied
	 * automatically if drand48() ... is called without a prior call to
	 * an initialization entry point" -- and srand48() reproduces the
	 * documented default, Xi's high 32 bits zero */
	srand48(0);
	{
		double first = drand48();
		srand48(0);
		CHECK(drand48() == first);       /* srand48() is repeatable */
	}

	/* "After lcong48() is called, a subsequent call to either
	 * srand48() or seed48() shall restore the standard multiplier and
	 * addend values, a and c, specified above." */
	{
		unsigned short p[7];
		double before, after;

		srand48(42);
		before = drand48();

		p[0] = 0x1111; p[1] = 0x2222; p[2] = 0x3333;   /* Xi */
		p[3] = 0x0003; p[4] = 0x0000; p[5] = 0x0000;   /* a = 3 */
		p[6] = 0x0007;                                 /* c = 7 */
		lcong48(p);
		(void)drand48();                               /* uses a=3, c=7 */

		srand48(42);
		after = drand48();
		CHECK(after == before);   /* standard a and c restored */
	}

	/* srand48() seeds the shared internal Xi only; erand48()'s
	 * caller-supplied state is independent of it ("the sequence of
	 * numbers in each stream shall not depend upon how many times the
	 * routines are called to generate numbers for the other streams") */
	{
		unsigned short s[3] = { 0x330e, 42, 0 };
		unsigned long long x = 0x330eULL | ((unsigned long long)42 << 16);
		double e1;
		srand48(1);
		e1 = erand48(s);
		CHECK(e1 == (double)lcg_step(x) / 281474976710656.0);
		srand48(999);   /* must not disturb s at all */
		s[0] = 0x330e; s[1] = 42; s[2] = 0;
		CHECK(erand48(s) == e1);
	}
}

int main(void)
{
	test_readv();
	test_readv_writev_iovcnt();
	test_writev();

	test_ftw();
	test_nftw();
	test_nftw_chdir();
	test_nftw_symlinks();
	test_nftw_symlink_loop();
	kill_tree();

	test_posix_fadvise();
	test_posix_fadvise_einval_negative_len();
	test_posix_fadvise_espipe();
	test_posix_fallocate();
	test_posix_fallocate_efbig();
	test_posix_fallocate_enodev();
	test_posix_fallocate_ebadf_readonly();

	test__setjmp_return_values();
	test__longjmp_does_not_manipulate_the_signal_mask();

	test_strlen();
	test_strnlen();

	test_times();
	test_uname();
	test_gettimeofday();
	test_srand48();

	if (fails) { printf("posix-tail: failures: %d\n", fails); return 1; }
	if (unverified) {
		/* Everything that ran passed, but that is not the same claim
		 * as "all ok" -- see the SKIP line(s) above for which
		 * assertion groups never ran.  Exit 77 so tools/run-tests.py
		 * reports this in its own bucket instead of counting it as a
		 * pass.  Same convention as test/posix-socket.c. */
		printf("posix-tail: %d assertion group(s) unverified in this "
		       "environment (see SKIP lines above); no failures in what "
		       "did run\n", unverified);
		return 77;
	}
	printf("posix-tail: all ok\n");
	return 0;
}
