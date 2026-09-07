/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <sys/uio.h> -- readv() and
 * writev(), both [XSI].
 *
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/readv.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/writev.html
 *   https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_uio.h.html
 *
 * The implementation is src/misc/uio.c; the header is include/sys/uio.h;
 * {IOV_MAX} is include/limits.h's.
 *
 * ==================== what was already here =========================
 *
 * test/POSIX-GAP-ACCOUNTING.md lists `sys/uio.h` (2 functions) under
 * "Implemented, not clause-audited".  That row is out of date twice
 * over, and saying so is the first thing this file owes a reader:
 *
 *   - test/posix-tail.c (group J3) audits the gather/scatter ordering,
 *     the [EINVAL] iovcnt range including the `iovcnt == IOV_MAX` upper
 *     edge, the [EINVAL] ssize_t-overflow clause with "no data shall be
 *     transferred" checked through st_size, writev()'s all-zero-lengths
 *     clause, and [EBADF] for the descriptor -1.
 *   - test/posix-grp.c re-asserts most of that and, more importantly,
 *     carries the argument that XSH 2.9.7's cross-thread atomicity
 *     requirement is UNIMPL rather than N/A.
 *
 * So this file does not re-audit what those two already assert; it
 * takes the clauses neither of them reaches, and it names them where it
 * skips them.  Both existing files audit readv()/writev() ONLY on a
 * regular file, and that turns out to be exactly where the remaining
 * gap lives.
 *
 * ==================== the finding, up front =========================
 *
 * RESOLVED: src/misc/uio.c now gathers a multi-area vector and issues
 * one write().  The original analysis below is retained as the reason
 * for the regression test, but its descriptions of the old per-iovec
 * loop are historical rather than descriptions of the current code.
 *
 * writev.html DESCRIPTION opens:
 *
 *     "The writev() function shall be equivalent to write(), except as
 *      described below."
 *
 * What follows "below" is entirely about the iov array -- the gather
 * order, the {IOV_MAX} range, "shall always write a complete area
 * before proceeding to the next", the all-zero-lengths case, the
 * {SSIZE_MAX} sum.  None of it lifts any clause of write().  One of
 * write()'s clauses is about pipes (write.html DESCRIPTION, in the list
 * headed "Write requests to a pipe or FIFO shall be handled in the same
 * way as a regular file with the following exceptions"):
 *
 *     "Write requests of {PIPE_BUF} bytes or less shall not be
 *      interleaved with data from other processes doing writes on the
 *      same pipe. Writes of greater than {PIPE_BUF} bytes may have data
 *      interleaved, on arbitrary boundaries, with writes by other
 *      processes, whether or not the O_NONBLOCK flag of the file status
 *      flags is set."
 *
 * src/misc/uio.c implements writev() as a loop that calls this
 * library's write() once per non-empty iovec.  Each of those calls is
 * whatever write() gives on its own; the SEQUENCE of them is not
 * anything.  So a writev() whose iov_len values sum to {PIPE_BUF} or
 * less is issued as several separate pipe writes, and another process
 * writing the same pipe can land between them.  {PIPE_BUF} is 4096 here
 * (include/limits.h), so this is not a corner of the clause -- it is
 * the whole of it: every vectored record small enough for the guarantee
 * to be about is a record that can be torn.
 *
 * This is a DIFFERENT clause from the atomicity requirement
 * src/misc/uio.c's banner argues about, and that banner's argument does
 * not reach it.  Three ways in which it does not:
 *
 *   1. Different scope.  The banner answers XSH 2.9.7 "Thread
 *      Interactions with Regular File Operations", which is stated over
 *      two THREADS and over REGULAR FILES.  This clause is stated over
 *      other PROCESSES and over PIPES.  spicule has no thread-creation
 *      interface, which is why test/posix-grp.c leaves 2.9.7
 *      unasserted -- but it does have fork() (src/process/fork.c) and
 *      pipe() (src/unistd/pipe.c), so this one is expressible in the
 *      library's own terms.  The fenced test below writes it.
 *
 *   2. The stated reason for the divergence does not apply.  The banner
 *      declines atomicity because NT's only scatter/gather primitives,
 *      NtReadFileScatter()/NtWriteFileGather(), are page-granular and
 *      cannot take arbitrary iovecs.  That is a real constraint and it
 *      is irrelevant here: satisfying the pipe clause needs no
 *      scatter/gather primitive at all.  A writev() whose lengths sum
 *      to {PIPE_BUF} or less can copy the pieces into one 4096-byte
 *      buffer and issue a single write().  The buffer is a bounded
 *      stack object, the copy is bounded by {PIPE_BUF}, and no
 *      alignment of any kind is required of the caller's vectors.
 *
 *   3. The cost the banner weighs is not the cost here.  It rejects the
 *      conforming route because it "would satisfy the atomicity clause
 *      but reject ordinary vectors".  The coalescing route above
 *      rejects nothing: every vector any caller can pass is still
 *      accepted, and the only vectors that pay the copy are the ones
 *      small enough for the clause to apply to.
 *
 * Classified UNIMPL, not BUG, and the counter-argument is worth writing
 * down because it is a reasonable thing to think.  AGAINST: writev()
 * exists, is handed a pipe, and answers wrongly -- the shape of a BUG
 * -- and the deliberate choice on file was made about a clause that is
 * not this one, so the pipe case was never actually declined, only
 * inherited.  FOR: what is missing is a guarantee, and the code that
 * would provide it does not exist anywhere in the tree -- no coalescing
 * path, no {PIPE_BUF} comparison, no branch on the descriptor's type in
 * src/misc/uio.c.  Nothing computes a wrong answer; a whole mechanism
 * is absent, which is this project's UNIMPL.  What does not survive
 * either way is the REASON ON FILE: src/misc/uio.c's banner presents
 * the loop as an argued trade-off, and the argument it makes is about
 * regular files and page granularity and does not reach pipes.
 *
 * The read side is not the mirror of this and is not a finding.
 * read.html DESCRIPTION says outright: "The behavior of multiple
 * concurrent reads on the same pipe, FIFO, or terminal device is
 * unspecified."  readv() inherits that, so there is no clause for the
 * loop in readv() to violate on a pipe.
 *
 * What a caller observes today: a program that uses writev() to put
 * whole records on a shared pipe -- the ordinary reason to reach for
 * it -- gets records other writers can split, silently and only under
 * load.  On Linux or a BSD the same program is correct.
 *
 * ==================== what is asserted live =========================
 *
 * Six live test functions, one fenced.  Each live group is a clause
 * neither posix-tail.c nor posix-grp.c reaches, or reaches only in a
 * shape that cannot separate two answers:
 *
 *   - writev.html RETURN VALUE's "the file-pointer shall remain
 *     unchanged" on failure, which is writev()'s own sentence and has
 *     no counterpart on write.html or readv.html.  posix-grp.c's
 *     test_iov_len_overflow does make an lseek(SEEK_CUR) before/after
 *     comparison on this path, attributed to "no data shall be
 *     transferred" -- but on a freshly O_TRUNC'd file at offset 0, so
 *     before and after are both 0 and "unchanged" is indistinguishable
 *     from "reset to zero".  Asserted here from offset 2;
 *   - the file offset moving by exactly the transferred count in both
 *     directions (read.html/write.html, inherited through the two
 *     "shall be equivalent to" sentences).  Nothing asserts the
 *     ADVANCE: posix-tail.c contains no SEEK_CUR at all, and every
 *     SEEK_CUR in posix-grp.c is one of the two "must not move" pairs;
 *   - readv()'s zero-sum edge (posix-tail.c has writev()'s side only);
 *   - the `iovcnt == IOV_MAX` upper edge on the READ side
 *     (posix-tail.c asserts it for writev() only);
 *   - the access-mode half of [EBADF] for both, i.e. a perfectly valid
 *     descriptor open the wrong way (posix-tail.c uses -1, which is the
 *     other half);
 *   - and a vectored round trip over a PIPE, since every existing
 *     assertion about these two functions is made on a regular file.
 *
 * NOT audited here, and where each lives instead: XSH 2.9.7's
 * cross-thread atomicity on a regular file (recorded and argued in
 * test/posix-grp.c; unassertable -- no threads); sysconf(_SC_IOV_MAX),
 * which does not exist and is already fenced as one of the 110 missing
 * _SC_ names in test/posix-unistd.c; {IOV_MAX} against its
 * {_XOPEN_IOV_MAX} floor (test/posix-limits.c); struct iovec's two
 * members (test/posix-grp.c).
 */
#include <sys/uio.h>
#include <limits.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "test-policy.h"

extern char **environ;

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* --------------------------------------------------------------------
 * writev.html RETURN VALUE: "Upon successful completion, writev() shall
 * return the number of bytes actually written. Otherwise, it shall
 * return a value of -1, the file-pointer shall remain unchanged, and
 * errno shall be set to indicate an error."
 *
 * The middle clause is writev()'s alone -- write.html's RETURN VALUE
 * says only "-1 shall be returned and errno set", and readv.html's
 * RETURN VALUE is just "Refer to read()".
 *
 * What the tree already has, exactly: posix-tail.c's test_writev
 * asserts that a failed writev() leaves st_size alone, which is the
 * "no data shall be transferred" half of a different clause and would
 * also hold of an implementation that moved the offset without
 * writing; posix-grp.c's test_iov_len_overflow does compare
 * lseek(fd, 0, SEEK_CUR) before against after, but on a file it has
 * just opened O_TRUNC and never seeked, so both readings are 0 and
 * an implementation that reset the offset to 0 on failure would pass
 * it unchanged.  This group seeks to 2 first, which separates the two,
 * and attributes the check to the sentence that actually requires it.
 * ------------------------------------------------------------------ */
static void test_writev_failure_leaves_file_pointer(void)
{
	const char *path = "uio-audit-fptr.tmp";
	struct iovec iov[2];
	char buf[1];
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "abcdef", 6) == 6);
	CHECK(lseek(fd, 2, SEEK_SET) == 2);

	/* *shall fail* "[EINVAL] The sum of the iov_len values in the iov
	 * array would overflow an ssize_t."  src/misc/uio.c's check_iov()
	 * rejects this before any I/O, so iov_base is never dereferenced. */
	iov[0].iov_base = buf; iov[0].iov_len = 1;
	iov[1].iov_base = buf; iov[1].iov_len = (size_t)SSIZE_MAX;
	errno = 0;
	CHECK(writev(fd, iov, 2) == -1);
	CHECK(errno == EINVAL);
	CHECK(lseek(fd, 0, SEEK_CUR) == 2);

	/* *may fail* "[EINVAL] The iovcnt argument was less than or equal
	 * to 0, or greater than {IOV_MAX}" -- spicule does implement it, so
	 * the same RETURN VALUE sentence is checked on that path too. */
	iov[0].iov_base = buf; iov[0].iov_len = 1;
	errno = 0;
	CHECK(writev(fd, iov, 0) == -1);
	CHECK(errno == EINVAL);
	CHECK(lseek(fd, 0, SEEK_CUR) == 2);

	close(fd);
	unlink(path);
}

/* --------------------------------------------------------------------
 * readv.html/writev.html DESCRIPTION: both are "equivalent to" read()
 * and write() apart from the vector handling, so read.html's "The file
 * offset shall be incremented by the number of bytes actually read" and
 * write.html's "Before successful return from write(), the file offset
 * shall be incremented by the number of bytes actually written" apply
 * unchanged.
 *
 * Neither existing file checks that the offset ADVANCES.  Checked, not
 * assumed: `grep -n SEEK_CUR test/posix-tail.c test/posix-grp.c`
 * returns nothing for posix-tail.c and four lines for posix-grp.c, and
 * all four are the two before/after pairs that assert the offset must
 * NOT move (test_iov_len_overflow, test_writev_all_zero).  So an
 * implementation that left the offset alone after a successful
 * transfer, or advanced it by the whole requested length rather than
 * the transferred one, passes both files today.
 *
 * Asserted here across an iovec boundary in each direction, with the
 * read split placed differently from the write split so that "the
 * number of bytes actually transferred" is not the same arithmetic
 * twice.
 * ------------------------------------------------------------------ */
static void test_offset_advances_by_transferred_count(void)
{
	const char *path = "uio-audit-offset.tmp";
	struct iovec iov[3];
	char r0[3], r1[2];
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;

	iov[0].iov_base = (void *)"abc"; iov[0].iov_len = 3;
	iov[1].iov_base = (void *)"";    iov[1].iov_len = 0;
	iov[2].iov_base = (void *)"de";  iov[2].iov_len = 2;
	CHECK(writev(fd, iov, 3) == 5);
	CHECK(lseek(fd, 0, SEEK_CUR) == 5);

	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	memset(r0, '#', sizeof r0);
	memset(r1, '#', sizeof r1);
	iov[0].iov_base = r0; iov[0].iov_len = sizeof r0;
	iov[1].iov_base = r1; iov[1].iov_len = sizeof r1;
	CHECK(readv(fd, iov, 2) == 5);
	CHECK(lseek(fd, 0, SEEK_CUR) == 5);
	CHECK(!memcmp(r0, "abc", 3));
	CHECK(!memcmp(r1, "de", 2));

	close(fd);
	unlink(path);
}

/* --------------------------------------------------------------------
 * readv.html has no counterpart to writev.html's "If fildes refers to a
 * regular file and all of the iov_len members in the array pointed to
 * by iov are 0, writev() shall return 0 and have no other effect."  It
 * inherits read.html's rule instead: "Before any action described below
 * is taken, and if nbyte is zero, the read() function may detect and
 * return errors as described below. In the absence of errors, or if
 * error detection is not performed, the read() function shall return
 * zero and have no other results."
 *
 * posix-tail.c asserts the writev() side.  The readv() side is asserted
 * here at a position with real data after it, so that a return of 0
 * cannot be mistaken for end-of-file: the offset must not have moved
 * and the next readv() must still see the data.
 * ------------------------------------------------------------------ */
static void test_readv_zero_sum(void)
{
	const char *path = "uio-audit-zerosum.tmp";
	struct iovec iov[3];
	char buf[4];
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "wxyz", 4) == 4);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);

	iov[0].iov_base = buf; iov[0].iov_len = 0;
	iov[1].iov_base = buf; iov[1].iov_len = 0;
	iov[2].iov_base = buf; iov[2].iov_len = 0;
	CHECK(readv(fd, iov, 3) == 0);
	CHECK(lseek(fd, 0, SEEK_CUR) == 0);	/* "have no other results" */

	/* not end-of-file: the data is still there and still readable */
	memset(buf, '#', sizeof buf);
	iov[0].iov_base = buf; iov[0].iov_len = sizeof buf;
	CHECK(readv(fd, iov, 1) == 4);
	CHECK(!memcmp(buf, "wxyz", 4));

	close(fd);
	unlink(path);
}

/* --------------------------------------------------------------------
 * readv.html DESCRIPTION: "The iovcnt argument is valid if greater than
 * 0 and less than or equal to {IOV_MAX}."  The upper edge is the half
 * an off-by-one gets wrong, and posix-tail.c asserts it for writev()
 * only.  src/misc/uio.c happens to share check_iov() between the two,
 * but a shared helper is an implementation detail and the sentence is
 * printed on both pages.
 *
 * limits.h.html gives {IOV_MAX} as "Maximum number of iovec structures
 * that one process has available for use with readv() or writev()",
 * Minimum Acceptable Value {_XOPEN_IOV_MAX}; the array below is sized
 * for this tree's value and the sizing is checked rather than assumed.
 * Every area is empty, so this is a pure iovcnt check that transfers
 * nothing.
 * ------------------------------------------------------------------ */
static void test_readv_iovcnt_upper_edge(void)
{
	static struct iovec big[1024];
	const char *path = "uio-audit-edge.tmp";
	char c = 0;
	int fd, i;

	CHECK(IOV_MAX <= (int)(sizeof big / sizeof big[0]));
	if (IOV_MAX > (int)(sizeof big / sizeof big[0])) return;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;

	for (i = 0; i < IOV_MAX; i++) { big[i].iov_base = &c; big[i].iov_len = 0; }
	errno = 0;
	CHECK(readv(fd, big, IOV_MAX) == 0);

	close(fd);
	unlink(path);
}

/* --------------------------------------------------------------------
 * ERRORS on both pages are "Refer to read()"/"Refer to write()", and
 * each of those spells [EBADF] with two halves in one sentence:
 *
 *   read.html:  "[EBADF] The fildes argument is not a valid file
 *                descriptor open for reading."
 *   write.html: "[EBADF] The fildes argument is not a valid file
 *                descriptor open for writing."
 *
 * posix-tail.c asserts the first half of each (the descriptor -1, not
 * valid at all).  The second half -- a perfectly valid descriptor open
 * the wrong way -- is a separate code path (src/unistd/read.c and
 * src/unistd/write.c each test O_ACCMODE before touching NT) and is
 * asserted here.
 * ------------------------------------------------------------------ */
static void test_ebadf_wrong_access_mode(void)
{
	const char *path = "uio-audit-access.tmp";
	struct iovec iov[1];
	char buf[4];
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "abcd", 4) == 4);
	CHECK(close(fd) == 0);

	fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	if (fd >= 0) {
		iov[0].iov_base = (void *)"z"; iov[0].iov_len = 1;
		errno = 0;
		CHECK(writev(fd, iov, 1) == -1);
		CHECK(errno == EBADF);
		close(fd);
	}

	fd = open(path, O_WRONLY);
	CHECK(fd >= 0);
	if (fd >= 0) {
		iov[0].iov_base = buf; iov[0].iov_len = sizeof buf;
		errno = 0;
		CHECK(readv(fd, iov, 1) == -1);
		CHECK(errno == EBADF);
		close(fd);
	}

	unlink(path);
}

/* --------------------------------------------------------------------
 * Neither page says "regular file" in its account of what the vector
 * means: writev() "shall gather output data from the iovcnt buffers
 * specified by the members of the iov array" and readv() "shall always
 * fill an area completely before proceeding to the next" are stated
 * about fildes, whatever fildes is.  Every existing assertion about
 * these two functions in this tree is made on a regular file, so what
 * this group establishes is that the vector handling is not
 * accidentally tied to seekability.
 *
 * Deliberately sized so nothing here can block or be short: five bytes
 * go into a fresh pipe -- src/unistd/pipe.c passes 65536 for both the
 * inbound and outbound quota of its NtCreateNamedPipeFile -- and the
 * reading vector asks for exactly those five, in one process, after
 * the write has returned.  No area is zero-length, because
 * write.html makes a zero-byte write to a non-regular file unspecified
 * ("If nbyte is zero and the file is not a regular file, the results
 * are unspecified") and this group is not the place to probe that.
 * ------------------------------------------------------------------ */
static void test_pipe_round_trip(void)
{
	struct iovec wiov[2], riov[2];
	char r0[2], r1[3];
	int p[2];
	int rc = pipe(p);

	CHECK(rc == 0);
	if (rc != 0) return;

	wiov[0].iov_base = (void *)"ab";  wiov[0].iov_len = 2;
	wiov[1].iov_base = (void *)"cde"; wiov[1].iov_len = 3;
	CHECK(writev(p[1], wiov, 2) == 5);

	memset(r0, '#', sizeof r0);
	memset(r1, '#', sizeof r1);
	riov[0].iov_base = r0; riov[0].iov_len = sizeof r0;
	riov[1].iov_base = r1; riov[1].iov_len = sizeof r1;
	CHECK(readv(p[0], riov, 2) == 5);
	CHECK(!memcmp(r0, "ab", 2));
	CHECK(!memcmp(r1, "cde", 3));

	close(p[0]);
	close(p[1]);
}

/* --------------------------------------------------------------------
 * The finding.  The banner has the full argument; the fence carries the
 * short form and what the test would establish.
 * ------------------------------------------------------------------ */
#if SPICULE_TEST(PASS, posix_uio_writev_pipe_below_pipe_buf_not_interleaved) /* Former BUG, now fixed by gathering the vector into one write.
	writev.html DESCRIPTION -- "The writev() function shall
	be equivalent to write(), except as described below" -- and so
	write.html DESCRIPTION's pipe clause: "Write requests of
	{PIPE_BUF} bytes or less shall not be interleaved with data
	from other processes doing writes on the same pipe. Writes of
	greater than {PIPE_BUF} bytes may have data interleaved, on
	arbitrary boundaries, with writes by other processes, whether
	or not the O_NONBLOCK flag of the file status flags is set."

	WHAT src/misc/uio.c ACTUALLY DOES, read from the file rather
	than inferred: writev()'s body is

	    for (i = 0; i < iovcnt; i++) {
	            if (!iov[i].iov_len) continue;
	            w = write(fd, iov[i].iov_base, iov[i].iov_len);
	            ...
	    }

	-- one call to this library's own write() per non-empty area,
	and no other I/O anywhere in the file.  So a writev() of four
	16-byte areas to a pipe is four calls to write(), whatever
	write() then does with each.  The 64-byte record is well under
	{PIPE_BUF}, which include/limits.h line 29 defines as 4096.

	That the file contains no {PIPE_BUF} test and no branch on the
	descriptor's type is not an impression: `grep -rn PIPE_BUF src/`
	returns exactly one line, src/unistd/sysconf.c's
	`case _PC_PIPE_BUF: return PIPE_BUF;`, and src/misc/uio.c is
	114 lines that include <sys/uio.h>, <limits.h>, <unistd.h> and
	<errno.h> and call nothing but read() and write().

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

	WHAT A GREEN PEDANTIC RUN HERE IS AND IS NOT EVIDENCE FOR.  The
	assertion forks (src/process/fork.c), and stock apt Wine 9.0 --
	what .github/workflows/ci.yml's setup-wine installs, and the
	only runner that ever enables this case, since windows-test runs
	tools/run-tests.py over prebuilt binaries and never un-fences
	anything -- has no ntdll.RtlCloneUserProcess.  Measured: the
	probe aborts with "unimplemented function
	ntdll.dll.RtlCloneUserProcess" before reaching the first
	interleaving check.  So the probe's FAIL is nonzero-exit, not a
	measurement of the clause, and must not be read as one.

	The claim does not rest on that probe.  It rests on
	src/misc/uio.c's writev(), which is a loop issuing one
	independent write() per iovec:

	  for (i = 0; i < iovcnt; i++) { ... w = write(fd, iov[i].iov_base,
	  iov[i].iov_len); ... }

	n iovecs summing to {PIPE_BUF} or less are therefore n separate
	pipe writes with n-1 windows between them, and write.html's
	"shall not be interleaved" cannot hold structurally, whatever a
	runner reports.  When the runner gains fork the assertion becomes
	live and measures the same thing directly.

	WHY NOT N/A.  Nothing about NT makes the clause
	meaningless: pipes exist (src/unistd/pipe.c builds them from
	NtCreateNamedPipeFile), other processes exist, and the
	conforming implementation needs no NT facility this library
	lacks.  When the lengths sum to {PIPE_BUF} or less, copy the
	pieces into one bounded stack buffer and issue a single
	write(); when they sum to more, the clause itself permits
	interleaving "on arbitrary boundaries", so the existing loop is
	already conforming there.  The missing thing is a mechanism.

	WHY THE OLDER VOCABULARY LEANED UNIMPL.  The two are close here
	and the case for BUG is real -- writev() exists, is handed a pipe, and
	answers wrongly.  What decides it is that no code in the tree
	attempts this guarantee at all: no coalescing path, no
	{PIPE_BUF} comparison, no branch on the descriptor's type.
	Nothing computes a wrong answer; a whole mechanism is absent.
	That reading is what the paragraph above supersedes.

	WHY src/misc/uio.c's BANNER DOES NOT ALREADY COVER THIS.  That
	banner declines XSH 2.9.7's atomicity -- stated over two
	threads and over regular files -- on the ground that NT's
	NtReadFileScatter()/NtWriteFileGather() are page-granular and
	would force page-aligned iovecs on every caller.

	That page-granularity claim is THE BANNER'S, not this file's.
	It is read from src/misc/uio.c as it stands at 9acc389 and has
	not been re-measured here -- there is no NT to measure against
	from where this was written, and this project has had "cannot
	be done here" claims in fence comments turn out to be stale
	before.  Nothing below depends on whether it is still true:
	this finding does not need a scatter/gather primitive at all.
	If someone does re-measure it and it has decayed, that reopens
	the 2.9.7 question in test/posix-grp.c, not this one.

	What matters here is that neither half of that argument reaches
	this clause: it is stated over other processes and over pipes,
	and satisfying it uses no scatter/gather primitive and imposes
	no alignment on anything the caller passes.  The divergence
	recorded there is argued; this one is inherited.

	WHY FENCED RATHER THAN ASSERTED, given that -- unlike XSH 2.9.7,
	which needs two threads this library cannot create -- the test
	below can actually be written here.

	Stated precisely, because it was reasoned from the source and
	not measured: nothing here was run.  What is known is
	structural.  src/misc/uio.c issues PIECES separate write()
	calls per writev(), so whatever atomicity each write() has, the
	group of them has none, and the guarantee the clause states
	cannot hold however the calls are scheduled.  The test's shape
	is deliberately one-sided on top of that: a conforming writev()
	makes every REC-byte block of the stream uniform, so the check
	can never fail against a correct implementation and no
	scheduling can make it report a defect that is not there.  It
	can only UNDER-report -- a run in which the two writers never
	actually overlap passes -- which is why it is fenced rather
	than run as a live assertion whose green would mean nothing,
	and a reason to run it with ROUNDS large if it is ever
	un-fenced.  A successor with a running tree should un-fence it
	once and record what it observed.

	The original fixture used fork(), which aborts under the Wine runner
	before testing writev().  This version uses posix_spawn() and the
	same inherited pipe, so the assertion reaches the clause on CI. */
static int writev_child(int fd)
{
	enum { REC = 64, PIECES = 4, ROUNDS = 64 };
	char record[REC];
	struct iovec iov[PIECES];
	int i;

	memset(record, 'B', sizeof record);
	for (i = 0; i < PIECES; i++) {
		iov[i].iov_base = record + i * (REC / PIECES);
		iov[i].iov_len = REC / PIECES;
	}
	for (i = 0; i < ROUNDS; i++)
		if (writev(fd, iov, PIECES) != REC) return 1;
	close(fd);
	return 0;
}

static void test_writev_pipe_below_pipe_buf_not_interleaved(const char *self)
{
	enum { REC = 64, PIECES = 4, ROUNDS = 64 };
	char mine[REC], stream[REC * ROUNDS * 2];
	char fdarg[24];
	char *child_argv[4];
	struct iovec iov[PIECES];
	int p[2], i, status, rc;
	pid_t child;
	ssize_t n, got = 0;

	CHECK(pipe(p) == 0);

	snprintf(fdarg, sizeof fdarg, "%d", p[1]);
	child_argv[0] = (char *)self;
	child_argv[1] = (char *)"writev-child";
	child_argv[2] = fdarg;
	child_argv[3] = 0;
	rc = posix_spawn(&child, self, 0, 0, child_argv, environ);
	CHECK(rc == 0);
	if (rc != 0) { close(p[0]); close(p[1]); return; }

	memset(mine, 'A', sizeof mine);
	for (i = 0; i < PIECES; i++) {
		iov[i].iov_base = mine + i * (REC / PIECES);
		iov[i].iov_len = REC / PIECES;
	}
	for (i = 0; i < ROUNDS; i++)
		CHECK(writev(p[1], iov, PIECES) == REC);
	close(p[1]);

	while (got < (ssize_t)sizeof stream &&
	       (n = read(p[0], stream + got, (size_t)((ssize_t)sizeof stream - got))) > 0)
		got += n;
	close(p[0]);
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(got == (ssize_t)sizeof stream);

	/* Every write was REC bytes and the total is a whole number of
	 * them, so under the clause the stream is a concatenation of whole
	 * records: byte k*REC starts one, and each block is uniform.  A
	 * block holding both letters is a record another process's writes
	 * were interleaved with. */
	for (i = 0; i + REC <= got; i += REC) {
		int j, uniform = 1;
		for (j = 1; j < REC; j++)
			if (stream[i + j] != stream[i]) uniform = 0;
		CHECK(uniform);
	}
}
#endif

int main(int argc, char **argv)
{
#if SPICULE_TEST(PASS, posix_uio_writev_pipe_below_pipe_buf_not_interleaved)
	if (argc == 3 && !strcmp(argv[1], "writev-child")) {
		int fd = 0;
		const char *p = argv[2];
		while (*p >= '0' && *p <= '9') fd = fd * 10 + (*p++ - '0');
		return *p ? 2 : writev_child(fd);
	}
#else
	(void)argc;
	(void)argv;
#endif
	test_writev_failure_leaves_file_pointer();
	test_offset_advances_by_transferred_count();
	test_readv_zero_sum();
	test_readv_iovcnt_upper_edge();
	test_ebadf_wrong_access_mode();
	test_pipe_round_trip();
#if SPICULE_TEST(PASS, posix_uio_writev_pipe_below_pipe_buf_not_interleaved) /* see the fence above
	test_writev_pipe_below_pipe_buf_not_interleaved.  The same
	fence, not a second one: the call site has to be guarded too,
	because the function it calls is inside the first #if 0. */
	test_writev_pipe_below_pipe_buf_not_interleaved(argv[0]);
#endif

	if (fails) { printf("posix-uio: failures: %d\n", fails); return 1; }
	printf("posix-uio: all ok\n");
	return 0;
}
