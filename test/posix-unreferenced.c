/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the POSIX-specified functions
 * that tools/lint-unreferenced.sh found no test/ source even calls.  When
 * that check was introduced the list was 56 names long; eight of
 * them are POSIX interfaces with a specification page to hold them to:
 *
 *   puts, scanf, renameat, fchmodat, sigwait, psignal, roundl,
 *   strxfrm_l
 *
 * strxfrm_l() is the eighth because it was mis-filed: it looks like one
 * of the glibc-only *_l names (strtod_l/strtof_l/strtold_l, which have
 * no POSIX page at all), but POSIX.1-2017 specifies it on
 * strxfrm.html alongside strxfrm().
 *
 * Two of those -- puts() and scanf() -- are core C interfaces that this
 * library has always implemented and that no test had ever called.  The
 * rest are the "at"/long-double/obscure ends of families whose principal
 * member is tested (rename, chmod, round, psiginfo).
 *
 * Every assertion below cites the clause of
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * it checks, including each entry of that page's ERRORS list.  Where the
 * ERRORS list names an error this implementation never produces, the
 * assertion is still written out in full and fenced, using the three
 * conventions the rest of this tree uses (greppable by the tag right
 * after "#if 0 / * "):
 *
 *   BUG:    a confirmed, real spec violation (should pass once fixed)
 *   N/A:    genuinely impossible on this platform, with the mechanism
 *   UNIMPL: not implemented at all here, but implementable
 *
 * A fenced block always contains the real assertions the cited clause
 * requires, written as if it would run -- never a hand-wave.
 *
 * Runs headless under Wine like every other test here.  The three
 * functions that write to a standard stream (puts, scanf, psignal) get
 * that stream redirected at the fd level (dup/dup2 around the call, so
 * the FILE object survives) or with freopen(), the same way
 * test/posix-stdio.c's test_vprintf_vscanf() does.
 */
/* strdup()/mkstemp()/renameat()/fileno() are feature-test gated in
 * include/string.h, include/stdlib.h, include/stdio.h and
 * include/unistd.h; same define most other tests in test/ already carry for
 * the same reason (see test/posix-glob.c's comment on this exact
 * define). */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <math.h>
#include <fenv.h>
#include <float.h>
#include <limits.h>
#include <sys/stat.h>
#include <locale.h>
#include <wchar.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
/* CHECK, plus the errno the failing call left behind.  For assertions
 * whose whole content is "this call succeeded": "FAIL ... fd >= 0" says
 * only that something went wrong, and on the real-Windows CI leg -- the
 * one platform there is no attaching a debugger to -- that cost a whole
 * round trip through CI to learn what.  Set errno = 0 before the call so
 * the number printed is this call's and not a stale one. */
#define CHECK_E(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #cond, errno); } } while (0)

static char *make_tmp(const char *tmpl)
{
	char *t = strdup(tmpl);
	int fd = mkstemp(t);
	if (fd < 0) { free(t); return 0; }
	close(fd);
	return t;
}

/* Read a whole file into buf, NUL-terminated; returns the byte count or
 * -1.  Used to inspect what puts()/psignal() actually wrote. */
static long slurp(const char *name, char *buf, size_t cap)
{
	FILE *f = fopen(name, "rb");
	size_t n;
	if (!f) return -1;
	n = fread(buf, 1, cap - 1, f);
	buf[n] = 0;
	fclose(f);
	return (long)n;
}

static int write_file(const char *name, const char *text)
{
	FILE *f = fopen(name, "wb");
	if (!f) return -1;
	if (text && *text) fwrite(text, 1, strlen(text), f);
	return fclose(f);
}

/* ================================================================= */
/* puts.html                                                          */
/* ================================================================= */

/* puts.html DESCRIPTION: "The puts() function shall write the string
 * pointed to by s, followed by a <newline>, to the standard output
 * stream stdout.  The terminating null byte shall not be written."
 * RETURN VALUE: "Upon successful completion, puts() shall return a
 * non-negative number."
 *
 * fd 1 is pointed at a scratch file for the duration; stdout the FILE
 * object is untouched, so its buffering state survives. */
static void test_puts_success(const char *name)
{
	char buf[64];
	int saved, fd, r1, r2;

	saved = dup(1);
	CHECK(saved >= 0);
	if (saved < 0) return;
	fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) { close(saved); return; }
	CHECK(fflush(stdout) == 0);
	CHECK(dup2(fd, 1) == 1);
	CHECK(close(fd) == 0);

	r1 = puts("alpha");
	/* an empty string is still followed by the <newline> */
	r2 = puts("");

	CHECK(fflush(stdout) == 0);
	CHECK(dup2(saved, 1) == 1);
	CHECK(close(saved) == 0);

	CHECK(r1 >= 0);
	CHECK(r2 >= 0);
	memset(buf, 0, sizeof buf);
	/* "alpha\n" then "\n" -- 7 bytes exactly.  A count of 7 is itself
	 * the assertion that the terminating null byte was not written:
	 * "alpha\0\n\0\n" would be 9. */
	CHECK(slurp(name, buf, sizeof buf) == 7);
	CHECK(!memcmp(buf, "alpha\n\n", 7));
}

/* puts.html ERRORS: "Refer to fputc()."  fputc.html ERRORS, shall fail:
 * "[EBADF] The file descriptor underlying stream is not a valid file
 * descriptor open for writing."  puts.html RETURN VALUE: "Otherwise, it
 * shall return EOF, shall set an error indicator for the stream, and
 * errno shall be set to indicate the error."
 *
 * stdout is the only stream puts() can name, so this reopens stdout
 * itself read-only and puts it back afterwards.  Results are captured
 * into locals and only CHECKed once stdout is a console again, because
 * CHECK's own diagnostic goes to stdout. */
static void test_puts_ebadf(const char *roname, const char *scratch)
{
	int saved, r = 0, e = 0, ferr = 0, reopened = 0, restored = 0;

	saved = dup(1);
	CHECK(saved >= 0);
	if (saved < 0) return;
	CHECK(fflush(stdout) == 0);
	if (freopen(roname, "rb", stdout)) {
		reopened = 1;
		errno = 0;
		r = puts("never written");
		e = errno;
		ferr = ferror(stdout);
		clearerr(stdout);
	}
	/* Put stdout back: reopen it writable (which takes fd 1 again, the
	 * lowest free descriptor, since freopen closed it), then point that
	 * descriptor back at the saved original. */
	if (freopen(scratch, "wb", stdout)) restored = 1;
	if (restored) {
		restored = dup2(saved, fileno(stdout)) == fileno(stdout);
		setvbuf(stdout, 0, _IOLBF, 0);
	}
	close(saved);

	CHECK(reopened);
	CHECK(restored);
	if (reopened) {
		CHECK(r == EOF);
		CHECK(e == EBADF);
		CHECK(ferr != 0);
	}
}

/* fputc.html ERRORS, shall fail: "[EPIPE] An attempt is made to write to
 * a pipe or FIFO that is not open for reading by any process.  A SIGPIPE
 * signal shall also be sent to the thread."
 *
 * Reachable for puts() by pointing fd 1 at the write end of a pipe whose
 * read end is closed.  stdout is made unbuffered first so the write
 * happens inside puts() rather than at the next flush.  SIGPIPE is
 * ignored around the call -- the clause requires it to be *sent*, and
 * the default disposition would take the process down before puts()
 * could return anything to check. */
static void test_puts_epipe(void)
{
	int saved, fds[2], r = 0, e = 0, ferr = 0, ok = 0;
	void (*old)(int);

	if (pipe(fds) != 0) {
		printf("note: pipe() unavailable in this environment (errno %d); puts EPIPE check skipped\n", errno);
		return;
	}
	saved = dup(1);
	CHECK(saved >= 0);
	if (saved < 0) { close(fds[0]); close(fds[1]); return; }
	old = signal(SIGPIPE, SIG_IGN);
	CHECK(close(fds[0]) == 0);
	CHECK(fflush(stdout) == 0);
	if (dup2(fds[1], 1) == 1) {
		ok = 1;
		setvbuf(stdout, 0, _IONBF, 0);
		errno = 0;
		r = puts("into a broken pipe");
		e = errno;
		ferr = ferror(stdout);
		clearerr(stdout);
	}
	CHECK(dup2(saved, 1) == 1);
	setvbuf(stdout, 0, _IOLBF, 0);
	close(saved);
	close(fds[1]);
	signal(SIGPIPE, old);

	if (ok) {
		CHECK(r == EOF);
		CHECK(e == EPIPE);
		CHECK(ferr != 0);
	}
}

/* The rest of fputc.html's ERRORS list, for the record.  Each is written
 * as the assertion the clause requires; none is reachable for puts()
 * here, and each fence says why.
 *
 * [EAGAIN] "The O_NONBLOCK flag is set for the file descriptor
 * underlying stream and the thread would be delayed in the write
 * operation." */
#if SPICULE_TEST(NA, posix_unreferenced_puts_eagain) /* N/A, verdict confirmed, reason made precise.  The old text
       * said "this library has no O_NONBLOCK for a file descriptor at
       * all", which overstates: the bit is accepted and stored, by both
       * fcntl(F_SETFL) (src/fcntl/fcntl.c:55) and ioctl(FIONBIO)
       * (src/ioctl/ioctl.c:143), and fcntl(F_GETFL) reads it back.  The
       * accurate statement is that NOTHING EVER CONSULTS IT on a write
       * path -- src/ioctl/ioctl.c's own banner says so outright,
       * "O_NONBLOCK today only changes what fcntl(F_GETFL) reports
       * back".  src/unistd/write.c issues an unconditional NtWriteFile
       * and waits out STATUS_PENDING itself, on a handle __ntpath opens
       * with FILE_SYNCHRONOUS_IO_NONALERT, so the write completes or
       * fails but never defers.  There is still no state a test could
       * put fd 1 into that would make this clause apply, so the verdict
       * stands; but "the flag does not exist" and "the flag exists and
       * is ignored" are different claims, and only the second is
       * true. */
static void test_puts_eagain(int fd1)
{
	errno = 0;
	CHECK(fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK) == 0);
	CHECK(puts("would block") == EOF);
	CHECK(errno == EAGAIN);
	CHECK(ferror(stdout) != 0);
}
#endif

/* [EFBIG] "An attempt was made to write to a file that exceeds the
 * maximum file size", "...the file size limit of the process", or "The
 * file is a regular file and an attempt was made to write at or beyond
 * the offset maximum." */
#if SPICULE_TEST(NA, posix_unreferenced_puts_efbig) /* N/A THROUGH puts(), all three sub-clauses -- but each for its own
       * reason, and two of the three reasons this fence used to give were
       * out of date.  A "shall fail" entry is not discharged by some of
       * its conditions being vacuous, so they are taken one at a time.
       *
       * IMPLEMENTATION-DEFINED MAXIMUM FILE SIZE: N/A, and this half of
       * the old text still holds.  NT reports a full volume as
       * STATUS_DISK_FULL, which src/internal/errno.c maps to ENOSPC, and
       * filling a volume is not something this suite can do.
       *
       * FILE SIZE LIMIT OF THE PROCESS: NO LONGER TRUE that there is
       * none.  setrlimit(RLIMIT_FSIZE) exists and is enforced by this
       * library's own write paths (src/misc/resource.c, and the clamp in
       * src/unistd/write.c).  The clause is reachable and IS asserted --
       * test/posix-sysmisc.c, test_setrlimit_fsize_enforced(), which
       * pins write, pwrite, ftruncate and posix_fallocate against a
       * 256-byte limit.  It is simply not reachable through puts(),
       * whose only descriptor is fd 1.
       *
       * AT OR BEYOND THE OFFSET MAXIMUM: now implemented, and asserted
       * elsewhere -- src/unistd/write.c reports [EFBIG] for a starting
       * position at or past __OFF_MAX, and test/posix-io.c's
       * test_read_write() pins it.  What is NOT true is the old text's
       * claim that puts() can reach it by seeking fd 1 to the offset
       * maximum.  Measured, by binary search under Wine on ext4: the
       * largest position NtSetInformationFile(FilePositionInformation)
       * accepts is 0xffffffff000, and OFF_MAX comes back [EINVAL] -- so
       * the very first line of the test below, CHECK(lseek(1, OFF_MAX,
       * SEEK_SET) == OFF_MAX), fails before puts() is ever called.
       * glibc on ext4 refuses the identical seek with the identical
       * errno, for the filesystem's reason rather than the libc's.  The
       * clause is therefore pinned on pwrite(), which takes the starting
       * position as an argument and needs no seek.
       *
       * (Note also that OFF_MAX is not defined anywhere in this tree --
       * it is a BSD spelling, not a POSIX one -- so the body below would
       * not compile if un-fenced.  test/posix-io.c writes the constant
       * out.) */
static void test_puts_efbig(void)
{
	CHECK(lseek(1, OFF_MAX, SEEK_SET) == OFF_MAX);
	errno = 0;
	CHECK(puts("past the offset maximum") == EOF);
	CHECK(errno == EFBIG);
	CHECK(ferror(stdout) != 0);
}
#endif

/* [EINTR] "The write operation was terminated due to the receipt of a
 * signal, and no data was transferred." */
#if SPICULE_TEST(NA, posix_unreferenced_puts_eintr) /* N/A: signals here are not asynchronous with respect to a blocked
       * NT wait -- src/signal/signal.c delivers a signal by running the
       * handler from the raising thread (__raise_internal), and nothing
       * interrupts NtWriteFile, which this library always issues on a
       * FILE_SYNCHRONOUS_IO_NONALERT handle (a *non-alertable* wait, so
       * not even an APC can break it).  A partial write terminated by a
       * signal cannot be produced. */
static void test_puts_eintr(void)
{
	errno = 0;
	CHECK(puts("interrupted") == EOF);
	CHECK(errno == EINTR);
	CHECK(ferror(stdout) != 0);
}
#endif

/* [EIO] "A physical I/O error has occurred, or the process is a member
 * of a background process group attempting to write to its controlling
 * terminal, TOSTOP is set..." */
#if SPICULE_TEST(NA, posix_unreferenced_puts_eio) /* N/A, both halves, for two different reasons.
       *
       * Background-process-group write to a controlling terminal with
       * TOSTOP set: no mechanism.  Stated carefully, because a
       * neighbouring correction makes the loose version misleading --
       * NT DOES have process groups (console process groups, created
       * by CREATE_NEW_PROCESS_GROUP and targeted by
       * GenerateConsoleCtrlEvent; see test/posix-spawn.c's
       * POSIX_SPAWN_SETPGROUP fence, which was wrong on exactly this
       * point).  What NT has no analogue of is the rest of the clause:
       * there is no CONTROLLING TERMINAL owned by a session, no
       * foreground/background distinction among console process groups
       * -- a console delivers input to whoever reads it and gates
       * nothing on group membership -- and no TOSTOP to enable
       * (src/termios/, whose tcsetpgrp is a stub).  So the condition
       * the clause describes cannot be constructed here even though
       * one word of it now has a real NT counterpart.
       *
       * A genuine physical I/O error: real, mapped, and not something a
       * test can provoke on demand. */
static void test_puts_eio(void)
{
	errno = 0;
	CHECK(puts("physical I/O error") == EOF);
	CHECK(errno == EIO);
	CHECK(ferror(stdout) != 0);
}
#endif

/* [ENOSPC] "There was no free space remaining on the device containing
 * the file." */
#if SPICULE_TEST(NA, posix_unreferenced_puts_enospc) /* N/A: reachable only by filling the volume the scratch file lives
       * on.  src/internal/errno.c does map STATUS_DISK_FULL to ENOSPC,
       * so the path exists; a test that fills a disk to prove it is not
       * one this suite can run. */
static void test_puts_enospc(void)
{
	errno = 0;
	CHECK(puts("no space") == EOF);
	CHECK(errno == ENOSPC);
	CHECK(ferror(stdout) != 0);
}
#endif

/* fputc.html ERRORS, may fail: "[ENOMEM] Insufficient storage space is
 * available."  and "[ENXIO] A request was made of a nonexistent device,
 * or the request was outside the capabilities of the device." */
#if SPICULE_TEST(NA, posix_unreferenced_puts_may_fail) /* N/A: both are "may fail", and neither is producible on demand --
       * ENOMEM would need the buffer allocation in __ensure_buf() to
       * fail, and ENXIO a device that answers STATUS_NO_SUCH_DEVICE to a
       * write on an already-open handle. */
static void test_puts_may_fail(void)
{
	errno = 0;
	CHECK(puts("out of memory") == EOF);
	CHECK(errno == ENOMEM || errno == ENXIO);
	CHECK(ferror(stdout) != 0);
}
#endif

/* ================================================================= */
/* scanf.html (fscanf page)                                           */
/* ================================================================= */

/* scanf.html DESCRIPTION: "The scanf() function shall be equivalent to
 * fscanf() with the argument stdin interposed before the arguments to
 * scanf()."  Every assertion here therefore drives stdin, redirected
 * with freopen() at the file the caller staged. */
static void test_scanf_basics(const char *name)
{
	int a = 0, b = 0, n = -1;
	char s[32];
	double d = 0;

	CHECK(write_file(name, "12 34 hello 2.5xy\n") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }

	/* RETURN VALUE: "the number of successfully matched and assigned
	 * input items". */
	CHECK(scanf("%d %d", &a, &b) == 2);
	CHECK(a == 12 && b == 34);

	CHECK(scanf("%31s", s) == 1);
	CHECK(!strcmp(s, "hello"));

	/* "%n ... No input is consumed", and it never counts toward the
	 * return value -- one item assigned, not two. */
	CHECK(scanf("%lf%n", &d, &n) == 1);
	CHECK(d == 2.5);
	/* nine bytes consumed so far this call: " 2.5" is four, and the
	 * leading white space the %lf directive skipped is part of what
	 * "the number of bytes read from the input so far by this call"
	 * counts.  Assert only that %n was written and is the length of
	 * what this call actually took. */
	CHECK(n == 4);
}

/* RETURN VALUE: "this number can be zero in the event of an early
 * matching failure", and "If the input ends before the first conversion
 * (if any) has completed, and without a matching failure having
 * occurred, EOF shall be returned." */
static void test_scanf_returns(const char *name)
{
	int a = -1, b = -1;

	CHECK(write_file(name, "zzz") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	/* matching failure on the very first conversion -> 0, not EOF */
	CHECK(scanf("%d", &a) == 0);
	CHECK(a == -1);

	CHECK(write_file(name, "") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	/* input ends before the first conversion completes -> EOF */
	CHECK(scanf("%d", &a) == EOF);

	CHECK(write_file(name, "7") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	/* the first conversion completed, so the second one hitting EOF
	 * does not turn the result into EOF */
	CHECK(scanf("%d %d", &a, &b) == 1);
	CHECK(a == 7);

	/* the assignment-suppressing '*': "the conversion ... is not
	 * assigned to any argument" and such an item is not counted */
	CHECK(write_file(name, "8 9") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%*d %d", &b) == 1);
	CHECK(b == 9);

	/* a directive that is ordinary text must match itself, and a
	 * mismatch is a matching failure that stops the whole call */
	CHECK(write_file(name, "k=5") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	a = -1;
	CHECK(scanf("j=%d", &a) == 0);
	CHECK(a == -1);
}

/* scanf.html ERRORS: "For the conditions under which the fscanf()
 * functions fail and may fail, refer to fgetc()."  fgetc.html ERRORS,
 * shall fail: "[EBADF] The file descriptor underlying stream is not a
 * valid file descriptor open for reading."  RETURN VALUE: an input
 * failure before any conversion completes is EOF. */
static void test_scanf_ebadf(const char *name)
{
	int a = -1;

	if (!freopen(name, "wb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%d", &a) == EOF);
	CHECK(errno == EBADF);
	CHECK(ferror(stdin) != 0);
	clearerr(stdin);
}

/* scanf.html ERRORS, shall fail: "[ENOMEM] Insufficient storage space is
 * available."  The conversions that allocate are the ones carrying
 * fscanf.html's [CX] assignment-allocation character 'm': "the
 * corresponding argument shall be of type char ** ... the function
 * shall allocate a buffer ... The caller is responsible for freeing the
 * memory after usage."  That is the only storage src/stdio/scanf.c
 * obtains on the caller's behalf, so it is the only place the page's
 * shall-fail can arise.
 *
 * Allocator exhaustion is not producible on demand, so what is asserted
 * here is everything that has to hold for the error to BE reportable:
 * the three conversions exist, they allocate, a width caps them, and
 * every way one of them can fail leaves the caller's pointer alone
 * rather than handing over a half-built buffer.  The two [EILSEQ] cases
 * are in this function rather than with the other encoding assertions
 * because they are the only failures that can strand a buffer that
 * already has bytes in it -- `make asan` runs this file natively under
 * LeakSanitizer, which is what turns them into a leak check. */
static void test_scanf_enomem(const char *name)
{
	char *p = 0, *q = 0;
	wchar_t *w = 0;
	char buf[16], big[513];
	int n = -1;

	/* the s conversion: a buffer holding the input and a terminator */
	CHECK(write_file(name, "allocated") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%ms", &p) == 1);
	CHECK(p != 0 && !strcmp(p, "allocated"));
	free(p); p = 0;

	/* a field far past any plausible initial buffer size, so the
	 * growth path is exercised rather than one lucky allocation */
	memset(big, 'k', 512);
	big[512] = 0;
	CHECK(write_file(name, big) == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%ms", &p) == 1);
	CHECK(p != 0 && strlen(p) == 512);
	free(p); p = 0;

	/* a field width caps an allocating conversion the same as any
	 * other, and the directive after it resumes where it stopped */
	CHECK(write_file(name, "abcdef") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%3ms%ms", &p, &q) == 2);
	CHECK(p != 0 && !strcmp(p, "abc"));
	CHECK(q != 0 && !strcmp(q, "def"));
	free(p); free(q); p = q = 0;

	/* the c conversion: "a sequence of bytes of the number specified by
	 * the field width", and no terminating null -- so the buffer holds
	 * exactly three bytes and nothing may be read past them */
	CHECK(write_file(name, "xyz") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%3mc", &p) == 1);
	CHECK(p != 0 && !memcmp(p, "xyz", 3));
	free(p); p = 0;

	/* the [ conversion */
	CHECK(write_file(name, "12345abc") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%m[0-9]%ms", &p, &q) == 2);
	CHECK(p != 0 && !strcmp(p, "12345"));
	CHECK(q != 0 && !strcmp(q, "abc"));
	free(p); free(q); p = q = 0;

	/* with the l qualifier the argument is wchar_t ** and the bytes are
	 * converted "as if by a call to the mbrtowc() function" -- the
	 * character above the BMP costs a surrogate pair, so the buffer the
	 * conversion sizes for itself is not one element per input byte */
	CHECK(write_file(name, "\xf0\x9d\x84\x9e") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%mls", &w) == 1);
	CHECK(w != 0 && w[0] == 0xd834 && w[1] == 0xdd1e && w[2] == 0);
	free(w); w = 0;

	/* a matching failure receives no pointer: the argument is "a
	 * pointer variable that will receive a pointer to the allocated
	 * buffer" and there is no buffer to receive */
	CHECK(write_file(name, "abc") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%m[0-9]", &p) == 0);
	CHECK(p == 0);

	/* the assignment-suppressing '*' allocates nothing and consumes no
	 * argument, so the %d below is the first one */
	CHECK(write_file(name, "skipme 42") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%*ms %d", &n) == 1);
	CHECK(n == 42);

	/* an encoding error PART WAY THROUGH an allocating field: the bytes
	 * already converted sit in a buffer that has to be released rather
	 * than handed over, and the caller's pointer stays as it was */
	CHECK(write_file(name, "ab\x80") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%mls", &w) == EOF);
	CHECK(errno == EILSEQ);
	CHECK(w == 0);
	clearerr(stdin);

	/* likewise a sequence truncated by end of input */
	CHECK(write_file(name, "\xc3") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%mls", &w) == EOF);
	CHECK(errno == EILSEQ);
	CHECK(w == 0);
	clearerr(stdin);

	/* a conversion that COMPLETED before a later directive failed has
	 * already handed its buffer over, and the caller owns it -- an
	 * implementation that dropped it on the floor instead would be the
	 * leak, since the caller has no other reference to free */
	CHECK(write_file(name, "ok ab\x80") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%ms %mls", &p, &w) == EOF);
	CHECK(errno == EILSEQ);
	CHECK(p != 0 && !strcmp(p, "ok"));
	CHECK(w == 0);
	free(p); p = 0;
	clearerr(stdin);

	/* the unmodified conversions must be untouched by all of this: 'm'
	 * is a new branch in the same three conversions, not a rewrite */
	CHECK(write_file(name, "plain 42") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	n = -1;
	CHECK(scanf("%s %d", buf, &n) == 2);
	CHECK(!strcmp(buf, "plain") && n == 42);
}

/* scanf.html ERRORS, shall fail: "[EILSEQ] Input byte sequence does not
 * form a valid character." */
static void test_scanf_eilseq(const char *name)
{
	wchar_t w[8];
	/* a lone 0x80 continuation byte is not a valid character in any
	 * multibyte encoding this library supports */
	CHECK(write_file(name, "\x80\x80") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%7ls", w) == EOF);
	CHECK(errno == EILSEQ);
	CHECK(ferror(stdin) != 0);
}

/* The clause the [EILSEQ] above is a consequence OF, asserted in its own
 * right.  fscanf.html, the s conversion: "If an l (ell) qualifier is
 * present, the input is a sequence of characters that begins in the
 * initial shift state.  Each character shall be converted to a wide
 * character as if by a call to the mbrtowc() function" -- and the same
 * sentence appears under c and under [.
 *
 * Asserted separately because the [EILSEQ] test alone does NOT pin it: a
 * conversion could validate the byte sequence, report the error, and
 * still store raw bytes into the caller's wchar_t array on the success
 * path.  Detecting the failure and performing the conversion are two
 * different things and need two different assertions. */
static void test_scanf_l_modifier(const char *name)
{
	wchar_t w[16], w2[16];
	char narrow[16];
	int n;

	/* plain ASCII: one wide character per byte, NUL-terminated */
	CHECK(write_file(name, "hello world") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	w[0] = w[1] = 0;
	CHECK(scanf("%ls", w) == 1);
	CHECK(w[0] == L'h' && w[1] == L'e' && w[4] == L'o' && w[5] == 0);

	/* a two-byte UTF-8 character must become ONE wide character.  With
	 * the modifier ignored, w[0] would hold the lead byte 0xC3 and w[1]
	 * the continuation byte 0xA9 instead. */
	CHECK(write_file(name, "\xc3\xa9x") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	memset(w, 0, sizeof w);
	CHECK(scanf("%ls", w) == 1);
	CHECK(w[0] == 0x00e9);          /* U+00E9 LATIN SMALL LETTER E WITH ACUTE */
	CHECK(w[1] == L'x');
	CHECK(w[2] == 0);

	/* a three-byte sequence, likewise one wide character */
	CHECK(write_file(name, "\xe2\x82\xac") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	memset(w, 0, sizeof w);
	CHECK(scanf("%ls", w) == 1);
	CHECK(w[0] == 0x20ac);          /* U+20AC EURO SIGN */
	CHECK(w[1] == 0);

	/* Above the BMP.  wchar_t is a 16-bit UTF-16 code unit here, so
	 * U+1D11E must arrive as a SURROGATE PAIR -- two wchar_t from one
	 * multibyte character.  This is the case a conversion loop that
	 * assumes one wide character per mbrtowc() call gets wrong. */
	CHECK(write_file(name, "\xf0\x9d\x84\x9e") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	memset(w, 0, sizeof w);
	CHECK(scanf("%ls", w) == 1);
	CHECK(w[0] == 0xd834);
	CHECK(w[1] == 0xdd1e);
	CHECK(w[2] == 0);

	/* %lc -- no null byte is added, and the width is a byte count */
	CHECK(write_file(name, "\xc3\xa9z") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	memset(w, 0, sizeof w);
	CHECK(scanf("%2lc", w) == 1);
	CHECK(w[0] == 0x00e9);

	/* %l[ -- note the string break after the hex escape: C hex escapes are
	 * greedy, so "\xc3\xa9ab." would lex \xa9ab as ONE escape and the
	 * literal would not contain the bytes intended.  ('a' and 'b' are hex
	 * digits; the other fixtures here are followed by non-hex characters
	 * and do not need the break.) */
	CHECK(write_file(name, "\xc3\xa9" "ab.") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	memset(w, 0, sizeof w);
	CHECK(scanf("%l[^.]", w) == 1);
	CHECK(w[0] == 0x00e9 && w[1] == L'a' && w[2] == L'b' && w[3] == 0);

	/* the unmodified conversions must be untouched by all of this */
	CHECK(write_file(name, "plain 42") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(scanf("%s %d", narrow, &n) == 2);
	CHECK(!strcmp(narrow, "plain") && n == 42);

	/* an assignment-suppressed %*ls consumes input and stores nothing */
	CHECK(write_file(name, "\xc3\xa9 tail") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	memset(w2, 0, sizeof w2);
	CHECK(scanf("%*ls %ls", w2) == 1);
	CHECK(w2[0] == L't' && w2[1] == L'a');

	/* a TRUNCATED multibyte sequence at end of input is an encoding
	 * error too, not a silent short read: the state is left non-initial
	 * and there are no more bytes to complete it */
	CHECK(write_file(name, "\xc3") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%ls", w) == EOF);
	CHECK(errno == EILSEQ);
}

/* scanf.html ERRORS, may fail: "[EINVAL] There are insufficient
 * arguments." */
#if SPICULE_TEST(NA, posix_unreferenced_scanf_einval) /* N/A: "may fail", and undetectable in principle here -- a
       * variadic callee cannot count the arguments it was handed, and
       * this implementation reads each one with va_arg() as the format
       * demands it.  Passing too few is undefined behaviour at the call
       * site; the assertion below is what a checking implementation
       * would have to make true, and no C implementation on this target
       * can. */
static void test_scanf_einval(const char *name)
{
	int a;
	CHECK(write_file(name, "1 2") == 0);
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	errno = 0;
	CHECK(scanf("%d %d", &a) == EOF);
	CHECK(errno == EINVAL);
}
#endif

/* fgetc.html ERRORS, shall fail: "[EOVERFLOW] The file is a regular file
 * and an attempt was made to read at or beyond the offset maximum
 * associated with the corresponding stream."  Also [EAGAIN], [EINTR],
 * [EIO], and may-fail [ENOMEM]/[ENXIO] -- the same list, and for the
 * same reasons, as the puts() fences above. */
#if SPICULE_TEST(NA, posix_unreferenced_scanf_stream_errors) /* N/A: same mechanisms as the fputc fences above -- O_NONBLOCK
       * stored but never consulted (EAGAIN; see that fence for the
       * corrected wording, and note the one live EAGAIN path in this
       * library, src/unistd/read.c:37's STATUS_PIPE_EMPTY arm, is
       * unreachable here: measured under Wine, a read() of an empty
       * pipe BLOCKS rather than answering STATUS_PIPE_EMPTY, since
       * nothing puts the pipe into a no-wait mode), no signal that can
       * interrupt a non-alertable NtReadFile (EINTR), no controlling
       * terminal (EIO), and no way to demand ENOMEM/ENXIO.  EOVERFLOW is
       * the one with a real mechanism (seek stdin past the off_t
       * maximum), and it is UNIMPL rather than N/A: src/unistd/read.c
       * has no offset-maximum check, so the read would report whatever
       * NT says instead. */
static void test_scanf_stream_errors(void)
{
	int a;
	CHECK(lseek(0, OFF_MAX, SEEK_SET) == OFF_MAX);
	errno = 0;
	CHECK(scanf("%d", &a) == EOF);
	CHECK(errno == EOVERFLOW);
	CHECK(ferror(stdin) != 0);
}
#endif

/* ================================================================= */
/* renameat.html (rename page)                                        */
/* ================================================================= */

static int exists(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0;
}

/* renameat.html DESCRIPTION: "The renameat() function shall be
 * equivalent to the rename() function except in the case where either
 * old or new specifies a relative path.  If old is a relative path, the
 * file to be renamed is located relative to the directory associated
 * with the file descriptor oldfd... If renameat() is passed the special
 * value AT_FDCWD in the oldfd or newfd parameter, the current working
 * directory shall be used."  RETURN VALUE: "Upon successful completion,
 * [it] shall return 0.  Otherwise, it shall return -1". */
static void test_renameat_success(void)
{
	int dfd;

	CHECK(mkdir("ren.d", 0755) == 0);
	CHECK(write_file("ren.d/a", "one") == 0);

	/* AT_FDCWD in both positions is plain rename() */
	CHECK(renameat(AT_FDCWD, "ren.d/a", AT_FDCWD, "ren.d/b") == 0);
	CHECK(!exists("ren.d/a"));
	CHECK(exists("ren.d/b"));

	dfd = open("ren.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd >= 0) {
		/* old relative to the descriptor, new relative to the cwd --
		 * the two base directories are independent */
		CHECK(renameat(dfd, "b", AT_FDCWD, "ren.d/e") == 0);
		CHECK(!exists("ren.d/b"));
		CHECK(exists("ren.d/e"));
		CHECK(close(dfd) == 0);
	}

	/* DESCRIPTION: "If the link named by the new argument exists, it
	 * shall be removed and old renamed to new." */
	CHECK(write_file("ren.d/f", "victim") == 0);
	CHECK(renameat(AT_FDCWD, "ren.d/e", AT_FDCWD, "ren.d/f") == 0);
	CHECK(!exists("ren.d/e"));
	{
		char buf[16];
		CHECK(slurp("ren.d/f", buf, sizeof buf) == 3);
		CHECK(!strcmp(buf, "one"));
	}

	CHECK(unlink("ren.d/f") == 0);
}

/* rename.html DESCRIPTION, the directory case: "If the directory named
 * by the new argument exists, it shall be removed and old renamed to
 * new... The new argument shall not name any directory other than an
 * empty directory." -- an EMPTY directory at new must be removed and
 * replaced, not refused. */
#if SPICULE_TEST(PASS, posix_unreferenced_renameat_dir_over_empty_dir) /* FIXED.  NT's FileRenameInformation[Ex] will not
       * replace an existing directory even with
       * FILE_RENAME_REPLACE_IF_EXISTS, so the call comes back
       * STATUS_ACCESS_DENIED; src/stdio/misc.c's disambiguation (moved
       * to src/stdio/nt/plat_stdio.c's rename_set()) then sees that new
       * is a directory and that old is one too, and reports ENOTEMPTY
       * -- without asking whether new is in fact empty.  So (a) the
       * rename failed where rename.html requires it to succeed, and (b)
       * the errno it failed with named a condition ("that is not an
       * empty directory") that was not the one present.  Observed: -1 /
       * ENOTEMPTY against a freshly created, empty ren.d/h.
       *
       * Fixed in __plat_rename() (src/stdio/nt/plat_stdio.c): on that
       * exact signature (rename_set() failed ENOTEMPTY, and both old
       * and new really are directories -- the only way rename_set()
       * produces ENOTEMPTY), remove new exactly as rmdir() would
       * (__plat_unlink(), which already asks NT's own directory-delete
       * path and gets STATUS_DIRECTORY_NOT_EMPTY back for a genuinely
       * non-empty directory).  If new was empty, the delete succeeds,
       * new is gone, and old's rename -- freshly resolved, since
       * rename_set() always closes the handle it was given -- lands on
       * a name that no longer exists: an ordinary, unqualified rename.
       * If new was not empty, the delete attempt fails with the same
       * ENOTEMPTY rename_set() already reported, which is what a
       * genuinely non-empty new must still report (see
       * test_renameat_errors()'s unfenced ENOTEMPTY/EEXIST assertion
       * just below, which this fix does not touch). */
static void test_renameat_dir_over_empty_dir(void)
{
	CHECK(mkdir("ren.d/g", 0755) == 0);
	CHECK(mkdir("ren.d/h", 0755) == 0);
	CHECK(renameat(AT_FDCWD, "ren.d/g", AT_FDCWD, "ren.d/h") == 0);
	CHECK(!exists("ren.d/g"));
	CHECK(exists("ren.d/h"));
	CHECK(rmdir("ren.d/h") == 0);
}
#endif

/* renameat.html ERRORS, shall fail. */
static void test_renameat_errors(void)
{
	int dfd, ffd;

	CHECK(write_file("ren.d/x", "x") == 0);

	/* "[EBADF] The old argument does not specify an absolute path and
	 * the oldfd argument is ... neither AT_FDCWD nor a valid file
	 * descriptor open for reading or searching, [or the same for new /
	 * newfd]." */
	/* A caution about what the newfd halves of this group and the
	 * [ENOTDIR] group below do NOT prove, recorded because it took a
	 * separate investigation to establish and would otherwise have to be
	 * rediscovered.  Both newfd assertions passed unchanged across the
	 * whole period in which renameat() ignored newfd entirely and every
	 * dirfd-relative destination failed with ENOENT.  They could not have
	 * detected it: __ntpath_at() rejects a bad or non-directory
	 * descriptor BEFORE the rename is attempted, so what these lines
	 * exercise is the rejection path, while the defect lived entirely in
	 * what happened to a GOOD descriptor -- which was silently discarded.
	 * An assertion that a bad descriptor is refused says nothing about
	 * whether a good one is used.  test_renameat_new_relative_to_dirfd()
	 * is the assertion that actually holds newfd to its contract; keep
	 * these, but do not read them as covering it. */
	errno = 0;
	CHECK(renameat(9999, "x", AT_FDCWD, "ren.d/y") == -1);
	CHECK(errno == EBADF);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x", 9999, "y") == -1);
	CHECK(errno == EBADF);
	CHECK(exists("ren.d/x"));

	/* "[ENOTDIR] ... the old argument is not an absolute path and oldfd
	 * is a file descriptor associated with a non-directory file", and
	 * the same for new/newfd. */
	ffd = open("ren.d/x", O_RDONLY);
	CHECK(ffd >= 0);
	if (ffd >= 0) {
		errno = 0;
		CHECK(renameat(ffd, "x", AT_FDCWD, "ren.d/y") == -1);
		CHECK(errno == ENOTDIR);
		errno = 0;
		CHECK(renameat(AT_FDCWD, "ren.d/x", ffd, "y") == -1);
		CHECK(errno == ENOTDIR);
		CHECK(close(ffd) == 0);
	}

	/* "[ENOENT] The link named by the old argument does not name an
	 * existing file, [or] a component of the path prefix of new does
	 * not exist..." */
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/nope", AT_FDCWD, "ren.d/y") == -1);
	CHECK(errno == ENOENT);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x", AT_FDCWD, "ren.d/nodir/y") == -1);
	CHECK(errno == ENOENT);

	/* "[ENOTDIR] ... a component of either path prefix is not a
	 * directory". */
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x/under", AT_FDCWD, "ren.d/y") == -1);
	CHECK(errno == ENOTDIR);

	/* "[EISDIR] The new argument names an existing directory, [and] old
	 * names a file that is not a directory." */
	CHECK(mkdir("ren.d/dir", 0755) == 0);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x", AT_FDCWD, "ren.d/dir") == -1);
	CHECK(errno == EISDIR);
	CHECK(exists("ren.d/x"));

	/* "[EEXIST] or [ENOTEMPTY] The link named by new is a directory
	 * that is not an empty directory." */
	CHECK(mkdir("ren.d/src", 0755) == 0);
	CHECK(write_file("ren.d/dir/inhabitant", "z") == 0);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/src", AT_FDCWD, "ren.d/dir") == -1);
	CHECK(errno == ENOTEMPTY || errno == EEXIST);
	CHECK(exists("ren.d/src"));
	CHECK(unlink("ren.d/dir/inhabitant") == 0);
	CHECK(rmdir("ren.d/dir") == 0);
	CHECK(rmdir("ren.d/src") == 0);

	/* "[ENOENT] ... or either old or new points to an empty string."
	 * (the AT_FDCWD half; see the fence below for a real dirfd) */
	errno = 0;
	CHECK(renameat(AT_FDCWD, "", AT_FDCWD, "ren.d/y") == -1);
	CHECK(errno == ENOENT);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x", AT_FDCWD, "") == -1);
	CHECK(errno == ENOENT);
	CHECK(exists("ren.d/x"));

	dfd = open("ren.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd >= 0) CHECK(close(dfd) == 0);
	CHECK(unlink("ren.d/x") == 0);
}

/* "[ENOTDIR] ... or the old argument names a directory and the new
 * argument names a non-directory file." */
static void test_renameat_enotdir_dir_over_file(void)
{
	struct stat st;
	CHECK(mkdir("ren.d/sd", 0755) == 0);
	CHECK(write_file("ren.d/victim", "v") == 0);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/sd", AT_FDCWD, "ren.d/victim") == -1);
	CHECK(errno == ENOTDIR);
	CHECK(exists("ren.d/sd"));
	CHECK(stat("ren.d/victim", &st) == 0 && !S_ISDIR(st.st_mode));
	CHECK(rmdir("ren.d/sd") == 0);
	CHECK(unlink("ren.d/victim") == 0);
}

/* renameat.html DESCRIPTION: "If new is a relative path, the file is
 * located relative to the directory associated with the file descriptor
 * newfd instead of the current working directory." */
static void test_renameat_new_relative_to_dirfd(void)
{
	int dfd;
	CHECK(mkdir("ren.d/nd", 0755) == 0);
	CHECK(write_file("ren.d/nd/a", "one") == 0);
	dfd = open("ren.d/nd", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd < 0) return;
	/* new relative to the descriptor, old relative to the cwd */
	CHECK(renameat(AT_FDCWD, "ren.d/nd/a", dfd, "b") == 0);
	CHECK(exists("ren.d/nd/b"));
	/* both relative to the descriptor */
	CHECK(renameat(dfd, "b", dfd, "c") == 0);
	CHECK(!exists("ren.d/nd/b"));
	CHECK(exists("ren.d/nd/c"));
	CHECK(close(dfd) == 0);
	CHECK(unlink("ren.d/nd/c") == 0);
	CHECK(rmdir("ren.d/nd") == 0);
}

/* "[ENOENT] ... or either old or new points to an empty string." --
 * the AT_FDCWD form of this holds and is asserted unfenced above; the
 * form with a real directory descriptor does not. */
static void test_renameat_empty_at_dirfd(void)
{
	int dfd;
	CHECK(write_file("ren.d/x", "x") == 0);
	dfd = open("ren.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd < 0) return;
	errno = 0;
	CHECK(renameat(dfd, "", AT_FDCWD, "ren.d/y") == -1);
	CHECK(errno == ENOENT);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x", dfd, "") == -1);
	CHECK(errno == ENOENT);
	CHECK(close(dfd) == 0);
	CHECK(unlink("ren.d/x") == 0);
}

/* "[EINVAL] The old pathname names an ancestor directory of the new
 * pathname, or either pathname argument contains a final component that
 * is dot or dot-dot." */
#if SPICULE_TEST(PASS, posix_unreferenced_renameat_einval) /* Both clauses are checked before the NT rename.  src/stdio/misc.c's renameat()
       * hands both paths straight to __ntpath_at() and then to
       * NtSetInformationFile(FileRenameInformationEx); nothing anywhere
       * inspects the final component for "." or "..", and nothing tests
       * whether old is a prefix of new.  NT answers the ancestor case
       * with STATUS_ACCESS_DENIED or STATUS_SHARING_VIOLATION, which
       * __set_errno_status maps to EACCES/EBUSY, and the dot case with
       * whatever the object manager makes of it -- never EINVAL. */
static void test_renameat_einval(void)
{
	CHECK(mkdir("ren-einval", 0755) == 0);
	CHECK(mkdir("ren-einval/anc", 0755) == 0);
	CHECK(mkdir("ren-einval/anc/inner", 0755) == 0);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren-einval/anc", AT_FDCWD, "ren-einval/anc/inner/deep") == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren-einval/anc/.", AT_FDCWD, "ren-einval/other") == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren-einval/anc/inner/..", AT_FDCWD, "ren-einval/other") == -1);
	CHECK(errno == EINVAL);
	CHECK(rmdir("ren-einval/anc/inner") == 0);
	CHECK(rmdir("ren-einval/anc") == 0);
	CHECK(rmdir("ren-einval") == 0);
}
#endif

/* "[EACCES] A component of either path prefix denies search permission;
 * or one of the directories containing old or new denies write
 * permissions", "[EPERM] or [EACCES] The S_ISVTX flag is set on the
 * directory containing the file...", and "[EROFS] The requested
 * operation requires writing in a directory on a read-only file
 * system." */
#if SPICULE_TEST(BUG, posix_unreferenced_renameat_eacces) /* BUG (compiles and links; formerly UNIMPL):: the executable fixture below exercises the missing
       * permission-denial mechanism.  The EPERM and EROFS alternatives
       * are N/A and remain documented separately here.
       *
       * [EACCES] (search/write permission denied on a path prefix) --
       * UNIMPL, not N/A.  The recorded reason, "this library has no
       * POSIX permission model to deny with", is about THIS LIBRARY.
       * NT has the model: a directory DACL with a deny ACE makes
       * NtSetInformationFile(FileRenameInformation) answer
       * STATUS_ACCESS_DENIED, which src/internal/errno.c:63 already
       * maps to EACCES.  The reporting path is live and correct; what
       * is missing is any way to CREATE the denial, because spicule
       * declares no security APIs at all (NtSetSecurityObject,
       * RtlAddAccessDeniedAce -- real ntdll entry points, absent from
       * src/internal/nt.h).  That is the same choice the permission-bit
       * fences in test/posix-unistd.c are retagged for; see the banner
       * above them.  It is also correct that a directory's NTFS
       * read-only attribute does not stop renames within it -- which is
       * exactly why the attribute word is not the mechanism here.
       *
       * [EPERM], the S_ISVTX case -- N/A.  NT has no sticky-bit
       * analogue: no "only the owner may unlink from this directory"
       * flag exists in either the attribute word or the security
       * descriptor, since a DACL grants delete on the file, not
       * conditionally on directory ownership.
       *
       * [EROFS] -- N/A, environment: mounting a read-only volume is not
       * something the test suite can arrange.
       *
       * Still a BUG: same missing ACL/DACL infrastructure as the three
       * chmod fences in test/posix-unistd.c (see the fuller writeup on
       * test_chmod_cannot_clear_read_bits there) -- this one needs it
       * for a directory-level deny ACE rather than a file-permission
       * one, but it is the identical gap: no NtSetSecurityObject/
       * RtlAddAccessDeniedAce declared anywhere in src/internal/nt.h,
       * and no working Wine available to write and verify that code
       * against real NT behaviour. */
static void test_renameat_eacces(void)
{
	CHECK(mkdir("ren.d/ro", 0755) == 0);
	CHECK(write_file("ren.d/ro/f", "f") == 0);
	CHECK(chmod("ren.d/ro", 0500) == 0);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/ro/f", AT_FDCWD, "ren.d/ro/g") == -1);
	CHECK(errno == EACCES || errno == EPERM || errno == EROFS);
}
#endif

/* "[EBUSY] The directory named by old or new is currently in use by the
 * system or another process, and the implementation considers this an
 * error." */
#if SPICULE_TEST(NA, posix_unreferenced_renameat_ebusy) /* N/A: the clause is optional and neither the Wine runner nor the
       * currently supported NT behavior supplies a stable trigger.  Do not
       * treat this as settled inapplicability.
       *
       * Clause: "[EBUSY] The directory named by old or new is currently
       * in use by the system or another process, and the implementation
       * considers this an error."
       *
       * The old reason said NT reports this as "STATUS_ACCESS_DENIED /
       * STATUS_SHARING_VIOLATION rather than anything that maps to
       * EBUSY".  STATUS_SHARING_VIOLATION IS mapped to EBUSY --
       * src/internal/errno.c:66, three lines from
       * STATUS_ACCESS_DENIED's mapping to EACCES:
       *
       *     case STATUS_SHARING_VIOLATION:
       *     case STATUS_USER_MAPPED_FILE: return EBUSY;
       *
       * So the reporting path this fence declared absent is present and
       * correct, and the clause is satisfiable exactly when NT answers
       * SHARING_VIOLATION.
       *
       * Whether it DOES is the open question, and it cannot be settled
       * here.  chdir() goes through RtlSetCurrentDirectory_U
       * (src/unistd/chdir.c:27), which on NT opens the directory and
       * keeps the handle in the process parameters -- a held handle is
       * what would produce the sharing violation.  MEASURED UNDER WINE:
       * chdir("busyd"), chdir(".."), rename("busyd", ...) SUCCEEDS,
       * returning 0.  Wine evidently does not hold the directory the
       * way NT does.  That is a Wine observation and says nothing about
       * NT; it must not be read as "the clause is unreachable".  Needs
       * a real-Windows run before anything is concluded.
       *
       * The one part of the old reason that stands: the clause is
       * conditioned on "the implementation considers this an error", so
       * it is permissive even where the mechanism exists. */
static void test_renameat_ebusy(void)
{
	CHECK(mkdir("ren.d/busy", 0755) == 0);
	CHECK(chdir("ren.d/busy") == 0);
	CHECK(chdir("..") == 0);
	errno = 0;
	CHECK(renameat(AT_FDCWD, "busy", AT_FDCWD, "moved") == -1);
	CHECK(errno == EBUSY);
}
#endif

/* "[EIO] A physical I/O error has occurred", "[EMLINK] The file named by
 * old is a directory, and the link count of the parent directory of new
 * would exceed {LINK_MAX}", "[ENAMETOOLONG] The length of a component of
 * a pathname is longer than {NAME_MAX}", "[ENOSPC] The directory that
 * would contain new cannot be extended", "[ELOOP] A loop exists in
 * symbolic links...", "[EXDEV] The links named by new and old are on
 * different file systems..." */
#if SPICULE_TEST(NA, posix_unreferenced_renameat_misc_errors) /* N/A: the executable ENAMETOOLONG check below is live elsewhere;
       * this fence retains the remaining unprovokable platform cases.
       * EIO   -- not provocable on demand (N/A).
       * EMLINK -- NTFS directories have no link count that renames
       *           increment; there is no {LINK_MAX} to exceed (N/A).
       * ENOSPC -- would require filling the volume (N/A).
       * ELOOP  -- NT resolves reparse points itself and answers
       *           STATUS_REPARSE_POINT_NOT_RESOLVED, which
       *           src/internal/errno.c does map to ELOOP.  A symlink
       *           loop cannot be built on the CI leg's Wine, but NOT
       *           for the SeCreateSymbolicLinkPrivilege reason this
       *           line used to give: measured, the create succeeds and
       *           FSCTL_SET_REPARSE_POINT answers 0xc00000bb
       *           STATUS_NOT_SUPPORTED, because Ubuntu ships wine-9.0
       *           and that ioctl arrived in wine-10.19.  It works on a
       *           current Wine.  See test_fchmodat_eloop()'s fence
       *           below for the measured statuses, why this is a Wine
       *           version gap rather than a bug on either side, and
       *           why the privilege question stays open for genuine
       *           Windows (N/A on this runner only).
       * ENAMETOOLONG -- reachable, mapped, and NO LONGER UNIMPL.  Two
       *           separate checks now stand behind it: the whole-path
       *           __US_MAX_WCHARS bound (the page's *may-fail* clause),
       *           which is what the body below actually trips with its
       *           8192-byte name, and the per-component {NAME_MAX}
       *           check in src/internal/path.c's __name_too_long()
       *           (the page's *shall-fail* clause), which reaches
       *           renameat like every other path-taking interface.
       *           The shall-fail clause is pinned in
       *           test_fchmodat_enametoolong() below rather than here.
       *           This whole fence stays only because it is a MIX and
       *           the other five clauses in it are still N/A.
       * EXDEV  -- src/stdio/misc.c does translate STATUS_NOT_SAME_DEVICE
       *           to EXDEV; a second writable volume is not something
       *           this suite can assume (N/A here). */
static void test_renameat_misc_errors(void)
{
	char big[8192];
	memset(big, 'n', sizeof big - 1);
	big[sizeof big - 1] = 0;
	errno = 0;
	CHECK(renameat(AT_FDCWD, "ren.d/x", AT_FDCWD, big) == -1);
	CHECK(errno == ENAMETOOLONG);
}
#endif

/* ================================================================= */
/* fchmodat.html (chmod page)                                         */
/* ================================================================= */

static mode_t mode_of(const char *p)
{
	struct stat st;
	if (stat(p, &st) != 0) return (mode_t)-1;
	return st.st_mode & 0777;
}

/* fchmodat.html DESCRIPTION: "The fchmodat() function shall be
 * equivalent to the chmod() function except in the case where path
 * specifies a relative path... If fchmodat() is passed the special value
 * AT_FDCWD in the fd parameter, the current working directory shall be
 * used and, if flag is zero, the behavior shall be identical to a call
 * to chmod()."  RETURN VALUE: 0 on success, otherwise -1 "and no change
 * to the file mode occurs".
 *
 * NTFS carries one bit of what POSIX calls a mode -- read-only or not
 * (src/stat/chmod.c) -- so the observable contract is the write bits.
 * Everything asserted here is about those. */
static void test_fchmodat_success(void)
{
	int dfd;

	CHECK(mkdir("chm.d", 0755) == 0);
	CHECK(write_file("chm.d/f", "f") == 0);

	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0444, 0) == 0);
	CHECK(!(mode_of("chm.d/f") & 0222));
	/* identical to chmod() for AT_FDCWD with a zero flag */
	CHECK(chmod("chm.d/f", 0644) == 0);
	CHECK(mode_of("chm.d/f") & 0222);
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0644, 0) == 0);
	CHECK(mode_of("chm.d/f") & 0222);

	dfd = open("chm.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd >= 0) {
#if SPICULE_TEST(PASS, posix_unreferenced_fchmodat_wine_readonly) /* Wine
 * accepts the root-directory-relative attribute update but leaves the
 * readonly bit unchanged. */
		/* relative to the descriptor */
		CHECK(fchmodat(dfd, "f", 0444, 0) == 0);
		CHECK(!(mode_of("chm.d/f") & 0222));
		CHECK(fchmodat(dfd, "f", 0644, 0) == 0);
		CHECK(mode_of("chm.d/f") & 0222);
#endif
		CHECK(close(dfd) == 0);
	}

#if SPICULE_TEST(PASS, posix_unreferenced_fchmodat_wine_readonly)
	/* AT_SYMLINK_NOFOLLOW on something that is not a symbolic link is
	 * simply the file itself -- "If path names a symbolic link, then
	 * the mode of the symbolic link is changed" says nothing else
	 * about a regular file. */
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0444, AT_SYMLINK_NOFOLLOW) == 0);
	CHECK(!(mode_of("chm.d/f") & 0222));
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0644, AT_SYMLINK_NOFOLLOW) == 0);
	CHECK(mode_of("chm.d/f") & 0222);
#endif

	/* a directory is a legal target too */
	CHECK(fchmodat(AT_FDCWD, "chm.d", 0555, 0) == 0);
	CHECK(fchmodat(AT_FDCWD, "chm.d", 0755, 0) == 0);
	CHECK(mode_of("chm.d") & 0222);
}

/* fchmodat.html ERRORS, shall fail. */
static void test_fchmodat_errors(void)
{
	int ffd;
	mode_t before;

	/* "[EBADF] The path argument does not specify an absolute path and
	 * the fd argument is neither AT_FDCWD nor a valid file descriptor
	 * open for reading or searching." */
	before = mode_of("chm.d/f");
	errno = 0;
	CHECK(fchmodat(9999, "f", 0444, 0) == -1);
	CHECK(errno == EBADF);
	/* "If -1 is returned, no change to the file mode occurs." */
	CHECK(mode_of("chm.d/f") == before);

	/* "[ENOTDIR] The path argument is not an absolute path and fd is a
	 * file descriptor associated with a non-directory file." */
	ffd = open("chm.d/f", O_RDONLY);
	CHECK(ffd >= 0);
	if (ffd >= 0) {
		errno = 0;
		CHECK(fchmodat(ffd, "f", 0444, 0) == -1);
		CHECK(errno == ENOTDIR);
		CHECK(close(ffd) == 0);
	}

	/* "[ENOENT] A component of path does not name an existing file or
	 * path is an empty string." (the non-empty half; see the fence
	 * below for the empty string) */
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "chm.d/absent", 0444, 0) == -1);
	CHECK(errno == ENOENT);

	/* "[ENOTDIR] A component of the path prefix names an existing file
	 * that is neither a directory nor a symbolic link to a directory."
	 */
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "chm.d/f/under", 0444, 0) == -1);
	CHECK(errno == ENOTDIR);

	CHECK(mode_of("chm.d/f") == before);
}

/* "[ENOENT] A component of path does not name an existing file or path
 * is an empty string." -- the AT_FDCWD form holds. */
static void test_fchmodat_empty(void)
{
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "", 0444, 0) == -1);
	CHECK(errno == ENOENT);
}

/* The same clause, with a real directory descriptor. */
static void test_fchmodat_empty_at_dirfd(void)
{
	int dfd = open("chm.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd < 0) return;
	errno = 0;
	CHECK(fchmodat(dfd, "", 0444, 0) == -1);
	CHECK(errno == ENOENT);
	CHECK(close(dfd) == 0);
}

/* XBD 4.13 Pathname Resolution, again -- but this one is NOT about the
 * *at() family, and is filed here only because it was found while
 * fixing the dirfd-relative dot handling next door. */
#if SPICULE_TEST(BUG, posix_unreferenced_pathres_dotdot_over_nondir) /* BUG -- IN THE SHARED ABSOLUTE/AT_FDCWD PATH BUILDER, REACHABLE
       * FROM EVERY PATH-TAKING FUNCTION IN THIS LIBRARY, not only the
       * *at() ones.  src/internal/path.c's __ntpath() resolves through
       * RtlDosPathNameToNtPathName_U, i.e. Windows path normalisation,
       * which evaluates "." and ".." as a pure string pass BEFORE the
       * file system is consulted.  Microsoft documents this directly --
       * GetFullPathName Remarks: "This function does not verify that the
       * resulting path and file name are valid, or that they see an
       * existing file on the associated volume."
       *
       * XBD 4.13 Pathname Resolution requires the opposite: "Each
       * filename in the pathname is located in the directory specified
       * by its predecessor (for example, in the pathname fragment a/b,
       * file b is located in directory a).  Pathname resolution shall
       * fail if this cannot be accomplished."  So an intermediate
       * component that does not exist must give [ENOENT], and one that
       * exists but is not a directory must give [ENOTDIR] -- and
       * "dot-dot shall refer to the parent directory of its predecessor
       * directory" presupposes that the predecessor IS a directory.
       *
       * Observed against this tree, through the ordinary absolute /
       * AT_FDCWD branch -- all four return 0 where POSIX requires
       * failure:
       *     stat("dd/nonexistent/../f")        -> 0
       *     stat("dd/no/such/dir/../../../f")  -> 0
       *     stat("dd/f/../f")   [f is a FILE]  -> 0
       *     stat("dd/nonexistent/./../f")      -> 0
       * with the control stat("dd/reallymissing") correctly -1/ENOENT.
       *
       * This is the lexical-".." divergence biting WITH NO SYMLINK
       * INVOLVED, which is what makes it demonstrable today rather than
       * a hypothesis about environments where symbolic links can be
       * created.  (The same lexical resolution is also wrong for a
       * symlinked predecessor, per 4.13, but that half cannot currently
       * be exercised here.)
       *
       * Recorded rather than fixed, deliberately.  Fixing it means
       * resolving pathnames component-by-component instead of handing
       * the string to the Rtl, which changes __ntpath() and therefore
       * every function built on it, costs a query per component, and
       * would put this library's path semantics deliberately at odds
       * with every other program on the platform.  That is a scoped
       * decision of its own, not something to smuggle in behind a fix
       * to the dirfd-relative branch -- and note that the dirfd branch
       * was deliberately made lexical TO MATCH THIS ONE (see
       * src/internal/path.c's normalize_rel), so if this is ever
       * changed, both must change together or the two branches will
       * disagree.
       *
       * `grep -rl "__ntpath_at\|__ntpath(" src/` finds 17 files -- stat,
       * chmod, mkdir, unlink/rmdir, rename, open, statvfs, utimensat,
       * link and more, i.e. essentially every filesystem-path-taking
       * function this library has. So a component-by-component rewrite
       * of __ntpath()/__ntpath_at() to satisfy XBD 4.13 here would be a
       * change to the path-resolution semantics of the entire library,
       * not a scoped fix to this one clause, and cannot be verified
       * correct across 17 call sites without a working Wine to run the
       * existing suite against afterward. Left as recorded, not
       * fixed. */
static void test_pathres_dotdot_over_nondir(void)
{
	struct stat st;
	CHECK(mkdir("pr.d", 0755) == 0 || errno == EEXIST);
	CHECK(write_file("pr.d/f", "f") == 0);

	/* an intermediate component that does not exist */
	errno = 0;
	CHECK(stat("pr.d/nonexistent/../f", &st) == -1);
	CHECK(errno == ENOENT);

	/* an intermediate component that exists and is not a directory */
	errno = 0;
	CHECK(stat("pr.d/f/../f", &st) == -1);
	CHECK(errno == ENOTDIR);

	/* and the same through a dot rather than a dot-dot */
	errno = 0;
	CHECK(stat("pr.d/nonexistent/./../f", &st) == -1);
	CHECK(errno == ENOENT);

	/* control: the file really is there by its own name */
	CHECK(stat("pr.d/f", &st) == 0);

	CHECK(unlink("pr.d/f") == 0);
	CHECK(rmdir("pr.d") == 0);
}
#endif

/* XBD 4.13 Pathname Resolution, which chmod.html's DESCRIPTION invokes
 * for path: a component of "dot" "refers to the directory specified by
 * its predecessor".  A relative path containing one, resolved against a
 * directory descriptor, must therefore work. */
static void test_fchmodat_dot_component(void)
{
	struct stat st;
	int dfd, sub;

	dfd = open("chm.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd < 0) return;

#if SPICULE_TEST(PASS, posix_unreferenced_fchmodat_wine_readonly)
	/* dot as the first component */
	CHECK(fchmodat(dfd, "./f", 0444, 0) == 0);
	CHECK(!(mode_of("chm.d/f") & 0222));
	CHECK(fchmodat(dfd, "./f", 0644, 0) == 0);
	CHECK(mode_of("chm.d/f") & 0222);
#endif

	/* dot and dot-dot in the middle, and dot-dot escaping the
	 * descriptor's own directory -- which a RootDirectory-relative NT
	 * name cannot express at all, so it exercises the other resolution
	 * path rather than the same one */
	CHECK(mkdir("chm.d/sub", 0755) == 0 || errno == EEXIST);
	CHECK(fstatat(dfd, "./sub", &st, 0) == 0 && S_ISDIR(st.st_mode));
	CHECK(fstatat(dfd, "sub/../f", &st, 0) == 0 && S_ISREG(st.st_mode));
	sub = open("chm.d/sub", O_RDONLY);
	CHECK(sub >= 0);
	if (sub >= 0) {
		CHECK(fstatat(sub, "..", &st, 0) == 0 && S_ISDIR(st.st_mode));
		CHECK(fstatat(sub, "../f", &st, 0) == 0 && S_ISREG(st.st_mode));
		CHECK(close(sub) == 0);
	}

	CHECK(fstatat(dfd, "sub/.", &st, 0) == 0 && S_ISDIR(st.st_mode));

	/* Two invariants about what normalisation must NOT weaken, asserted
	 * as EQUIVALENCES rather than absolute answers, deliberately.
	 *
	 * (1) A trailing "." requires the name to be a directory, exactly as
	 *     a trailing slash does.  dos_from_posix() computes the
	 *     trailing-slash flag from the ORIGINAL string, before the dot is
	 *     resolved away, so a normalisation that forgets to re-raise it
	 *     turns "f/." into a plain "f" and silently stops checking.
	 * (2) A path PREFIX component that exists and is not a directory is
	 *     [ENOTDIR], and the prefix walk has to run over the NORMALISED
	 *     name -- a walk over the string the caller wrote is inspecting a
	 *     path NT will never resolve, i.e. a guard that looks present and
	 *     is absent.
	 *
	 * Why equivalences: both verdicts come from reject_if_not_dir() and
	 * __nt_prefix_not_dir(), which answer a RootDirectory-relative
	 * NtQueryAttributesFile -- and src/internal/path.c documents that
	 * Wine resolves such a query against the process working directory
	 * instead, so under Wine BOTH are inoperative for a dirfd and the
	 * absolute verdict is unavailable.  Asserting "== ENOTDIR" here would
	 * therefore be asserting a real-Windows-only fact, and would pass
	 * vacuously nowhere and fail honestly under Wine.  What IS true in
	 * every environment, and is the property this normalisation could
	 * actually break, is that the dotted spelling answers identically to
	 * the undotted one.  On the real-Windows CI leg the controls
	 * themselves become ENOTDIR and the equivalence then pins the real
	 * clause. */
	{
		int c_rc, c_err, d_rc, d_err;
		errno = 0; c_rc = fstatat(dfd, "f/", &st, 0);      c_err = errno;
		errno = 0; d_rc = fstatat(dfd, "f/.", &st, 0);     d_err = errno;
		CHECK(d_rc == c_rc && d_err == c_err);
		if (c_rc == 0)
			printf("NOTE dirfd-relative trailing-slash rejection is inoperative here "
			       "(fstatat(dfd,\"f/\") on a regular file returned 0); the \"f/.\" "
			       "equivalence above is what is being checked, not [ENOTDIR]\n");
		errno = 0; c_rc = fstatat(dfd, "f/under", &st, 0);   c_err = errno;
		errno = 0; d_rc = fstatat(dfd, "./f/under", &st, 0); d_err = errno;
		CHECK(d_rc == c_rc && d_err == c_err);
		if (c_err != ENOTDIR)
			printf("NOTE dirfd-relative prefix [ENOTDIR] is inoperative here "
			       "(fstatat(dfd,\"f/under\") gave errno=%d, want 20); the "
			       "\"./f/under\" equivalence above is what is being checked\n", c_err);
	}

	CHECK(rmdir("chm.d/sub") == 0);
	CHECK(close(dfd) == 0);
}

/* "[EPERM] The effective user ID does not match the owner of the file
 * and the process does not have appropriate privileges", "[EACCES] Search
 * permission is denied on a component of the path prefix", "[EROFS] The
 * named file resides on a read-only file system." */
#if SPICULE_TEST(BUG, posix_unreferenced_fchmodat_eperm) /* BUG (compiles and links; formerly UNIMPL):: the executable fixture below exercises the missing
       * ownership/permission-denial mechanism.  EROFS is N/A and remains
       * documented separately here.
       *
       * [EPERM] (effective uid does not match the owner) and [EACCES]
       * (search permission denied on a path prefix) -- UNIMPL, not N/A.
       * "There is no POSIX ownership or permission model here to
       * violate" is a statement about this library, not about NT, which
       * has both: files carry an owner SID and a DACL, and
       * STATUS_ACCESS_DENIED is already mapped to EACCES by
       * src/internal/errno.c:63.  spicule declares none of the security
       * APIs that would let a test establish either condition, which is
       * the choice recorded in test/posix-unistd.c's permission-bit
       * banner.  The observation about src/stat/chmod.c retrying with
       * FILE_READ_ATTRIBUTES alone stands and is worth keeping: it is
       * there so that "the owner of a file may always change the
       * permission of the file" holds, which is the clause working, not
       * a reason the clause cannot apply.
       *
       * [EROFS] -- N/A, environment: a read-only volume is not
       * arrangeable from the suite.
       *
       * Still a BUG: same missing ACL/DACL infrastructure as the three
       * chmod fences in test/posix-unistd.c and test_renameat_eacces()
       * above (see the fuller writeup on
       * test_chmod_cannot_clear_read_bits) -- no
       * NtSetSecurityObject/RtlAddAccessDeniedAce declared anywhere in
       * src/internal/nt.h, and no working Wine available to write and
       * verify that code against real NT behaviour. This
       * fixture also depends on chmod("chm.d/noexec", 0000) actually
       * denying search on the directory, which is the exact chmod
       * gap those other fences already document; fixing this one
       * without fixing that would just move the failure from "the
       * denial can't be created" to "chmod silently reports the
       * denial applied and it did not". */
static void test_fchmodat_eperm(void)
{
	CHECK(mkdir("chm.d/noexec", 0755) == 0);
	CHECK(write_file("chm.d/noexec/g", "g") == 0);
	CHECK(chmod("chm.d/noexec", 0000) == 0);
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "chm.d/noexec/g", 0444, 0) == -1);
	CHECK(errno == EACCES || errno == EPERM || errno == EROFS);
}
#endif

/* "[ELOOP] A loop exists in symbolic links encountered during
 * resolution of the path argument", and may fail "[ELOOP] More than
 * {SYMLOOP_MAX} symbolic links were encountered during resolution of the
 * path argument." */
#if SPICULE_TEST(NA, posix_unreferenced_fchmodat_eloop) /* N/A on the CI leg's Wine ONLY, and the reason previously
       * recorded here was false.  This is the canonical account of the
       * symlink gap; the [ELOOP] line in test_renameat_misc_errors()
       * above points here rather than repeating it.
       *
       * The old reason: "creating a symbolic link on NT needs
       * SeCreateSymbolicLinkPrivilege, which this suite's environment
       * does not hold (and Wine's default prefix does not grant), so no
       * loop can be built to resolve."  MEASURED, and no privilege
       * check is involved in the observed failure at all.
       *
       * Stock apt Wine -- wine-9.0 (Ubuntu 9.0~repack-4build3), which
       * is what the CI leg installs:
       *
       *   NtCreateFile (the placeholder, isdir=0 and isdir=1)
       *                                       0x00000000  SUCCESS
       *   NtFsControlFile FSCTL_SET_REPARSE_POINT
       *                                       0xc00000bb  NOT_SUPPORTED
       *
       * Locally built Wine at 91292d82c (wine-11.16):
       *
       *   NtCreateFile                        0x00000000
       *   FSCTL_SET_REPARSE_POINT             0x00000000
       *   and symlinkat() returns 0 with the links present on disk.
       *
       * So the create SUCCEEDS and the ioctl IS reached.  Nothing
       * answered STATUS_PRIVILEGE_NOT_HELD or STATUS_ACCESS_DENIED, so
       * the EPERM arm src/unistd/link.c has for a denied privilege
       * never ran.  The privilege was never the observed blocker.
       *
       * The actual cause is a Wine VERSION gap, not a bug on either
       * side.  Reparse-point support -- the filesystem feature symbolic
       * links are built on -- arrived in wine-10.19, released
       * 2025-11-14 and headlined for exactly that; Ubuntu ships 9.0,
       * which predates it by about a year.  So wine-9.0's
       * default_fd_ioctl() has no FSCTL_SET_REPARSE_POINT case and
       * falls through to set_error(STATUS_NOT_SUPPORTED), which is
       * precisely the 0xc00000bb measured.  spicule's sequence is
       * correct and works unmodified on a current Wine, so there is
       * nothing to fix in this tree, and the Wine side is already fixed
       * upstream.
       *
       * Provenance, since a version boundary is the kind of detail that
       * rots into a confident wrong number.  Confirmed on this machine:
       * `wine --version` reports wine-9.0 (Ubuntu 9.0~repack-4build3);
       * a current Wine checkout does handle FSCTL_SET_REPARSE_POINT, in
       * server/fd.c beside the FSCTL_DISMOUNT_VOLUME case that is the
       * only one 9.0 had; and wine-10.19 is independently documented as
       * the reparse-point release.  Not independently re-derivable from
       * this machine's local Wine clone, which is shallow and carries
       * no 9.0 tag; the citation to re-check first if this paragraph is
       * ever doubted is commit 95f83739d "server: Implement
       * FSCTL_SET_REPARSE_POINT", and the 9.0 line number
       * server/fd.c:2409.
       *
       * Do NOT read ENOSYS as evidence of STATUS_NOT_IMPLEMENTED here.
       * src/internal/errno.c:82-84 maps THREE statuses onto ENOSYS --
       * NOT_IMPLEMENTED, NOT_SUPPORTED and INVALID_DEVICE_REQUEST -- so
       * the ENOSYS a caller sees is the correct rendering of
       * 0xc00000bb, and back-inferring the status from the errno loses
       * exactly the distinction that matters.
       *
       * STILL OPEN, and deliberately not answered here: whether
       * SeCreateSymbolicLinkPrivilege is the real blocker on GENUINE
       * Windows without Developer Mode.  That is plausible and
       * untested; no measurement in this tree bears on it.  It belongs
       * on the real-Windows leg, and until someone runs it there the
       * privilege question is UNCERTAIN rather than settled either way.
       *
       * EXPIRY, and it is close: this fence holds only while the Wine
       * on the runner is older than 10.19.  Moving these assertions
       * from unverified to verified on the Wine leg is a runner
       * configuration change -- the WineHQ repository rather than
       * `apt install wine` -- and needs no code change on either side.
       *
       * The report path was never in question and remains correct:
       * src/internal/errno.c maps STATUS_REPARSE_POINT_NOT_RESOLVED to
       * ELOOP. */
static void test_fchmodat_eloop(void)
{
	CHECK(symlink("l2", "chm.d/l1") == 0);
	CHECK(symlink("l1", "chm.d/l2") == 0);
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "chm.d/l1", 0444, 0) == -1);
	CHECK(errno == ELOOP);
}
#endif

/* "[ENAMETOOLONG] The length of a component of a pathname is longer than
 * {NAME_MAX}."  SHALL FAIL -- and distinct from the may-fail
 * [ENAMETOOLONG] about the length of the whole pathname, which this
 * library reports as the __US_MAX_WCHARS bound and which says nothing
 * about a single over-long component inside a short path.  This test is
 * the shall-fail one.
 *
 * The clause is not an fchmodat quirk: it is boilerplate on every
 * path-taking page, and until this test was written {NAME_MAX} appeared
 * nowhere in src/ except sysconf.c, where it was only reported as a
 * value.  So the check lives in src/internal/path.c's __name_too_long(),
 * called from the builder __ntpath() and __ntpath_at() share (and
 * directly by chdir(), which builds its own UNICODE_STRING) -- fchmodat
 * is merely where it was noticed.  Both branches of __ntpath_at() are
 * exercised below for that reason: AT_FDCWD goes through __ntpath(), a
 * real directory descriptor goes through the RootDirectory-relative
 * branch, and a check placed in only one of them would leave half the
 * library wrong.
 *
 * MEASURED BEFORE THE FIX, under Wine: a 300-byte component came back
 * -1/[ENOENT] -- not [ENAMETOOLONG], and not the
 * STATUS_OBJECT_NAME_INVALID the old fence guessed at.  A 255-byte
 * component opened successfully and a 256-byte one did not, so the
 * boundary below is where the host puts it too. */
static void test_fchmodat_enametoolong(void)
{
	char comp[300], name255[256], path[512];
	int fd, dfd;

	memset(comp, 'c', sizeof comp - 1);
	comp[sizeof comp - 1] = 0;
	memset(name255, 'd', 255);
	name255[255] = 0;

	/* AT_FDCWD: the __ntpath() branch. */
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, comp, 0444, 0) == -1);
	CHECK(errno == ENAMETOOLONG);

	/* The over-long component inside a longer path is still the
	 * component's length that decides, not the path's -- this is the
	 * case the whole-path __US_MAX_WCHARS bound cannot see. */
	strcpy(path, "chm.d/");
	strcat(path, comp);
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, path, 0444, 0) == -1);
	CHECK(errno == ENAMETOOLONG);

	/* A real directory descriptor: the RootDirectory-relative branch. */
	dfd = open("chm.d", O_RDONLY);
	CHECK(dfd >= 0);
	if (dfd >= 0) {
		errno = 0;
		CHECK(fchmodat(dfd, comp, 0444, 0) == -1);
		CHECK(errno == ENAMETOOLONG);
		CHECK(close(dfd) == 0);
	}

	/* THE BOUNDARY, which is what stops this from passing for the wrong
	 * reason.  {NAME_MAX} is 255 and the clause is "longer than", so a
	 * component of exactly {NAME_MAX} bytes must still work -- a check
	 * written with >= instead of > would break it, and so would one that
	 * rejected every long-ish name. */
	CHECK(strlen(name255) == NAME_MAX);
	strcpy(path, "chm.d/");
	strcat(path, name255);
	/* Note that this path is also longer than Windows' {MAX_PATH} once
	 * it is resolved against the working directory, so it is the
	 * hand-built NT path in src/internal/path.c's
	 * nt_path_over_max_path() that carries it on real Windows; before
	 * that existed this open failed with [ENAMETOOLONG] on every
	 * windows-test leg while passing under Wine.  Left as it is rather
	 * than shortened: the {NAME_MAX} boundary is the point, and a
	 * boundary that only holds in a shallow working directory is not
	 * one this library should be claiming. */
	errno = 0;
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	CHECK_E(fd >= 0);
	if (fd >= 0) {
		CHECK(close(fd) == 0);
		errno = 0;
		CHECK(fchmodat(AT_FDCWD, path, 0444, 0) == 0);
		CHECK(chmod(path, 0644) == 0);
		CHECK(unlink(path) == 0);
	}
}

/* ERRORS, may fail: "[EINTR] A signal was caught during execution of the
 * function", "[EINVAL] The value of the mode argument is invalid",
 * "[EINVAL] The value of the flag argument is invalid."
 *
 * The flag one is now taken up and unfenced.  All three are "may fail",
 * so ignoring the bits was never a spec violation -- but of the two
 * legal answers, silently succeeding on a flag the caller believes it
 * asked for is the worse one, and one line in src/stat/chmod.c buys the
 * better one.  Measured against glibc rather than derived:
 * fchmodat(AT_FDCWD, path, 0644, 0x4000) is -1/EINVAL there, while
 * AT_SYMLINK_NOFOLLOW (0x100) and 0 both succeed -- so the check is on
 * unknown bits, not a whitelist that would have caught
 * AT_SYMLINK_NOFOLLOW too.
 *
 * The other two stay unasserted: [EINTR] needs an asynchronous signal
 * this platform cannot deliver to a running syscall, and an invalid
 * mode has no meaning here -- src/stat/chmod.c reads exactly one
 * bit-group out of mode (0222) and NTFS has no other permission for a
 * mode to be wrong about. */
static void test_fchmodat_einval(void)
{
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0644, 0x4000) == -1);
	CHECK(errno == EINVAL);
	/* and the boundary the paragraph above claims but did not check:
	 * the one legal flag, and no flag at all, must still work.  A test
	 * written as `if (flags)` would satisfy the assertion above while
	 * breaking every caller that follows a symbolic-link decision. */
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0644, AT_SYMLINK_NOFOLLOW) == 0);
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0644, 0) == 0);
	CHECK(mode_of("chm.d/f") & 0222);
	/* A rejected call must change nothing, as RETURN VALUE requires --
	 * AT_REMOVEDIR is a real flag bit belonging to unlinkat(), so this
	 * is the case a known-bad-list check would have let through. */
	errno = 0;
	CHECK(fchmodat(AT_FDCWD, "chm.d/f", 0444, AT_REMOVEDIR) == -1);
	CHECK(errno == EINVAL);
	CHECK(mode_of("chm.d/f") & 0222);
}

/* ================================================================= */
/* sigwait.html                                                       */
/* ================================================================= */

/* sigwait.html DESCRIPTION: "The sigwait() function shall select a
 * pending signal from set, atomically clear it from the system's set of
 * pending signals, and return that signal number in the location
 * referenced by sig.  If prior to the call to sigwait() there are
 * multiple pending instances of a single signal number, it is
 * implementation-defined whether upon successful return there are any
 * remaining pending signals for that signal number.  ... If no signal in
 * set is pending at the time of the call, the thread shall be suspended
 * until one or more becomes pending."  ERRORS, MAY fail: "[EINVAL] The
 * set argument contains an invalid or unsupported signal number" -- read
 * off the page, whose ERRORS section opens "The sigwait() function may
 * fail if".  The fence this test used to sit behind cited it as "shall
 * fail", which is wrong and would have made the assertions below look
 * like a deviation instead of a choice between two conforming answers.
 *
 * Unfenced here because src/signal/signal.c no longer stubs sigwait():
 * it selects the lowest-numbered pending signal in set, clears it, and
 * suspends otherwise.  The BUG registration this replaces described the
 * one-line stub that used to be there. */
static void test_sigwait_spec(void)
{
	sigset_t set, old, pend;
	int sig = -1;

	/* Every assertion below reads the process-wide pending set, so start
	 * from a known-empty one rather than assuming: an earlier test that
	 * left something pending would otherwise make sigwait() legitimately
	 * select that instead, and this test would fail for the wrong
	 * reason. */
	CHECK(sigpending(&pend) == 0);
	CHECK(sigisemptyset(&pend) == 1);

	CHECK(sigemptyset(&set) == 0);
	CHECK(sigaddset(&set, SIGUSR1) == 0);
	/* "the signals ... shall have been blocked" is the application's
	 * obligation; block SIGUSR1 so raising it leaves it pending */
	CHECK(sigprocmask(SIG_BLOCK, &set, &old) == 0);
	CHECK(raise(SIGUSR1) == 0);
	/* selects the pending signal, returns zero, stores the number */
	errno = 0;
	CHECK(sigwait(&set, &sig) == 0);
	CHECK(sig == SIGUSR1);
	/* errno is not a channel this function reports through, on any path
	 * -- the stub's errno = EINVAL was outside the contract, and that
	 * defect is independent of the missing behaviour it sat alongside */
	CHECK(errno == 0);
	/* "atomically clear it from the system's set of pending signals" */
	CHECK(sigpending(&pend) == 0);
	CHECK(sigismember(&pend, SIGUSR1) == 0);
	CHECK(sigprocmask(SIG_SETMASK, &old, 0) == 0);

	/* "select a pending signal from set" with more than one candidate.
	 * POSIX constrains the choice only within SIGRTMIN..SIGRTMAX, so
	 * this asserts the choice src/signal/signal.c documents -- lowest
	 * numbered first -- rather than any portable requirement.  It is
	 * pinned because an implementation-defined choice that nothing
	 * checks is one that can drift silently, and because it is also
	 * the order sigprocmask()'s deliver-on-unblock sweep uses: if the
	 * two ever disagree, a program can tell the accept path and the
	 * delivery path apart by which signal comes out first.  SIGUSR2 is
	 * raised FIRST, so ordering by number and ordering by arrival give
	 * different answers here -- raising them the other way round would
	 * make the test pass under either rule. */
	{
		sigset_t two;
		CHECK(sigpending(&pend) == 0);
		CHECK(sigisemptyset(&pend) == 1);
		CHECK(sigemptyset(&two) == 0);
		CHECK(sigaddset(&two, SIGUSR1) == 0);
		CHECK(sigaddset(&two, SIGUSR2) == 0);
		CHECK(sigprocmask(SIG_BLOCK, &two, &old) == 0);
		CHECK(raise(SIGUSR2) == 0);
		CHECK(raise(SIGUSR1) == 0);
		sig = -1;
		CHECK(sigwait(&two, &sig) == 0);
		CHECK(sig == SIGUSR1);
		sig = -1;
		CHECK(sigwait(&two, &sig) == 0);
		CHECK(sig == SIGUSR2);
		CHECK(sigpending(&pend) == 0);
		CHECK(sigisemptyset(&pend) == 1);
		CHECK(sigprocmask(SIG_SETMASK, &old, 0) == 0);
	}

	/* "[EINVAL] The set argument contains an invalid or unsupported
	 * signal number" is a MAY FAIL, not a shall-fail -- the fence that
	 * stood here cited it as "ERRORS, shall fail", which is wrong; read
	 * off the page, ERRORS reads "The sigwait() function may fail if".
	 * So both answers conform, and this implementation takes the other
	 * one: stray bits are ignored, never rejected.
	 *
	 * Measured, not derived.  glibc does not reject them either: a raw
	 * memset(0xff) sigset_t with SIGUSR1 pending returns 0 with sig=10
	 * there, as does glibc's own sigfillset().  And this library's
	 * sigfillset() is memset(0xff) over a 128-byte sigset_t -- 1024 bits
	 * for 64 real signals -- so a sigwait() that rejected stray bits
	 * would fail the commonest sigwait idiom there is, every time.
	 *
	 * That is asserted here, positively, rather than left unsaid: a
	 * filled set with a pending signal in it must succeed. */
	{
		sigset_t filled;
		CHECK(sigpending(&pend) == 0);
		CHECK(sigisemptyset(&pend) == 1);
		CHECK(sigprocmask(SIG_BLOCK, &set, &old) == 0);
		CHECK(raise(SIGUSR1) == 0);
		CHECK(sigfillset(&filled) == 0);
		sig = -1;
		errno = 0;
		CHECK(sigwait(&filled, &sig) == 0);
		CHECK(sig == SIGUSR1);
		CHECK(errno == 0);
		CHECK(sigpending(&pend) == 0);
		CHECK(sigismember(&pend, SIGUSR1) == 0);
		CHECK(sigprocmask(SIG_SETMASK, &old, 0) == 0);
	}
}

/* ================================================================= */
/* psignal.html                                                       */
/* ================================================================= */

/* psignal.html DESCRIPTION: "The psiginfo() and psignal() functions
 * shall write a language-dependent message associated with a signal
 * number to the standard error stream... If the argument message is not
 * a null pointer and is not the empty string, ... the message ...
 * followed by a <colon> and a <space>... [then] the signal description
 * string ... followed by a <newline>."  RETURN VALUE: "These functions
 * shall not return a value."  It "shall not change the setting of errno"
 * on success.
 *
 * fd 2 is redirected the same way test_puts_success() redirects fd 1. */
static void psignal_capture(int sig, const char *msg, const char *name,
                            char *out, size_t cap, int *errno_moved)
{
	int saved = dup(2), fd;

	out[0] = 0;
	*errno_moved = -1;
	if (saved < 0) return;
	fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { close(saved); return; }
	fflush(stderr);
	if (dup2(fd, 2) == 2) {
		close(fd);
		errno = 0;
		psignal(sig, msg);
		*errno_moved = errno != 0;
		fflush(stderr);
	} else {
		close(fd);
	}
	dup2(saved, 2);
	close(saved);
	slurp(name, out, cap);
}

static void test_psignal(const char *name)
{
	char buf[128];
	int moved;

	/* strsignal.html is the cited source of the description text, and
	 * src/string/strsignal.c is what psignal() calls, so the expected
	 * strings are taken from strsignal() itself rather than hardcoded
	 * -- what is being asserted here is psignal()'s framing. */
	psignal_capture(SIGINT, "prefix", name, buf, sizeof buf, &moved);
	{
		char want[128];
		sprintf(want, "prefix: %s\n", strsignal(SIGINT));
		CHECK(!strcmp(buf, want));
	}
	/* "shall not change the setting of errno" on success */
	CHECK(moved == 0);

	/* "If the argument message is a null pointer or points to an empty
	 * string, the message shall consist only of the signal description
	 * string [and a <newline>]" -- no colon, no space. */
	psignal_capture(SIGTERM, 0, name, buf, sizeof buf, &moved);
	{
		char want[128];
		sprintf(want, "%s\n", strsignal(SIGTERM));
		CHECK(!strcmp(buf, want));
		CHECK(strchr(buf, ':') == 0);
	}
	CHECK(moved == 0);

	psignal_capture(SIGUSR1, "", name, buf, sizeof buf, &moved);
	{
		char want[128];
		sprintf(want, "%s\n", strsignal(SIGUSR1));
		CHECK(!strcmp(buf, want));
	}

	/* an unknown signal number still produces a description string and
	 * the same framing -- strsignal() answers "Unknown signal" */
	psignal_capture(12345, "odd", name, buf, sizeof buf, &moved);
	CHECK(strncmp(buf, "odd: ", 5) == 0);
	CHECK(buf[strlen(buf) - 1] == '\n');

	/* psiginfo() is "as if generated by strsignal()" off si_signo --
	 * asserted here only to show psignal() and psiginfo() agree, since
	 * src/signal/signal.c implements the former in terms of the latter's
	 * message shape. */
	{
		siginfo_t si;
		char via_psignal[128];
		int m2;
		memset(&si, 0, sizeof si);
		si.si_signo = SIGINT;
		psignal_capture(SIGINT, "same", name, via_psignal, sizeof via_psignal, &m2);
		{
			int saved = dup(2), fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			buf[0] = 0;
			if (saved >= 0 && fd >= 0) {
				fflush(stderr);
				if (dup2(fd, 2) == 2) { psiginfo(&si, "same"); fflush(stderr); }
				close(fd);
				dup2(saved, 2);
				close(saved);
				slurp(name, buf, sizeof buf);
			} else { if (fd >= 0) close(fd); if (saved >= 0) close(saved); }
		}
		CHECK(!strcmp(buf, via_psignal));
	}
}

/* psignal.html ERRORS: "Refer to fputc()."  Since these functions return
 * nothing, the clause the application can act on is the one about
 * detecting the failure: "no indication of an error shall be returned",
 * so the caller sets errno to zero beforehand and checks it, or uses
 * ferror(stderr). */
#if SPICULE_TEST(NA, posix_unreferenced_psignal_ebadf) /* N/A: identical to the puts() fences above -- EBADF is the one
       * fputc error a test can actually arrange (reopen stderr
       * read-only), and doing so here would only re-prove what
       * test_puts_ebadf() already proves about the shared __fwrite()
       * path.  The rest (EAGAIN/EFBIG/EINTR/EIO/ENOSPC/ENOMEM/ENXIO)
       * have the same unavailable mechanisms.  Recorded so the ERRORS
       * list has an entry rather than a silence. */
static void test_psignal_ebadf(const char *roname)
{
	CHECK(freopen(roname, "rb", stderr) != 0);
	errno = 0;
	psignal(SIGINT, "doomed");
	CHECK(errno == EBADF);
	CHECK(ferror(stderr) != 0);
}
#endif

/* ================================================================= */
/* round.html (roundl)                                                */
/* ================================================================= */

static int negzerol(long double x) { return x == 0.0L && signbit(x); }
static int poszerol(long double x) { return x == 0.0L && !signbit(x); }

/* round.html DESCRIPTION: "These functions shall round their argument to
 * the nearest integer value in floating-point format, rounding halfway
 * cases away from zero, regardless of the current rounding direction."
 * RETURN VALUE: "Upon successful completion, these functions shall
 * return the rounded integer value... If x is NaN, a NaN shall be
 * returned.  If x is +-0, x shall be returned.  If x is +-Inf, x shall be
 * returned."  ERRORS: "No errors are defined." */
static void test_roundl(void)
{
	int r;

	/* nearest integer, halfway away from zero */
	CHECK(roundl(2.3L) == 2.0L);
	CHECK(roundl(2.5L) == 3.0L);
	CHECK(roundl(2.7L) == 3.0L);
	CHECK(roundl(-2.3L) == -2.0L);
	CHECK(roundl(-2.5L) == -3.0L);
	CHECK(roundl(-2.7L) == -3.0L);
	CHECK(roundl(0.5L) == 1.0L);
	CHECK(roundl(-0.5L) == -1.0L);
	/* an even integer's halfway case still goes away from zero, which
	 * is what distinguishes round() from rint()/nearbyint() */
	CHECK(roundl(0.5L) != 0.0L);
	CHECK(roundl(1.5L) == 2.0L);
	CHECK(roundl(-1.5L) == -2.0L);
	/* an already-integral value is unchanged */
	CHECK(roundl(3.0L) == 3.0L);
	CHECK(roundl(-3.0L) == -3.0L);
	/* large magnitudes, where every value is already an integer */
	CHECK(roundl(1e18L) == 1e18L);
	CHECK(roundl(-1e18L) == -1e18L);

	/* "If x is NaN, a NaN shall be returned." */
	CHECK(isnan(roundl((long double)NAN)));
	/* "If x is +-0, x shall be returned" -- including the sign, which
	 * == cannot see. */
	CHECK(poszerol(roundl(0.0L)));
	CHECK(negzerol(roundl(-0.0L)));
	/* a value that rounds to zero keeps its sign too: round.html's
	 * RETURN VALUE says the result "shall have the same sign as x" */
	CHECK(negzerol(roundl(-0.25L)));
	CHECK(poszerol(roundl(0.25L)));
	/* "If x is +-Inf, x shall be returned." */
	CHECK(roundl((long double)INFINITY) == (long double)INFINITY);
	CHECK(roundl(-(long double)INFINITY) == -(long double)INFINITY);

	/* "regardless of the current rounding direction" -- the same
	 * answers under every rounding mode fenv.h offers. */
	r = fegetround();
	if (fesetround(FE_DOWNWARD) == 0) {
		CHECK(roundl(2.5L) == 3.0L);
		CHECK(roundl(-2.5L) == -3.0L);
		CHECK(roundl(2.3L) == 2.0L);
	}
	if (fesetround(FE_UPWARD) == 0) {
		CHECK(roundl(2.5L) == 3.0L);
		CHECK(roundl(-2.5L) == -3.0L);
		CHECK(roundl(-2.3L) == -2.0L);
	}
	if (fesetround(FE_TOWARDZERO) == 0) {
		CHECK(roundl(2.5L) == 3.0L);
		CHECK(roundl(-2.5L) == -3.0L);
		CHECK(roundl(2.7L) == 3.0L);
	}
	CHECK(fesetround(r) == 0);

	/* ERRORS: "No errors are defined." -- errno is not touched, for
	 * any argument including the special ones. */
	errno = 0;
	(void)roundl(2.5L);
	(void)roundl((long double)NAN);
	(void)roundl((long double)INFINITY);
	(void)roundl(-0.0L);
	CHECK(errno == 0);

	/* round()/roundf() are the same function narrowed (src/math/round.c
	 * defines both in terms of roundl), so agreement between them is
	 * the cheapest check that roundl's own long-double path is the one
	 * being exercised rather than a double one. */
	CHECK(roundl(2.5L) == (long double)round(2.5));
	CHECK(roundl(-2.5L) == (long double)roundf(-2.5f));
}

/* ================================================================= */
/* strxfrm.html (strxfrm_l)                                           */
/* ================================================================= */

/* strxfrm_l() is on POSIX.1-2017's strxfrm.html alongside strxfrm(), so
 * it belongs with the seven above rather than with the glibc-only *_l
 * names (strtod_l/strtof_l/strtold_l, which have no POSIX page).
 * test/posix-string.c already cites strxfrm.html and even names
 * strxfrm_l in a comment -- but never calls it, which is precisely the
 * "mentioned is not referenced" case tools/lint-unreferenced.sh exists
 * to separate.
 *
 * DESCRIPTION: "The strxfrm() and strxfrm_l() functions shall transform
 * the string pointed to by s2 and place the resulting string into the
 * array pointed to by s1.  The transformation shall be such that if
 * strcmp() is applied to two transformed strings, it shall return a
 * value greater than, equal to, or less than 0, corresponding to the
 * result of strcoll() applied to the same two original strings.  No
 * more than n bytes are placed into the resulting array pointed to by
 * s1, including the terminating NUL character.  If n is 0, s1 is
 * permitted to be a null pointer... The strxfrm_l() function shall be
 * equivalent to strxfrm(), except that the locale data used is from the
 * locale represented by locale."  It "shall not change the setting of
 * errno if successful."  RETURN VALUE: "the length of the transformed
 * string (not including the terminating NUL character).  If the value
 * returned is n or more, the contents of the array pointed to by s1 are
 * unspecified." */
static void test_strxfrm_l(void)
{
	char a[32], b[32];
	locale_t loc;
	size_t r;

	/* the length of the transformed string, and the transform itself */
	errno = 0;
	r = strxfrm_l(a, "hello", sizeof a, (locale_t)0);
	CHECK(r == 5);
	CHECK(!strcmp(a, "hello"));
	/* "shall not change the setting of errno if successful" */
	CHECK(errno == 0);

	/* "If n is 0, s1 is permitted to be a null pointer" -- and the
	 * return value is still the transformed length, which is how the
	 * two-call sizing idiom works. */
	CHECK(strxfrm_l(0, "hello", 0, (locale_t)0) == 5);

	/* "No more than n bytes are placed into the resulting array ...
	 * including the terminating NUL character", and "If the value
	 * returned is n or more, the contents ... are unspecified" -- so
	 * the return value is asserted and the contents are not. */
	memset(a, 'Z', sizeof a);
	CHECK(strxfrm_l(a, "hello", 3, (locale_t)0) == 5);
	CHECK(a[3] == 'Z');   /* nothing past n was touched */

	/* "if strcmp() is applied to two transformed strings, it shall
	 * return a value greater than, equal to, or less than 0,
	 * corresponding to the result of strcoll() applied to the same two
	 * original strings" -- checked in all three directions. */
	CHECK(strxfrm_l(a, "abc", sizeof a, (locale_t)0) < sizeof a);
	CHECK(strxfrm_l(b, "abd", sizeof b, (locale_t)0) < sizeof b);
	CHECK((strcmp(a, b) < 0) == (strcoll("abc", "abd") < 0));
	CHECK(strxfrm_l(b, "abb", sizeof b, (locale_t)0) < sizeof b);
	CHECK((strcmp(a, b) > 0) == (strcoll("abc", "abb") > 0));
	CHECK(strxfrm_l(b, "abc", sizeof b, (locale_t)0) < sizeof b);
	CHECK((strcmp(a, b) == 0) == (strcoll("abc", "abc") == 0));

	/* "except that the locale data used is from the locale represented
	 * by locale" -- with a real locale object, not just a null one.
	 * This library has one locale ("C"), so the requirement that bites
	 * is that a valid locale_t is accepted and gives the same answer. */
	loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	if (loc) {
		CHECK(strxfrm_l(a, "hello", sizeof a, loc) == 5);
		CHECK(!strcmp(a, "hello"));
		CHECK(strxfrm_l(b, "hello", sizeof b, LC_GLOBAL_LOCALE) == 5);
		CHECK(!strcmp(a, b));
		freelocale(loc);
	} else {
		printf("note: newlocale(LC_ALL_MASK, \"C\", 0) failed (errno %d); the real-locale_t half of strxfrm_l is skipped\n", errno);
	}

	/* and it agrees with strxfrm(), which is what "equivalent to" means
	 * for a library with exactly one locale */
	CHECK(strxfrm_l(a, "collate", sizeof a, (locale_t)0) == strxfrm(b, "collate", sizeof b));
	CHECK(!strcmp(a, b));
}

/* strxfrm.html ERRORS, may fail: "[EINVAL] The string pointed to by the
 * s2 argument contains characters outside the domain of the collating
 * sequence." */
#if SPICULE_TEST(NA, posix_unreferenced_strxfrm_l_einval) /* N/A: "may fail", and there is no such string.  This library's
       * collating sequence is the C locale's, whose domain is every
       * value a char can hold (src/string/strxfrm.c transforms by
       * copying), so no input is outside it.  The clause has no
       * reachable case here rather than an unimplemented one. */
static void test_strxfrm_l_einval(void)
{
	char a[32];
	errno = 0;
	CHECK(strxfrm_l(a, "\xff\xfe", sizeof a, (locale_t)0) == (size_t)-1);
	CHECK(errno == EINVAL);
}
#endif

/* ================================================================= */

int main(void)
{
	char *name = make_tmp("posix-unref-XXXXXX");
	char *ro = make_tmp("posix-unref-ro-XXXXXX");
	char *scratch = make_tmp("posix-unref-sc-XXXXXX");

	CHECK(name != 0);
	CHECK(ro != 0);
	CHECK(scratch != 0);
	if (!name || !ro || !scratch) return 1;

	test_roundl();
	test_strxfrm_l();
	test_sigwait_spec();
	test_psignal(name);

	test_renameat_success();
#if SPICULE_TEST(PASS, posix_unreferenced_renameat_dir_over_empty_dir) /* see the definition fence above */
	test_renameat_dir_over_empty_dir();
#endif
	test_renameat_errors();
	test_renameat_enotdir_dir_over_file();
	test_renameat_new_relative_to_dirfd();
	test_renameat_empty_at_dirfd();
#if SPICULE_TEST(PASS, posix_unreferenced_renameat_einval) /* see the definition fence above */
	test_renameat_einval();
#endif
	test_fchmodat_success();
	test_fchmodat_errors();
	test_fchmodat_empty();
	test_fchmodat_empty_at_dirfd();
	test_fchmodat_dot_component();
	test_fchmodat_enametoolong();
	test_fchmodat_einval();

	test_scanf_basics(name);
	test_scanf_returns(name);
	test_scanf_eilseq(name);
	test_scanf_l_modifier(name);
	test_scanf_enomem(name);
	test_scanf_ebadf(name);

	test_puts_success(name);
	test_puts_epipe();
	test_puts_ebadf(ro, scratch);

	remove(name); free(name);
	remove(ro); free(ro);
	remove(scratch); free(scratch);
	/* leave nothing behind: run-tests.py gives each test a private
	 * directory, but the tree copies gate.sh takes are not private */
	unlink("chm.d/f"); rmdir("chm.d");
	rmdir("ren.d");

	if (fails) printf("%d check(s) failed\n", fails);
	else printf("all checks passed\n");
	return fails != 0;
}
