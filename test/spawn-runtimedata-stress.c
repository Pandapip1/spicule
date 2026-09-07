/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Regression test for a dangling-RuntimeData bug in __spawn (src/process/
 * spawn.c): RuntimeData -- the field of RTL_USER_PROCESS_PARAMETERS that
 * carries the inherited-descriptor table crt1's __fd_init reads back
 * (src/internal/fd.c) -- used to be set to a pointer to a *separate*
 * heap allocation (__fd_runtime_data's return value) *after*
 * RtlCreateProcessParametersEx had already returned, rather than being
 * handed to that call as its RuntimeInfo argument and packed into the
 * parameters block with everything else.
 *
 * RTL_USER_PROCESS_PARAMETERS crosses into the child as an uninterpreted
 * blob (see spawn.c's comment where RuntimeInfo is now built, citing
 * ReactOS's sdk/lib/rtl/ppb.c and dll/win32/kernel32/client/proc.c,
 * which mirror real Windows here): only the block's own bytes make the
 * trip. A field pointing *outside* the block survives as 8 bytes of
 * parent virtual address, not as a pointer the child can use -- and
 * crt1's __fd_init dereferences it unconditionally whenever it looks
 * nonzero. Two parent processes started from the same binary often get
 * similar enough heap layouts for that stale address to *happen* to be
 * valid in the child too, which is what made this intermittent rather
 * than a hard, always-reproducing failure: downstream, roughly 1 spawn
 * in 150 under make-style load.
 *
 * This spawns many children in a loop, each one inheriting one ordinary
 * (non-standard, not 0/1/2) descriptor purely via the RuntimeData table,
 * and checks that every single one of them can actually read through it
 * -- while deliberately varying argv and environment-block sizes across
 * iterations to churn the parent's heap between spawns, since a flat
 * failure rate is exactly what a coincidentally-still-valid address
 * would hide. (The stress loop reads from the inherited descriptor
 * rather than writing to it, which was originally a workaround: the
 * separate, 100%-reproducible bug described in the next paragraph made
 * writing impossible. It is kept as a read because a read is what
 * exercises the RuntimeData round-trip most cheaply, not because it
 * still has to be.)
 *
 * That second bug -- __fd_init's RuntimeData reconstruction never
 * recording an access mode, so every inherited descriptor read back as
 * O_RDONLY and write() refused it with EBADF whatever the handle could
 * actually do -- is FIXED, and test_inherited_fd_access_mode() below is
 * its regression test. Anyone who deletes that test on the grounds that
 * this file is "about RuntimeData pointers" should know it is about
 * RuntimeData *contents*, and that the two bugs were found together.
 *
 * Wine has much lower address-space entropy and a different allocator
 * than real Windows, so a clean pass here is not proof the underlying
 * bug is gone on real Windows -- it is only proof this code path still
 * works at all.  The fix is what src/process/spawn.c's comments and
 * RtlCreateProcessParametersEx call now do; this test exists so a
 * regression -- someone poking a pointer into pp after creation again --
 * has a chance of being caught even under Wine.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

extern char **environ;
int __spawn(const char *, char *const *, char *const *);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

#define N_ITERS 300
#define STRESS_FD 5
#define FILLER_MAX 4000

#define RC_BADARGC 2
#define RC_NOENV 3
#define RC_READFAIL 4
#define RC_MISMATCH 5

/* test_inherited_fd_access_mode()'s child, one code per assertion so a
 * failure says which half broke rather than only that something did. */
#define RC_AM_MODE_WRONLY 10
#define RC_AM_MODE_RDONLY 11
#define RC_AM_MODE_RDWR   12
#define RC_AM_WRITE_WO    13
#define RC_AM_WRITE_RW    14
#define RC_AM_RDONLY_WROTE 15
#define RC_AM_RDONLY_ERRNO 16
#define RC_AM_READ_RO     17
#define RC_AM_MODE_APPEND 18
#define RC_AM_WRITE_AP    19

#define AM_WO 3
#define AM_RO 4
#define AM_RW 5
#define AM_AP 6

/* Child role: fd number is argv[2]; read from it and compare against the
 * SPICULE_STRESS_MARK environment variable, which also exercises env-block
 * marshalling under the same heap churn. */
static int readfd_child(int argc, char **argv)
{
	int fd;
	const char *mark;
	char buf[128];
	ssize_t n;

	if (argc != 3) return RC_BADARGC;
	fd = atoi(argv[2]);
	mark = getenv("SPICULE_STRESS_MARK");
	if (!mark) return RC_NOENV;
	n = read(fd, buf, sizeof buf - 1);
	if (n <= 0) return RC_READFAIL;
	buf[n] = 0;
	return strcmp(buf, mark) ? RC_MISMATCH : 0;
}

/* Child role for test_inherited_fd_access_mode(): three descriptors were
 * inherited, opened by the parent O_WRONLY / O_RDONLY / O_RDWR.  Check
 * the mode came across AND that it is actually enforced -- in BOTH
 * directions.  The negative half is the point: a "fix" that simply
 * deleted write()'s access check would make the writable descriptors
 * work and would also let the read-only one be written, which is a
 * different bug in the opposite direction and must not pass. */
static int accmode_child(void)
{
	char b[8];

	if ((fcntl(AM_WO, F_GETFL) & O_ACCMODE) != O_WRONLY) return RC_AM_MODE_WRONLY;
	if ((fcntl(AM_RO, F_GETFL) & O_ACCMODE) != O_RDONLY) return RC_AM_MODE_RDONLY;
	if ((fcntl(AM_RW, F_GETFL) & O_ACCMODE) != O_RDWR)   return RC_AM_MODE_RDWR;
	/* O_APPEND is the case that gets the access mask wrong most easily:
	 * open() implements it by trading FILE_WRITE_DATA for
	 * FILE_APPEND_DATA (src/fcntl/open.c), so a writability test that
	 * looks only at FILE_WRITE_DATA reads an appending descriptor back
	 * as read-only and refuses every write to it. */
	if ((fcntl(AM_AP, F_GETFL) & O_ACCMODE) != O_WRONLY) return RC_AM_MODE_APPEND;

	/* positive: inherited writable descriptors accept writes */
	if (write(AM_WO, "w", 1) != 1) return RC_AM_WRITE_WO;
	if (write(AM_RW, "w", 1) != 1) return RC_AM_WRITE_RW;
	if (write(AM_AP, "w", 1) != 1) return RC_AM_WRITE_AP;

	/* negative: an inherited read-only descriptor still refuses, with the
	 * [EBADF] write.html requires for "not a valid file descriptor open
	 * for writing" -- and still reads */
	errno = 0;
	if (write(AM_RO, "w", 1) != -1) return RC_AM_RDONLY_WROTE;
	if (errno != EBADF) return RC_AM_RDONLY_ERRNO;
	if (read(AM_RO, b, 1) != 1) return RC_AM_READ_RO;
	return 0;
}

/* The access mode of an inherited descriptor.
 *
 * RuntimeData is msvcrt's _osfile format and has no access-mode bit, so
 * __fd_init used to install every inherited descriptor with no mode at
 * all.  O_RDONLY is 0, so they all read back as read-only, and
 * src/unistd/write.c refuses an O_RDONLY descriptor with EBADF before
 * the kernel is ever asked -- making an inherited writable descriptor
 * unwritable, while ftruncate() and posix_fallocate() on the SAME
 * descriptor succeeded, because they ask the kernel instead.  Ordinary
 * shell redirection ("prog 3>file") lands exactly here.
 *
 * The mode is now recovered from the handle itself, via
 * NtQueryObject(ObjectBasicInformation)'s GrantedAccess, which needs no
 * change to the interop format and works whatever CRT the parent used. */
static void test_inherited_fd_access_mode(const char *self)
{
	int wo, ro, rw, ap, pid, status;
	char *av[3];

	{ int s = open("am-ro.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	  CHECK(s >= 0); if (s >= 0) { CHECK(write(s, "seed", 4) == 4); close(s); } }

	wo = open("am-wo.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ro = open("am-ro.txt", O_RDONLY);
	rw = open("am-rw.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
	/* NO O_TRUNC here, deliberately: open() adds FILE_WRITE_DATA back for
	 * O_TRUNC ("overwrite needs it", src/fcntl/open.c), which would put
	 * the ordinary write bit on the mask and stop this exercising the
	 * append-only case at all.  O_APPEND alone yields FILE_APPEND_DATA
	 * with no FILE_WRITE_DATA, which is the mask that matters. */
	ap = open("am-ap.txt", O_WRONLY | O_APPEND | O_CREAT, 0644);
	CHECK(wo >= 0 && ro >= 0 && rw >= 0 && ap >= 0);
	if (wo < 0 || ro < 0 || rw < 0 || ap < 0) return;
	if (wo != AM_WO) { CHECK(dup2(wo, AM_WO) == AM_WO); close(wo); }
	if (ro != AM_RO) { CHECK(dup2(ro, AM_RO) == AM_RO); close(ro); }
	if (rw != AM_RW) { CHECK(dup2(rw, AM_RW) == AM_RW); close(rw); }
	if (ap != AM_AP) { CHECK(dup2(ap, AM_AP) == AM_AP); close(ap); }

	/* the parent's own modes are right -- so a child failure is about
	 * inheritance, not about open() */
	CHECK((fcntl(AM_WO, F_GETFL) & O_ACCMODE) == O_WRONLY);
	CHECK((fcntl(AM_RO, F_GETFL) & O_ACCMODE) == O_RDONLY);
	CHECK((fcntl(AM_RW, F_GETFL) & O_ACCMODE) == O_RDWR);
	CHECK((fcntl(AM_AP, F_GETFL) & O_ACCMODE) == O_WRONLY);

	av[0] = (char *)self; av[1] = (char *)"--accmode"; av[2] = 0;
	fflush(stdout);
	pid = __spawn(self, av, environ);
	CHECK(pid > 0);
	if (pid > 0) {
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status));
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			printf("FAIL %s:%d: accmode child exited %d "
			       "(10/11/12 mode wrong, 13/14 writable fd refused a write, "
			       "15/16 read-only fd accepted one, 17 read-only fd unreadable, "
			       "18/19 O_APPEND fd lost its mode)\n",
			       __FILE__, __LINE__, WEXITSTATUS(status));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	close(AM_WO); close(AM_RO); close(AM_RW); close(AM_AP);
	unlink("am-wo.txt"); unlink("am-ro.txt"); unlink("am-rw.txt"); unlink("am-ap.txt");
}

static void test_runtimedata_survives_heap_churn(const char *self)
{
	int i, ok = 0;
	char *filler = malloc(FILLER_MAX + 1);
	int nenv = 0;

	CHECK(filler != 0);
	if (!filler) return;
	while (environ[nenv]) nenv++;

	for (i = 0; i < N_ITERS; i++) {
		int p[2];
		char fdbuf[16], markbuf[64];
		char *av[4];
		char **ev;
		char *markvar = 0, *fillvar = 0;
		int pid, status;
		size_t fillen = (size_t)((i * 137 + 11) % (FILLER_MAX - 32)) + 1;
		size_t marklen;

		/* Vary the size of one environment entry across iterations to
		 * churn the parent's malloc arena between spawns -- the same
		 * kind of variation the downstream report singled out (command
		 * line length, environment size) as plausibly correlated with
		 * failure probability. */
		memset(filler, 'f', fillen);
		filler[fillen] = 0;

		if (pipe(p) != 0) { CHECK(0); continue; }
		/* Land the read end on a fixed, non-standard descriptor so
		 * __fd_init has to reconstruct it from RuntimeData, not from
		 * StandardInput/Output/Error (which are handle-by-value fields,
		 * not pointer fields, and are not what this bug is about). */
		if (dup2(p[0], STRESS_FD) != STRESS_FD) { CHECK(0); close(p[0]); close(p[1]); continue; }
		close(p[0]);

		snprintf(fdbuf, sizeof fdbuf, "%d", STRESS_FD);
		snprintf(markbuf, sizeof markbuf, "MARK-%d-%lu", i, (unsigned long)fillen);
		marklen = strlen(markbuf);

		ev = malloc((size_t)(nenv + 3) * sizeof *ev);
		if (!ev) { CHECK(0); close(p[1]); close(STRESS_FD); continue; }
		markvar = malloc(marklen + sizeof "SPICULE_STRESS_MARK=");
		fillvar = malloc(FILLER_MAX + sizeof "SPICULE_STRESS_FILLER=");
		CHECK(markvar != 0 && fillvar != 0);
		if (markvar && fillvar) {
			int k;
			for (k = 0; k < nenv; k++) ev[k] = environ[k];
			sprintf(markvar, "SPICULE_STRESS_MARK=%s", markbuf);
			sprintf(fillvar, "SPICULE_STRESS_FILLER=%s", filler);
			ev[nenv] = markvar;
			ev[nenv + 1] = fillvar;
			ev[nenv + 2] = 0;

			av[0] = (char *)self; av[1] = (char *)"--readfd";
			av[2] = fdbuf; av[3] = 0;

			fflush(stdout);
			pid = __spawn(self, av, ev);
			CHECK(pid > 0);

			if (pid > 0) {
				/* The write end feeds the child's read; the parent's
				 * own copy of the read end is already gone (dup2'd
				 * over), so this write cannot deadlock. */
				CHECK((size_t)write(p[1], markbuf, marklen) == marklen);
				close(p[1]);
				close(STRESS_FD);
				CHECK(waitpid(pid, &status, 0) == pid);
				if (WIFEXITED(status) && WEXITSTATUS(status) == 0) ok++;
				else printf("FAIL %s:%d: iter %d exited %d (status 0x%08x)\n",
				            __FILE__, __LINE__, i,
				            WIFEXITED(status) ? WEXITSTATUS(status) : -1, (unsigned)status);
				CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			} else {
				close(p[1]);
				close(STRESS_FD);
			}
		} else {
			close(p[1]);
			close(STRESS_FD);
		}
		free(ev);
		free(markvar);
		free(fillvar);
	}
	free(filler);
	printf("spawn-runtimedata-stress: %d/%d iterations round-tripped the inherited fd\n",
	       ok, N_ITERS);
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--readfd")) return readfd_child(argc, argv);
	if (argc > 1 && !strcmp(argv[1], "--accmode")) return accmode_child();

	test_inherited_fd_access_mode(argv[0]);
	test_runtimedata_survives_heap_churn(argv[0]);

	if (!fails) printf("spawn-runtimedata-stress: all tests passed\n");
	return fails != 0;
}
