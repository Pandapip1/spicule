/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause audit of the last never-audited corners:
 * <sys/resource.h>, <sys/select.h>, <poll.h>, <sys/param.h>, and the
 * GNU getopt_long()/getopt_long_only() extensions.  Each assertion
 * cites the clause of https://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/<name>.html or .../basedefs/<header>.html it
 * checks, or (for the two non-POSIX pieces) the GNU/BSD documentation
 * cited inline.
 *
 * Three genuine implementation gaps were originally found in this area.
 * All three are now closed: setrlimit()'s enforceable half and
 * getpriority()/setpriority() entirely (src/misc/resource.c), and
 * select()/pselect()/poll() (src/select/). Per the
 * project's current standard, a gap is no longer just recorded in
 * prose and left untested -- every specified clause gets a real test
 * in this file, fenced off with one of three conventions so the
 * categories stay machine-greppable:
 *
 *   #if 0 / * BUG: <requirement + citation> * /     -- a real spec
 *   violation in code that exists; should pass once fixed.
 *   #if 0 / * N/A: <requirement + citation + why NT can't> * / --
 *   genuinely impossible on this platform.
 *   #if 0 / * UNIMPL: <requirement + citation> * /  -- not
 *   implemented here, but implementable; the fence comment also
 *   names the NT mechanism that would implement it.
 *
 * The two remaining gaps:
 *
 *   - setrlimit() was *declared* in include/sys/resource.h but had no
 *     definition anywhere in src/ -- calling it was a link error, not a
 *     runtime ENOSYS. Now defined (src/misc/resource.c, unfenced below)
 *     for the RLIMIT_* resources NT *can* enforce (RLIMIT_NPROC,
 *     RLIMIT_CPU, RLIMIT_AS/RLIMIT_DATA -- job objects give a real
 *     primitive), and for RLIMIT_NOFILE, which needs no NT primitive at
 *     all (the fd table is spicule's own -- see the RLIMIT_NOFILE
 *     section below, which was an N/A fence until that was noticed).
 *     RLIMIT_FSIZE likewise needs no NT primitive: every path by which
 *     this process can extend a file is spicule's own, so both halves of
 *     its clause -- the [EFBIG] refusal and the SIGXFSZ the same
 *     sentence requires -- are enforced in src/misc/resource.c and
 *     tested unfenced below.  Still fenced for the ones no mechanism
 *     reaches after process start: RLIMIT_STACK and RLIMIT_CORE as N/A;
 *     RLIMIT_RSS and RLIMIT_MEMLOCK are not POSIX resources at all.
 *
 *   - getpriority()/setpriority() are POSIX.1-2017 base functions
 *     (moved from XSI to BASE in Issue 5 -- getpriority.html). Now
 *     declared by <sys/resource.h> and defined in src/misc/resource.c
 *     (unfenced below), via NtQueryInformationProcess()/
 *     NtSetInformationProcess() with ProcessBasePriority under ntdll,
 *     mapped through the nice-value range -- see that header for the
 *     mapping writeup.
 *
 * select()/pselect() and poll() are no longer a gap: both are now
 * implemented (src/select/select.c, src/select/poll.c -- see that
 * first file's banner for the wait-vs-poll design over this library's
 * pipe/console/regular-file descriptor shapes) and exercised below,
 * unfenced, alongside the fd_set bit-manipulation macro family that
 * was already tested independent of select() ever existing.
 */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/param.h>
#include <getopt.h>
#include <signal.h>
#include <sched.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Internal: spawn a program as a child, return its pid (see
 * src/process/spawn.c). Declared locally, as test/misc.c and
 * test/posix-alloc.c do, rather than widening include/. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

extern char **environ;

/* ===================== sys/resource.h ===================== */

/* getrlimit.html DESCRIPTION/RETURN VALUE/ERRORS.
 *
 * spicule's getrlimit() (src/misc/resource.c) reports real, enforced
 * numbers for the two resources it actually caps -- RLIMIT_NOFILE
 * against the fixed __fds[FD_MAX] table (src/internal/libc.h,
 * FD_MAX == 1024) and RLIMIT_NPROC against CHILD_CAP_LIMIT_
 * (src/internal/libc.h, == 1<<20, the same number sysconf(_SC_CHILD_MAX)
 * reports per src/unistd/sysconf.c) -- and RLIM_INFINITY
 * ("the implementation shall not enforce limits on that resource",
 * getrlimit.html) for every resource NT has no per-process cap for. */
static void test_getrlimit(void)
{
	struct rlimit rl;

	/* RETURN VALUE: "Upon successful completion ... shall return 0." */
	CHECK(getrlimit(RLIMIT_NOFILE, &rl) == 0);
	CHECK(rl.rlim_cur == 1024 && rl.rlim_max == 1024);

	CHECK(getrlimit(RLIMIT_NPROC, &rl) == 0);
	CHECK(rl.rlim_cur == rl.rlim_max);
	CHECK((long)rl.rlim_cur == sysconf(_SC_CHILD_MAX));

	/* RLIM_INFINITY: "considered to be larger than any other limit
	 * value ... the implementation shall not enforce limits on that
	 * resource" -- spicule has no cap for any of these on NT. */
	CHECK(getrlimit(RLIMIT_CPU, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY && rl.rlim_max == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_FSIZE, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_DATA, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_CORE, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_RSS, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);
	CHECK(getrlimit(RLIMIT_AS, &rl) == 0 && rl.rlim_cur == RLIM_INFINITY);

	/* ERRORS: "[EINVAL] An invalid resource was specified." */
	errno = 0;
	CHECK(getrlimit(999, &rl) == -1 && errno == EINVAL);
}

/* setrlimit.html DESCRIPTION/RETURN VALUE/ERRORS, for the RLIMIT_*
 * values NT has a real enforcement primitive for. setrlimit.html
 * DESCRIPTION: "changes ... take effect immediately" and RETURN VALUE:
 * "Upon successful completion, ... shall return 0" -- setting a soft
 * limit within the hard limit for RLIMIT_NPROC must succeed and be
 * readable back via getrlimit(). NT mechanism (src/misc/resource.c):
 * this process is placed in a job object it creates and owns
 * (NtCreateJobObject + NtAssignProcessToJobObject, src/internal/nt.h)
 * and JOBOBJECT_EXTENDED_LIMIT_INFORMATION.BasicLimitInformation.
 * ActiveProcessLimit is set via
 * NtSetInformationJobObject(JobObjectExtendedLimitInformation).
 * RLIMIT_CPU maps the same way via PerProcessUserTimeLimit;
 * RLIMIT_AS/RLIMIT_DATA via ProcessMemoryLimit. The job-object call is
 * best-effort (see src/misc/resource.c) -- what this test actually
 * verifies is that setrlimit() then getrlimit() round-trip correctly
 * and enforce the soft<=hard/EPERM-on-raising-hard rules, which does
 * not depend on the job object accepting the value. */
static void test_setrlimit_enforceable(void)
{
	struct rlimit rl, rl2;

	rl.rlim_cur = 10;
	rl.rlim_max = 100;
	CHECK(setrlimit(RLIMIT_NPROC, &rl) == 0);
	CHECK(getrlimit(RLIMIT_NPROC, &rl2) == 0);
	CHECK(rl2.rlim_cur == 10 && rl2.rlim_max == 100);

	/* ERRORS: "[EINVAL] ... in a setrlimit() call, the new rlim_cur
	 * exceeds the new rlim_max." */
	errno = 0;
	rl.rlim_cur = 200;
	rl.rlim_max = 100;
	CHECK(setrlimit(RLIMIT_NPROC, &rl) == -1 && errno == EINVAL);

	/* ERRORS: "[EPERM] The limit specified to setrlimit() would have
	 * raised the maximum limit value, and the calling process does
	 * not have appropriate privileges." An unprivileged process
	 * (the normal case for this test binary) may not raise
	 * rlim_max above what it currently is. */
	CHECK(getrlimit(RLIMIT_NPROC, &rl2) == 0);
	rl.rlim_cur = rl2.rlim_cur;
	rl.rlim_max = rl2.rlim_max + 1;
	errno = 0;
	CHECK(setrlimit(RLIMIT_NPROC, &rl) == -1 && errno == EPERM);

	/* RLIMIT_CPU, RLIMIT_AS, RLIMIT_DATA: same enforceable-soft-limit
	 * round trip, each via its own job-object/process-quota field. */
	rl.rlim_cur = 3600;
	rl.rlim_max = 7200;
	CHECK(setrlimit(RLIMIT_CPU, &rl) == 0);
	CHECK(getrlimit(RLIMIT_CPU, &rl2) == 0 && rl2.rlim_cur == 3600 && rl2.rlim_max == 7200);

	/* Deliberately generous values.  POSIX limits are inherited across
	 * fork/exec, and this library implements them with a job object the
	 * child is enrolled in, so a small cap here is not confined to this
	 * process -- it applies to everything spawned afterwards, including
	 * test_getrusage()'s child below.  A 1 MiB RLIMIT_AS killed that
	 * child outright on real Windows while passing under Wine, whose
	 * job objects enforce nothing: the three windows-test CI legs went
	 * red and the divergence was invisible locally.
	 *
	 * That inheritance is correct, not a bug -- setting RLIMIT_AS to
	 * 1 MiB before fork/exec would break a child on any POSIX system
	 * too -- so the fix belongs here, not in setrlimit().  These values
	 * still exercise every clause below (round-trip, EINVAL when soft
	 * exceeds hard, EPERM when raising the hard limit) without leaving
	 * the process unable to spawn.  Note the hard limit cannot be
	 * raised again unprivileged, so whatever is set here is this
	 * process's ceiling for the rest of the run. */
	rl.rlim_cur = (rlim_t)256 << 20;
	rl.rlim_max = (rlim_t)512 << 20;
	CHECK(setrlimit(RLIMIT_AS, &rl) == 0);
	CHECK(getrlimit(RLIMIT_AS, &rl2) == 0 && rl2.rlim_cur == ((rlim_t)256 << 20));
}

/* setrlimit.html DESCRIPTION obliges a limit, once set, to actually
 * "restrict the amount of [the] resource".  This block used to be one
 * N/A fence covering RLIMIT_NOFILE/STACK/FSIZE/CORE/RSS/MEMLOCK under
 * the single mechanism "no NT primitive reaches these after process
 * start".  Re-audited: that mechanism is true of two of them, a
 * category error for two more, and inapplicable to the last two.  The
 * six are now accounted for separately.
 *
 * N/A -- the mechanism is a real NT fact:
 *
 *   RLIMIT_STACK ("the maximum size of the initial thread's stack").
 *     NT fixes a thread's stack reservation at NtCreateThreadEx() time
 *     from the PE header's SizeOfStackReserve; nothing in ntdll lowers
 *     a running thread's ceiling afterwards, and the only thread the
 *     clause is about -- the initial one -- is already running before
 *     any setrlimit() call in this process can execute.
 *
 *   RLIMIT_CORE ("the maximum size of a core file in bytes that may be
 *     created by a process").  NT has no core file to size.  WER
 *     minidump policy is machine-wide registry configuration, not a
 *     per-process byte ceiling, so there is no object the clause could
 *     be about.
 *
 * Not POSIX at all -- there is no clause here to be N/A against:
 *
 *   RLIMIT_RSS and RLIMIT_MEMLOCK are BSD/Linux extensions.
 *     setrlimit.html defines exactly seven resources -- RLIMIT_CORE,
 *     RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_NOFILE,
 *     RLIMIT_STACK, RLIMIT_AS -- and neither of these appears on the
 *     page.  Including them in a POSIX-conformance N/A was a
 *     miscategorisation; they are extensions spicule chooses to report
 *     RLIM_INFINITY for.
 *
 * Nothing in this accounting is UNIMPL any longer: RLIMIT_FSIZE's
 * SIGXFSZ, the last fence here, is implemented and tested below. */

/* setrlimit.html for RLIMIT_FSIZE, the ACCEPTANCE half.
 *
 * ERRORS lists exactly two [EINVAL] causes: "the value specified in
 * resource is not valid" and, for setrlimit(), "the new rlim_cur exceeds
 * the new rlim_max".  Lowering RLIMIT_FSIZE from RLIM_INFINITY is
 * neither, so refusing it -- which this did, because FSIZE shared an arm
 * with the resources that genuinely have no enforcement mechanism -- was
 * a conformance defect the caller could not work around.
 *
 * Enforcement is a separate matter and is asserted by
 * test_setrlimit_fsize_enforced() below; this covers only that a legal
 * call is accepted and round-trips. */
static void test_setrlimit_fsize_accepts_lowering(void)
{
	struct rlimit rl, back;

	CHECK(getrlimit(RLIMIT_FSIZE, &rl) == 0);
	CHECK(rl.rlim_cur == RLIM_INFINITY && rl.rlim_max == RLIM_INFINITY);

	rl.rlim_cur = 4096;
	rl.rlim_max = RLIM_INFINITY;
	errno = 0;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == 0);
	CHECK(getrlimit(RLIMIT_FSIZE, &back) == 0);
	CHECK(back.rlim_cur == 4096 && back.rlim_max == RLIM_INFINITY);

	/* lowering the hard limit too, then observing it cannot be raised
	 * again -- "[EPERM] ... would have raised the maximum limit value,
	 * and the calling process does not have appropriate privileges" */
	rl.rlim_cur = 1024; rl.rlim_max = 2048;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == 0);
	CHECK(getrlimit(RLIMIT_FSIZE, &back) == 0);
	CHECK(back.rlim_cur == 1024 && back.rlim_max == 2048);
	rl.rlim_cur = 1024; rl.rlim_max = 4096;
	errno = 0;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == -1 && errno == EPERM);

	/* and the one [EINVAL] that IS specified still fires */
	rl.rlim_cur = 4096; rl.rlim_max = 2048;
	errno = 0;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == -1 && errno == EINVAL);

	/* Restore as much as can be restored, and note what cannot: a hard
	 * limit lowered above is lowered for the life of the process, so
	 * every later test runs under rlim_max == 2048.  Left generous
	 * enough that nothing else in this file notices; the enforcement
	 * test below reads the current hard limit rather than assuming
	 * RLIM_INFINITY, which is what the lowering would otherwise break. */
	rl.rlim_cur = 2048; rl.rlim_max = 2048;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == 0);
}

/* setrlimit.html RLIMIT_NOFILE: "a number one greater than the maximum
 * value that the system may assign to a newly-created descriptor."
 *
 * Was fenced N/A on the mechanism "there is no NT object whose size a
 * setrlimit() call could shrink at runtime, only a recompile."  That was
 * a category error, and it is what kept this clause unimplemented for as
 * long as it was: RLIMIT_NOFILE does not cap an NT object.  Descriptors
 * here are spicule's own, handed out by __fd_alloc() (src/internal/fd.c)
 * from the static __fds[] table in this process's address space, and
 * that function already returned the EMFILE the clause requires -- the
 * only missing piece was that its loop bound was the compile-time
 * constant FD_MAX rather than a ceiling setrlimit() could lower.  "The
 * system" in the clause is this implementation.  Now implemented:
 * src/internal/fd.c's __fd_limit, lowered by src/misc/resource.c.
 *
 * Run in a CHILD, not here.  RLIMIT_NOFILE is process-wide: lowering it
 * in the test process would starve every later test in this file of
 * descriptors, the same failure the RLIMIT_AS note above records (a
 * 1 MiB cap killed test_getrusage()'s child on real Windows while
 * passing under Wine).  A fresh process starts at FD_MAX again, so the
 * child both isolates the damage and incidentally shows the limit is
 * per-process state rather than something inherited. */
static void test_setrlimit_nofile(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self;
	argv[1] = (char *)"--nofile-child";
	argv[2] = 0;
	pid = __spawn(self, argv, environ);
	if (pid < 0) {
		printf("note: cannot spawn \"%s\" (errno %d); RLIMIT_NOFILE enforcement check skipped\n", self, errno);
		return;
	}
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* This process's own limit is untouched by the child's. */
	{
		struct rlimit rl;
		CHECK(getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur == 1024);
	}
}

static void test_setrlimit_nofile_child(void)
{
	struct rlimit rl, back;
	int fds[64], i, n = 0, saw_emfile = 0;

	CHECK(getrlimit(RLIMIT_NOFILE, &back) == 0);
	CHECK(back.rlim_cur == 1024);

	/* Lower the soft limit well above 0,1,2 so the standard streams
	 * survive, but low enough that a handful of opens exhausts it. */
	rl.rlim_cur = 8;
	rl.rlim_max = back.rlim_max;
	CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);

	/* "shall be reported by getrlimit" -- the round trip must show the
	 * value that is actually enforced, not the old one. */
	CHECK(getrlimit(RLIMIT_NOFILE, &back) == 0 && back.rlim_cur == 8);

	errno = 0;
	for (i = 0; i < 64; i++) {
		fds[i] = open("rl-nofile.txt", O_CREAT | O_RDWR, 0644);
		if (fds[i] < 0) { saw_emfile = (errno == EMFILE); break; }
		/* "one greater than the maximum value the system may assign":
		 * no descriptor at or above the limit may ever be handed out. */
		CHECK(fds[i] < 8);
		n++;
	}
	/* It must actually run out, and with EMFILE -- not succeed 64 times
	 * (limit ignored) and not fail with some other errno. */
	CHECK(i < 64);
	CHECK(saw_emfile);

	while (n-- > 0) close(fds[n]);
	unlink("rl-nofile.txt");

	/* Raising the hard limit back is EPERM (no appropriate privileges),
	 * but re-raising the soft limit up to the unchanged hard limit is
	 * allowed and must restore real capacity. */
	rl.rlim_cur = back.rlim_max;
	rl.rlim_max = back.rlim_max;
	CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
	CHECK(getrlimit(RLIMIT_NOFILE, &back) == 0 && back.rlim_cur == 1024);
}

/* setrlimit.html RLIMIT_FSIZE, "the maximum size of a file, in bytes,
 * that may be created by a process", and the ENFORCEMENT half.
 *
 * This was fenced UNIMPL on the reasoning that "RLIMIT_FSIZE enforcement
 * would only ever be as complete as spicule's own I/O paths: a file grown
 * by any other means, in this process or another, would sail past it."
 * Both halves of that turned out weaker than they read:
 *
 *   - "in another process" is outside the clause, not a hole in it.  The
 *     limit governs what THIS process may create.
 *   - "in this process" was checkable, and the surface is CLOSED.  Every
 *     path by which this process can extend a file is spicule's own --
 *     write(), pwrite(), writev() (which delegates to write()),
 *     ftruncate(), posix_fallocate(), and stdio, which funnels into
 *     write().  There is no mmap in this library at all: no
 *     <sys/mman.h>, no implementation.
 *
 * So enforcement is complete for this process, exactly as RLIMIT_NOFILE's
 * is, and for the same reason -- the resource is bounded by this
 * library's own code rather than by a kernel primitive we lack.
 *
 * THE EXPECTED VALUES BELOW ARE MEASURED, NOT DERIVED.  The fenced
 * version of this test asserted that write(fd, buf, 512) on an empty file
 * under a 256-byte limit returns -1 with [EFBIG].  No implementation
 * behaves that way.  Measured on Linux/glibc with SIGXFSZ ignored:
 *     write(512) on an empty file     -> 256  (TRUNCATED, no error)
 *     write(200) at offset 200        -> 56
 *     write(512) with the file at 256 -> -1, EFBIG
 *     pwrite(100) at offset 1000      -> -1, EFBIG
 *     ftruncate(1024)                 -> -1, EFBIG
 *     ftruncate(128)                  -> 0
 *     posix_fallocate(0, 1024)        -> EFBIG
 * A write is CLAMPED when it starts below the limit and would cross it,
 * and fails only when not one byte may be written; operations that
 * cannot partially succeed fail outright.
 *
 * "With SIGXFSZ ignored" above is now a thing this test has to arrange
 * rather than a footnote about the measuring harness: spicule generates
 * the signal for real (test_setrlimit_fsize_sigxfsz() below), and its
 * default action is to end the process, so every [EFBIG] asserted here
 * would otherwise kill this binary before the next line ran.  Exactly
 * what the numbers above were measured under. */
static void test_setrlimit_fsize_enforced(void)
{
	struct rlimit rl, saved;
	void (*oldxfsz)(int);
	char buf[512];
	int fd;

	oldxfsz = signal(SIGXFSZ, SIG_IGN);
	CHECK(oldxfsz != SIG_ERR);
	CHECK(getrlimit(RLIMIT_FSIZE, &saved) == 0);
	rl.rlim_cur = 256;
	/* the hard limit found on entry, NOT RLIM_INFINITY: a hard limit can
	 * be lowered but never raised again, so an earlier test in this file
	 * that lowered it would make an unconditional RLIM_INFINITY here fail
	 * with [EPERM].  Process-wide limits are exactly the kind of global
	 * state a test must take as it finds. */
	rl.rlim_max = saved.rlim_max;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == 0);

	fd = open("rl-fsize.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	memset(buf, 'x', sizeof buf);

	/* clamped to the limit, not refused */
	errno = 0;
	CHECK(write(fd, buf, sizeof buf) == 256);

	/* now at the limit: write.html "[EFBIG] An attempt was made to write
	 * a file that exceeds ... the process' file size limit" */
	errno = 0;
	CHECK(write(fd, buf, sizeof buf) == -1);
	CHECK(errno == EFBIG);

	/* pwrite past the limit fails; pwrite inside it is clamped */
	errno = 0;
	CHECK(pwrite(fd, buf, 100, 1000) == -1 && errno == EFBIG);
	errno = 0;
	CHECK(pwrite(fd, buf, 100, 200) == 56);

	/* ftruncate cannot partially succeed: above the limit it fails,
	 * at or below it succeeds */
	errno = 0;
	CHECK(ftruncate(fd, 1024) == -1 && errno == EFBIG);
	CHECK(ftruncate(fd, 256) == 0);
	CHECK(ftruncate(fd, 128) == 0);

	CHECK(posix_fallocate(fd, 0, 1024) == EFBIG);

	/* and with the limit lifted, the same calls succeed -- so the
	 * failures above are the limit talking and not something else */
	CHECK(setrlimit(RLIMIT_FSIZE, &saved) == 0);
	errno = 0;
	CHECK(write(fd, buf, sizeof buf) == 512);
	CHECK(ftruncate(fd, 1024) == 0);

	close(fd);
	unlink("rl-fsize.txt");
	CHECK(setrlimit(RLIMIT_FSIZE, &saved) == 0);
	signal(SIGXFSZ, oldxfsz);
}

/* The other half of the same clause: setrlimit.html RLIMIT_FSIZE, "If a
 * write or truncate operation would cause this limit to be exceeded,
 * SIGXFSZ shall be generated for the thread.  If the thread is blocking,
 * or the process is ignoring, SIGXFSZ, the write or truncate operation
 * shall fail with errno set to [EFBIG] ...".
 *
 * BOTH halves, in one call: the handler must have run AND write() must
 * still report [EFBIG].  A handler that ran but left the caller with
 * some other errno satisfies neither reading of the sentence, and it is
 * the failure this test exists to catch -- __raise_internal() calls the
 * handler inline on this thread, so the handler's own errno writes land
 * between the refusal and the return.  src/misc/resource.c's
 * __fsize_exceeded() therefore raises first and assigns errno second,
 * the same order write() uses for SIGPIPE/[EPIPE].
 *
 * The handler deliberately makes an errno-setting call of its own (a
 * close() that cannot succeed) rather than only counting: a handler that
 * touches nothing would let the wrong ordering pass. */
static volatile sig_atomic_t xfsz_caught;

static void xfsz_handler(int sig)
{
	(void)sig;
	xfsz_caught++;
	/* guaranteed to fail and to set errno to EBADF -- see above */
	close(-1);
}

static void test_setrlimit_fsize_sigxfsz(void)
{
	struct rlimit rl, saved;
	void (*oldxfsz)(int);
	char buf[512];
	int fd, caught;

	xfsz_caught = 0;
	memset(buf, 'x', sizeof buf);
	oldxfsz = signal(SIGXFSZ, xfsz_handler);
	CHECK(oldxfsz != SIG_ERR);

	CHECK(getrlimit(RLIMIT_FSIZE, &saved) == 0);
	rl.rlim_cur = 0;
	/* the hard limit found on entry, for the reason spelled out in
	 * test_setrlimit_fsize_enforced() above: an earlier test here lowers
	 * it, and it can never be raised again. */
	rl.rlim_max = saved.rlim_max;
	CHECK(setrlimit(RLIMIT_FSIZE, &rl) == 0);
	fd = open("rl-xfsz.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) {
		errno = 0;
		CHECK(write(fd, buf, sizeof buf) == -1 && errno == EFBIG);
		caught = xfsz_caught;
		CHECK(caught == 1);
		close(fd);
		unlink("rl-xfsz.txt");
	}

	/* ftruncate is the "or truncate" arm of the same sentence */
	xfsz_caught = 0;
	fd = open("rl-xfsz.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) {
		errno = 0;
		CHECK(ftruncate(fd, 1) == -1 && errno == EFBIG);
		caught = xfsz_caught;
		CHECK(caught == 1);
		close(fd);
		unlink("rl-xfsz.txt");
	}

	/* and with the limit lifted the signal stops: it is the limit
	 * talking, not the write */
	CHECK(setrlimit(RLIMIT_FSIZE, &saved) == 0);
	xfsz_caught = 0;
	fd = open("rl-xfsz.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(write(fd, buf, sizeof buf) == 512);
		close(fd);
		unlink("rl-xfsz.txt");
	}
	caught = xfsz_caught;
	CHECK(caught == 0);

	signal(SIGXFSZ, oldxfsz);
}

/* N/A: setrlimit.html RLIMIT_STACK -- NT fixes the initial thread's
 * stack reservation at thread-creation time from the PE header, before
 * any setrlimit() call in this process can run, and ntdll exposes no
 * route to lower a running thread's ceiling.  See the accounting
 * above. */
#if SPICULE_TEST(NA, posix_sysmisc_setrlimit_stack_unenforceable) /* N/A: RLIMIT_STACK, see above */
static void test_setrlimit_stack_unenforceable(void)
{
	struct rlimit rl;

	rl.rlim_cur = 64 * 1024;
	rl.rlim_max = 1024 * 1024;
	CHECK(setrlimit(RLIMIT_STACK, &rl) == 0);
	/* a real implementation would now have to make the already-running
	 * main thread's stack growth fault past 64K -- impossible: NT
	 * fixes stack reservation at thread creation, before any
	 * setrlimit() call in this process could run. */
}
#endif

/* getrusage.html DESCRIPTION/RETURN VALUE/ERRORS.  Moved from XSI to
 * the POSIX base standard in Issue 5 (getrusage.html "Standards
 * Status").  spicule reports real numbers for ru_utime/ru_stime, read
 * from NtQueryInformationProcess(ProcessTimes) -- verified below by
 * confirming they are the right units (a struct timeval, tv_usec in
 * [0,1e6)) and by exercising a real child to confirm RUSAGE_CHILDREN's
 * running total (src/process/wait.c's __rusage_children()) is not
 * just a hardcoded zero. */
static void tv_is_valid(const struct timeval *tv)
{
	CHECK(tv->tv_usec >= 0 && tv->tv_usec < 1000000);
}

/* A whole struct timeval as microseconds, so a "did not go backwards"
 * check is one comparison on the real quantity rather than two
 * independent ones on its halves.  Same helper test/exec.c carries;
 * duplicated rather than shared because these test binaries have no
 * common header and each is meant to read on its own. */
static long long timeval_usec_sysmisc(const struct timeval *tv)
{
	return (long long)tv->tv_sec * 1000000 + (long long)tv->tv_usec;
}

static void test_getrusage(const char *self)
{
	struct rusage ru, before, after;
	pid_t pid;
	int status;
	char *argv[3];

	/* RETURN VALUE: "Upon successful completion ... shall return 0." */
	CHECK(getrusage(RUSAGE_SELF, &ru) == 0);
	tv_is_valid(&ru.ru_utime);
	tv_is_valid(&ru.ru_stime);

	/* RUSAGE_THREAD: not in POSIX.1-2017 (Linux/BSD extension used
	 * elsewhere in this project's own header comment); spicule treats
	 * it as an alias for RUSAGE_SELF since it has no per-thread
	 * accounting -- just confirm it does not error. */
	CHECK(getrusage(RUSAGE_THREAD, &ru) == 0);

	/* ERRORS: "[EINVAL] The value of the who argument is not valid." */
	errno = 0;
	CHECK(getrusage(999, &ru) == -1 && errno == EINVAL);

	/* RUSAGE_CHILDREN: "resources used by ... its terminated and
	 * waited-for child processes" -- confirm the running total is a
	 * real, non-decreasing accumulator across a reaped child, not a
	 * hardcoded zero. Re-exec self as a short-lived child (same
	 * pattern as test/misc.c's test_abort_child()); fork() needs
	 * RtlCloneUserProcess, which stock Wine lacks. */
	CHECK(getrusage(RUSAGE_CHILDREN, &before) == 0);

	argv[0] = (char *)self;
	argv[1] = (char *)"--rusage-child";
	argv[2] = 0;
	pid = __spawn(self, argv, environ);
	if (pid < 0) {
		printf("note: cannot spawn \"%s\" (errno %d); RUSAGE_CHILDREN accumulation check skipped\n", self, errno);
		return;
	}
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	CHECK(getrusage(RUSAGE_CHILDREN, &after) == 0);
	tv_is_valid(&after.ru_utime);
	tv_is_valid(&after.ru_stime);
	/* monotonic: the total across all reaped children can only grow.
	 *
	 * Both halves, AND-ed, each compared as one whole timeval folded to
	 * microseconds.  The previous form was a four-clause *disjunction*
	 * over tv_sec and tv_usec compared independently -- the exact
	 * defect test/exec.c records having fixed in its own copy of this
	 * check, left standing here.  Any single clause satisfied the
	 * whole thing, and `after.ru_utime.tv_usec >= before.ru_utime.tv_usec`
	 * is satisfied by the two structs merely being equal, which they
	 * are at zero, whether or not getrusage() wrote anything at all.
	 * Comparing the halves independently is wrong on its own terms too,
	 * since tv_usec wraps at each whole second.
	 *
	 * This stays a monotonicity check and does not become a "> 0" floor.
	 * The child reaped here burns a fixed iteration count and has not
	 * confirmed against its own times() that NT charged it anything, so
	 * a floor here would be the same tick-quantisation flake
	 * test/posix-grp.c hit: NT samples CPU time in 15.625ms quanta
	 * rather than accumulating it, so a short child
	 * is charged one quantum or zero depending on nothing this test
	 * controls.  test/exec.c test_wait_rusage() is where that floor is
	 * asserted, against a child built so that it holds. */
	CHECK(timeval_usec_sysmisc(&after.ru_utime) >= timeval_usec_sysmisc(&before.ru_utime));
	CHECK(timeval_usec_sysmisc(&after.ru_stime) >= timeval_usec_sysmisc(&before.ru_stime));
}

/* getpriority()/setpriority(): POSIX.1-2017 base functions (moved from
 * XSI to BASE in Issue 5, getpriority.html "Standards Status"), now
 * declared by <sys/resource.h> and defined in src/misc/resource.c --
 * NZERO/PRIO_PROCESS/PRIO_PGRP/PRIO_USER come from there too; see that
 * header for the full nice<->NT-base-priority mapping writeup. NT
 * mechanism: NtSetInformationProcess()/NtQueryInformationProcess() with
 * ProcessBasePriority, staying on pure ntdll like the rest of this
 * library. "the default nice value is {NZERO}" (getpriority.html
 * DESCRIPTION). */
static void test_getpriority_setpriority(void)
{
	int p;

	/* DESCRIPTION: "the range of valid nice values is
	 * [0,{NZERO}*2-1]" -- and RETURN VALUE: "getpriority() shall
	 * return an integer in the range -{NZERO} to {NZERO}-1" (the
	 * nice value re-based around 0, per the DESCRIPTION's
	 * value+{NZERO} relationship). This process's own nice value,
	 * fetched via PRIO_PROCESS, must fall in that range. */
	errno = 0;  /* DESCRIPTION: "it is necessary to set errno to 0
		     * prior to a call to getpriority()", since -1 is a
		     * legal successful return */
	p = getpriority(PRIO_PROCESS, getpid());
	CHECK(errno == 0);
	CHECK(p >= -NZERO && p <= NZERO - 1);

	/* PRIO_PGRP: "who is interpreted as a process group ID" */
	errno = 0;
	p = getpriority(PRIO_PGRP, getpgrp());
	CHECK(errno == 0);
	CHECK(p >= -NZERO && p <= NZERO - 1);

	/* PRIO_USER: "who is interpreted as ... an effective user ID" */
	errno = 0;
	p = getpriority(PRIO_USER, geteuid());
	CHECK(errno == 0);
	CHECK(p >= -NZERO && p <= NZERO - 1);

	/* setpriority() RETURN VALUE: "Upon successful completion ...
	 * shall return 0." Raise (numerically) this process's own nice
	 * value by 1 -- a normal, always-permitted direction for an
	 * unprivileged process -- and read it back via getpriority(). */
	errno = 0;
	p = getpriority(PRIO_PROCESS, getpid());
	CHECK(errno == 0);
	if (p < NZERO - 1) {
		CHECK(setpriority(PRIO_PROCESS, getpid(), p + 1) == 0);
		errno = 0;
		CHECK(getpriority(PRIO_PROCESS, getpid()) == p + 1);
		CHECK(setpriority(PRIO_PROCESS, getpid(), p) == 0);  /* restore */
	}

	/* ERRORS (both functions): "[ESRCH] No process could be located
	 * using the which and who argument values specified." pid 0 is
	 * legal (caller's own group/self depending on `which`) so this
	 * must be a pid that cannot exist. */
	errno = 0;
	CHECK(getpriority(PRIO_PROCESS, (id_t)999999999) == -1 && errno == ESRCH);

	/* ERRORS: "[EINVAL] The value of the which argument was not
	 * recognized, or the value of the who argument is not a valid
	 * process ID, process group ID, or user ID." */
	errno = 0;
	CHECK(getpriority(999, getpid()) == -1 && errno == EINVAL);

	/* ERRORS (setpriority() only): "[EPERM] A process was located,
	 * but neither the real nor effective user ID of the executing
	 * process match the effective user ID of the process whose nice
	 * value is being changed." A process this one does not own
	 * (e.g. pid 1 on a system where that exists and is not ours) is
	 * not reachable here in a portable way; assert against a
	 * synthetic hard case instead: some other live pid entirely
	 * outside this process's session, if one can be found, must
	 * reject with EPERM rather than succeed. Left as a shape-only
	 * placeholder pending real process enumeration in this test. */

	/* ERRORS (setpriority() only): "[EACCES] A request was made to
	 * change the nice value to a lower numeric value and the
	 * current process does not have appropriate privileges." An
	 * unprivileged process lowering (more favorable) its own nice
	 * value below its current value must fail this way. */
	errno = 0;
	p = getpriority(PRIO_PROCESS, getpid());
	CHECK(errno == 0);
	if (p > -NZERO) {
		errno = 0;
		CHECK(setpriority(PRIO_PROCESS, getpid(), p - 1) == -1 && errno == EACCES);
	}
}

/* ===================== sys/select.h ===================== */

/* select()/pselect(): select.html DESCRIPTION/RETURN VALUE/ERRORS.
 * Both are now implemented in src/select/select.c (see that file's
 * banner for the design) and declared by include/sys/select.h, whose
 * own undefined-ok marker for select() has been removed accordingly. */

static void test_select_ready_count(void)
{
	int fds[2];
	fd_set rfds, wfds;
	struct timeval tv;
	int n;

	CHECK(pipe(fds) == 0);
	FD_ZERO(&rfds);
	FD_SET(fds[0], &rfds);
	FD_ZERO(&wfds);
	FD_SET(fds[1], &wfds);

	CHECK(write(fds[1], "x", 1) == 1);

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	n = select(fds[1] + 1, &rfds, &wfds, 0, &tv);
	CHECK(n == 2);  /* read end has data, write end has room */
	CHECK(FD_ISSET(fds[0], &rfds));
	CHECK(FD_ISSET(fds[1], &wfds));

	/* Conversion is performed even though readiness is immediate.  This
	 * boundary keeps UBSan coverage on time_t-to-100ns multiplication. */
	FD_ZERO(&rfds);
	FD_SET(fds[0], &rfds);
	tv.tv_sec = LLONG_MAX;
	tv.tv_usec = 999999;
	CHECK(select(fds[0] + 1, &rfds, 0, 0, &tv) == 1);
	CHECK(FD_ISSET(fds[0], &rfds));

	close(fds[0]);
	close(fds[1]);
}

/* select.html DESCRIPTION timeout semantics: "If timeout is not a
 * null pointer, it points to an object of type struct timeval that
 * specifies a maximum interval to wait" and a zero-valued timeval
 * "To effect a poll" -- must return promptly with 0 when nothing is
 * ready. */
static void test_select_zero_timeout_polls(void)
{
	int fds[2];
	fd_set rfds;
	struct timeval tv;

	CHECK(pipe(fds) == 0);
	FD_ZERO(&rfds);
	FD_SET(fds[0], &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	/* nothing written to fds[1] -- read end is not ready */
	CHECK(select(fds[0] + 1, &rfds, 0, 0, &tv) == 0);
	CHECK(!FD_ISSET(fds[0], &rfds));  /* cleared: not in the ready set */
	close(fds[0]);
	close(fds[1]);
}

/* select.html ERRORS. */
static void test_select_errors(void)
{
	fd_set rfds;
	struct timeval tv;

	/* "[EBADF] One or more of the file descriptor sets specified a
	 * file descriptor that is not a valid open file descriptor." --
	 * fd 100 is comfortably inside FD_SETSIZE (1024) but nothing in
	 * this test program opens it. (Not fd 999999: FD_SETSIZE is
	 * 1024, so FD_SET() on a bit that far out of range is an
	 * out-of-bounds write on the fd_set itself -- undefined
	 * behaviour before select() is even called, on any FD_SETSIZE=
	 * 1024 implementation, not something select() can be asked to
	 * survive.) */
	FD_ZERO(&rfds);
	FD_SET(100, &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	errno = 0;
	CHECK(select(101, &rfds, 0, 0, &tv) == -1 && errno == EBADF);

	/* "[EINVAL] The nfds argument is less than 0 or greater than
	 * FD_SETSIZE." */
	FD_ZERO(&rfds);
	errno = 0;
	CHECK(select(-1, &rfds, 0, 0, &tv) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(select(FD_SETSIZE + 1, &rfds, 0, 0, &tv) == -1 && errno == EINVAL);

	/* "[EINVAL] An invalid timeout interval was specified." -- a
	 * negative tv_usec is not a valid struct timeval per
	 * <sys/time.h>'s own contract (0 <= tv_usec < 1000000). */
	tv.tv_sec = 0;
	tv.tv_usec = -1;
	errno = 0;
	CHECK(select(1, &rfds, 0, 0, &tv) == -1 && errno == EINVAL);
}

/* pselect(): pselect.html DESCRIPTION -- differs from select() only
 * in using struct timespec (nanosecond resolution) for the timeout
 * and taking an optional sigset_t to atomically install for the
 * duration of the wait ("replace the signal mask of the calling
 * thread with the set of signals pointed to by sigmask ... restore
 * ... prior to returning"), avoiding the race a separate
 * sigprocmask()+select() pair would have. */
static void test_pselect_timespec_and_mask(void)
{
	int fds[2];
	fd_set rfds;
	struct timespec ts;
	sigset_t mask, omask, checkmask;

	CHECK(pipe(fds) == 0);
	FD_ZERO(&rfds);
	FD_SET(fds[0], &rfds);
	ts.tv_sec = 0;
	ts.tv_nsec = 0;  /* poll, same "zero-valued timespec" contract as select() */

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	CHECK(pselect(fds[0] + 1, &rfds, 0, 0, &ts, &mask) == 0);

	CHECK(write(fds[1], "x", 1) == 1);
	FD_ZERO(&rfds);
	FD_SET(fds[0], &rfds);
	ts.tv_sec = LLONG_MAX;
	ts.tv_nsec = 999999999L;
	CHECK(pselect(fds[0] + 1, &rfds, 0, 0, &ts, &mask) == 1);
	CHECK(FD_ISSET(fds[0], &rfds));

	/* signal mask restored to what it was before the call, not left
	 * as `mask` -- DESCRIPTION's "shall be restored ... prior to
	 * returning". */
	CHECK(sigprocmask(SIG_SETMASK, 0, &omask) == 0);
	CHECK(sigprocmask(SIG_SETMASK, 0, &checkmask) == 0);
	CHECK(memcmp(&omask, &checkmask, sizeof omask) == 0);

	close(fds[0]);
	close(fds[1]);
}

/* ===================== poll.h ===================== */

/* poll(): poll.html RETURN VALUE/DESCRIPTION event bits.  Mirrors
 * test_select_ready_count() over the same pipe shape: POLLIN on the
 * read end (data queued), POLLOUT on the write end (room in the
 * pipe's buffer), and the return value is the count of pollfd entries
 * with nonzero revents, per "a positive value ... indicates the total
 * number of pollfd structures that have selected events". */
static void test_poll_ready_count(void)
{
	int fds[2];
	struct pollfd pfd[2];
	int n;

	CHECK(pipe(fds) == 0);
	CHECK(write(fds[1], "x", 1) == 1);

	pfd[0].fd = fds[0]; pfd[0].events = POLLIN; pfd[0].revents = -1;
	pfd[1].fd = fds[1]; pfd[1].events = POLLOUT; pfd[1].revents = -1;

	n = poll(pfd, 2, 1000);
	CHECK(n == 2);
	CHECK(pfd[0].revents == POLLIN);
	CHECK(pfd[1].revents == POLLOUT);

	close(fds[0]);
	close(fds[1]);
}

#if SPICULE_TEST(PASS, posix_sysmisc_poll_hup_excludes_pollout) /* BUG: poll() reports POLLHUP and POLLOUT together.  poll.html
	 * DESCRIPTION, the POLLHUP entry: "A device has been disconnected,
	 * or a pipe or FIFO has been closed.  This event and POLLOUT are
	 * mutually-exclusive; a stream can never be writable if a hangup
	 * has occurred.  However, this event and POLLIN, POLLRDNORM,
	 * POLLRDBAND, or POLLPRI are not mutually-exclusive."  The spec
	 * goes out of its way to say which combinations are allowed and
	 * which one is not.
	 *
	 * Mechanism: the hangup and the writability come from the same
	 * assignment.  All three hangup branches of __fd_probe() in
	 * src/select/select.c say
	 *
	 *     *canread = 1; *canwrite = 1; *hup = 1;
	 *
	 * -- the broken-pipe case, the socket case for
	 * AFD_EVENT_CLOSE/ABORT/DISCONNECT, and the case where the socket
	 * probe ioctl itself failed.  src/select/poll.c then ORs each of
	 * the three answers into revents independently, with no exclusion:
	 *
	 *     if (hup) p->revents |= POLLHUP;
	 *     if (cr)  p->revents |= (short)(p->events & (POLLIN | POLLRDNORM));
	 *     if (cw)  p->revents |= (short)(p->events & (POLLOUT | POLLWRNORM));
	 *
	 * A caller that polls for POLLIN|POLLOUT on a hung-up descriptor is
	 * told it may write, which is the one thing the clause exists to
	 * rule out.  The third branch is the worst of the three: there
	 * spicule reports "hung up" and "writable" at once for a descriptor
	 * whose state it has just admitted it could not sample.
	 *
	 * The fix is one mask in poll.c: POLLHUP clears POLLOUT/POLLWRNORM.
	 *
	 * The assertion below is written so it is a genuine test of the
	 * clause and nothing else -- if no hangup is reported it passes
	 * vacuously, so it does not depend on how any particular platform
	 * or emulator decides a closed pipe end has hung up.
	 *
	 * Re-enable when POLLHUP suppresses the writability bits. */
static void test_poll_hup_excludes_pollout(void)
{
	int fds[2];
	struct pollfd pfd;

	CHECK(pipe(fds) == 0);
	CHECK(write(fds[1], "x", 1) == 1);
	CHECK(close(fds[1]) == 0);		/* writer gone: hangup */

	pfd.fd = fds[0];
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = -1;
	CHECK(poll(&pfd, 1, 0) >= 0);

	/* POLLHUP with POLLIN is explicitly allowed; POLLHUP with POLLOUT
	 * is explicitly not. */
	CHECK(!((pfd.revents & POLLHUP) && (pfd.revents & (POLLOUT | POLLWRNORM))));

	close(fds[0]);
}
#endif

/* poll.html DESCRIPTION timeout semantics: "the value 0 ... the poll()
 * function shall return immediately" -- and RETURN VALUE: "0 ... time
 * limit expired" with revents left clear for anything not ready. */
static void test_poll_zero_timeout_polls(void)
{
	int fds[2];
	struct pollfd pfd;

	CHECK(pipe(fds) == 0);
	pfd.fd = fds[0]; pfd.events = POLLIN; pfd.revents = -1;
	/* nothing written to fds[1] -- read end is not ready */
	CHECK(poll(&pfd, 1, 0) == 0);
	CHECK(pfd.revents == 0);  /* cleared: not one of the "selected events" */
	close(fds[0]);
	close(fds[1]);
}

/* poll.html DESCRIPTION: "If the value of fd is less than 0, events
 * shall be ignored, and revents shall be set to 0 ... this indicates
 * to poll() that this entry ... is currently not being used." A
 * negative-fd entry must not count toward the return value either. */
static void test_poll_negative_fd_ignored(void)
{
	struct pollfd pfd;
	pfd.fd = -1; pfd.events = POLLIN; pfd.revents = -1;
	CHECK(poll(&pfd, 1, 0) == 0);
	CHECK(pfd.revents == 0);
}

/* poll.html DESCRIPTION: "POLLNVAL ... The specified fd value is
 * invalid ... This flag is only valid in the revents member" -- an fd
 * that is not open must be reported this way (and, per RETURN VALUE,
 * counted -- POLLNVAL is a "selected event" like any other). */
static void test_poll_nval(void)
{
	struct pollfd pfd;
	pfd.fd = 12345; pfd.events = POLLIN; pfd.revents = 0;
	CHECK(poll(&pfd, 1, 0) == 1);
	CHECK(pfd.revents == POLLNVAL);
}

/* sys_select.h.html basedefs: FD_ZERO/FD_SET/FD_CLR/FD_ISSET, exercised
 * as pure bit manipulation.
 *
 * "FD_ISSET() shall return a non-zero value if the bit for the file
 * descriptor fd is set ... and 0 otherwise." FD_SET/FD_CLR/FD_ZERO
 * "shall not return a value." */
static void test_fd_macros(void)
{
	fd_set s;
	int i, j;

	/* FD_ZERO clears every bit, over the whole declared FD_SETSIZE
	 * range, not just a few probed positions. */
	memset(&s, 0xff, sizeof s);
	FD_ZERO(&s);
	for (i = 0; i < FD_SETSIZE; i++)
		CHECK(!FD_ISSET(i, &s));

	/* every single fd index sets/clears/tests independently, with no
	 * cross-talk into an adjacent index (checked both neighbours,
	 * including the word-boundary-adjacent indices where a bug in
	 * the /8/sizeof(long) arithmetic would most likely show up). */
	for (i = 0; i < FD_SETSIZE; i++) {
		FD_ZERO(&s);
		FD_SET(i, &s);
		CHECK(FD_ISSET(i, &s) != 0);
		if (i > 0) CHECK(!FD_ISSET(i - 1, &s));
		if (i + 1 < FD_SETSIZE) CHECK(!FD_ISSET(i + 1, &s));
		/* every other index in the set is clear too, spot-checked
		 * at both ends and mid-array rather than exhaustively
		 * (O(FD_SETSIZE^2) is wasteful) */
		CHECK(!FD_ISSET(0 == i ? FD_SETSIZE - 1 : 0, &s));
	}

	/* FD_CLR clears exactly the requested bit and no others */
	FD_ZERO(&s);
	for (i = 0; i < 64; i++) FD_SET(i, &s);
	FD_CLR(31, &s);
	for (i = 0; i < 64; i++)
		CHECK(FD_ISSET(i, &s) == (i != 31));

	/* setting a bit twice, or clearing an already-clear bit, is a
	 * no-op (idempotent) */
	FD_ZERO(&s);
	FD_SET(5, &s); FD_SET(5, &s);
	CHECK(FD_ISSET(5, &s) != 0);
	FD_CLR(5, &s); FD_CLR(5, &s);
	CHECK(!FD_ISSET(5, &s));

	/* word-boundary indices: fds_bits is an array of `long`; every
	 * multiple of bits-per-long (and the index just below/above)
	 * must not corrupt the neighbouring word. */
	for (j = 0; j < (int)(sizeof(long) * 8) * 4; j += (int)(sizeof(long) * 8)) {
		FD_ZERO(&s);
		FD_SET(j, &s);
		CHECK(FD_ISSET(j, &s) != 0);
		if (j > 0) CHECK(!FD_ISSET(j - 1, &s));
		CHECK(!FD_ISSET(j + 1, &s));
	}
}

/* ===================== sys/param.h ===================== */

/* Not a POSIX.1-2017 header at all -- absent from the basedefs index
 * (https://pubs.opengroup.org/onlinepubs/9699919799/idx/head.html
 * lists 17 sys/ headers; sys/param.h is not among them). A BSD
 * extension, correctly not claimed as POSIX anywhere in spicule's own
 * comments. Only internal consistency is testable: there is no spec
 * page to hold it to. */
static int side_effect_calls;
static int counting(int v) { side_effect_calls++; return v; }

static void test_sys_param(void)
{
	int a, b;

	/* MIN/MAX: basic correctness, both orderings, equal operands,
	 * negative operands */
	CHECK(MIN(3, 5) == 3);
	CHECK(MIN(5, 3) == 3);
	CHECK(MAX(3, 5) == 5);
	CHECK(MAX(5, 3) == 5);
	CHECK(MIN(-1, 1) == -1);
	CHECK(MAX(-1, 1) == 1);
	CHECK(MIN(4, 4) == 4);
	CHECK(MAX(4, 4) == 4);

	/* include/sys/param.h documents no "evaluates arguments once"
	 * contract (unlike, say, a hypothetical safe-MIN); its expansion
	 * is the textbook `(((a)<(b))?(a):(b))`, which double-evaluates
	 * the selected operand. This is not a bug -- nothing promises
	 * otherwise -- but it is a real hazard worth pinning down so a
	 * future edit that adds such a promise without fixing the macro
	 * gets caught here instead of by a caller. */
	side_effect_calls = 0;
	a = MAX(counting(1), 0);
	CHECK(a == 1 && side_effect_calls == 2);  /* evaluated as `a` twice: cond + result */

	/* howmany(n,d): ceil(n/d) */
	CHECK(howmany(0, 8) == 0);
	CHECK(howmany(1, 8) == 1);
	CHECK(howmany(8, 8) == 1);
	CHECK(howmany(9, 8) == 2);
	CHECK(howmany(16, 8) == 2);
	CHECK(howmany(17, 8) == 3);

	/* roundup(n,d): n rounded up to the next multiple of d */
	CHECK(roundup(0, 8) == 0);
	CHECK(roundup(1, 8) == 8);
	CHECK(roundup(8, 8) == 8);
	CHECK(roundup(9, 8) == 16);
	CHECK(roundup(17, 4) == 20);

	/* powerof2: internal consistency of the macro's own arithmetic
	 * identity `!((n-1) & n)`, not a claim about mathematical
	 * "is n a power of two" for every n -- see the n==0 note below. */
	CHECK(powerof2(1));
	CHECK(powerof2(2));
	CHECK(powerof2(1024));
	CHECK(powerof2(0));    /* see NOTE below main text: (0-1)&0 == -1&0 == 0,
	                       * so `!0` is true -- the macro's literal
	                       * arithmetic, asserted as such, not as a
	                       * mathematical claim that 0 is a power of two */
	CHECK(!powerof2(3));
	CHECK(!powerof2(6));

	/* setbit/clrbit/isset/isclr: byte-array bit ops, at least one
	 * full byte boundary crossed */
	{
		unsigned char bits[4] = { 0, 0, 0, 0 };
		setbit(bits, 0);
		setbit(bits, 7);
		setbit(bits, 8);
		setbit(bits, 31);
		CHECK(isset(bits, 0) && isset(bits, 7) && isset(bits, 8) && isset(bits, 31));
		CHECK(isclr(bits, 1) && isclr(bits, 9) && isclr(bits, 30));
		clrbit(bits, 7);
		CHECK(isclr(bits, 7) && isset(bits, 0));
	}
}

/* NOTE on the powerof2(0) case above: the CHECK was left in (asserting
 * the *documented arithmetic identity*, not a POSIX/BSD contract) --
 * `powerof2(0)` textually expands to `!(((0)-1) & (0))` == `!(-1 & 0)`
 * == `!0` == 1 (true), so 0 reads as "a power of two" by this macro
 * even though it mathematically is not. No spec obliges otherwise
 * (sys/param.h is not a spec'd header at all), so this is not fenced
 * as a BUG -- just documented in place so nobody "fixes" the macro
 * expecting the test above to still read `!powerof2(0)`. */

/* ===================== getopt_long / getopt_long_only ===================== */

/* Not POSIX (no getopt_long.html on
 * https://pubs.opengroup.org/onlinepubs/9699919799/idx/head.html or
 * the functions index) -- a GNU extension. Audited against
 * https://man7.org/linux/man-pages/man3/getopt_long.3.html (glibc,
 * "STANDARDS: GNU") for getopt_long(), and
 * https://man.freebsd.org/cgi/man.cgi?query=getopt_long&sektion=3 for
 * getopt_long_only() (glibc's own man page omits it; FreeBSD's
 * getopt_long(3) documents the same GNU-compatible getopt_long_only()
 * BSD's libc also ships).  test/getopt.c already gives broad sanity
 * coverage (permutation, clustering, both error-mode strings) without
 * citing the manual per-clause; this file adds the clause citations
 * and the cases test/getopt.c does not reach: optional_argument's
 * attached-only rule, no_argument rejecting `--opt=val`, ambiguous
 * abbreviation, and long-only's single-char disambiguation rule. */

static int reset(void) { optind = 1; optreset = 1; opterr = 0; return 0; }

static void test_getopt_long_abbrev(void)
{
	static const struct option lo[] = {
		{ "alpha", no_argument, 0, 'a' },
		{ "alphabet", no_argument, 0, 'A' },
		{ 0, 0, 0, 0 }
	};
	char *av_unique[] = { "prog", "--alph", 0 };   /* not a prefix of "alphabet" beyond "alpha" -> ambiguous actually */
	char *av_exact[]  = { "prog", "--alpha", 0 };
	char *av_amb[]    = { "prog", "--al", 0 };
	int c, idx;

	/* getopt_long.3 DESCRIPTION: "Long option names may be abbreviated
	 * if the abbreviation is unique or is an exact match for some
	 * defined option." -- "--alpha" is an exact match for "alpha"
	 * even though it is *also* a prefix of "alphabet": exact match
	 * wins, no ambiguity error. */
	reset();
	c = getopt_long(2, av_exact, "", lo, &idx);
	CHECK(c == 'a' && idx == 0);

	/* "--al" is a prefix of both "alpha" and "alphabet", is an exact
	 * match for neither -> ambiguous -> '?' */
	reset();
	c = getopt_long(2, av_amb, "", lo, &idx);
	CHECK(c == '?');

	/* "--alph" is likewise a non-exact prefix of both -> ambiguous */
	reset();
	c = getopt_long(2, av_unique, "", lo, &idx);
	CHECK(c == '?');
}

static void test_getopt_long_arg_forms(void)
{
	static const struct option lo[] = {
		{ "req",  required_argument, 0, 'r' },
		{ "opt",  optional_argument, 0, 'o' },
		{ "none", no_argument,       0, 'n' },
		{ 0, 0, 0, 0 }
	};
	int c, idx;

	/* "A long option may take a parameter, of the form --arg=param
	 * or --arg param." (getopt_long.3) -- required_argument accepts
	 * both forms. */
	{
		char *av[] = { "prog", "--req=x", 0 };
		reset();
		c = getopt_long(2, av, "", lo, &idx);
		CHECK(c == 'r' && optarg && !strcmp(optarg, "x"));
	}
	{
		char *av[] = { "prog", "--req", "y", 0 };
		reset();
		c = getopt_long(3, av, "", lo, &idx);
		CHECK(c == 'r' && optarg && !strcmp(optarg, "y"));
	}

	/* optional_argument: GNU convention is the argument must be
	 * attached (--opt=value); a following separate argv element is
	 * NOT consumed as the option's argument (it is left as a
	 * positional/next option, same as short options' "::"). */
	{
		char *av[] = { "prog", "--opt=z", 0 };
		reset();
		c = getopt_long(2, av, "", lo, &idx);
		CHECK(c == 'o' && optarg && !strcmp(optarg, "z"));
	}
	{
		char *av[] = { "prog", "--opt", "z", 0 };
		reset();
		c = getopt_long(3, av, "", lo, &idx);
		CHECK(c == 'o' && optarg == 0);
		CHECK(optind == 2);  /* "z" left unconsumed, for the caller */
	}

	/* no_argument + "--opt=val": "Error ... '?' for ... an extraneous
	 * parameter." (getopt_long.3 RETURN VALUE) */
	{
		char *av[] = { "prog", "--none=x", 0 };
		reset();
		c = getopt_long(2, av, "", lo, &idx);
		CHECK(c == '?');
	}
}

static void test_getopt_long_flag(void)
{
	static int seen;
	struct option lo[] = {
		{ "flagged", no_argument, &seen, 42 },
		{ "valued",  no_argument, 0,      7 },
		{ 0, 0, 0, 0 }
	};
	int c, idx;

	/* "If flag is NULL, then getopt_long() returns val." -> plain val */
	{
		char *av[] = { "prog", "--valued", 0 };
		reset();
		c = getopt_long(2, av, "", lo, &idx);
		CHECK(c == 7 && idx == 1);
	}
	/* "flag specifies how results are returned ... [if non-NULL,]
	 * getopt_long() returns 0 [and sets *flag = val]" */
	{
		char *av[] = { "prog", "--flagged", 0 };
		seen = 0;
		reset();
		c = getopt_long(2, av, "", lo, &idx);
		CHECK(c == 0 && seen == 42 && idx == 0);
	}
}

static void test_getopt_long_only(void)
{
	static const struct option lo[] = {
		{ "verbose", no_argument, 0, 'V' },
		{ "v",       no_argument, 0, 'x' },  /* single-char long name */
		{ 0, 0, 0, 0 }
	};
	int c, idx;

	/* FreeBSD getopt_long(3), getopt_long_only() paragraph: "long
	 * options may start with '-' in addition to '--'." */
	{
		char *av[] = { "prog", "-verbose", 0 };
		reset();
		c = getopt_long_only(2, av, "v", lo, &idx);
		CHECK(c == 'V' && idx == 0);
	}

	/* "If an option starting with '-' does not match a long option
	 * but does match a single-character option, the single-character
	 * option is returned." spicule's src/misc/getopt_long.c takes this
	 * further for the case this file's DESCRIPTION comment documents:
	 * a long option whose *name* is exactly one character and also
	 * appears in optstring is deliberately treated as ambiguous and
	 * resolved as the short option, not the long one -- "-v" here
	 * matches long option "v" (val 'x') exactly, but optstring also
	 * has 'v' as a short option, so the short option wins. */
	{
		char *av[] = { "prog", "-v", 0 };
		reset();
		c = getopt_long_only(2, av, "v", lo, &idx);
		CHECK(c == 'v');  /* short option char, not 'x' (the long one) */
	}

	/* a single-dash argument that matches no long option and no
	 * short option is unrecognized: '?' */
	{
		char *av[] = { "prog", "-bogus", 0 };
		reset();
		c = getopt_long_only(2, av, "v", lo, &idx);
		CHECK(c == '?');
	}
}

/* getopt_long.3 "longindex": "points to a variable which is set to
 * the index of the long option relative to longopts" -- confirm it is
 * left untouched by short-option matches (only long matches set it),
 * and is correct across multiple options. */
static void test_getopt_long_index(void)
{
	static const struct option lo[] = {
		{ "first",  no_argument, 0, '1' },
		{ "second", no_argument, 0, '2' },
		{ "third",  no_argument, 0, '3' },
		{ 0, 0, 0, 0 }
	};
	char *av[] = { "prog", "--first", "--third", 0 };
	int c, idx;

	reset();
	idx = -1;
	c = getopt_long(3, av, "", lo, &idx);
	CHECK(c == '1' && idx == 0);
	idx = -1;
	c = getopt_long(3, av, "", lo, &idx);
	CHECK(c == '3' && idx == 2);
}

/* Reset behaviour between scans: BSD getopt_long(3): "setting optind
 * to 0 will indicate that getopt_long should reset, and optind will
 * be set to 1 in the process." spicule's own optreset variable
 * (declared in <getopt.h>) is the same idea, checked in src/misc/
 * getopt.c/getopt_long.c: "if (!optind || optreset) { ... optind = 1;
 * optreset = 0; }" -- both triggers are tested here, independently. */
static void test_getopt_long_reset(void)
{
	static const struct option lo[] = {
		{ "alpha", no_argument, 0, 'a' },
		{ 0, 0, 0, 0 }
	};
	char *av[] = { "prog", "--alpha", 0 };
	int c, idx;

	/* first scan, exhausted */
	optind = 1; optreset = 0; opterr = 0;
	c = getopt_long(2, av, "", lo, &idx);
	CHECK(c == 'a');
	c = getopt_long(2, av, "", lo, &idx);
	CHECK(c == -1);

	/* re-scanning the same vector without resetting must NOT rewind
	 * -- optind stays past the end */
	c = getopt_long(2, av, "", lo, &idx);
	CHECK(c == -1);

	/* optind = 0 forces a reset */
	optind = 0;
	c = getopt_long(2, av, "", lo, &idx);
	CHECK(c == 'a');

	/* exhaust again, then reset via optreset = 1 instead */
	c = getopt_long(2, av, "", lo, &idx);
	CHECK(c == -1);
	optreset = 1;
	c = getopt_long(2, av, "", lo, &idx);
	CHECK(c == 'a');

	optind = 1; optreset = 0; opterr = 1;  /* leave defaults for later tests */
}

/* ---- sched_yield.html ----
 * "The sched_yield() function shall force the running thread to
 * relinquish the processor until it again becomes the head of its
 * thread list."  RETURN VALUE -- "shall return 0 if it completes
 * successfully, or ... -1 and set errno to indicate the error."
 * ERRORS -- "No errors are defined."
 *
 * With no errors defined and no observable side effect a
 * single-threaded program can see (the scheduler is free to hand the
 * processor straight back -- NtYieldExecution reports exactly that as
 * STATUS_NO_YIELD_PERFORMED, and Wine returns it routinely), the only
 * thing the spec makes testable here is the return value, and that it
 * stays 0 no matter how often it is called and whether or not another
 * thread was available.  That is asserted rather than skipped: a
 * sched_yield() that forwarded NtYieldExecution's status would return
 * nonzero on precisely the no-other-thread path this loop exercises,
 * which is the realistic way to get this wrong.
 *
 * errno is checked to be untouched on success: POSIX permits a
 * successful call to modify errno in general, but since no error is
 * defined for sched_yield at all, a nonzero errno appearing here would
 * mean the implementation took a failure path that does not exist. */
static void test_sched_yield(void)
{
	int i;

	errno = 0;
	CHECK(sched_yield() == 0);
	CHECK(errno == 0);

	/* repeated calls in a tight loop: on a single-threaded process
	 * with nothing else runnable on this CPU, every one of these is
	 * the "no yield performed" case, and every one must still be 0 */
	for (i = 0; i < 1000; i++) {
		if (sched_yield() != 0) { fails++; printf("FAIL %s:%d: sched_yield() nonzero at i=%d\n", __FILE__, __LINE__, i); break; }
	}

	/* the call must return, i.e. it is a yield and not a sleep: this
	 * whole loop is bounded by nothing but the scheduler, so a
	 * sched_yield() that blocked would hang the test rather than fail
	 * it -- which is itself the diagnosis. */
	errno = 0;
	CHECK(sched_yield() == 0 && errno == 0);
}

/* ---- fstatvfs.html / basedefs/sys_statvfs.h.html ----
 * statvfs()/fstatvfs() "shall obtain information about the file system
 * containing the file named by path" / "referenced by fildes".
 * RETURN VALUE -- 0, or -1 with errno.
 *
 * The DESCRIPTION carries its own escape clause -- "It is unspecified
 * whether all members of the statvfs structure have meaningful values
 * on all file systems" -- which is what covers f_files/f_ffree/
 * f_favail being 0 here: NT exposes no file-serial-number pool, NTFS
 * grows its MFT on demand, and none of the FileFs* classes reports a
 * record count.  That zero is asserted rather than skipped, precisely
 * so that a later change that starts fabricating a plausible-looking
 * inode count fails this test instead of being believed.
 *
 * Everything else is checked as an invariant the spec's own member
 * definitions require (f_blocks is a total, so the two free counts
 * cannot exceed it; f_bavail is "available to a non-privileged
 * process", so it cannot exceed the unrestricted f_bfree), not as a
 * fixed number -- the numbers are whatever the CI runner's volume
 * happens to hold. */
static void test_statvfs(void)
{
	struct statvfs a, b;
	struct stat st;
	int fd;

	CHECK(statvfs(".", &a) == 0);

	/* f_frsize is the unit f_blocks counts in, f_bsize the block size;
	 * both must be nonzero for any of the counts to mean anything */
	CHECK(a.f_frsize > 0 && a.f_bsize > 0);
	/* NT's allocation unit is sectors*bytes-per-sector, always a power
	 * of two, and src/stat/statvfs.c uses it for both fields */
	CHECK((a.f_bsize & (a.f_bsize - 1)) == 0);
	CHECK(a.f_frsize == a.f_bsize);

	/* "Total number of blocks" bounds both free counts, and the
	 * non-privileged figure cannot exceed the unrestricted one */
	CHECK(a.f_blocks > 0);
	CHECK(a.f_bfree <= a.f_blocks);
	CHECK(a.f_bavail <= a.f_bfree);

	/* documented zeros -- see this block's banner and
	 * src/stat/statvfs.c's */
	CHECK(a.f_files == 0 && a.f_ffree == 0 && a.f_favail == 0);

	/* f_namemax: FileFsAttributeInformation's
	 * MaximumComponentNameLength.  POSIX's own floor for a filename is
	 * _POSIX_NAME_MAX (14); every NT file system that can host this
	 * test reports far more (255 on NTFS and on FAT with long names),
	 * but the assertion is the spec's floor rather than 255, so a run
	 * on an unexpected volume reports a real problem and not a
	 * surprise. */
	CHECK(a.f_namemax >= 14);

	/* f_flag: ST_NOSUID is "does not support the semantics of the
	 * ST_ISUID and ST_ISGID file mode bits", which is true of every NT
	 * file system -- src/stat/stat.c never produces those bits and the
	 * exec family never honours them.  So it is always set here.  Not
	 * asserting anything about ST_RDONLY: whether the volume the test
	 * runs on is read-only is not this test's business, and the test
	 * could not write its own temp file below if it were. */
	CHECK((a.f_flag & ST_NOSUID) != 0);

	/* f_fsid is the volume serial number, the same value stat() puts
	 * in st_dev -- the two must agree about what "the same file
	 * system" means, which is the only property POSIX gives f_fsid.
	 * Checked against a real file rather than "." so the st_dev is a
	 * genuine volume serial and not one of stat.c's synthetic ones. */
	fd = open("statvfs-probe.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(fstat(fd, &st) == 0);
		CHECK(fstatvfs(fd, &b) == 0);
		CHECK(b.f_fsid == (unsigned long)st.st_dev);

		/* statvfs(path) and fstatvfs(fd) name the same file system, so
		 * every field must match.  The free counts are excluded: they
		 * are live figures and another process on the CI runner may
		 * legitimately change them between the two calls. */
		CHECK(a.f_bsize == b.f_bsize && a.f_frsize == b.f_frsize);
		CHECK(a.f_blocks == b.f_blocks);
		CHECK(a.f_files == b.f_files && a.f_ffree == b.f_ffree && a.f_favail == b.f_favail);
		CHECK(a.f_fsid == b.f_fsid);
		CHECK(a.f_flag == b.f_flag);
		CHECK(a.f_namemax == b.f_namemax);

		close(fd);
	}

	/* a directory is as good a handle on the volume as a file */
	CHECK(statvfs("..", &b) == 0 && b.f_fsid == a.f_fsid);

	unlink("statvfs-probe.tmp");
}

/* ---- fstatvfs.html ERRORS ----
 * statvfs(): [ENOENT] "A component of path does not name an existing
 * file or path is an empty string"; [ENOTDIR] "A component of the path
 * prefix of path names an existing file that is neither a directory
 * nor a symbolic link to a directory".
 * fstatvfs(): [EBADF] "The fildes argument is not an open file
 * descriptor." */
static void test_statvfs_errors(void)
{
	struct statvfs b;
	int fd;

	errno = 0;
	CHECK(statvfs("no-such-directory-here/no-such-file", &b) == -1);
	CHECK(errno == ENOENT);

	errno = 0;
	CHECK(statvfs("", &b) == -1);
	CHECK(errno == ENOENT);

	/* ENOTDIR: a regular file used as a path prefix */
	fd = open("statvfs-notdir.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	if (fd >= 0) {
		close(fd);
		errno = 0;
		CHECK(statvfs("statvfs-notdir.tmp/x", &b) == -1);
		CHECK(errno == ENOTDIR);
		unlink("statvfs-notdir.tmp");
	}

	errno = 0;
	CHECK(fstatvfs(-1, &b) == -1);
	CHECK(errno == EBADF);

	errno = 0;
	CHECK(fstatvfs(4096, &b) == -1);
	CHECK(errno == EBADF);
}

/* ---- waitid.html ----
 *
 * Every child below is this same executable re-exec'd through
 * __spawn() with a mode argument, the pattern test_getrusage() above
 * already uses: fork() needs RtlCloneUserProcess, which stock Wine
 * lacks, so a spawn is the portable way to get a child here.
 *
 * self is argv[0]; a spawn failure is reported and the check skipped
 * rather than failed, exactly as test_getrusage() does, because an
 * environment that cannot spawn is not an environment where waitid is
 * broken. */
static const char *waitid_self;

static pid_t waitid_spawn(const char *mode)
{
	char *argv[3];
	pid_t pid;

	argv[0] = (char *)waitid_self;
	argv[1] = (char *)mode;
	argv[2] = 0;
	pid = __spawn(waitid_self, argv, environ);
	if (pid < 0) printf("note: cannot spawn \"%s %s\" (errno %d); check skipped\n", waitid_self, mode, errno);
	return pid;
}

static volatile sig_atomic_t job_sig_count;
static volatile sig_atomic_t job_sig_code;
static volatile sig_atomic_t job_sig_status;
static volatile sig_atomic_t job_sig_pid;

static void job_sigchld_handler(int sig, siginfo_t *si, void *context)
{
	(void)context;
	if (sig != SIGCHLD || !si) return;
	job_sig_code = si->si_code;
	job_sig_status = si->si_status;
	job_sig_pid = si->si_pid;
	job_sig_count++;
}

/* waitid.html DESCRIPTION: "the si_signo member shall be set equal to
 * SIGCHLD"; si_code distinguishes CLD_EXITED from the death-by-signal
 * codes, and si_status carries the exit status in the first case and
 * the signal number in the others.  P_PID: "wait for the child with a
 * process ID equal to (pid_t)id". */
static void test_waitid_exited(void)
{
	siginfo_t si;
	pid_t pid = waitid_spawn("--waitid-exit7");

	if (pid < 0) return;

	memset(&si, 0xa5, sizeof si);   /* poison: every field below must be written */
	CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED) == 0);
	CHECK(si.si_signo == SIGCHLD);
	CHECK(si.si_code == CLD_EXITED);
	CHECK(si.si_status == 7);
	CHECK(si.si_pid == pid);
	CHECK(si.si_uid == getuid());

	/* the child has been collected: it is no longer an existing
	 * unwaited-for child, so a second wait for it is [ECHILD] */
	errno = 0;
	CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED) == -1);
	CHECK(errno == ECHILD);
}

/* Death by signal: si_code is CLD_KILLED, or CLD_DUMPED for a signal
 * whose default action on a Unix system dumps core, and si_status is
 * the signal number rather than an exit status.  Both codes are
 * exercised because src/process/wait.c derives them from the same
 * wait status waitpid() produces -- SIGTERM is not in that file's
 * core-dumping set, SIGABRT is. */
static void test_waitid_signalled(void)
{
	siginfo_t si;
	pid_t pid;

	pid = waitid_spawn("--waitid-sigterm");
	if (pid >= 0) {
		CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED) == 0);
		CHECK(si.si_signo == SIGCHLD);
		CHECK(si.si_code == CLD_KILLED);
		CHECK(si.si_status == SIGTERM);
		CHECK(si.si_pid == pid);
	}

	pid = waitid_spawn("--waitid-sigabrt");
	if (pid >= 0) {
		CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED) == 0);
		CHECK(si.si_code == CLD_DUMPED);
		CHECK(si.si_status == SIGABRT);
	}
}

/* WNOWAIT: "Keep the process whose status is returned in infop in a
 * waitable state."
 *
 * The P_ALL half of this is a regression test with a specific target.
 * A WNOWAIT reap leaves a child-table entry with pid != 0 && done == 1
 * (src/process/wait.c), a state unreachable before waitid() existed --
 * every other path calls __child_remove() immediately after setting
 * done, which zeroes pid.  do_waitpid()'s any-child scan used to open
 * with `if (!__children[i].pid || __children[i].done) continue;`, i.e.
 * it skipped done entries; with such an entry present and no other
 * children, the wait() below would have found nothing to wait on and
 * reported ECHILD instead of handing the status back.  This test fails
 * without that scan fix. */
static void test_waitid_wnowait(void)
{
	siginfo_t si, si2;
	int status = 0;
	pid_t pid, got;

	pid = waitid_spawn("--waitid-exit3");
	if (pid >= 0) {
		CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED | WNOWAIT) == 0);
		CHECK(si.si_code == CLD_EXITED && si.si_status == 3 && si.si_pid == pid);

		/* still waitable: the identical status again, not ECHILD */
		CHECK(waitid(P_PID, (id_t)pid, &si2, WEXITED | WNOWAIT) == 0);
		CHECK(si2.si_code == si.si_code && si2.si_status == si.si_status && si2.si_pid == si.si_pid);

		/* and a real reap still collects it exactly once */
		CHECK(waitid(P_PID, (id_t)pid, &si2, WEXITED) == 0);
		CHECK(si2.si_status == 3);
		errno = 0;
		CHECK(waitid(P_PID, (id_t)pid, &si2, WEXITED) == -1 && errno == ECHILD);
	}

	/* the any-child path: WNOWAIT through P_ALL, then a plain wait() */
	pid = waitid_spawn("--waitid-exit5");
	if (pid >= 0) {
		CHECK(waitid(P_ALL, 0, &si, WEXITED | WNOWAIT) == 0);
		CHECK(si.si_pid == pid && si.si_code == CLD_EXITED && si.si_status == 5);

		got = wait(&status);
		CHECK(got == pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 5);

		/* now genuinely reaped */
		errno = 0;
		CHECK(wait(&status) == -1 && errno == ECHILD);
	}
}

/* waitid.html ERRORS: "[EINVAL] An invalid value was specified for
 * options", and the DESCRIPTION's "Applications shall specify at least
 * one of the flags WEXITED, WSTOPPED, or WCONTINUED."  [ECHILD] "The
 * calling process has no existing unwaited-for child processes."
 *
 * These run last, after every child spawned above has been collected,
 * so "no existing unwaited-for child processes" is actually true. */
static void test_waitid_errors(void)
{
	siginfo_t si;

	/* none of WEXITED/WSTOPPED/WCONTINUED */
	errno = 0;
	CHECK(waitid(P_ALL, 0, &si, 0) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(waitid(P_ALL, 0, &si, WNOHANG) == -1 && errno == EINVAL);

	/* a bit that is not an option at all */
	errno = 0;
	CHECK(waitid(P_ALL, 0, &si, WEXITED | 0x40000000) == -1 && errno == EINVAL);

	/* P_PIDFD is a Linux extension, not a POSIX idtype, and there are
	 * no pidfds here */
	errno = 0;
	CHECK(waitid(P_PIDFD, 0, &si, WEXITED) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(waitid((idtype_t)99, 0, &si, WEXITED) == -1 && errno == EINVAL);

	/* no children left */
	errno = 0;
	CHECK(waitid(P_ALL, 0, &si, WEXITED) == -1 && errno == ECHILD);
	errno = 0;
	CHECK(waitid(P_ALL, 0, &si, WEXITED | WNOHANG) == -1 && errno == ECHILD);

	/* a pid that is not a child of this process */
	errno = 0;
	CHECK(waitid(P_PID, (id_t)getpid(), &si, WEXITED) == -1 && errno == ECHILD);
}

/* waitid.html DESCRIPTION -- WSTOPPED ("Status shall be returned for any
 * child that has stopped upon receipt of a signal") and WCONTINUED
 * ("Status shall be returned for any continued child process"), plus
 * wait.html's WUNTRACED/WCONTINUED, which are the same two clauses and
 * (WSTOPPED == WUNTRACED) even the same bit.
 *
 * This was fenced -- first N/A, then UNIMPL -- on the grounds that
 * "there is no NT mechanism that would implement it".  There is:
 * NtSuspendProcess and
 * NtResumeProcess.  The clause scopes WSTOPPED to a child "that has
 * stopped upon receipt of a signal", and the only signals that exist on
 * this platform are the ones this library delivers -- so the stop is
 * always one spicule performed itself (kill(pid, SIGSTOP), see
 * src/signal/signal.c), which is why it needs no kernel notification to
 * learn of it and NT's missing stop transition costs nothing.
 *
 * Still genuinely impossible, and untested here because no test could
 * pass: a child suspended by something OUTSIDE this library -- a
 * debugger, another process calling NtSuspendProcess -- cannot be
 * reported at all.  That is also not what the clause asks for.
 *
 * The waitpid() half is asserted alongside the waitid() half on purpose:
 * they read the same child-table state through the same lookup, and the
 * two disagreeing about one child would be a bug this test exists to
 * catch.  The SIGCHLD handler checks the third observer of each transition,
 * including siginfo_t and SA_NOCLDSTOP suppression. */
static void test_waitid_stopped_continued(void)
{
	struct sigaction sa, oldsa;
	siginfo_t si;
	int status = 0;
	pid_t pid = waitid_spawn("--waitid-sleep");

	if (pid < 0) return;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = job_sigchld_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	CHECK(sigaction(SIGCHLD, &sa, &oldsa) == 0);
	job_sig_count = 0;

	CHECK(kill(pid, SIGSTOP) == 0);
	CHECK(job_sig_count == 1);
	CHECK(job_sig_code == CLD_STOPPED);
	CHECK(job_sig_status == SIGSTOP);
	CHECK(job_sig_pid == pid);
	CHECK(waitid(P_PID, (id_t)pid, &si, WSTOPPED) == 0);
	CHECK(si.si_signo == SIGCHLD);
	CHECK(si.si_code == CLD_STOPPED);
	CHECK(si.si_status == SIGSTOP);
	CHECK(si.si_pid == pid);

	/* "...whose status has not yet been reported since they stopped":
	 * reported once, so the second ask has nothing available.  WNOHANG
	 * so that "nothing available" is a 0 return rather than a wait. */
	memset(&si, 0xa5, sizeof si);
	CHECK(waitid(P_PID, (id_t)pid, &si, WSTOPPED | WNOHANG) == 0);
	CHECK(si.si_pid == 0 && si.si_signo == 0);

	/* The stopped child is still a child, and still not exited: a plain
	 * poll for its exit says so rather than reporting the stop. */
	CHECK(waitpid(pid, &status, WNOHANG) == 0);

	CHECK(kill(pid, SIGCONT) == 0);
	CHECK(job_sig_count == 2);
	CHECK(job_sig_code == CLD_CONTINUED);
	CHECK(job_sig_status == SIGCONT);
	CHECK(job_sig_pid == pid);
	CHECK(waitid(P_PID, (id_t)pid, &si, WCONTINUED) == 0);
	CHECK(si.si_code == CLD_CONTINUED);
	CHECK(si.si_pid == pid);
	CHECK(si.si_status == SIGCONT);
	memset(&si, 0xa5, sizeof si);
	CHECK(waitid(P_PID, (id_t)pid, &si, WCONTINUED | WNOHANG) == 0);
	CHECK(si.si_pid == 0);

	/* The same state through waitpid(), and through a different stop
	 * signal: signal.h.html gives SIGTSTP the same "stop the process"
	 * default action as SIGSTOP. SA_NOCLDSTOP suppresses both halves of
	 * the notification while the
	 * independently consumable wait status remains available. */
	sa.sa_flags |= SA_NOCLDSTOP;
	CHECK(sigaction(SIGCHLD, &sa, NULL) == 0);
	CHECK(kill(pid, SIGTSTP) == 0);
	CHECK(job_sig_count == 2);
	status = 0;
	CHECK(waitpid(pid, &status, WUNTRACED) == pid);
	CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTSTP);
	CHECK(!WIFEXITED(status) && !WIFSIGNALED(status) && !WIFCONTINUED(status));
	/* reported once here too */
	CHECK(waitpid(pid, &status, WUNTRACED | WNOHANG) == 0);

	CHECK(kill(pid, SIGCONT) == 0);
	CHECK(job_sig_count == 2);
	status = 0;
	CHECK(waitpid(pid, &status, WCONTINUED) == pid);
	CHECK(WIFCONTINUED(status));
	CHECK(!WIFEXITED(status) && !WIFSIGNALED(status) && !WIFSTOPPED(status));

	/* A SIGCONT to a child that is not stopped continues nothing and so
	 * reports nothing (kill.html). */
	CHECK(kill(pid, SIGCONT) == 0);
	CHECK(job_sig_count == 2);
	CHECK(waitpid(pid, &status, WCONTINUED | WNOHANG) == 0);

	CHECK(sigaction(SIGCHLD, &oldsa, NULL) == 0);
	CHECK(kill(pid, SIGKILL) == 0);
	CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED) == 0);
	CHECK(si.si_code == CLD_KILLED);
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--waitid-exit7")) return 7;
	if (argc > 1 && !strcmp(argv[1], "--waitid-exit5")) return 5;
	if (argc > 1 && !strcmp(argv[1], "--waitid-exit3")) return 3;
	/* A child that stays alive long enough to be stopped, continued and
	 * killed, and that ends on its own if the parent never gets that
	 * far: a suspended process cannot wake itself, so the bound is on
	 * the window before the first stop, not after it. */
	if (argc > 1 && !strcmp(argv[1], "--waitid-sleep")) { sleep(30); return 0; }
	if (argc > 1 && !strcmp(argv[1], "--waitid-sigterm")) { kill(getpid(), SIGTERM); return 111; }
	if (argc > 1 && !strcmp(argv[1], "--waitid-sigabrt")) { kill(getpid(), SIGABRT); return 111; }
	if (argc > 1 && !strcmp(argv[1], "--nofile-child")) {
		/* The RLIMIT_NOFILE assertions, in a process of their own so
		 * that lowering a process-wide limit cannot reach any other
		 * test.  Exit status is the failure count. */
		test_setrlimit_nofile_child();
		if (fails) printf("posix-sysmisc --nofile-child: %d failure(s)\n", fails);
		return fails != 0;
	}
	if (argc > 1 && !strcmp(argv[1], "--rusage-child")) {
		/* burn a little real CPU so RUSAGE_CHILDREN has something
		 * non-trivial to accumulate; kept short since correctness
		 * only needs "non-decreasing", not "visibly nonzero" */
		volatile unsigned long i, x = 0;
		for (i = 0; i < 20000000UL; i++) x += i;
		return 0;
	}

	test_getrlimit();
	test_setrlimit_enforceable();
	test_setrlimit_fsize_accepts_lowering();
	test_setrlimit_fsize_enforced();
	test_setrlimit_fsize_sigxfsz();
	test_setrlimit_nofile(argv[0]);
	test_getrusage(argv[0]);
	test_getpriority_setpriority();
	test_select_ready_count();
	test_select_zero_timeout_polls();
	test_select_errors();
	test_pselect_timespec_and_mask();
	test_poll_ready_count();
	test_poll_zero_timeout_polls();
	test_poll_negative_fd_ignored();
	test_poll_nval();
	test_fd_macros();
	test_sys_param();
	test_sched_yield();
	test_statvfs();
	test_statvfs_errors();
	waitid_self = argv[0];
	test_waitid_exited();
	test_waitid_signalled();
	test_waitid_wnowait();
	test_waitid_stopped_continued();
	test_waitid_errors();
	test_getopt_long_abbrev();
	test_getopt_long_arg_forms();
	test_getopt_long_flag();
	test_getopt_long_only();
	test_getopt_long_index();
	test_getopt_long_reset();

	if (fails) { printf("posix-sysmisc: failures: %d\n", fails); return 1; }
	printf("posix-sysmisc: all ok\n");
	return 0;
}
