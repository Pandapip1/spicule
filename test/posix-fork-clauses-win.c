/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of fork() --
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html
 * -- one of the 43 names in test/POSIX-GAP-ACCOUNTING.md's
 * "Implemented, not clause-audited (357)" unistd.h row.
 *
 * WHY THE "-win" SUFFIX, AND WHY IT IS NOT NEGOTIABLE.  fork() here is
 * RtlCloneUserProcess (src/process/fork.c's banner explains why no
 * other NT primitive gets there).  Stock apt Wine does not implement
 * it: a call does not fail, it *hangs*, into `winedbg --auto` forever.
 * The Makefile's TEST_RUN = $(filter-out %-win.exe,$(TEST_EXES)) is
 * the established mechanism for keeping such a test out of the Wine
 * leg while still building it, and test/fork-win.c,
 * test/fork-handles-win.c and test/fork-cloexec-exec-win.c all use it.
 * A hang costs a CI job its entire timeout, so anything added here
 * that forks must keep the suffix.
 *
 * Division of labour with the three existing fork tests, none of which
 * cites fork.html: test/fork-win.c checks the 0-vs-pid split and that
 * the child's writes to globals do not leak back;
 * test/fork-handles-win.c pins what happens to *pre-existing sibling*
 * process handles; test/fork-cloexec-exec-win.c reproduces one
 * specific handle-reuse bug.  This file takes the page's own
 * DESCRIPTION list -- the enumerated ways the child is and is not an
 * exact copy -- and its RETURN VALUE and ERRORS sections.
 *
 * Fence vocabulary is test/posix-termios.c's: BUG / UNIMPL / N/A.
 *
 * Oracle: real Windows CI.  Under the locally patched Wine that does
 * have RtlCloneUserProcess this file runs and passes, but Wine's clone
 * is an emulation of the primitive under test, so the windows-test
 * legs are the authority for everything below.
 */
/* sigset_t and the sigemptyset()/sigismember()/sigpending() family are
 * feature-test gated in include/signal.h; same define most other
 * tests in test/ already carry for the same reason (see test/posix-glob.c's
 * comment on this exact define). */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/times.h>
#include <sys/stat.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Exit codes a child uses to report a clause verdict to the parent.
 * 0 is "every clause I was asked to check held"; anything else names
 * the first that did not. */
#define RC_OK            0
#define RC_PID_SAME      11
#define RC_PPID_WRONG    12
#define RC_FORK_RET      13
#define RC_OFFSET        14
#define RC_PENDING       15
#define RC_TIMES         16
#define RC_FD_GONE       17
#define RC_LOCK          18

static int wait_child(pid_t pid)
{
	int status = -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	if (!WIFEXITED(status)) return -1;
	return WEXITSTATUS(status);
}

/* ============================================================
 * RETURN VALUE, and the identity clauses
 * ============================================================ */

/* fork.html RETURN VALUE: "Upon successful completion, fork() shall
 * return 0 to the child process and shall return the process ID of the
 * child process to the parent process.  Both processes shall continue
 * to execute from the fork() function."
 *
 * DESCRIPTION: "The child process shall have a unique process ID." and
 * "The child process shall have a different parent process ID, which
 * shall be the process ID of the calling process."
 *
 * All three are checked from both sides at once: the child compares
 * its own getpid()/getppid() against values the parent wrote into
 * ordinary memory before the fork (which the clone carries over), and
 * the parent compares fork()'s return against the pid the child
 * reports. */
static void test_identity(void)
{
	pid_t parent_pid = getpid();
	pid_t pid;
	int fd[2];
	pid_t child_says = 0;

	CHECK(pipe(fd) == 0);

	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		pid_t me = getpid();
		int rc = RC_OK;
		close(fd[0]);
		/* "shall return 0 to the child process" -- being here at all
		 * is that clause; the variable is checked for completeness. */
		if (me == parent_pid) rc = RC_PID_SAME;
		else if (getppid() != parent_pid) rc = RC_PPID_WRONG;
		(void)write(fd[1], &me, sizeof me);
		close(fd[1]);
		_exit(rc);
	}
	close(fd[1]);
	CHECK(read(fd[0], &child_says, sizeof child_says) == (ssize_t)sizeof child_says);
	close(fd[0]);

	/* "shall return the process ID of the child process to the parent
	 * process" -- the number fork() handed back is the number the
	 * child answers to. */
	CHECK(pid == child_says);
	CHECK(pid != parent_pid);
	CHECK(getpid() == parent_pid);		/* the parent is unmoved */

	CHECK(wait_child(pid) == RC_OK);
}

/* ============================================================
 * "The new process (child process) shall be an exact copy of the
 *  calling process (parent process) except as detailed below:" --
 *  fork.html DESCRIPTION's own lead sentence, followed by the
 *  enumerated list test_shared_open_file_description() and the other
 *  clause tests in this file each cover one item of.  errno is not a
 *  Special Process Attribute, not a file descriptor, not a signal
 *  disposition, not any of the other named exceptions -- it is
 *  ordinary per-thread memory in the calling thread's own storage
 *  (src/internal/errno.c's `static __thread int __errno_val`), so it
 *  is covered only by the lead sentence itself: whatever the parent's
 *  errno held at the instant of the call is what the child's copy
 *  holds too, not 0.  Nothing in this page's DESCRIPTION, RETURN
 *  VALUE, or APPLICATION USAGE sections says otherwise.
 * ============================================================ */
static void test_errno_inherited_not_cleared(void)
{
	pid_t pid;
	int fd[2];
	int child_errno = -1;

	CHECK(pipe(fd) == 0);

	/* A real failing call, not a bare assignment to errno, so this
	 * also proves the clause for errno exactly as this library sets
	 * it, not just for a hand-picked int stashed in the same cell. */
	errno = 0;
	CHECK(close(-1) == -1);
	CHECK(errno == EBADF);

	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		int e = errno;
		close(fd[0]);
		(void)write(fd[1], &e, sizeof e);
		close(fd[1]);
		_exit(RC_OK);
	}
	close(fd[1]);
	CHECK(read(fd[0], &child_errno, sizeof child_errno) == (ssize_t)sizeof child_errno);
	close(fd[0]);

	if (child_errno != EBADF)
		printf("    errno_inherited: child errno=%d, want EBADF=%d (0 would mean the child cleared it)\n",
		       child_errno, EBADF);
	CHECK(child_errno == EBADF);
	CHECK(errno == EBADF);		/* the parent's own copy is unmoved too */

	CHECK(wait_child(pid) == RC_OK);
}

/* ============================================================
 * "The child process shall have its own copy of the parent's file
 *  descriptors.  Each of the child's file descriptors shall refer to
 *  the same open file description with the corresponding file
 *  descriptor of the parent."
 * ============================================================ */

/* Two halves, and they pull in opposite directions -- which is exactly
 * why this is the clause worth spending a test on:
 *
 *   "own copy of the descriptors"   -- close() in the child must not
 *                                      close the parent's fd
 *   "the same open file description" -- lseek() in the child MUST move
 *                                      the parent's file offset
 *
 * An implementation that duplicated the file too deeply would pass the
 * first and fail the second; one that shared the descriptor table
 * would do the reverse. */
static void test_shared_open_file_description(void)
{
	pid_t pid;
	int fd, other;
	char buf[8];

	fd = open("fk-shared.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "0123456789", 10) == 10);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);

	other = open("fk-shared.txt", O_RDONLY);	/* a second, separate description */
	CHECK(other >= 0);

	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		int rc = RC_OK;
		/* the child's copy of fd is usable at all */
		if (read(fd, buf, 3) != 3 || memcmp(buf, "012", 3)) rc = RC_FD_GONE;
		/* and moving it must be visible to the parent */
		else if (lseek(fd, 7, SEEK_SET) != 7) rc = RC_OFFSET;
		/* closing the child's copy must not close the parent's */
		if (rc == RC_OK) close(other);
		_exit(rc);
	}
	CHECK(wait_child(pid) == RC_OK);

	/* "the same open file description": the child's lseek moved the
	 * shared offset, so the parent reads from 7. */
	CHECK(lseek(fd, 0, SEEK_CUR) == 7);
	CHECK(read(fd, buf, 3) == 3);
	CHECK(!memcmp(buf, "789", 3));

	/* "its own copy of the parent's file descriptors": the child
	 * closed `other`, and the parent's `other` is still open. */
	CHECK(lseek(other, 0, SEEK_SET) == 0);
	CHECK(read(other, buf, 3) == 3);
	CHECK(!memcmp(buf, "012", 3));

	CHECK(close(fd) == 0);
	CHECK(close(other) == 0);
	CHECK(unlink("fk-shared.txt") == 0);
}

/* ============================================================
 * "File locks set by the parent process shall not be inherited by the
 *  child process."
 * ============================================================ */
static void test_locks_not_inherited(void)
{
	pid_t pid;
	int fd;
	struct flock fl;

	fd = open("fk-lock.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "lock me", 7) == 7);

	memset(&fl, 0, sizeof fl);
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 7;

	if (fcntl(fd, F_SETLK, &fl) != 0) {
		printf("note: F_SETLK unavailable here (errno %d); fork lock-inheritance "
		       "clause not reached\n", errno);
		CHECK(close(fd) == 0);
		CHECK(unlink("fk-lock.txt") == 0);
		return;
	}

	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		/* A record lock belongs to the parent process, not to the open
		 * file description inherited here.  It must therefore be visible
		 * as a conflicting lock, and the child must not acquire it. */
		struct flock probe;
		memset(&probe, 0, sizeof probe);
		probe.l_type = F_WRLCK;
		probe.l_whence = SEEK_SET;
		probe.l_start = 1;
		probe.l_len = 6;
		if (fcntl(fd, F_GETLK, &probe) < 0 || probe.l_type != F_WRLCK)
			_exit(RC_LOCK);
		if (fcntl(fd, F_SETLK, &probe) == 0 ||
		    (errno != EACCES && errno != EAGAIN))
			_exit(RC_LOCK);
		_exit(RC_OK);
	}
	CHECK(wait_child(pid) == RC_OK);

	CHECK(close(fd) == 0);
	CHECK(unlink("fk-lock.txt") == 0);
}

/* ============================================================
 * "The set of signals pending for the child process shall be
 *  initialized to the empty set."
 * "The child process values of tms_utime, tms_stime, tms_cutime, and
 *  tms_cstime shall be set to 0."
 * ============================================================ */

/* What the child saw, carried back to the parent over a pipe so that a
 * failure names its own cause.  The exit status alone cannot: RC_TIMES
 * and RC_PENDING and a wait_child() failure all print the same line,
 * and this file only ever runs on the windows-test legs (see the "-win"
 * banner above), where nobody can attach a debugger and re-run it.  The
 * numbers below are what makes the next CI log say what happened. */
struct child_state {
	int wrote;             /* the child got far enough to send this */
	int pending_sig;       /* signal found pending, 0 if none */
	int times_failed;      /* times() returned (clock_t)-1 */
	long long tms[4];      /* utime, stime, cutime, cstime */
};

static void test_child_state_reset(void)
{
	pid_t pid;
	int fd[2];
	struct child_state cs;
	int rc;

	memset(&cs, 0, sizeof cs);
	CHECK(pipe(fd) == 0);

	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		sigset_t pending;
		struct tms t;
		struct child_state r;
		int rcc = RC_OK;

		memset(&r, 0, sizeof r);
		r.wrote = 1;
		close(fd[0]);

		/* pending signals: the empty set */
		sigemptyset(&pending);
		if (sigpending(&pending) == 0) {
			int i;
			for (i = 1; i < 32; i++)
				if (sigismember(&pending, i) == 1) {
					rcc = RC_PENDING;
					r.pending_sig = i;
					break;
				}
		}

		/* tms_cutime/tms_cstime are the two the clause can be held to
		 * without a clock: a freshly forked child has waited for no
		 * children of its own, so both must be 0 whatever the
		 * platform's timing resolution is.  tms_utime/tms_stime are
		 * checked only for being non-negative -- "set to 0" is the
		 * requirement, but any nonzero value could equally be time
		 * this child itself has since spent. */
		memset(&t, 0, sizeof t);
		if (times(&t) == (clock_t)-1) {
			r.times_failed = 1;
		} else {
			r.tms[0] = (long long)t.tms_utime;
			r.tms[1] = (long long)t.tms_stime;
			r.tms[2] = (long long)t.tms_cutime;
			r.tms[3] = (long long)t.tms_cstime;
			if (rcc == RC_OK) {
				if (t.tms_cutime != 0 || t.tms_cstime != 0) rcc = RC_TIMES;
				else
				if (t.tms_utime < 0 || t.tms_stime < 0) rcc = RC_TIMES;
			}
		}

		(void)write(fd[1], &r, sizeof r);
		close(fd[1]);
		_exit(rcc);
	}
	close(fd[1]);
	(void)read(fd[0], &cs, sizeof cs);
	close(fd[0]);

	rc = wait_child(pid);
	if (rc != RC_OK) {
		printf("    child_state_reset: rc=%d (RC_PENDING=%d RC_TIMES=%d, -1=wait_child failed)\n",
		       rc, RC_PENDING, RC_TIMES);
		if (!cs.wrote)
			printf("    child sent no report (died before times())\n");
		else if (cs.times_failed)
			printf("    times() returned (clock_t)-1\n");
		else
			printf("    tms_utime=%lld tms_stime=%lld tms_cutime=%lld tms_cstime=%lld\n",
			       cs.tms[0], cs.tms[1], cs.tms[2], cs.tms[3]);
		printf("    pending signal in child: %d (0 = none)\n", cs.pending_sig);
	}
	CHECK(rc == RC_OK);
}

/* ============================================================
 * "After fork(), both the parent and the child processes shall be
 *  capable of executing independently before either one terminates."
 * ============================================================ */
static void test_independent_execution(void)
{
	pid_t pid;
	int up[2], down[2];
	char c;

	CHECK(pipe(up) == 0);
	CHECK(pipe(down) == 0);

	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		char b;
		close(up[0]); close(down[1]);
		/* speak first, then wait to be spoken to: this can only
		 * complete if both processes are genuinely running at the
		 * same time. */
		if (write(up[1], "c", 1) != 1) _exit(RC_FORK_RET);
		if (read(down[0], &b, 1) != 1 || b != 'p') _exit(RC_FORK_RET);
		close(up[1]); close(down[0]);
		_exit(RC_OK);
	}
	close(up[1]); close(down[0]);
	CHECK(read(up[0], &c, 1) == 1 && c == 'c');
	CHECK(write(down[1], "p", 1) == 1);
	CHECK(wait_child(pid) == RC_OK);
	close(up[0]); close(down[1]);
}

/* ============================================================
 * "The time left until an alarm clock signal shall be reset to zero,
 *  and the alarm, if any, shall be canceled"
 * ============================================================ */
static void test_alarm_cleared_in_child(void)
{
	/* alarm.html's RETURN VALUE is the only way to observe whether an
	 * alarm is pending, so this reads the clause off both sides of the
	 * fork at once: the child must report none, and -- the half that
	 * makes the first half mean something -- the parent must still
	 * report its own.  A fork() that cleared nothing would fail the
	 * first; one that cancelled the shared timer object would fail the
	 * second.
	 *
	 * The mechanism being checked is in src/unistd/sleep.c: the
	 * deadline lives in a static, and RtlCloneUserProcess copies the
	 * address space, so the child arrives holding the parent's figure
	 * and fork() has to forget it explicitly
	 * (__alarm_reset_after_fork(), called beside the tms_cutime reset
	 * in src/process/fork.c for the same reason). */
	pid_t pid;
	unsigned left;
	CHECK(alarm(100) == 0);
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) _exit(alarm(0) == 0 ? RC_OK : 1);
	CHECK(wait_child(pid) == RC_OK);
	left = alarm(0);		/* the parent's alarm survived */
	CHECK(left >= 99 && left <= 100);
}

int main(void)
{
#ifndef _WIN32
	/* tools/asan-build.sh compiles this suite natively against
	 * fuzz/ntstubs.c.  That file's RtlCloneUserProcess is a real host
	 * fork(2) -- which is why fork tests are no longer on its
	 * not_native() list -- but the clauses below are about NT's clone
	 * and about spicule's own descriptor model on top of it, and the
	 * stub reproduces neither faithfully enough to hold them to.
	 *
	 * Measured there, with a standalone probe against the same
	 * objects: pipe() and fork() both succeed and the child reaches
	 * its own code, but a child writing to the pipe is killed by
	 * SIGPIPE (wait status 13) even though the parent still holds the
	 * read end open, and the parent's read() sees EOF.  Under the PE
	 * build -- Wine and real Windows both -- the identical sequence
	 * works, and test/fork-handles-win.c has passed a child-to-parent
	 * pipe across a fork for as long as it has existed.  So this is a
	 * property of the host-fork/host-pipe stand-in, not of
	 * src/process/fork.c or src/unistd/pipe.c, and asserting into it
	 * would be measuring fuzz/ntstubs.c.
	 *
	 * Reported as rc=77 "unverified" with a SKIP line rather than as
	 * a pass, and rather than as an entry in tools/asan-build.sh's
	 * not_native() table -- the SKIP-plus-77 route needs no change to
	 * the runner (test/posix-socket.c is the model).  The
	 * `windows-test` legs, and a local run under a Wine that has
	 * RtlCloneUserProcess, are where these clauses are checked. */
	printf("SKIP posix-fork-clauses (native ASan build: fuzz/ntstubs.c's "
	       "RtlCloneUserProcess is a host fork(2) and its pipes are host "
	       "pipes -- a child writing to one is SIGPIPEd with the read end "
	       "still open, which the PE build does not do)\n");
	printf("posix-fork-clauses: nothing ran here; exiting 77 (unverified)\n");
	return 77;
#else
	char tmpl[] = "posixforkclauses-XXXXXX";
	char *dir = mkdtemp(tmpl);
	char origcwd[4096];

	CHECK(getcwd(origcwd, sizeof origcwd) == origcwd);
	CHECK(dir == tmpl);
	if (!dir) return 1;
	CHECK(chdir(dir) == 0);

	test_identity();
	test_errno_inherited_not_cleared();
	test_shared_open_file_description();
	test_locks_not_inherited();
	test_child_state_reset();
	test_independent_execution();
	test_alarm_cleared_in_child();

	CHECK(chdir(origcwd) == 0);
	CHECK(rmdir(dir) == 0);

	/* N/A, with the mechanism, for the rest of fork.html:
	 *
	 * "[EAGAIN] The system lacked the necessary resources to create
	 * another process, or the system-imposed limit ... {CHILD_MAX}
	 * would be exceeded" and the may-fail "[ENOMEM]".  Reaching
	 * either means exhausting NT's process table or the heap from
	 * inside a test whose own failure mode would then be
	 * indistinguishable from the condition under test -- and this
	 * suite's own runner would be the first casualty.  src/process/
	 * fork.c does route a failed RtlCloneUserProcess through
	 * __set_errno_status(), so the -1 path exists; it is the trigger
	 * that is unconstructible.
	 *
	 * "The child process shall have its own copy of the parent's open
	 * directory streams" -- src/dirent/opendir.c builds a DIR on the
	 * heap around a descriptor, and both are ordinary memory that the
	 * clone carries; the clause explicitly permits the child's stream
	 * to "share directory stream positioning with the corresponding
	 * directory stream of the parent", so both possible behaviours
	 * conform and there is nothing to assert.
	 *
	 * Message catalogs, semaphores, semadj, interval timers,
	 * per-process timers, message queues, asynchronous I/O, memory
	 * locks, MAP_PRIVATE mappings, SCHED_FIFO/SCHED_RR inheritance,
	 * trace streams and CPU-time clocks: every one of those names a
	 * facility this library does not have at all
	 * (test/POSIX-GAP-ACCOUNTING.md's "absent" table), so the clause
	 * has no object.
	 *
	 * "A process shall be created with a single thread" -- true by
	 * construction: RtlCloneUserProcess clones only the calling
	 * thread (src/process/fork.c's banner says so), and nothing in
	 * this library creates a second one to test it with. */

	if (!fails) printf("posix-fork-clauses: all tests passed\n");
	return fails != 0;
#endif
}
