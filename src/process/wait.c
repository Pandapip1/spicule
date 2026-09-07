/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Waiting for children.
 *
 * A pid is a process id; the handle needed to wait on it is kept in the
 * child table __spawn/fork filled in. The exit code becomes a POSIX
 * wait status: an ordinary exit is (code << 8), so all 256 exit codes
 * survive intact. A death by signal comes from one of exactly two
 * places, neither of which a plain exit() can imitate:
 * __ENCODE_SIGNAL_EXIT(sig) (libc.h), the out-of-range status this
 * library's kill()/abort()/raise() end a process with, or an NT
 * exception code the kernel itself terminated the process with
 * (0xC0000xxx/0x8000xxxx NTSTATUS).
 *
 * wait3()/wait4() add a struct rusage for the reaped child, filled from
 * NtQueryInformationProcess(ProcessTimes) before its handle closes -- the
 * only piece of struct rusage NT actually has an answer for
 * (src/misc/resource.c). Every reap also folds into a running total for
 * getrusage(RUSAGE_CHILDREN), whether or not the caller asked for it.
 *
 * That per-child query only ever sees the reaped child's OWN CPU time,
 * never time it already collected from ITS OWN children -- but
 * times.html's tms_cutime/tms_cstime clause requires the recursive
 * total. fill_child_rusage() below gets that from a job object instead
 * when one is available (struct __child.job): every new child is placed
 * in a job of its own at creation, and ordinary job-membership
 * inheritance carries that down to whatever the child spawns too, so the
 * job's own accounting already covers the whole subtree by the time this
 * process reaps the child at its root. See __plat_process_times()'s
 * comment (plat_process.h) for the rest. */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "libc.h"
#include "plat_process.h"
#include "ownership_stubs.h"

/* WIFSIGNALED, WTERMSIG == sig, plus the WCOREDUMP bit for the signals
 * whose default action on Unix is "terminate and dump core". */
static int sig_status(int sig)
{
	int core;
	switch (sig) {
	case SIGQUIT: case SIGILL: case SIGTRAP: case SIGABRT:
	case SIGBUS: case SIGFPE: case SIGSEGV: case SIGSYS:
	case SIGXCPU: case SIGXFSZ:
		core = 0x80; break;
	default:
		core = 0; break;
	}
	return (sig & 0x7f) | core;
}

/* Exposed (not static) purely so test/posix-signal.c can drive the
 * exit-code -> wait-status mapping directly, without spawning a real
 * process for every boundary case -- same reasoning as
 * __errno_from_status() in src/internal/errno.c.  Declared in libc.h,
 * not include/: this is not part of the public API. */
int __wait_encode_status(int exitcode)
{
	unsigned code = (unsigned)exitcode;

	/* Ended by this library on behalf of a signal. */
	if (__IS_SIGNAL_EXIT(code) && (code & 0x7f))
		return sig_status((int)(code & 0x7f));

	/* Ended by NT itself with an exception code. */
	switch (code) {
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_STACK_OVERFLOW:      return sig_status(SIGSEGV);
	case EXCEPTION_DATATYPE_MISALIGNMENT: return sig_status(SIGBUS);
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_PRIV_INSTRUCTION:    return sig_status(SIGILL);
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_INT_OVERFLOW:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case EXCEPTION_FLT_INVALID_OPERATION:
	case EXCEPTION_FLT_OVERFLOW:        return sig_status(SIGFPE);
	case EXCEPTION_BREAKPOINT:          return sig_status(SIGTRAP);
	case (unsigned)STATUS_CONTROL_C_EXIT:
	case DBG_CONTROL_C:
	case DBG_CONTROL_BREAK:             return sig_status(SIGINT);
	default:                            break;
	}

	return (exitcode & 0xff) << 8;       /* WIFEXITED, WEXITSTATUS */
}

/* Cumulative rusage of every child reaped so far, for RUSAGE_CHILDREN
 * (src/misc/resource.c).  100ns NT ticks, converted to a timeval only
 * when read out -- see __rusage_children(). */
static unsigned long long children_ktime100ns, children_utime100ns;

static void ticks_to_timeval(unsigned long long t100ns, struct timeval *tv)
{
	tv->tv_sec = (time_t)(t100ns / 10000000ULL);
	tv->tv_usec = (suseconds_t)((t100ns % 10000000ULL) / 10);
}

void __rusage_children(struct rusage *ru)
{
	memset(ru, 0, sizeof *ru);
	ticks_to_timeval(children_ktime100ns, &ru->ru_stime);
	ticks_to_timeval(children_utime100ns, &ru->ru_utime);
}

/* These two are ordinary process-lifetime globals, and
 * RtlCloneUserProcess copies the address space holding them -- so a
 * fork()ed child would otherwise start life reporting the *parent's*
 * reaped-children times as its own. fork.html requires tms_cutime/
 * tms_cstime be reset to 0 in the child; KERNEL_USER_TIMES has no
 * child-time fields at all, so nothing but this call resets them
 * (fork.c, on the STATUS_PROCESS_CLONED arm). */
void __rusage_children_reset(void)
{
	children_ktime100ns = 0;
	children_utime100ns = 0;
}

/* Fill *ru with the resource usage of one child, from its still-open
 * process handle -- wait3()/wait4()'s ru is "resource usage of the
 * terminated child", not the RUSAGE_CHILDREN running total. A query
 * failure just leaves *ru zeroed rather than failing the whole wait: the
 * pid was already reaped successfully, and losing the accounting detail
 * isn't worth losing that.
 *
 * `job` (c->job, or __PLAT_HANDLE_NULL) is what makes the total the
 * RECURSIVE figure times.html's tms_cutime/tms_cstime clause asks for,
 * rather than just this child's own CPU time: see __plat_process_times()
 * for how the job accounts for grandchildren this child already reaped
 * before exiting -- a figure this process has no other way to learn,
 * since it lives only in the child's own now-closing address space and
 * NT offers no ReadProcessMemory-shaped primitive this library uses. */
static void fill_child_rusage(__plat_handle_t h, __plat_handle_t job, struct rusage *ru)
{
	unsigned long long ktime = 0, utime = 0;

	memset(ru, 0, sizeof *ru);
	if (!h) return;
	if (__plat_process_times(h, job, &ktime, &utime) < 0) return;
	ticks_to_timeval(ktime, &ru->ru_stime);
	ticks_to_timeval(utime, &ru->ru_utime);
	children_ktime100ns += ktime;
	children_utime100ns += utime;
}

/* The pending stop-or-continue report for a child, if any.
 *
 * wait.html's WUNTRACED and waitid.html's WSTOPPED are the same clause
 * and even the same bit (<sys/wait.h>), likewise WCONTINUED, so one
 * lookup serves both interfaces and they cannot disagree about a child.
 *
 * A stop sent by this parent is recorded immediately by kill(). A child
 * that stopped itself cannot write this private table, so it publishes
 * an auto-reset named event before suspending; discover_self_stops()
 * consumes that event and records the same status here.
 *
 * `want` is a pid, or 0 for any child. `which` is WSTOPPED (== WUNTRACED)
 * and/or WCONTINUED. Consuming is the caller's job -- it clears
 * c->jobstat, which is what "has not yet been reported" turns on, unless
 * WNOWAIT asked for the report to stay available. */
static struct __child *job_report(pid_t want, int which) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int i;

	for (i = 0; i < __child_cap; i++) {
		struct __child *c = &__children[i];
		int js = c->jobstat;

		if (!c->pid || !js) continue;
		if (want && c->pid != want) continue;
		if (!(which & (WIFCONTINUED(js) ? WCONTINUED : WSTOPPED))) continue;
		return c;
	}
	return 0;
}

static void discover_self_stops(pid_t want)
{
	int i;

	for (i = 0; i < __child_cap; i++) {
		struct __child *c = &__children[i];
		int sig;

		if (!c->pid || c->done || c->stopsig) continue;
		if (want && c->pid != want) continue;
		sig = __sig_consume_child_stop(c->pid);
		if (!sig) continue;
		c->stopsig = sig;
		c->jobstat = __W_STOPPED(sig);
		__sigchld_job_control(c, sig);
	}
}

/* One reaping engine for wait/waitpid/wait3/wait4/waitid.
 *
 * `nowait` is waitid()'s WNOWAIT ("keep the process ... in a waitable
 * state"). It's expressible because reaping is two separable steps: the
 * status is recorded in the table entry (c->done/c->status), and
 * __child_remove() is what closes the handle and frees the slot -- a
 * WNOWAIT call does only the first, so the child stays genuinely
 * waitable, not merely reported as such.
 *
 * That leaves a table entry with pid != 0 && done == 1, a state no
 * caller could reach before waitid existed. The any-child scan below
 * must therefore look for already-known statuses first, or it would
 * skip such an entry and report ECHILD for a child whose status POSIX
 * requires handing back again. */
/* The __PLAT_WAIT_* mode a wait on a child's handle should use for this
 * call's options: NOHANG polls once and returns; WUNTRACED cannot block
 * indefinitely because a self-stop marker is not a handle any wait can
 * see, so it has to keep re-checking; anything else blocks until the
 * child exits. */
static int wait_mode(int options)
{
	if (options & WNOHANG) return __PLAT_WAIT_NOHANG;
	if (options & WUNTRACED) return __PLAT_WAIT_POLL;
	return __PLAT_WAIT_BLOCK;
}

/* The pid job_report()/discover_self_stops() should look for: 0 for "any
 * child" (waitpid's pid == -1 or 0), or the process id a negative pid
 * names -- process groups are single processes here, the same
 * normalization do_waitpid() applies to pid itself further down. */
static pid_t stop_report_target(pid_t pid)
{
	if (pid == -1 || pid == 0) return 0;
	return pid < 0 ? -pid : pid;
}

static pid_t do_waitpid(pid_t pid, int *status, int options, struct rusage *ru, int nowait)
{
	struct __child *c;
	int wr;

	/* wait.html ERRORS (waitpid() only): "[EINVAL] The value of the
	 * options argument is not valid."  wait()/wait3()/wait4() always
	 * pass a value of their own choosing (0, or a caller-supplied
	 * options through wait3/wait4, which share this same contract), so
	 * checking here covers all of them uniformly. */
	if (options & ~(WNOHANG | WUNTRACED | WCONTINUED)) { errno = EINVAL; return -1; }
	/* pid < -1 selects the process group whose ID is the absolute value
	 * of pid.  INT_MIN has no positive pid_t counterpart; negating it in
	 * the job-control lookup below is signed-overflow UB.  Since no pid_t
	 * can name that mathematical group ID, it cannot contain a child. */
	if (pid == INT_MIN) { errno = ECHILD; return -1; }

	retry:
	/* A stopped or continued child, ahead of any exit wait.  The order
	 * matters and is not a preference: a stopped child never becomes
	 * signalled, so waiting on its handle first would block forever
	 * holding a status the caller asked for and that is sitting right
	 * here.  The entry is not removed -- the child has not exited and
	 * is still to be waited for -- only the report is consumed. */
	if (options & (WUNTRACED | WCONTINUED)) {
		if (options & WUNTRACED)
			discover_self_stops(stop_report_target(pid));
		c = job_report(stop_report_target(pid), options & (WUNTRACED | WCONTINUED));
		if (c) {
			if (status) *status = c->jobstat;
			if (ru) {
				unsafe_assume_writable_span(ru, sizeof *ru);
				memset(ru, 0, sizeof *ru);
			}
			if (!nowait) c->jobstat = 0;
			return c->pid;
		}
	}

	if (pid == -1 || pid == 0) {
		/* Any child.  With one table, scan for a done one, or wait on
		 * all live handles.  Simple approach: find the first not-yet
		 * reaped child; if WNOHANG, poll each; else wait on the first. */
		int i, any = 0;
		/* An entry left done-but-unreaped by an earlier WNOWAIT: its
		 * status is already known, so it is available right now and
		 * needs no wait at all. */
		for (i = 0; i < __child_cap; i++)
			if (__children[i].pid && __children[i].done) {
				c = &__children[i];
				if (status) *status = c->status;
				pid = c->pid;
				if (ru) {
					memset(ru, 0, sizeof *ru);
				}
				if (!nowait) __child_remove(c);
				return pid;
			}
		for (i = 0; i < __child_cap; i++) {
			if (!__children[i].pid || __children[i].done) continue;
			any = 1;
			wr = __plat_process_wait(__children[i].h, wait_mode(options));
			if (wr == 0) continue;
			if (wr < 0) return -1;
			c = &__children[i];
			goto reap;
		}
		if (!any) { errno = ECHILD; return -1; }
		if (options & WNOHANG) return 0;
		if (options & WUNTRACED) goto retry;
		/* Every remaining child is live; wait on the first live one. */
		for (i = 0; i < __child_cap; i++)
			if (__children[i].pid && !__children[i].done) {
				c = &__children[i];
				wr = __plat_process_wait(c->h, __PLAT_WAIT_BLOCK);
				if (wr < 0) return -1;
				goto reap;
			}
		errno = ECHILD;
		return -1;
	}

	if (pid < 0) pid = -pid;   /* process groups are single processes here */
	c = __child_find(pid);
	if (!c) {
		/* Not in the table means not waitable, full stop. Reopening the
		 * pid with NtOpenProcess is not a safe fallback: on real Windows
		 * the kernel process object outlives its last handle, so an
		 * already-reaped, no-longer-existing child could still be opened
		 * and hand back its pid and exit status a second time, where
		 * POSIX requires ECHILD. A child that never made it into the
		 * table is therefore unwaitable, the honest outcome -- waitpid(-1)/
		 * wait() could never see it either, since they only scan the table. */
		errno = ECHILD;
		return -1;
	}
	if (c->done) {
		if (status) *status = c->status;
		pid = c->pid;
		if (ru) {
			memset(ru, 0, sizeof *ru);
		}
		if (!nowait) __child_remove(c);
		return pid;
	}

	wr = __plat_process_wait(c->h, wait_mode(options));
	if (wr == 0) {
		if (options & WNOHANG) return 0;
		goto retry;
	}
	if (wr < 0) return -1;

reap:
	/* Never invent a status: if the handle can't be queried, the entry is
	 * left as it is (a retry may still reach it) and the caller gets the
	 * real error rather than a fabricated "exited 0". */
	{
		int code;
		if (__plat_process_exit_code(c->h, &code) < 0) return -1;
		c->status = __wait_encode_status(code);
	}
	c->done = 1;
	if (status) *status = c->status;
	pid = c->pid;
	if (ru) fill_child_rusage(c->h, c->job, ru);
	else { struct rusage tmp; fill_child_rusage(c->h, c->job, &tmp); }
	/* fill_child_rusage() already folded this child's times into
	 * RUSAGE_CHILDREN, so a WNOWAIT call must not let a later real reap
	 * fold them in a second time. It doesn't: c->done is set above, and
	 * every path that sees done == 1 returns the recorded status without
	 * touching the handle again -- so any backend cached reap info is
	 * safe to release regardless of `nowait` (see
	 * __plat_process_reap_release(), plat_process.h). */
	__plat_process_reap_release(c->h);
	if (!nowait) __child_remove(c);
	return pid;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	return do_waitpid(pid, status, options, 0, 0);
}

pid_t wait(int *status)
{
	return do_waitpid(-1, status, 0, 0, 0);
}

/* waitid --
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/waitid.html
 *
 * The reaping itself is do_waitpid() above, unchanged: waitid() differs
 * from waitpid() only in how the caller names the child (idtype/id
 * rather than a signed pid) and in how the result is reported (a
 * siginfo_t rather than a packed int).
 *
 * idtype: P_ALL is do_waitpid's pid == -1; P_PID is a plain pid; P_PGID
 * is the same as P_PID here, since every process is its own process
 * group of one (src/unistd/ids.c), so a process group id *is* a process
 * id, not an approximation of one. P_PIDFD is a Linux extension with no
 * pidfds here, rejected with EINVAL like any other value.
 *
 * options: a call naming none of WEXITED/WSTOPPED/WCONTINUED is EINVAL.
 *
 * WSTOPPED and WCONTINUED are real, sharing their whole implementation
 * with waitpid()'s WUNTRACED/WCONTINUED (job_report() above): a
 * parent-sent stop is recorded directly, and a self-stopping child
 * publishes the marker discovered above. A child suspended by anything
 * *else* (a debugger, etc.) stays unreportable, since nothing notifies
 * this process -- which is also not what the clause asks for.
 *
 * WNOWAIT is real, not accepted-and-ignored: it maps onto do_waitpid's
 * `nowait`, which records the status without releasing the entry, so a
 * following wait/waitpid/waitid returns the same status again.
 */
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int status = 0;
	pid_t pid, want;

	if (options & ~(WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT)) {
		errno = EINVAL;
		return -1;
	}
	if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) {
		errno = EINVAL;
		return -1;
	}

	switch (idtype) {
	case P_ALL:  want = -1; break;
	case P_PID:
	case P_PGID: want = (pid_t)id; break;
	default:     errno = EINVAL; return -1;
	}
	/* do_waitpid reads pid == 0 as "any child" and pid < 0 as a process
	 * group; P_PID/P_PGID with an id of 0 must not silently become
	 * P_ALL, and a negative id is not a process id at all. */
	if (idtype != P_ALL && want <= 0) { errno = ECHILD; return -1; }

	if (options & WEXITED) {
		/* WSTOPPED/WCONTINUED share bits with WUNTRACED/WCONTINUED
		 * (<sys/wait.h>), so they pass straight through to
		 * do_waitpid()'s own job_report(). WEXITED has no waitpid()
		 * spelling -- it's what waitpid() always does -- so it must be
		 * masked off, since do_waitpid() rejects any bit it doesn't know. */
		pid = do_waitpid(want, &status, options & (WNOHANG | WSTOPPED | WCONTINUED),
		                 0, options & WNOWAIT ? 1 : 0);
		if (pid < 0) return -1;
		/* WNOHANG with no status available returns 0; POSIX.1-2017
		 * leaves infop implementation-defined in that case, and zeroing
		 * it (si_signo == 0) is what makes "nothing happened" detectable
		 * by a caller with only the 0 return to go on. */
		if (pid == 0) {
			if (infop) {
				memset(infop, 0, sizeof *infop);
			}
			return 0;
		}
	} else {
		/* No WEXITED: the caller wants a stop/continue report only, so
		 * do_waitpid() must not run at all -- it would wait on the
		 * process handle and reap a child this call didn't ask about.
		 * Read the report directly instead. */
		struct __child *c = job_report(want < 0 ? 0 : want, options & (WSTOPPED | WCONTINUED));

		if (c) {
			status = c->jobstat;
			pid = c->pid;
			if (!(options & WNOWAIT)) c->jobstat = 0;
		} else {
			/* Nothing pending, and nothing can make one pending later:
			 * only this process's own kill() stops or continues a
			 * child, and a blocked waitid() isn't calling kill(). So
			 * the wait POSIX describes would hang forever -- WNOHANG
			 * makes that "no status available" (0); without it, ECHILD
			 * is simply true. */
			if (infop) {
				memset(infop, 0, sizeof *infop);
			}
			if (options & WNOHANG) return 0;
			errno = ECHILD;
			return -1;
		}
	}

	if (infop) {
		memset(infop, 0, sizeof *infop);
		/* "the si_signo member shall be set equal to SIGCHLD"
		 * (DESCRIPTION). */
		infop->si_signo = SIGCHLD;
		infop->si_pid = pid;
		/* The child inherited this process's immutable token identity, so
		 * its token-derived real user ID is this process's too. */
		infop->si_uid = getuid();
		if (WIFEXITED(status)) {
			infop->si_code = CLD_EXITED;
			/* For CLD_EXITED, si_status is the exit status the child
			 * passed to _exit(); for every other code it is the
			 * signal number.  All of them come straight out of the
			 * same wait status waitpid() would hand back, so waitid
			 * and waitpid can never disagree about a child. */
			infop->si_status = WEXITSTATUS(status);
		} else if (WIFSTOPPED(status)) {
			/* "the signal that caused the process to terminate, stop,
			 * or continue" -- here the stop signal kill() was called
			 * with, which is SIGSTOP or one of the three terminal
			 * stops (see sig_stops() in src/signal/signal.c). */
			infop->si_code = CLD_STOPPED;
			infop->si_status = WSTOPSIG(status);
		} else if (WIFCONTINUED(status)) {
			/* A continue has no signal of its own to carry: SIGCONT is
			 * the only thing that produces one. */
			infop->si_code = CLD_CONTINUED;
			infop->si_status = SIGCONT;
		} else {
			infop->si_code = WCOREDUMP(status) ? CLD_DUMPED : CLD_KILLED;
			infop->si_status = WTERMSIG(status);
		}
		/* si_utime/si_stime are not POSIX members of the SIGCHLD
		 * siginfo (waitid.html names only si_pid, si_uid, si_signo,
		 * si_status and si_code); they are left zero here rather than
		 * filled, and wait3()/wait4()'s struct rusage is the supported
		 * way to get a reaped child's times. */
	}
	return 0;
}

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
pid_t wait3(int *status, int options, struct rusage *ru)
{
	return do_waitpid(-1, status, options, ru, 0);
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *ru)
{
	return do_waitpid(pid, status, options, ru, 0);
}
#endif

// NOLINTEND(misc-include-cleaner)
