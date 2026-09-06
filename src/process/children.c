/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The child table: one entry per living-or-unreaped child, holding the
 * pid and the process HANDLE waitpid needs to wait on it and read its
 * exit code.
 *
 * The handle is the only thing keeping a child reapable -- a pid names a
 * process *object* that vanishes (and can be reused) once its last handle
 * closes -- so the table grows on demand rather than ever dropping one.
 * It starts as a static array (no malloc for the common case, or for any
 * fork/spawn before the allocator exists); only the 257th concurrently-
 * unreaped child grows it, from the process heap, which survives
 * RtlCloneUserProcess along with everything else fork() copies (see
 * fork.c's header comment).
 *
 * If growth fails, __child_add returns -1 and the caller closes the
 * handle, losing the child rather than losing the fork.
 *
 * __child_find returns a pointer *into* the table, which a later growth
 * may move; every caller is done with it before the next __child_add, so
 * this is safe, but anything holding one across a fork/spawn must
 * remember the pid instead.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <signal.h>
#include <string.h>
#include "libc.h"
#include "plat_fd.h"
#include "plat_process.h"
#include "plat_signal.h"

static struct __child __child_seed[CHILD_MAX_]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

struct __child *__children = __child_seed;
int __child_cap = CHILD_MAX_;

static int child_grow(void)
{
	struct __child *n;
	size_t cap2, bytes;
	int cap, i;

	if (__child_cap >= CHILD_CAP_LIMIT_) return -1;
	if (!__size_mul_checked((size_t)__child_cap, 2, &cap2)) return -1;
	cap = cap2 > CHILD_CAP_LIMIT_ ? CHILD_CAP_LIMIT_ : (int)cap2;
	if (!__size_mul_checked((size_t)cap, sizeof *n, &bytes)) return -1;
	n = __malloc(bytes);
	if (!n) return -1;
	for (i = 0; i < __child_cap; i++) n[i] = __children[i];
	for (; i < cap; i++) n[i] = (struct __child){0};
	if (__children != __child_seed) __free(__children);
	__children = n;
	__child_cap = cap;
	return 0;
}

int __child_add(int pid, __plat_handle_t h, __plat_handle_t job)
{
	int i;
	/* SA_NOCLDWAIT: this child must never be something wait()/waitpid()
	 * can find (signal.c's __sigchld_nocldwait()). Failing here, like a
	 * table that can't grow, makes both callers (fork.c, spawn.c) take
	 * the same degrade: close the handle, let the child run untracked. */
	if (__sigchld_nocldwait()) return -1;
	for (;;) {
		for (i = 0; i < __child_cap; i++)
			if (!__children[i].pid) {
				__children[i].pid = pid;
				__children[i].h = h;
				__children[i].job = job;
				__children[i].done = 0;
				__children[i].status = 0;
				__children[i].stopsig = 0;
				__children[i].jobstat = 0;
				return 0;
			}
		if (child_grow() < 0) return -1;
	}
}

struct __child *__child_find(int pid)
{
	int i;
	for (i = 0; i < __child_cap; i++)
		if (__children[i].pid == pid) return &__children[i];
	return 0;
}

void __child_remove(struct __child *c)
{
	if (c->h) __plat_close(c->h);
	if (c->job) __plat_close(c->job);
	c->pid = 0;
	c->h = __PLAT_HANDLE_NULL;
	c->job = __PLAT_HANDLE_NULL;
}

static void clear_stops(int resume)
{
	int i;
	for (i = 0; i < __child_cap; i++) {
		if (!__children[i].pid) continue;
		/* Best effort: a status here means the child is already gone,
		 * which is the outcome this is trying to reach anyway.  Resume
		 * only a child that is actually stopped; jobstat may instead hold
		 * an already-running child's pending WCONTINUED report. */
		if (resume && __children[i].stopsig && __children[i].h) {
			/* exit.html: SIGHUP before SIGCONT.  Sent for real only
			 * where kill() can actually deliver it as a real signal
			 * instead of destroying the child -- see the big comment
			 * below __child_resume_stopped(). */
			if (__plat_sig_deliverable_to_other_process())
				kill(__children[i].pid, SIGHUP);
			__plat_process_resume(__children[i].h);
		}
		__children[i].stopsig = 0;
		/* A forked child did not cause either a sibling's stop or its
		 * continue, so neither inherited report belongs to it.  Clearing
		 * both fields also makes the helper's name describe the complete
		 * job-control state rather than only the kernel suspension. */
		__children[i].jobstat = 0;
	}
}

/* exit.html: "if the exit of the process causes a process group to
 * become orphaned, and if any member ... is stopped, then a SIGHUP
 * signal followed by a SIGCONT signal shall be sent to each process."
 * Every process is its own group of one here (src/unistd/ids.c), so a
 * child this process stopped is always orphaned the instant it exits.
 *
 * SIGCONT is unconditional: the suspend count lives in the kernel, the
 * only handle to the child dies with this process, and nothing else
 * could ever open it by pid again -- so a child left suspended here
 * would stay suspended forever. Resuming clears that completely.
 *
 * SIGHUP is sent for real only where the platform can actually deliver
 * it, applying the child's own disposition, rather than destroy the
 * child outright (__plat_sig_deliverable_to_other_process()). On Linux
 * that is a genuine pidfd_send_signal(2) honoring whatever real
 * disposition the child last synced (ignore, default Term, or a real
 * installed handler). NT has no cross-process signal delivery at all --
 * kill(child, SIGHUP) there is NtTerminateProcess, strictly worse than
 * what the clause intends -- so NT sends only the SIGCONT half.
 *
 * Coverage follows __exit_internal(): exit()/_exit()/_Exit(), abort(),
 * the default-terminate action for an uncaught signal, and a parent that
 * dies of a SIGSEGV (exception_handler() funnels into the same path). A
 * process ended without this library running at all (raw
 * NtTerminateProcess, an unmapped exception) leaves the same residue any
 * POSIX system leaves for SIGKILL. */
void __child_resume_stopped(void) { clear_stops(1); }

void __child_forget_stops(void) { clear_stops(0); }

// NOLINTEND(misc-include-cleaner)
