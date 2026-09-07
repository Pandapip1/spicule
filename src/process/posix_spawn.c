/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * posix_spawn() and posix_spawnp() -- see
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawn.html
 *
 * Almost all of this is already done by __spawn() (src/process/spawn.c),
 * which execve(), fork() and system() are also built on. Two things are
 * added here: the POSIX interface shape, and replaying a
 * posix_spawn_file_actions_t.
 *
 *
 * Replaying file actions without a child to replay them in
 * -------------------------------------------------------
 *
 * POSIX describes posix_spawn() as a fork() whose child performs the
 * recorded file actions and then execs. There is no child to perform
 * them in here: NT starts a process from an image file, so __spawn()
 * hands the future child its descriptor table up front, packed into
 * RTL_USER_PROCESS_PARAMETERS' RuntimeData (src/internal/fd.c). So the
 * actions run in the *parent*, on the parent's own table, immediately
 * before __spawn() reads it, and are undone immediately after -- the
 * child sees exactly the table the actions produced, and the parent
 * gets its own back.
 *
 * Three things make that safe: ntlibc has no threads, so nothing can
 * race the parent's table during the window; the save is of the *table
 * slot*, not a descriptor (struct __fd copied out and the slot zeroed),
 * since __fd_runtime_data() rewrites every inheritable slot's handle in
 * place and a handle it can still see cannot be safely restored later;
 * and restoring closes whatever the actions left in the slot before
 * writing the original back, so nothing leaks and no inheritable handle
 * lingers for the *next* spawn to pick up.
 *
 * A failing action therefore fails posix_spawn() itself with the errno
 * of the underlying close()/dup2()/open(), one of the two dispositions
 * ERRORS allows -- no process is created, and no exit status 127 is
 * ever manufactured here.
 *
 *
 * Which spawn attributes can be acted on
 * --------------------------------------
 *
 * A flag this platform cannot honour makes posix_spawn() fail rather
 * than being silently dropped -- a caller told success but given a
 * child that does not run at the requested priority is worse off than
 * with an error it is already written to expect:
 *
 *   POSIX_SPAWN_SETSIGDEF -- satisfied by construction: an NT process
 *     runs its own crt1 before main(), and signal.c's `handlers[]` is a
 *     static SIG_DFL for every fresh child regardless of the mask named.
 *
 *   POSIX_SPAWN_SETSIGMASK -- honoured on NT via an ntlibc-specific
 *     trailer on the same RuntimeData blob that carries the descriptor
 *     table (SIG_RUNTIME_MAGIC): __spawn_set_pending_sigmask() sets it
 *     before __spawn(), __fd_init() reads it back before the child's
 *     main() runs at all, so the mask is in place before the child's
 *     first instruction. Not equivalent to POSIX in one respect: the
 *     kernel there carries the mask across exec for *any* image, while
 *     this trailer only reaches an ntlibc-built child. Refused with
 *     EINVAL on Linux -- the mechanism is NT-specific and unverified
 *     there (test/posix-spawn.c's fence).
 *
 *   POSIX_SPAWN_RESETIDS -- inapplicable and honoured: an NT access
 *     token has no real/effective/saved triple to differ, so the
 *     postcondition is unconditionally true.
 *
 *   POSIX_SPAWN_SETPGROUP -- honoured only for the caller's own process
 *     group. src/unistd/ids.c keeps that group as per-process
 *     bookkeeping rather than something NT lets a process join; a
 *     spawn-pgroup naming the caller's own group is accepted (already
 *     true of any child, which is born into that same group), and
 *     anything else -- including 0, "a new group of its own" -- is
 *     EINVAL, matching setpgid()'s own "not a value supported" clause.
 *
 *   POSIX_SPAWN_SETSCHEDPARAM / POSIX_SPAWN_SETSCHEDULER -- honoured on
 *     NT via the same suspended-process window __spawn_set_pending_
 *     priority() uses: __plat_priority_set() runs on the child's handle
 *     before its first instruction. The POSIX shape does not survive:
 *     NT has priorities but no SCHED_FIFO/RR/OTHER distinction, so
 *     `policy` is accepted unconditionally and only `sched_priority` is
 *     applied (mapped by nice_from_sched_priority(), below). Best-effort
 *     like every __plat_priority_set() caller: a target this process
 *     cannot raise just keeps its default priority, silently. Refused
 *     with EINVAL on Linux, where real scheduling policies exist and
 *     nothing here applies `sched_priority` for real there;
 *     spawnattr.c's accessors still store/return the value regardless.
 *
 *   POSIX_SPAWN_USEVFORK -- not POSIX; accepted and satisfied by
 *     construction, since __spawn() never copies the parent's address
 *     space anyway.
 *
 * Any other bit is EINVAL.
 *
 *
 * errno
 * -----
 *
 * The error from posix_spawn()/posix_spawnp() is the function's return
 * value, not errno -- the single most commonly botched thing about
 * these two functions -- so errno is captured on entry and restored on
 * every path out, including success.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include "libc.h"
#include "spawn_internal.h"
#include "plat_fd.h"

/* signal.c always provides this helper; signal.h exposes its public
 * declaration only for BSD/GNU feature profiles.  The implementation uses
 * it internally regardless of the caller-facing feature selection. */
int sigisemptyset(const sigset_t *);

/* One saved descriptor-table slot.
 *
 * `slot` is the struct __fd as it stood before the actions ran; the
 * table entry it came from was zeroed at the same moment, so nothing in
 * __fds[] refers to slot.h any more and __fd_runtime_data() cannot
 * rewrite it out from under the save. */
struct saved_slot {
	int fd;
	struct __fd slot;
};

/* Vacate fd so an action can put something there, remembering the
 * parent's contents the *first* time -- an fd named by two actions is
 * saved once, by what was in it before any of them ran, and the second
 * action closes what the first left rather than overwriting it (an
 * overwrite would strand an inheritable handle, e.g. a pipe write end,
 * open in the parent forever: test_order_two_targets() in
 * test/posix-spawn.c).
 *
 * The first-visit path also marks the vacated descriptor close-on-exec
 * via __plat_set_cloexec(), for as long as it stays vacated: removing it
 * from __fds[] alone is enough when inheritance is table-driven (NT),
 * but not when it's kernel-fd-driven (Linux) -- there, a descriptor this
 * library's table stopped mentioning is still just as inheritable to the
 * kernel while __spawn()'s real fork()+execve() runs. Without this,
 * posix_spawn_file_actions_addclose() would remove the descriptor from
 * this process's bookkeeping without ever making the child unable to see
 * it. An in-place fcntl(F_SETFD), not a duplicate, is used because the
 * slot may still need to hand back the exact original object afterward.
 *
 * Returns 0, or -1 if the save array is full, which cannot happen (it is
 * sized at one entry per action, each vacating at most one slot) but is
 * checked rather than assumed. */
/* nsv is required: every real call site passes &nsv, a local, never
 * NULL. sv is left unmarked -- genuinely only reached when cap >= 1 in
 * every real call, but that isn't a documented hard invariant. */
static int take_slot(struct saved_slot *sv, int *nsv, int cap, int fd)
    __attribute__((nonnull(2)));
static int take_slot(struct saved_slot *sv, int *nsv, int cap, int fd) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int i;
	for (i = 0; i < *nsv; i++) {
		if (sv[i].fd != fd) continue;
		if (__fds[fd].h) __plat_close(__fds[fd].h);
		__fd_release_dynamic(&__fds[fd]);
		memset(&__fds[fd], 0, sizeof __fds[fd]);
		return 0;
	}
	if (*nsv >= cap) return -1;
	sv[*nsv].fd = fd;
	sv[*nsv].slot = __fds[fd];
	(*nsv)++;
	if (__fds[fd].h) __plat_set_cloexec(__fds[fd].h, 1);
	/* The live slot's dbuf, if any, has already been handed off to
	 * sv[*nsv-1].slot above (a plain struct copy) -- restore_slots()
	 * gives it back to __fds[fd] later, so this memset must not free
	 * it, only clear the live slot's own copy of the pointer. */
	memset(&__fds[fd], 0, sizeof __fds[fd]);
	return 0;
}

/* Put every saved slot back, closing whatever the actions left behind
 * first.  Called on the success path and on every failure path, so the
 * parent's table is identical afterwards either way. */
static void restore_slots(struct saved_slot *sv, int nsv)
{
	int i;
	for (i = nsv - 1; i >= 0; i--) {
		int fd = sv[i].fd;
		if (__fds[fd].h) __plat_close(__fds[fd].h);
		__fd_release_dynamic(&__fds[fd]);
		__fds[fd] = sv[i].slot;
		/* Undo take_slot()'s own close-on-exec marking -- back to
		 * whatever the saved slot's own flags actually say, almost
		 * always clear, but not assumed to be (see take_slot()'s own
		 * comment). */
		if (__fds[fd].h) __plat_set_cloexec(__fds[fd].h, (__fds[fd].flags & O_CLOEXEC) != 0);
	}
}

/* Perform one action.  Returns 0, or the error number to hand back. */
/* a is required (`switch (a->kind)` dereferences it unconditionally at
 * entry); sv/nsv are left unmarked -- both are only ever forwarded
 * into take_slot(), never dereferenced by do_action() itself. */
static int do_action(const struct __spawn_action *a, struct saved_slot *sv, int *nsv, int cap)
    __attribute__((nonnull(1)));
static int do_action(const struct __spawn_action *a, struct saved_slot *sv, int *nsv, int cap)
{
	switch (a->kind) {
	case __SPAWN_CLOSE:
		/* A close of an already-closed descriptor is a success, not
		 * EBADF: the action's postcondition ("fildes is not open")
		 * already holds, and a caller listing every descriptor it
		 * wants shut has no way to know which happen to be open.
		 * glibc's posix_spawn does the same. */
		if (take_slot(sv, nsv, cap, a->u.close.fd) < 0) return ENOMEM;
		return 0;

	case __SPAWN_DUP2: {
		/* The duplicate is made before the target slot is vacated: with
		 * adddup2(fd, fd) source and target are the same slot, so
		 * vacating first would close the handle about to be duplicated.
		 *
		 * O_CLOEXEC is dropped: a descriptor a file action names is one
		 * the caller wants the child to have (same as dup2() here,
		 * src/unistd/dup.c dup_to with cloexec=0), which is what makes
		 * adddup2(fd, fd) meaningful -- POSIX's step 4 closes every
		 * FD_CLOEXEC descriptor in the child, so naming a descriptor as
		 * its own dup2 target is how a caller says "keep this one". */
		__plat_handle_t h;
		unsigned flags;
		int type;
		struct __fd *f = __fd_get(a->u.dup2.fd);
		if (!f) return EBADF;
		flags = f->flags & ~(unsigned)O_CLOEXEC;
		type = f->type;
		if (__plat_dup(f->h, 1, &h) < 0) return errno;
		if (take_slot(sv, nsv, cap, a->u.dup2.newfd) < 0) { __plat_close(h); return ENOMEM; }
		__fd_install_at(a->u.dup2.newfd, h, flags, type);
		return 0;
	}

	case __SPAWN_OPEN: {
		/* "as if open() had been called ... and the returned file
		 * descriptor, if not fildes, had been changed to fildes"
		 * (posix_spawn_file_actions_addopen.html DESCRIPTION).  open()
		 * hands back the lowest free slot, which may or may not be
		 * fildes; the slot has just been vacated, so it often is. */
		int t;
		if (take_slot(sv, nsv, cap, a->u.open.fd) < 0) return ENOMEM;
		t = open(a->u.open.path, a->u.open.oflag, a->u.open.mode);
		if (t < 0) return errno;
		if (t != a->u.open.fd) {
			if (dup2(t, a->u.open.fd) < 0) { int e = errno; (void)close(t); return e; }
			(void)close(t);
		}
		/* Checker gap (ntlibc.ResourceLeak): when t == a->u.open.fd
		 * already, it IS the requested slot from here on (no dup2/close
		 * needed or wanted) -- the checker can't see that aliasing, so
		 * it reports t as never released. */
		return 0;
	}
	default:
		return EINVAL;
	}
}

/* Everything posix_spawn() must decide *before* it starts editing the
 * descriptor table, so a rejected attribute costs no undo. Returns 0 or
 * the error number.
 *
 * POSIX_SPAWN_SETSIGMASK (non-empty) and POSIX_SPAWN_SETSCHEDPARAM/
 * SETSCHEDULER are accepted on NT (they ride the suspended-process
 * window before the child's first instruction, see this file's banner)
 * but refused on Linux, where the mechanism each flag rides is
 * NT-specific and unverified. */
static int check_attr(const posix_spawnattr_t *at)
{
	short f;
	if (!at) return 0;
	f = at->__flags;
	if (f & ~(short)(POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF
	                 | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSCHEDPARAM
	                 | POSIX_SPAWN_SETSCHEDULER | POSIX_SPAWN_USEVFORK))
		return EINVAL;
#if defined(__linux__)
	if (f & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER)) return EINVAL;
	if ((f & POSIX_SPAWN_SETSIGMASK) && !sigisemptyset(&at->__sigmask)) return EINVAL;
#endif
	if ((f & POSIX_SPAWN_SETPGROUP) && at->__pgroup != getpgrp()) return EINVAL;
	return 0;
}

/* sched_priority has no POSIX scheduling policy behind it here to
 * interpret it against, so this mapping onto NT's priority classes is
 * invented, not specified: treat the number as a nice value and clamp it
 * exactly as setpriority() clamps one for an unprivileged target
 * (src/misc/resource.c: never below 0), so applying it can only lower or
 * hold the child's priority, never silently fail to raise one the caller
 * thought it had. */
static int nice_from_sched_priority(int sched_priority)
{
	if (sched_priority < 0) return 0;
	if (sched_priority > NZERO - 1) return NZERO - 1;
	return sched_priority;
}

/* Every __SPAWN_DUP2 target above 2, as the parent's table stands once
 * every action has replayed -- the list Linux's __plat_process_spawn()
 * needs to move each one onto the right real descriptor NUMBER in the
 * CHILD, rather than wherever do_action()'s __plat_dup() put it in the
 * parent (struct __spawn_dup2_target's comment in libc.h explains why NT
 * needs none of this). `out` needs room for fa->__len entries: at most
 * that many distinct DUP2 targets above 2 can exist before the dedup
 * below shrinks it.
 *
 * Consulting the FINAL state of __fds[target], not the handle do_action()
 * installed at the moment its action ran, is what makes a target touched
 * more than once come out right with no extra bookkeeping: take_slot()
 * has already collapsed any such chain to one slot, so a walk of the
 * finished table sees exactly what the child should end up with --
 * including "nothing" for a target later closed, correctly left out
 * rather than staged and closed again. Returns the count written to
 * `out`.
 *
 * fa is required (the one real call site only reaches here inside its
 * own `if (fa && fa->__len)`); out is left unmarked, sized to fa->__len
 * regardless by that same call site. */
static int build_dup2_targets(const posix_spawn_file_actions_t *fa, struct __spawn_dup2_target *out)
    __attribute__((nonnull(1)));
static int build_dup2_targets(const posix_spawn_file_actions_t *fa, struct __spawn_dup2_target *out)
{
	int i, n = 0;
	for (i = 0; i < fa->__len; i++) {
		const struct __spawn_action *a = &fa->__actions[i];
		struct __fd *f;
		int j, dup = 0;
		if (a->kind != __SPAWN_DUP2 || a->u.dup2.newfd <= 2) continue;
		for (j = 0; j < n; j++) if (out[j].fd == a->u.dup2.newfd) { dup = 1; break; }
		if (dup) continue;
		f = __fd_get(a->u.dup2.newfd);
		if (!f) continue; /* final state: closed -- nothing to re-home */
		out[n].fd = a->u.dup2.newfd;
		out[n].h = f->h;
		n++;
	}
	return n;
}

static int spawn_common(pid_t *pid, const char *path,
                        const posix_spawn_file_actions_t *fa,
                        const posix_spawnattr_t *at,
                        char *const argv[], char *const envp[], int use_path)
{
	struct saved_slot *sv = 0;
	struct __spawn_dup2_target *extra = 0;
	int nsv = 0, cap = 0, nextra = 0;
	int i, rc, child = -1, saved_errno = errno;
	char *full = 0;

	rc = check_attr(at);
	if (rc) goto out;

	/* posix_spawnp() "shall do a path search" for a file argument with
	 * no slash; posix_spawn() never does one.  __find_program() takes
	 * that as its second argument and applies the same has-a-directory
	 * test execvp() uses, plus the ".exe" suffix an NT image wants. */
	errno = 0;
	full = __find_program(path, use_path);
	/* __find_program() sets ENOENT when a PATH search came up empty and
	 * leaves errno alone when its malloc() failed, so a cleared errno is
	 * how the second case is told from the first. */
	if (!full) { rc = errno ? errno : ENOMEM; goto out; }

	/* fa->__actions[i] below isn't expressible via nonnull on fa itself:
	 * fa is genuinely nullable here (POSIX allows a null file_actions),
	 * and what makes the subscript safe inside the `if (fa && ...)`
	 * branch is a field invariant of posix_spawn_file_actions_t
	 * (fa_push(), spawn_file_actions.c): fa->__len > 0 implies
	 * fa->__actions != NULL by construction. */
	if (fa && fa->__len) {
		size_t svbytes, extrabytes;
		cap = fa->__len;
		if (!__size_mul_checked((size_t)cap, sizeof *sv, &svbytes) ||
		    !__size_mul_checked((size_t)cap, sizeof *extra, &extrabytes)) {
			rc = ENOMEM;
			goto out;
		}
		sv = malloc(svbytes);
		/* At most one distinct __SPAWN_DUP2 target above 2 per action,
		 * so `cap` is as much room as build_dup2_targets() below could
		 * ever need -- see that function's own comment. */
		extra = malloc(extrabytes);
		if (!sv || !extra) { rc = ENOMEM; goto out; }
		for (i = 0; i < fa->__len; i++) {
			rc = do_action(&fa->__actions[i], sv, &nsv, cap);
			if (rc) goto out;
		}
		nextra = build_dup2_targets(fa, extra);
	}

	/* Set immediately before __spawn() and cleared immediately after,
	 * success or failure either way, so neither leaks onto a later,
	 * unrelated spawn (see __spawn_set_pending_sigmask(), libc.h).
	 * build_dup2_targets()'s list rides the identical channel for the
	 * identical reason. */
	if (at && (at->__flags & POSIX_SPAWN_SETSIGMASK) && !sigisemptyset(&at->__sigmask))
		__spawn_set_pending_sigmask(&at->__sigmask);
	if (at && (at->__flags & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER)))
		__spawn_set_pending_priority(nice_from_sched_priority(at->__param.sched_priority));
	if (nextra) __spawn_set_pending_dup2s(extra, nextra);

	child = __spawn(full, argv, envp);
	if (child < 0) rc = errno;

	__spawn_clear_pending_sigmask();
	__spawn_clear_pending_priority();
	__spawn_clear_pending_dup2s();

out:
	restore_slots(sv, nsv);
	free(sv);
	free(extra);
	free(full);
	if (!rc && pid) *pid = child;
	errno = saved_errno;
	return rc;
}

int posix_spawn(pid_t *__restrict pid, const char *__restrict path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *__restrict at,
                char *const *__restrict argv, char *const *__restrict envp)
{
	return spawn_common(pid, path, fa, at, argv, envp, 0);
}

int posix_spawnp(pid_t *__restrict pid, const char *__restrict file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *__restrict at,
                 char *const *__restrict argv, char *const *__restrict envp)
{
	return spawn_common(pid, file, fa, at, argv, envp, 1);
}

// NOLINTEND(misc-include-cleaner)
