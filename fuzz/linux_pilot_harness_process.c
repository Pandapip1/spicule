/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux process/fork/wait pilot -- NOT
 * part of spicule, exactly like fuzz/ntstubs.c is "not part of spicule" for
 * the native ASan build, and fuzz/linux_pilot_harness.c is for the
 * mman/unistd-fd-ops pilot this one sits alongside.
 *
 * src/process/fork.c, wait.c and children.c -- the real front doors this
 * test links and exercises -- call out to a wide net of other
 * subsystems' "forget this state, it does not survive a fork" hooks and
 * job-control helpers. On real spicule those are each a real function
 * owned by a different subsystem (thread, signal, mman's own front door,
 * malloc, aio, WOW64 detection). Six OTHER sessions are porting those
 * subsystems to Linux in parallel, each in an isolated worktree this one
 * cannot see -- so every one of them is stubbed here, LOCAL TO THIS TEST
 * HARNESS ONLY, rather than given a real implementation that would
 * collide with or preempt that other work.
 * Every stub below is a no-op or a fixed "nothing pending" answer, which
 * is exactly correct for a test process that has no threads, no pending
 * AIO, no alarm, no signal-delivery thread and no WOW64 involved to begin
 * with -- not a shortcut around real behavior this test needs and does
 * not get.
 *
 * The fd-table pieces (__fds[]/__fd_alloc/__fd_install (and _at)/__fd_get,
 * __fd_pos_save/__fd_pos_restore, __mq_fd_closed/__mq_fd_replaced,
 * __fsize_*) are copied from fuzz/linux_pilot_harness.c's own minimal
 * reimplementation verbatim, for the same reason that file gives: the
 * real src/internal/fd.c's __handle_type() is NT-only, so linking it
 * would need Windows syscalls this native build cannot make.
 *
 * __malloc()/__free() are stubbed to fail outright (return 0 / do
 * nothing): src/process/children.c's child table only reaches for the
 * allocator once its static 256-entry seed array (CHILD_MAX_, libc.h)
 * is full, which this pilot's test -- a handful of children, never more
 * than one or two outstanding at once -- never comes close to. Reporting
 * allocation failure if that path were ever hit is honest (it correctly
 * degrades to "this child becomes unwaitable" rather than silently
 * fabricating heap the real allocator was never asked to hand out) and
 * unreachable in practice for what this test actually does.
 */
#include <string.h>
#include "libc.h"

/* ---- fd table (verbatim copy of linux_pilot_harness.c's own reasoning) */

struct __fd __fds[FD_MAX];
int __fd_limit = FD_MAX;

int __fd_alloc(int lowest)
{
	int i;
	if (lowest < 0) lowest = 0;
	for (i = lowest; i < __fd_limit; i++)
		if (!__fds[i].h) return i;
	errno = EMFILE;
	return -1;
}

/* Real fd.c's own version (src/internal/fd.c): frees getdents()'s
 * lazily-allocated continuation buffer before a slot is wiped and
 * reused -- needed here because both src/unistd/close.c and
 * src/process/posix_spawn.c (this pilot's own front door) call it.
 * __free() below is already a no-op stand-in for this pilot, so this
 * just forwards to it like the real implementation does. */
void __fd_release_dynamic(struct __fd *f)
{
	if (f->dbuf) { __free(f->dbuf); f->dbuf = 0; }
}

int __fd_install_at(int fd, HANDLE h, unsigned flags, int type)
{
	struct __fd *f = &__fds[fd];
	__fd_release_dynamic(f);
	memset(f, 0, sizeof *f);
	f->h = h;
	f->flags = flags;
	f->type = (unsigned char)type;
	f->pos = -1;
	return fd;
}

int __fd_install(HANDLE h, unsigned flags, int type)
{
	int fd = __fd_alloc(0);
	if (fd < 0) return -1;
	return __fd_install_at(fd, h, flags, type);
}

struct __fd *__fd_get(int fd)
{
	if (fd < 0 || fd >= FD_MAX || !__fds[fd].h) { errno = EBADF; return 0; }
	return &__fds[fd];
}

int __fd_pos_save(HANDLE h, long long *pos)
{
	(void)h;
	*pos = 0;
	return 0;
}

void __fd_pos_restore(HANDLE h, long long pos)
{
	(void)h;
	(void)pos;
}

void __mq_fd_closed(int fd) { (void)fd; }
void __mq_fd_replaced(int fd, __plat_handle_t h) { (void)fd; (void)h; }

int __fsize_limited(void) { return 0; }
long long __fsize_clamp(__plat_handle_t h, int append, size_t count)
{
	(void)h; (void)append;
	return (long long)count;
}
long long __fsize_room_at(long long off) { (void)off; return 0x7fffffffffffffffLL; }
int __fsize_exceeded(void) { return -1; }

/* ---- cross-subsystem fork()/job-control hooks -- LOCAL-ONLY stubs, --- */
/* ---- see this file's own banner -------------------------------------- */

void __pthread_atfork_prepare(void) {}
void __pthread_atfork_parent(void) {}
void __pthread_atfork_child(void) {}
void __pthread_reset_after_fork(void) {}
void __alarm_reset_after_fork(void) {}
void __mman_reset_after_fork(void) {}
void __aio_reset_after_fork(void) {}
void __sig_delivery_reinit_after_fork(void) {}

/* "Is SIGCHLD's SA_NOCLDWAIT set" -- signal.c, unported here. Always "no"
 * is correct for a test that never touches sigaction() at all. */
int __sigchld_nocldwait(void) { return 0; }

/* "Has this child published a self-stop marker" -- signal.c's job-control
 * machinery, unported here. This pilot's __plat_process_resume() test
 * (see linux_pilot_test_process.c) synchronizes on a raw wait4(WUNTRACED)
 * probe of its own instead of going through this path, exactly because
 * this stub cannot answer it for real. */
int __sig_consume_child_stop(int pid) { (void)pid; return 0; }
void __sigchld_job_control(struct __child *c, int sig) { (void)c; (void)sig; }

/* Never meaningful off i386 (see libc.h's own __is_wow64() comment); this
 * build's ARCH is x86_64 regardless of the aarch64 host actually running
 * it, so "no" is not a stand-in, it is the real answer. */
int __is_wow64(void) { return 0; }

void *__malloc(size_t n) { (void)n; errno = ENOMEM; return 0; }
void __free(void *p) { (void)p; }
