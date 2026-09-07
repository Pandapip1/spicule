/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Starting another program.
 *
 * Windows starts a process from an image file, not by copying a running
 * one, so __spawn is what execve and posix_spawn are built on: it builds
 * the child's process parameters (command line, environment, current
 * directory, and the inherited descriptor table), creates the process
 * suspended with RtlCreateUserProcess, and resumes it.
 *
 * Handing a child its file descriptors has non-obvious parts:
 *
 *   - Only OBJ_INHERIT handles are copied into the child, so the ones it
 *     should keep are duplicated inheritable first (__fd_runtime_data),
 *     with their numbers written into the RuntimeData block the child's
 *     crt1 reads back.
 *
 *   - STARTF_USESTDHANDLES must be set in WindowFlags directly (measured
 *     necessary on Windows 11; RtlCreateUserProcess offers no API for
 *     it), or the standard handles written below do not reach the child
 *     intact.
 *
 *   - A *closed* standard descriptor cannot be represented by writing 0
 *     or INVALID_HANDLE_VALUE into the field: on real Windows 11,
 *     something between the write here and the child's first instruction
 *     silently replaces either sentinel with a live, open descriptor
 *     (measured; neither kernel32 nor kernelbase is even mapped into
 *     these -nostdlib/-lntdll-only processes, so it is not a kernel32-side
 *     console bring-up doing it). The replacement is value-blind, so what
 *     works instead is a real, valid, non-pseudo HANDLE that is not a
 *     file/console/pipe -- closed_placeholder() below duplicates the
 *     current-process pseudohandle for this; the receiving side cannot
 *     identify it as a process handle (__handle_type()), so the
 *     descriptor still comes up closed in the child. This placeholder
 *     also has to survive Windows filling in NULL std-handle slots when
 *     it allocates a fresh console for a detached child (a NULL slot
 *     gets filled in; a live placeholder handle is left alone) -- why
 *     passing NULL for "closed" is not equivalent, and why the
 *     difference only shows up for a detached parent.
 *
 * The command line is built by the quoting rules CommandLineToArgvW and
 * every Windows C runtime agree on, so an argument with spaces, quotes or
 * backslashes survives the round trip into the child's argv.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "libc.h"
#include "plat_fd.h"
#include "plat_process.h"

/* posix_spawn()'s POSIX_SPAWN_SETSCHEDPARAM/POSIX_SPAWN_SETSCHEDULER
 * (full story in libc.h). Lives here, portable, since its one consumer
 * (NT's __plat_process_spawn()) and one producer (posix_spawn.c's
 * spawn_common()) both already reach this file's __spawn() for
 * everything else a spawn needs. */
static int pending_priority;
static int pending_priority_set;

void __spawn_set_pending_priority(int nice_value)
{
	pending_priority = nice_value;
	pending_priority_set = 1;
}

void __spawn_clear_pending_priority(void)
{
	pending_priority_set = 0;
}

int __spawn_pending_priority(int *out)
{
	if (!pending_priority_set) return 0;
	*out = pending_priority;
	return 1;
}

/* posix_spawn_file_actions_adddup2() targets above 2, for Linux's own
 * __plat_process_spawn() (src/process/linux/plat_process.c) alone -- see
 * struct __spawn_dup2_target's own comment (libc.h) for why this is the
 * mirror image of pending_priority above: NT never reads it back, Linux
 * is the only backend that needs a channel here at all. */
static const struct __spawn_dup2_target *pending_dup2s;
static int pending_dup2s_n;

void __spawn_set_pending_dup2s(const struct __spawn_dup2_target *list, int n)
{
	pending_dup2s = list;
	pending_dup2s_n = n;
}

void __spawn_clear_pending_dup2s(void)
{
	pending_dup2s = 0;
	pending_dup2s_n = 0;
}

const struct __spawn_dup2_target *__spawn_pending_dup2s(int *out_n)
{
	*out_n = pending_dup2s_n;
	return pending_dup2s;
}

/* Building the UTF-16 command line and environment block (see this
 * file's banner for the quoting rules and standard-handle fix-up),
 * resolving the image path, and the RtlCreateProcessParametersEx ->
 * RtlCreateUserProcess -> resume sequence all live in
 * src/process/nt/plat_process.c's __plat_process_spawn(), one coarse
 * call (see plat_process.h's banner for why). What is left here is
 * POSIX-level bookkeeping: resolving the three standard descriptors from
 * this process's own fd table, and adding the new pid to the child table
 * so waitpid() can find it. */
int __spawn(const char *path, char *const argv[], char *const envp[])
{
	struct __fd *f0 = __fd_get(0), *f1 = __fd_get(1), *f2 = __fd_get(2);
	__plat_handle_t std[3];
	__plat_handle_t process = __PLAT_HANDLE_NULL;
	__plat_handle_t job = __PLAT_HANDLE_NULL;
	int pid;

	/* A close-on-exec standard descriptor is not the child's to have,
	 * and its handle is not inheritable anyway, so it is represented to
	 * the backend exactly like a fully closed one -- __PLAT_HANDLE_NULL,
	 * which __plat_process_spawn() turns into a real, value-blind
	 * placeholder rather than a sentinel a Windows fix-up could
	 * mistake for a live handle (see plat_process.h/plat_process.c). */
	if (f0 && (f0->flags & O_CLOEXEC)) f0 = 0;
	if (f1 && (f1->flags & O_CLOEXEC)) f1 = 0;
	if (f2 && (f2->flags & O_CLOEXEC)) f2 = 0;
	std[0] = f0 ? f0->h : __PLAT_HANDLE_NULL;
	std[1] = f1 ? f1->h : __PLAT_HANDLE_NULL;
	std[2] = f2 ? f2->h : __PLAT_HANDLE_NULL;

	pid = __plat_process_spawn(path, argv, envp ? envp : __environ, std, &process, &job);
	if (pid < 0) return -1;

	/* The process exists, running (the backend already resumed its
	 * initial thread); track it like any other child so waitpid() can
	 * find it. */
	if (__child_add(pid, process, job) < 0) {
		/* The table grows on demand (src/process/children.c), so this
		 * only happens when the heap is exhausted.  Degrade rather than
		 * fail the spawn: the process still runs, but it is unwaitable
		 * -- waitpid() only ever consults the table (src/process/wait.c). */
		__plat_close(process);
		if (job) __plat_close(job);
	}
	return pid;
}

// NOLINTEND(misc-include-cleaner)
