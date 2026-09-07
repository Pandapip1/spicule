/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-descriptor interface src/unistd/{close,read,write,lseek,
 * dup}.c's POSIX-facing front doors call into instead of a raw
 * Nt{Close,ReadFile,WriteFile,QueryInformationFile,SetInformationFile,
 * DuplicateObject} call.  See src/unistd/nt/plat_fd.c for the
 * implementation these declare.
 *
 * Every function here takes POSIX-shaped arguments and returns a
 * POSIX-shaped result -- errno already set on failure, never a raw
 * platform status for the front door to interpret.  Every NT-specific
 * interpretation step lives entirely inside the backend function's
 * body: STATUS_PENDING waits, end-of-file/broken-pipe detection,
 * translating "the write's starting position was at the offset
 * maximum" into EFBIG.  The fd-table bookkeeping around these calls
 * (__fd_get, __fd_pos_save/restore, __fd_install_at, ...) is NOT part
 * of this interface -- it stays in the front door, unchanged, exactly
 * like mman.c's own reservation table (see plat_mem.h).
 */
#ifndef _SPICULE_PLAT_FD_H
#define _SPICULE_PLAT_FD_H

#include <stddef.h>
#include <sys/types.h>
#include "plat_handle.h"

int __plat_close(__plat_handle_t h);

ssize_t __plat_read(__plat_handle_t h, void *buf, size_t count);
ssize_t __plat_pread(__plat_handle_t h, void *buf, size_t count, off_t off);

/* `append` is O_APPEND && the descriptor is a regular file -- exactly
 * write()'s own condition for "position the write past the current
 * end of file rather than at the descriptor's saved position",
 * which is where FILE_WRITE_TO_END_OF_FILE (an NT-only positioning
 * token) is decided, entirely inside the backend. A failure whose
 * starting position was at or past the POSIX offset maximum reports
 * EFBIG; a broken/disconnected/closing pipe raises SIGPIPE and
 * reports EPIPE.  The signal is raised inside the backend, not by the
 * front door testing errno==EPIPE afterward: the generic status-to-
 * errno mapping also produces EPIPE for other statuses that must NOT
 * raise SIGPIPE, and only the backend still has the real status in
 * hand to tell them apart. */
ssize_t __plat_write(__plat_handle_t h, const void *buf, size_t count, int append);
ssize_t __plat_pwrite(__plat_handle_t h, const void *buf, size_t count, off_t off);

/* The descriptor's current byte position (`at_eof` zero) or the
 * object's end-of-file offset (`at_eof` nonzero) -- lseek()'s
 * SEEK_CUR and SEEK_END queries, respectively.  -1/errno on failure. */
long long __plat_seek_query(__plat_handle_t h, int at_eof);
/* Set the descriptor's byte position to exactly `target` (already
 * computed and overflow-checked by the front door).  0/-1(errno). */
int __plat_seek_set(__plat_handle_t h, long long target);

/* Duplicate `h`; the new handle is inheritable by a child process iff
 * `inheritable` is nonzero.  0/-1(errno) via *out.
 *
 * out required: both real implementations write `*out = ...`
 * unconditionally on the success path, with no NULL check of out
 * itself anywhere. Every real call site (src/unistd/dup.c, src/mman/
 * mman.c, src/process/fork.c, src/process/posix_spawn.c) always passes
 * the address of its own local, never NULL. */
int __plat_dup(__plat_handle_t h, int inheritable, __plat_handle_t *out)
    __attribute__((nonnull(3)));

/* Duplicate `h` the way dup2(2)/dup3(2) do: the result is required to
 * BE `newfd`, not merely to be reachable through the fd table at index
 * `newfd`. On NT that distinction is vacuous -- a HANDLE's numeric
 * value is never externally significant (a spawned child's descriptor
 * table is built from an explicit RuntimeData mapping, never by a raw
 * handle-value coincidence surviving process creation the way a raw fd
 * number does across Linux's real fork()+execve()), so `newfd` is
 * unused there and this behaves exactly like __plat_dup(). On Linux it
 * matters for real: __plat_dup() above is plain dup(2), which hands
 * back an arbitrary low fd, and using it to fill a *specific* table
 * slot (src/unistd/dup.c dup_to(), this function's only caller today)
 * only coincidentally lines up the real kernel descriptor with the
 * spicule-level index it is filed under -- when it does not, the
 * mismatch is invisible to every caller in THIS process (every
 * operation here dereferences the handle, never the table index, to
 * reach the real descriptor) but breaks the moment a child is
 * spawned: a Linux child inherits real descriptor NUMBERS directly
 * (src/process/linux/plat_process.c's own banner), so a caller-
 * requested "fd N in the child" only survives if the parent's own
 * real descriptor N, at the instant of the spawning clone(2), is the
 * one actually meant. `newfd` is a REAL kernel fd number on that
 * backend, not merely a table index -- dup2()/dup3()'s own target is
 * always used as the matching __fds[] table index by the same caller,
 * and the two staying equal is the whole invariant this function
 * exists to preserve; see src/internal/linux/plat_fd_init.c's own
 * banner for the freshly-exec'd child's half of the same invariant.
 *
 * `old` is whatever handle previously occupied the fd table's own
 * `newfd` slot (__PLAT_HANDLE_NULL if none) -- disposing of it is
 * THIS function's job, not the caller's, because only a per-backend
 * body knows how: on Linux, dup3(2) below already closes the real
 * descriptor numbered `newfd` atomically as an unavoidable part of
 * making the new duplicate BE that number, so `old` needs no separate
 * close there (and closing it anyway, after the fact, would close the
 * brand new duplicate this call just made instead -- `old`'s own
 * boxed value names the same real number `newfd` does by then). NT's
 * NtDuplicateObject() has no such "replace this target" mode at all,
 * so `old` genuinely needs a real close there, same as any caller of
 * plain __plat_dup() above already has to do by hand. A caller naming
 * a descriptor as its own dup2 target (POSIX_SPAWN_FILE_ACTIONS-style
 * adddup2(fd, fd), src/process/posix_spawn.c's do_action() comment)
 * would pass the same handle as both h and old -- not reachable through
 * this function even now (that call site still uses __plat_dup()
 * directly, for a target above 2 as much as one at 2 or below: see
 * do_action()'s own comment for why the duplicate is always made
 * against the CURRENT source at that exact point in the action list
 * regardless of target, and src/process/linux/plat_process.c's
 * __plat_process_spawn() for how a target above 2 still reaches the
 * child at the requested number without this function's help, via
 * struct __spawn_dup2_target, libc.h) but handled correctly regardless
 * if it ever were: never closed out from under the duplicate just
 * made. */
int __plat_dup_to(__plat_handle_t h, int newfd, __plat_handle_t old, int inheritable, __plat_handle_t *out)
    __attribute__((nonnull(5)));

/* Hide or unhide `h` from a concurrent exec -- IN PLACE, without
 * creating a new descriptor, closing the old one, or changing its
 * identity in any way that would keep it from being handed back later
 * as though nothing happened. The only caller is src/process/
 * posix_spawn.c's take_slot()/restore_slots(): file-actions replay
 * temporarily removes a descriptor from THIS process's own __fds[]
 * table so a caller-requested close()/dup2()/open() action can use its
 * slot, then restores the table afterward, on every path out, so the
 * parent is left exactly as it was (posix_spawn.c's own banner).
 *
 * On NT that removal is already the whole story: __fd_runtime_data()
 * (src/internal/nt/plat_fd_init.c) only ever serialises what IS in
 * __fds[] at the moment __spawn() reads it, so a slot take_slot() has
 * already zeroed is already fully invisible to the child -- nothing
 * further to do, and this is a no-op there.
 *
 * On Linux it is not the whole story, and was the gap behind a real,
 * previously-masked bug (posix_spawn_file_actions_addclose() silently
 * not closing anything the child could actually see): removing a
 * descriptor from __fds[] changes nothing about whether the KERNEL
 * still has it open, and a still-open, non-close-on-exec descriptor
 * survives ANY concurrent fork()+execve() regardless of what this
 * library's own table says (src/internal/linux/plat_fd_init.c's own
 * banner) -- including the one __spawn() performs while file actions
 * are mid-replay on this very table. `cloexec` nonzero marks the real
 * descriptor close-on-exec for the vacated window's duration (a plain
 * in-place fcntl(F_SETFD), the same command __plat_dup()'s own
 * `!inheritable` path already issues on a DIFFERENT, freshly-
 * duplicated fd -- this one never duplicates at all); `cloexec` zero
 * on restore puts the real bit back to whatever the saved slot's own
 * flags say it originally was (almost always clear, but a caller
 * naming an already-O_CLOEXEC descriptor as a file action is not
 * disallowed and must not have that flag quietly dropped by passing
 * through this window). Never fails in any way a caller here needs to
 * observe: a live descriptor's own FD_CLOEXEC bit does not fail to
 * toggle in practice, and the caller has no useful fallback if it
 * somehow did (see the two implementations' own comments). */
void __plat_set_cloexec(__plat_handle_t h, int cloexec);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
