/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/select/select.c and poll.c's POSIX-facing
 * front doors call into instead of raw
 * Nt{QueryInformationFile,WaitForSingleObject,WaitForMultipleObjects,
 * DelayExecution,QuerySystemTime} calls and the raw IOCTL_AFD_SELECT
 * dance (src/internal/afd.h).  See src/select/nt/plat_select.c for the
 * implementation these declare.
 *
 * Every function here takes POSIX-shaped arguments and returns a
 * POSIX-shaped result.  The wait-vs-poll design itself -- which
 * descriptor shapes are probed instantaneously vs. re-probed on a
 * timer, the console-wait-plus-signal-event bundling, the elapsed-time
 * accounting across a wait -- is this library's own strategy for
 * satisfying select()/poll() on top of NT's primitives (see select.c's
 * own banner) and stays in the front door entirely, unchanged; only the
 * raw syscalls each step of that strategy needs are relocated here.
 */
#ifndef _SPICULE_PLAT_SELECT_H
#define _SPICULE_PLAT_SELECT_H

#include "plat_handle.h"

/* Query a pipe end's local state for select()/poll()'s per-descriptor
 * probe.  Returns 1 and fills *read_avail / *write_quota when `h` is a
 * healthy, connected pipe whose FILE_PIPE_LOCAL_INFORMATION was
 * successfully read; 0 (out-params untouched) when the query failed or
 * the pipe is not in the connected state -- __fd_probe() (select.c)
 * treats a 0 here as "ready and hung up", the platform's own fact
 * rather than a decision this interface makes. */
/* read_avail/write_quota required: both real implementations write
 * `*read_avail = ...`/`*write_quota = ...` unconditionally on the
 * success (return 1) path, with no NULL check of either anywhere. Its
 * one real call site (select.c's __fd_probe(), __FD_PIPE case) always
 * passes `&read_avail, &write_quota`, the addresses of its own locals,
 * never NULL. */
int __plat_pipe_probe(__plat_handle_t h, unsigned long *read_avail, unsigned long *write_quota)
    __attribute__((nonnull(2, 3)));

/* Behavioral, uncached probe: does this platform's pipe implementation
 * actually populate FILE_PIPE_LOCAL_INFORMATION's WriteQuotaAvailable?
 * See select.c's wqa_works() for the full reasoning (a wine-9.0-vs-
 * wine-10.0 history) and why this cannot be assumed either way. 1
 * trustworthy, 0 not (including "could not even create a private probe
 * pipe"). Caching, if wanted, is the caller's job -- this always
 * re-probes. */
int __plat_pipe_wqa_trustworthy(void);

/* Zero-timeout peek at one waitable handle (a console input handle,
 * here): 1 if it was already signalled, 0 if not. */
int __plat_wait_ready(__plat_handle_t h);

/* The read-readiness pair for a console fd, kept behind the platform
 * boundary because on NT the answer may not come from the handle at
 * all: once src/internal/nt/conin.c's reader thread owns a console
 * input handle it is the only NtReadFile caller, so the handle stops
 * being signalled for anyone else and readiness means "that thread's
 * queue has something", not "the device does".
 *
 * __plat_console_ready() is the zero-timeout peek and is the only
 * readiness answer -- never re-derived from whatever
 * __plat_console_wait() returned, which is a wakeup object and may be
 * auto-reset.  __plat_console_wait() is the handle to park on until
 * that answer can change.  On Linux both are the identity: nothing
 * there is ever classified __FD_CONSOLE (src/unistd/linux/
 * plat_isatty.c), so neither is reachable with a real console handle. */
int __plat_console_ready(__plat_handle_t h);
__plat_handle_t __plat_console_wait(__plat_handle_t h);

/* The IOCTL_AFD_SELECT probe for a socket -- see select.c's __fd_probe()
 * __FD_SOCKET case (moved here verbatim) for the reasoning behind every
 * field of afd.h this touches.  Always sets *canread / *canwrite / *hup;
 * there is no failure this reports outward -- a probe that could not be
 * taken at all reports ready-and-hung-up, the same over-eager stance
 * the pipe/console cases take for their own unanswerable queries. */
/* canread/canwrite/hup required: all three are written directly by
 * name in both real implementations (unconditionally in
 * linux/plat_select.c's own body; nt/plat_select.c's own body writes
 * *canread / *canwrite unconditionally on every path and *hup whenever an
 * event actually needs reporting, relying on its one real caller --
 * select.c's __fd_probe(), which does `*hup = 0;` as its own very first
 * statement before ever dispatching here -- to have it already
 * zeroed on the "nothing to report" path; not a NULL-safety concern
 * either way, just why "always sets" in this comment's own banner above
 * is about the observable *value*, not about which statement in which
 * backend writes it). No NULL check of canread/canwrite/hup exists
 * anywhere in this file's own body. The one real call site forwards its
 * own canread/canwrite/hup straight through -- already required at
 * __fd_probe()'s own signature -- never NULL. */
void __plat_socket_probe(__plat_handle_t h, int *canread, int *canwrite, int *hup)
    __attribute__((nonnull(2, 3, 4)));

/* Wait for any of nhandles waitable handles to become signalled, or
 * wait_ticks 100ns ticks to pass (ignored when infinite), whichever
 * comes first.  Called only when nhandles > 0; no return value, since
 * neither select() nor poll() distinguishes "woke because something
 * signalled" from "woke because the budget ran out" -- the next poll
 * pass re-probes everything either way. */
/* handles required: subscripted unconditionally (`handles[i]`) whenever
 * nhandles >= 1 (clamped to FD_SETSIZE + 1), with no NULL check anywhere
 * in either real implementation. Its one real call site
 * (select.c's __fd_wait_or_delay()) always passes `handles`, the
 * address of its own fixed-size local array, and only when n > 0 (this
 * comment's own "Called only when nhandles > 0" above) -- never NULL
 * either way. */
void __plat_wait_multiple(const __plat_handle_t *handles, int nhandles, long long wait_ticks, int infinite)
    __attribute__((nonnull(1)));

/* Sleep for wait_ticks 100ns ticks, or indefinitely when infinite --
 * used when there is nothing to wait on at all. */
void __plat_delay(long long wait_ticks, int infinite);

/* Current time, in the same 100ns-tick unit as everything else in this
 * interface -- select_core()'s elapsed-time accounting across a wait
 * (select.c).  The same clock CLOCK_REALTIME reads
 * (src/time/clock_gettime.c). */
long long __plat_now_100ns(void);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
