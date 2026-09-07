/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The console input line discipline: one dedicated thread that owns the
 * console input handle, and the queue every read()/select()/poll() of
 * that console goes through once it does.  NT-only; see
 * src/internal/nt/conin.c for the whole implementation and the
 * reasoning behind it.
 */
#ifndef _SPICULE_CONIN_H
#define _SPICULE_CONIN_H

#include "nt.h"
#include "plat_fd.h"

/* Start the reader thread on `h` and hand it the handle for good.  Idempotent:
 * a second call for the same handle succeeds without starting a second thread,
 * and a call for a different handle fails (there is only ever one console
 * session here -- src/unistd/ttyname.c). 0 on success, -1 if no thread could
 * be started, in which case nothing has changed and the caller must leave the
 * console mode alone. */
int __conin_takeover(__plat_handle_t h);

/* Whether the reader thread, rather than the console, is responsible for
 * turning the interrupt character into SIGINT -- true exactly when the
 * console has been taken out of processed-input mode while termios still
 * says ISIG. */
void __conin_set_isig(int on);

/* Does the reader thread own this handle?  The one question every
 * would-be NtReadFile on a console handle has to ask first. */
int __conin_owns(__plat_handle_t h);

/* Take up to `count` buffered bytes, blocking until at least one arrives.
 * 0 at end of input, -1 with errno set (EINTR when a signal was caught
 * during the wait, exactly as select() reports one). */
ssize_t __conin_read(void *buf, size_t count);

/* Is there anything to take right now (bytes, or a terminal condition)?
 * The readiness answer select()/poll() need, read off the queue rather
 * than off the handle underneath the reader thread. */
int __conin_pending(void);

/* The wakeup the queue signals on every arrival, for a caller that has
 * to sleep until then. Purely a wakeup: readiness is always re-derived
 * from __conin_pending() afterwards, never from this object's state. */
__plat_handle_t __conin_event(void);

/* RtlCloneUserProcess clones only the calling thread, so the reader
 * thread does not exist in the child; re-arm on the same handle. */
void __conin_reinit_after_fork(void);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
