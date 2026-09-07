/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/ioctl/ioctl.c's FIONREAD handling calls
 * into instead of a raw NtQueryInformationFile call.  See
 * src/ioctl/nt/plat_ioctl.c for the implementation this declares.
 * ioctl()'s FIONBIO request needs no platform call of this kind at
 * all: it only ever touches this library's own fd-table flag. Its
 * TIOCGWINSZ request is split by platform: on NT it goes through the
 * separate, out-of-scope SPICULE_USE_KERNEL32 path
 * (src/internal/kernel32.h), inline in src/ioctl/ioctl.c itself, not an
 * Nt-or-Zw- call and not this header; on Linux it is
 * __plat_tiocgwinsz() below, a real, unconditional ioctl(2) -- see that
 * declaration's own comment for why NT does not implement it.
 */
#ifndef _SPICULE_PLAT_IOCTL_H
#define _SPICULE_PLAT_IOCTL_H

#include "plat_handle.h"
#include <sys/ioctl.h> /* struct winsize */

/* Bytes immediately readable from a pipe (FilePipeLocalInformation's
 * ReadDataAvailable, clamped to INT_MAX -- see ioctl.c's own banner
 * for why this reuses the exact query select()'s __fd_probe() already
 * makes). 0/-1(errno) via *out.
 *
 * out is required: both backends (src/ioctl/{nt,linux}/plat_ioctl.c)
 * write through it unconditionally on the success path (`*out = ...;
 * return 0;`), with no NULL check of the pointer itself. Its one real
 * call site, src/ioctl/ioctl.c's own static fionread_pipe(), forwards
 * its own out parameter verbatim, which is in turn always ioctl()'s
 * own `&n`, a real local's address, never NULL. */
int __plat_fionread_pipe(__plat_handle_t h, int *out)
    __attribute__((nonnull(2)));

/* The two raw quantities FIONREAD on a regular file is computed from:
 * FileStandardInformation's EndOfFile and FilePositionInformation's
 * CurrentByteOffset.  The front door does the actual subtraction (and
 * its own [EOVERFLOW] check, which has nothing to do with NT) via
	 * __file_remaining_count(). 0/-1(errno) via *eof and *pos.
 *
 * eof/pos are both required: both backends write through both
 * unconditionally on the success path (NT: `*eof = si.EndOfFile; *pos
 * = pi.CurrentByteOffset;`; Linux: `*eof = ... stx_size; *pos =
 * ret;`), with no NULL check of either pointer. Its one real call
 * site, src/ioctl/ioctl.c's own static fionread_file(), always passes
 * `&eof, &pos`, two real locals' addresses, never NULL. */
int __plat_file_eof_and_pos(__plat_handle_t h, long long *eof, long long *pos)
    __attribute__((nonnull(2, 3)));

/* Terminal window size (TIOCGWINSZ), Linux only: a real, unconditional
 * ioctl(2) against h -- unlike NT, Linux has no console-specific
 * escape-hatch gate (SPICULE_USE_KERNEL32) to reach this; any real
 * tty/pty fd answers it directly, the same "no kernel32-equivalent
 * gate needed" call src/ioctl/ioctl.c's own TIOCGWINSZ case makes for
 * this platform. No NT implementation exists (NT's own path stays
 * entirely inline in src/ioctl/ioctl.c, unchanged) -- this declaration
 * is reachable only from code already behind `#ifdef __linux__`, so an
 * NT build never references, and therefore never needs to link, a
 * symbol this header only declares once for both platforms to share
 * the prototype text. 0/-1(errno) via *ws (ENOTTY when h does not name
 * a real terminal -- the real ioctl(2) call itself decides this, not
 * an fd-type pre-check: see src/ioctl/linux/plat_ioctl.c's own
 * comment). ws is required: the one implementation writes through it
 * unconditionally on the success path, with no NULL check of its own;
 * its one call site (src/ioctl/ioctl.c's TIOCGWINSZ case) always passes
 * ioctl()'s own varargs pointer, which every real caller supplies as a
 * real `struct winsize *` (see that file's own banner on why the
 * variadic argument itself cannot be `nonnull`-marked). */
int __plat_tiocgwinsz(__plat_handle_t h, struct winsize *ws)
    __attribute__((nonnull(2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
