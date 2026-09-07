/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * An opaque, backend-defined descriptor token -- the one type every
 * __plat_* platform-interface function (src/internal/plat_fd.h,
 * plat_mem.h, ...) passes instead of a raw NT HANDLE.  Every named
 * future backend fits in one pointer-sized value: NT's own HANDLE is
 * void* (nt.h's `typedef void *HANDLE, **PHANDLE;`), a Linux backend's
 * fd fits through intptr_t, and UEFI's EFI_HANDLE is void*-shaped by
 * spec.  This layer commits to exactly that and no more -- storing it,
 * comparing it against __PLAT_HANDLE_NULL, and passing it to __plat_*
 * calls, nothing else.
 *
 * For the only backend that exists today this is a zero-cost, zero-
 * behavior-change relabeling: NT's HANDLE already is void*, so
 * __plat_handle_t and HANDLE are bit-identical, and every call site
 * that has not yet been converted to go through a __plat_* function
 * keeps compiling and behaving exactly as before.
 */
#ifndef _SPICULE_PLAT_HANDLE_H
#define _SPICULE_PLAT_HANDLE_H

typedef void *__plat_handle_t;
#define __PLAT_HANDLE_NULL ((__plat_handle_t)0)

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
