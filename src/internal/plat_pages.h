/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The one primitive src/internal/plat_malloc_generic.h's allocator
 * needs from whatever platform includes it: raw, page-granular
 * anonymous memory from the OS, with no allocator of its own
 * underneath it. This is deliberately NOT src/internal/plat_mem.h's
 * __plat_mmap_anon() -- that interface is POSIX mmap()'s own shape
 * (prot, fixed-address requests, the reservation-table bookkeeping
 * mman.c's front door needs), for the library's own callers of the
 * public mmap() function. malloc() is more foundational than that:
 * it must not risk any ordering or circular-dependency hazard with
 * the mman subsystem, the same reasoning crt/linux/crt1.c's own
 * bootstrap TLS allocation already applies to itself. A page source
 * is a much smaller contract than mmap() -- always anonymous, always
 * zeroed, never fixed-address, never partially unmapped -- and every
 * platform that needs one at all (Linux today; a future UEFI backend
 * would use AllocatePages/FreePages here) can implement exactly that
 * in a handful of lines.
 *
 * `n` is always already rounded up to whatever granularity the
 * platform needs (a page, or a multiple of one) by the caller;
 * implementations are not expected to round anything themselves.
 */
#ifndef _SPICULE_PLAT_PAGES_H
#define _SPICULE_PLAT_PAGES_H

#include <features.h>
#include <ownership.h>
#include <stddef.h>

tokdef platform_pages_allocated
	dynamic_storage;

/* Returns freshly zeroed memory, or NULL on failure. */
withtok(platform_pages_allocated)
void *__plat_pages_alloc(size_t n);

/* `n` must be the exact size a matching __plat_pages_alloc() call
 * returned (or was rounded up to) -- implementations are free to
 * assume it, the same way munmap(2) itself does. */
void __plat_pages_free(void *p consume(platform_pages_allocated), size_t n);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
