/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform allocator interface src/malloc/malloc.c's POSIX-facing
 * front door calls into instead of a raw RtlAllocateHeap/RtlFreeHeap/
 * RtlReAllocateHeap/RtlSizeHeap call. See src/malloc/nt/plat_malloc.c
 * for the implementation these declare, and src/malloc/linux/
 * plat_malloc.c for the real backend a platform with no process-wide
 * heap manager to delegate to needs instead.
 *
 * Everything genuinely POSIX-shaped -- the overflow checks in calloc()/
 * reallocarray(), and posix_memalign()/aligned_alloc()/memalign()/
 * valloc(), which were already expressed purely in terms of malloc()/
 * free() rather than any raw heap call -- stays in the front door
 * unchanged. Only the four primitives with no portable equivalent move
 * here: allocate, resize, query the usable size of a live allocation,
 * and free.
 *
 * `zero`: NT's RtlAllocateHeap(HEAP_ZERO_MEMORY) zero-fills in the same
 * call that allocates, which calloc() wants to keep rather than pay
 * for a second, separate memset() pass over freshly-mapped (and on
 * some backends, already-zero) pages.
 */
#ifndef _SPICULE_PLAT_MALLOC_H
#define _SPICULE_PLAT_MALLOC_H

#include <features.h>
#include <allocation_tokens.h>
#include <ownership.h>
#include <stddef.h>

withtok(platform_heap_allocated)
void *__plat_alloc(size_t n, int zero);
withtok(platform_heap_allocated)
void *__plat_realloc(void *p consume_if_nonnull_return(platform_heap_allocated), size_t n);
size_t __plat_alloc_size(void *p);
void __plat_dealloc(void *p consume(platform_heap_allocated));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
