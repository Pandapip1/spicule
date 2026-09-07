/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * malloc on top of the NT heap.
 *
 * Every process has a heap ntdll made for it before the first instruction
 * ran, and ntdll's own allocator is a serious one (size classes, a
 * low-fragmentation front end, coalescing, guard pages under the
 * debugger), so this is RtlAllocateHeap on the process heap rather than a
 * second allocator over NtAllocateVirtualMemory.
 *
 * RtlAllocateHeap(0) returns a usable pointer, which is what malloc(0) is
 * allowed to do. Alignment is 8 on i386 and 16 on x86_64, which is what
 * the heap gives -- src/malloc/malloc.c's posix_memalign() over-allocates
 * for anything larger, entirely above this interface.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "plat_malloc.h"
#include "libc.h"

withtok(platform_heap_allocated)
void *__plat_alloc(size_t n, int zero)
{
	return RtlAllocateHeap(__process_heap(), zero ? HEAP_ZERO_MEMORY : 0, n);
}

withtok(platform_heap_allocated)
void *__plat_realloc(void *p consume_if_nonnull_return(platform_heap_allocated), size_t n)
{
	return RtlReAllocateHeap(__process_heap(), 0, p, n);
}

size_t __plat_alloc_size(void *p)
{
	return RtlSizeHeap(__process_heap(), 0, p);
}

void __plat_dealloc(void *p consume(platform_heap_allocated))
{
	RtlFreeHeap(__process_heap(), 0, p);
}

// NOLINTEND(misc-include-cleaner)
