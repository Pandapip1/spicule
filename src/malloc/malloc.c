/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The POSIX-facing allocator front door: argument validation and
 * overflow checks stay here, portable across every platform; allocate,
 * resize, query usable size, and free live behind
 * src/internal/plat_malloc.h (NT delegates to ntdll's process heap,
 * Linux implements a real one — see src/malloc/linux/plat_malloc.c).
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_malloc.h"

withtok(heap_allocated)
withtok(writable_span(size))
void *malloc(size_t size)
{
	void *p = __plat_alloc(size, 0);
	if (!p) errno = ENOMEM;
	return p;
}

withtok(heap_allocated)
withtok(writable_span(count * size))
void *calloc(size_t count, size_t size)
{
	void *p;
	if (size && count > (size_t)-1 / size) { errno = ENOMEM; return 0; }
	p = __plat_alloc(count * size, 1);
	if (!p) errno = ENOMEM;
	return p;
}

withtok(heap_allocated)
withtok(writable_span(size))
void *realloc(void *p consume_if_nonnull_return(heap_allocated), size_t size)
{
	void *q;
	if (!p) return malloc(size);
	q = __plat_realloc(p, size);
	if (!q) errno = ENOMEM;
	return q;
}

/* __malloc()/__free(), used by crt/crt1.c before main() runs, live in
 * their own translation unit (src/malloc/crt_alloc.c) — see its banner
 * for the link-time reason. */

size_t malloc_usable_size(void *p)
{
	return p ? __plat_alloc_size(p) : 0;
}

withtok(heap_allocated)
withtok(writable_span(count * size))
void *reallocarray(void *p consume_if_nonnull_return(heap_allocated), size_t count, size_t size)
{
	size_t bytes;
	if (size && count > (size_t)-1 / size) { errno = ENOMEM; return 0; }
	bytes = count * size; /* proven <= SIZE_MAX by the guard just above */
	return realloc(p, bytes); // NOLINT(clang-analyzer-optin.portability.UnixAPI) -- realloc(p, 0) is a deliberate, defined passthrough here
}

/* Blocks with alignment above the heap's own are carved out of a larger
 * heap block, and the pair (returned pointer, real block) is remembered
 * in a small list so that free can hand the real block back.  Aligned
 * allocation is rare enough that a list is the right structure. */
struct aligned_rec { void *user, *base; struct aligned_rec *next; };
static struct aligned_rec *aligned_list;

int posix_memalign(void **res, size_t align, size_t len)
{
	void *base, *p;
	struct aligned_rec *r;
	if (align < sizeof(void *) || (align & (align - 1))) return EINVAL;
	if (align <= 2 * sizeof(void *)) {
		p = malloc(len);
		if (!p) return ENOMEM;
		*res = p;
		return 0;
	}
	if (len > (size_t)-1 - align) return ENOMEM;
	r = malloc(sizeof *r);
	if (!r) return ENOMEM;
	{
		size_t bytes = len + align; /* proven <= SIZE_MAX by the guard just above */
		base = malloc(bytes);
	}
	if (!base) { free(r); return ENOMEM; }
	p = (void *)(((uintptr_t)base + align - 1) & ~(uintptr_t)(align - 1));
	r->user = p; r->base = base; r->next = aligned_list; aligned_list = r;
	*res = p;
	return 0;
}

withtok(heap_allocated)
withtok(writable_span(size))
void *aligned_alloc(size_t alignment, size_t size)
{
	void *p;
	int e = posix_memalign(&p, alignment < sizeof(void *) ? sizeof(void *) : alignment, size);
	if (e) { errno = e; return 0; }
	return p;
}

withtok(heap_allocated)
void *memalign(size_t align, size_t len) { return aligned_alloc(align, len); }
withtok(heap_allocated)
void *valloc(size_t len) { return aligned_alloc(4096, len); }

void free(void *p consume(heap_allocated))
{
	struct aligned_rec **pp;
	if (!p) return;
	for (pp = &aligned_list; *pp; pp = &(*pp)->next) {
		if ((*pp)->user == p) {
			struct aligned_rec *r = *pp;
			*pp = r->next;
			__plat_dealloc(r->base);
			__plat_dealloc(r);
			return;
		}
	}
	__plat_dealloc(p);
}

// NOLINTEND(misc-include-cleaner)
