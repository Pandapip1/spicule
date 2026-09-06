/* C library headers must use the implementation-reserved namespace for
 * guards, type plumbing, and implementation extensions so they cannot
 * collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _ALLOCATION_TOKENS_H
#define _ALLOCATION_TOKENS_H

#include <ownership.h>

/* Declared together so every TU seeing a public boundary can validate the
 * whole nominal graph. On Linux the platform allocator is a terminal family:
 * it returns interior slab chunks, not the same object as the page mappings
 * backing them. */
tokdef rtl_heap_allocated
	dynamic_storage;
tokdef platform_heap_allocated
	dynamic_storage
#if !defined(__linux__)
	implemented_by(rtl_heap_allocated);
#else
	;
#endif
tokdef internal_heap_allocated
	dynamic_storage
	implemented_by(platform_heap_allocated);
tokdef heap_allocated
	dynamic_storage
	implemented_by(platform_heap_allocated);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
