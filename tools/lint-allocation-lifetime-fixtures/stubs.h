/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

typedef __SIZE_TYPE__ size_t;

tokdef widget_allocated
	dynamic_storage
	implemented_by(heap_allocated);
tokdef heap_allocated
	dynamic_storage
	implemented_by(backend_allocated);
tokdef backend_allocated
	dynamic_storage;
tokdef sentinel_allocated
	dynamic_storage
	implemented_by(heap_allocated)
	sentinel_exclude(-1);
tokdef foreign_terminal_allocated
	dynamic_storage
	sentinel_exclude(-1);
tokdef missing_implementation_allocated
	dynamic_storage;
tokdef sentinel_implementation_allocated
	dynamic_storage
	implemented_by(foreign_terminal_allocated);

/* Header-only declarations are explicit external assumptions.  If a .c
 * definition of free exists in the scanned tree, that definition must repeat
 * consume contract and its body is then proved. */
withtok(heap_allocated)
void *malloc(size_t);
void free(void *consume(heap_allocated));
withtok(backend_allocated)
void *backend_alloc(size_t);
void backend_free(void *consume(backend_allocated));
withtok(heap_allocated)
void *realloc(void *consume_if_nonnull_return(heap_allocated), size_t);
withtok(heap_allocated)
void *conditional_buffer(void *withtok(heap_allocated));

void *make_widget(void) withtok(widget_allocated);
void destroy_widget(void *object consume(widget_allocated));
withtok(sentinel_allocated)
void *sentinel_producer(int fail);
void sentinel_release(void *object consume(sentinel_allocated));

/* The real include/wordexp.h shape: an out-parameter struct whose field is
 * filled by an intermediate withtok-declared producer (pv_pack() there,
 * pack_items() here), not by a direct malloc() call in the same frame as
 * the field assignment. See safe.c's fill_word_vector()/
 * missing_release_is_not_caught() and unsafe.c's
 * fill_word_vector_leaks_on_error_path(). */
struct word_vector {
	void *items withtok(heap_allocated);
};
withtok(heap_allocated)
void *pack_items(void);
