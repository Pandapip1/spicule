/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "stubs.h"

void local_release(void)
{
	void *p = malloc(16);
	free(p);
}

void file_correct_usage(void)
{
	void *f = fopen_stub("path");
	if (f) fclose_stub(f);
}

withtok(heap_allocated)
void *heap_boundary(size_t size)
{
	return backend_alloc(size);
}

void free(void *object consume(heap_allocated))
{
	backend_free(object);
}

withtok(widget_allocated)
void *nested_boundary(size_t size)
{
	return heap_boundary(size);
}

withtok(heap_allocated)
void *nullable_producer(void);

withtok(heap_allocated)
void *nullable_producer(void)
{
	void *p = malloc(16);
	if (!p)
		return 0;
	return p;
}

void conditional_reallocation(void)
{
	void *old = malloc(8);
	void *replacement = realloc(old, 16);
	if (replacement)
		free(replacement);
	else
		free(old);
}

withtok(heap_allocated)
void *same_family_transform(void *old consume(heap_allocated))
{
	free(old);
	return malloc(16);
}

void transformed_release(void)
{
	free(same_family_transform(malloc(8)));
}

void repeated_reallocation(void)
{
	void *first = malloc(8);
	void *second = realloc(first, 16);
	if (!second) {
		free(first);
		return;
	}
	void *third = realloc(second, 32);
	if (!third) {
		free(second);
		return;
	}
	free(third);
}

withtok(heap_allocated)
void *conditional_buffer(void *buffer withtok(heap_allocated))
{
	return buffer ? buffer : malloc(8);
}

void conditional_return(void)
{
	char supplied[8];
	(void)conditional_buffer(supplied);
	free(conditional_buffer(0));
}

void *make_widget(void) withtok(widget_allocated)
{
	return malloc(16);
}

void destroy_widget(void *widget consume(widget_allocated))
{
	free(widget);
}

withtok(widget_allocated)
void *make_or_cleanup_widget(int fail)
{
	void *widget = malloc(16);
	if (fail) {
		destroy_widget(widget);
		return 0;
	}
	return widget;
}

void use_contract(void)
{
	void *widget = make_widget();
	destroy_widget(widget);
}

struct widget_box {
	void *widget withtok(widget_allocated);
};

void aggregate_transfer(void)
{
	struct widget_box box;
	box.widget = make_widget();
	destroy_widget(box.widget);
}

withtok(sentinel_allocated)
void *sentinel_producer(int fail)
{
	return fail ? (void *)-1 : malloc(16);
}

void sentinel_release(void *object consume(sentinel_allocated))
{
	free(object);
}

void sentinel_result(int fail)
{
	void *object = sentinel_producer(fail);
	if (object != (void *)-1)
		sentinel_release(object);
}

/* The ordinary out-parameter idiom: the caller's slot is reached through
 * one dereference of a parameter, not by name or member access. */
void out_param_transfer(void **out withtok(heap_allocated))
{
	*out = malloc(8);
}

void use_out_param_transfer(void)
{
	void *object;
	out_param_transfer(&object);
	free(object);
}

withtok(heap_allocated)
void *pack_items(void)
{
	return malloc(8);
}

/* Same shape as src/wordexp/wordexp.c's real wordexp_t.we_wordv/pv_pack()
 * pairing: a struct field reached through an out-parameter pointer is
 * filled by an intermediate withtok-declared producer, not by a direct
 * malloc() call in this same frame -- proven not to leak on this function's
 * own single path (see unsafe.c's fill_word_vector_leaks_on_error_path()
 * for the same shape's leak on an error path that never reaches the
 * assignment). */
void fill_word_vector(struct word_vector *out)
{
	out->items = pack_items();
}

void use_word_vector(void)
{
	struct word_vector wv;
	fill_word_vector(&wv);
	free(wv.items);
}

/* The real, verified boundary of that same shape: nothing in this checker
 * can turn a caller's own missing release into a finding. checkPostCall
 * only ever mints a freshly tracked fact from a callee's own pointer-typed
 * return value (returnsOwnership) or an argument echoed back unchanged
 * (returnedArgument) -- never from an out-parameter's field populated as a
 * side effect of a call whose own return type is not the tracked family.
 * fill_word_vector() returns void, so this forgotten free(wv.items)
 * produces no diagnostic at all: this is the same reason
 * include/wordexp.h's wordexp()/wordfree() pairing cannot be proven at
 * src/sh/execute.c's real call sites, not a gap in this fixture. */
void missing_release_is_not_caught(void)
{
	struct word_vector wv;
	fill_word_vector(&wv);
	(void)wv;
}
