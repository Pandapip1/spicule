/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "stubs.h"
#include "bad-contract.h"

void local_leak(void)
{
	(void)malloc(8);
} /* allocation-lifetime-expect: local */

void lost_reallocation(void)
{
	void *p = malloc(8);
	p = realloc(p, 16);
	if (p)
		free(p);
} /* allocation-lifetime-expect: realloc failure loses old allocation */

void conditional_return_leak(void)
{
	(void)conditional_buffer(0);
} /* allocation-lifetime-expect: null destination owns return */

void *uncontracted_return(void)
{
	return malloc(8); /* allocation-lifetime-expect: return-contract */
}

withtok(broken_allocated)
void *make_broken(void)
{
	return malloc(8);
}

void broken_destroy(void *object consume(broken_allocated))
{
	(void)object;
} /* allocation-lifetime-expect: broken-freer */

void wrong_freer(void)
{
	void *object = make_broken();
	free(object); /* allocation-lifetime-expect: direct wrong-family release */
} /* allocation-lifetime-expect: wrong-family */

void double_release(void)
{
	void *object = malloc(8);
	free(object);
	free(object); /* allocation-lifetime-expect: double release */
}

withtok(widget_allocated)
void *skip_implementation_edge(void)
{
	return backend_alloc(8); /* allocation-lifetime-expect: direct A-to-C producer */
}

void skip_release_edge(void)
{
	void *object = make_widget();
	backend_free(object); /* allocation-lifetime-expect: direct A-to-C release */
} /* allocation-lifetime-expect: direct A-to-C lifecycle havoc */

withtok(missing_implementation_allocated)
void *make_missing_implementation(void)
{
	return malloc(8); /* allocation-lifetime-expect: missing producer morphism */
}

void destroy_missing_implementation(
	void *object consume(missing_implementation_allocated))
{
	free(object); /* allocation-lifetime-expect: missing freer morphism */
} /* allocation-lifetime-expect: missing freer lifecycle havoc */

withtok(sentinel_implementation_allocated)
void *make_wrong_implementation(void)
{
	return malloc(8); /* allocation-lifetime-expect: wrong producer morphism */
}

void destroy_wrong_implementation(
	void *object consume(sentinel_implementation_allocated))
{
	free(object); /* allocation-lifetime-expect: wrong freer morphism */
} /* allocation-lifetime-expect: wrong freer lifecycle havoc */

void leaked_sentinel_result(int fail)
{
	(void)sentinel_producer(fail);
} /* allocation-lifetime-expect: sentinel-result */

/* Superficially the same out-parameter idiom as safe.c's
 * out_param_transfer, but the transfer only happens on one branch: this
 * must still be caught on the path that returns without ever reaching
 * `*out = buf`. */
void out_param_transfer_conditional_leak(void **out withtok(heap_allocated),
                                         int ok)
{
	void *buf = malloc(8);
	if (ok) {
		*out = buf;
		return;
	}
} /* allocation-lifetime-expect: out-param transfer skipped on this path */

/* Same dereference shape again, but `out` carries no withtok contract at
 * all, so it is not an owning slot -- the fix must not have broadened
 * the match to accept every `*param = allocation` regardless of
 * annotation. */
void out_param_transfer_unannotated(void **out)
{
	*out = malloc(8);
} /* allocation-lifetime-expect: unannotated out-parameter is not a proven destination */

/* Same producer-chain shape as safe.c's fill_word_vector(), but this path
 * never reaches `out->items = items` -- caught because the leaked
 * allocation still belongs to THIS frame, exactly as include/wordexp.h's
 * real wordexp_t.we_wordv/pv_pack() pairing is proven not to leak the array
 * it produces on any of expand_impl()'s own error paths. */
void fill_word_vector_leaks_on_error_path(struct word_vector *out, int fail)
{
	void *items = pack_items();
	if (fail)
		return; /* allocation-lifetime-expect: leaked producer result before reaching the struct field */
	out->items = items;
}

void *make_inherited(void)
{
	return malloc(8);
} /* allocation-contract-expect: inherited producer attribute is an error */

/* The header-style declaration above is not enough for an in-tree body:
 * this definition must repeat consume explicitly. */
void inherited_destroy(void *object)
{
	free(object);
} /* allocation-contract-expect: inherited attribute is an error */

/* allocation-contract-expect: unknown implementation family is an error */
/* allocation-contract-expect: malformed implementation is an error */
/* allocation-contract-expect: conflicting implementation is an error */
/* allocation-contract-expect: same-family transformer is not a terminal freer */
