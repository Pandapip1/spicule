/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "stubs.h"

/* Producer side: elements_withtok(family, extent) alone -- with no
 * redundant plain withtok(family) on the same field -- is proof enough
 * that a same-frame element write transfers ownership, one more subscript
 * of indirection down from the scalar destination plain withtok(family)
 * already recognizes (src/wordexp/wordexp.c's struct pv.v carries both
 * annotations together; this isolates the one this checker used to be
 * blind to). storage[] is a fixed local array, never itself reallocated,
 * so the array block's own (deliberately unaddressed here) ownership never
 * enters into this proof. */
struct line_table {
	char **v elements_withtok(heap_allocated, n);
	size_t n, cap;
};

static int add_line(struct line_table *t)
{
	if (t->n >= t->cap)
		return 0;
	t->v[t->n++] = malloc(8);
	return 1;
}

void fixed_storage_add_line(void)
{
	char *storage[4];
	struct line_table t;
	t.v = storage;
	t.n = 0;
	t.cap = 4;
	(void)add_line(&t);
}

/* Caller side: a call whose own callee parameter carries
 * elements_withtok(family, extent) hands the caller `n` independent
 * allocations reachable through that array. Each one only becomes its own
 * tracked obligation the first time something actually reads it -- there
 * is no way to hand out n distinct symbols before that, since this call's
 * own body is never inlined here (see AggregateObligationExtent's comment
 * in AllocationLifetimeChecker.cpp for why that has to be lazy). Freeing
 * every element the contract promises, in a loop bounded by that same
 * extent, proves none of them leak. */
int populate(char **out elements_withtok(heap_allocated, n), size_t n);

int use_populate(char **arr, size_t n)
{
	size_t i;
	if (populate(arr, n))
		return -1;
	for (i = 0; i < n; i++)
		free(arr[i]);
	return 0;
}
