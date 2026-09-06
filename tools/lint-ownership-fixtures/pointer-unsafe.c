/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "allocator-fixture.h"

long getline(char **, size_t *, void *);

int nullable_pointer(int *pointer)
{
	return *pointer; /* ownership-expect: pointer-null */
}

int out_of_bounds(void)
{
	int values[2] = {1, 2};
	return values[2]; /* ownership-expect: pointer-extent */
}

int misaligned(void)
{
	char storage[sizeof(int) + 1];
	int *pointer = (int *)(void *)(storage + 1);
	return *pointer; /* ownership-expect: pointer-alignment */
}

int consumed_storage(void)
{
	int *pointer = malloc(sizeof *pointer);
	if (!pointer)
		return 0;
	free(pointer);
	return *pointer; /* ownership-expect: pointer-consumed */
}

/* `nonnull(1)` covers only the first parameter; the second is exactly as
 * unguarded as nullable_pointer above and must still be flagged --
 * checkBeginFunction (OwnershipChecker.cpp) must not over-generalize a
 * single-argument nonnull attribute into trusting every pointer
 * parameter of the function. */
int nonnull_attribute_does_not_cover_every_param(int *checked, int *unchecked)
    __attribute__((nonnull(1)));
int nonnull_attribute_does_not_cover_every_param(int *checked, int *unchecked)
{
	(void)*checked;
	return *unchecked; /* ownership-expect: pointer-null */
}

/* OwnershipChecker::allocationSizeInBytes gives __malloc's own result a
 * real tracked extent (see pointer-safe.c's heap_allocation_extent_is_
 * trusted), and ValidPointerChecker's fixed-offset leniency in the real-
 * extent branch is deliberately asymmetric: it only trusts a fixed
 * offset when the real extent leaves sufficiency merely UNPROVEN, never
 * when the real extent makes sufficiency PROVABLY IMPOSSIBLE. Here the
 * allocation is 4 bytes (sizeof(int)) and `b` sits at a fixed offset of
 * 4 bytes into an 8-byte struct -- a genuinely too-small allocation,
 * concretely resolvable, that must still be caught through the exact
 * same fixed-offset path the leniency above exists for. */
struct pair { int a; int b; };

int too_small_heap_allocation_via_fixed_offset(void)
{
	struct pair *p = __malloc(sizeof(int));
	if (!p) return 0;
	return p->b; /* ownership-expect: pointer-extent */
}

/* The getline summary is conditional on a nonnegative return.  Its failure
 * branch must retain the original, possibly-null output pointer rather than
 * leaking the success branch's nonnull fact across both outcomes. */
int failed_line_input_does_not_validate_the_buffer(void *stream)
    __attribute__((nonnull(1)));
int failed_line_input_does_not_validate_the_buffer(void *stream)
{
	char *line = 0;
	size_t capacity = 0;
	long length = getline(&line, &capacity, stream);
	if (length >= 0)
		return 0;
	return *line; /* ownership-expect: pointer-null */
}

/* The adversarial twin of pointer-safe.c's doubled_extent_via_
 * multiplication_index: the terminator is written one byte PAST the
 * doubled extent (`2 * n + 1` against an allocation of only `n + n + 1`
 * bytes, i.e. valid indices 0..2n), a genuinely out-of-bounds access.
 * Both the ad hoc prover and the new z3ExtentProvenInBounds fallback
 * must still report this -- the fallback proving a real, different
 * shape (the sibling fixture) must never loosen this one: Z3 correctly
 * finds a counterexample (any n) rather than proving sufficiency. */
char *doubled_extent_off_by_one_via_multiplication_index(size_t n)
{
	char *d = __malloc(n + n + 1);
	if (!d) return 0;
	d[2 * n + 1] = 0; /* ownership-expect: pointer-extent-z3 */
	return d;
}

/* The adversarial twin of pointer-safe.c's linear_combination_extent_
 * cancels: same allocation, but the write leaves a real (unsigned,
 * exact-arithmetic-only) margin -- l2 is a genuine leftover term, never
 * referenced by the index at all -- rather than the sibling's exact
 * match. linearExtentProvenInBounds() used to trust this shape
 * unconditionally (any unsigned leftover term with a positive net
 * coefficient), but it is not actually safe: with l1 == SIZE_MAX - 1 and
 * l2 == 0, `l1 + l2 + 2` (the real malloc() argument) wraps to 0 -- a
 * genuine 0-byte allocation -- while the index `l1` itself does not
 * wrap, so the write lands far out-of-bounds. Both the ad hoc prover
 * (now correctly declining to trust an unbounded leftover term) and
 * z3ExtentProvenInBounds (which finds exactly that counterexample) must
 * still report this. */
char *linear_combination_extent_leftover_term_not_provably_bounded(size_t l1,
                                                                   size_t l2)
{
	char *s = __malloc(l1 + l2 + 2);
	if (!s) return 0;
	s[l1] = '='; /* ownership-expect: pointer-extent-z3 */
	return s;
}

/* The adversarial twin of pointer-safe.c's element_width_is_peeled: same
 * shape, but the write is one element short of the full extent (`ne[n]`
 * rather than `ne[n + 1]`) -- a real margin through the element-width
 * peel, not an exact match. Deliberately __malloc(), not realloc(): a
 * plain realloc() call here would let Clang's OWN built-in realloc
 * summary establish that a successful call's real size argument is
 * nonzero, which happens to rule out the exact single wraparound point
 * this counterexample needs (`sizeof(char *) * (n + 2) == 0`) -- a real,
 * legitimate proof, but one that says nothing about __malloc(), this
 * project's own allocator family, which carries no such built-in
 * assumption (see OwnershipChecker::allocationSizeInBytes). At n == 2^61
 * - 2, `sizeof(char *) * (n + 2)` (the real __malloc() argument, in
 * bytes) wraps to 0 while `n * sizeof(char *)` (the write's own byte
 * offset) does not, so the write lands far out-of-bounds -- the
 * identical wraparound-margin risk as linear_combination_extent_
 * leftover_term_not_provably_bounded above, reached through a real
 * multiplication instead of pure addition. */
char **element_width_leftover_margin_not_provably_bounded(size_t n, char *s)
{
	char **ne = __malloc(sizeof(char *) * (n + 2));
	if (!ne) return 0;
	ne[n] = s; /* ownership-expect: pointer-extent-z3 */
	return ne;
}

/* The adversarial twin of pointer-safe.c's struct_field_array_element_
 * nonnull_axiom_is_trusted: the identical struct argv_slice shape and
 * the identical fixed-offset element read, with the
 * __ownership_pointer_nonnull() call removed. This is the other half of
 * that fixture's own proof obligation -- confirming the new axiom did
 * not accidentally widen ValidPointerChecker::checkPointerExpression's
 * proof for every struct-field array read regardless of whether the
 * axiom was actually invoked, only for the one exact call this checker
 * now recognizes by name (see ValidPointerChecker::isPointerNonNullAxiom
 * in OwnershipChecker.cpp). */
struct argv_slice2 { char **v; size_t i; };

char *struct_field_array_element_is_flagged_without_the_axiom(
    struct argv_slice2 *slice) __attribute__((nonnull(1)));
char *struct_field_array_element_is_flagged_without_the_axiom(
    struct argv_slice2 *slice)
{
	return slice->v[0]; /* ownership-expect: pointer-null */
}
