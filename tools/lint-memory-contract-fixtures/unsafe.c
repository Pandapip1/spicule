/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

typedef __SIZE_TYPE__ size_t;
#include "../../include/ownership.h"

tokdef fixture_readable_span l_unlimited implicit_drop extent_at_least zero_vacuous;
tokdef fixture_writable_span l_unlimited implicit_drop extent_at_least zero_vacuous;
tokdef fixture_disjoint_span l_unlimited implicit_drop disjoint_extent zero_vacuous;
tokdef fixture_readable_elements l_unlimited implicit_drop element_extent zero_vacuous;
tokdef fixture_writable_elements l_unlimited implicit_drop element_extent zero_vacuous;

void *memcpy(void *destination withtok(fixture_writable_span(length))
	withtok(fixture_disjoint_span(source, length)),
	const void *source withtok(fixture_readable_span(length)), size_t length);
void *memset(void *destination withtok(fixture_writable_span(length)), int,
	size_t length);
withtok(fixture_writable_span(length))
void *__malloc(size_t length);
void *opaque_allocator(size_t length);
withtok(fixture_writable_span(length))
void *allocate_unknown_extent(size_t length);
withtok(fixture_writable_span(count * size))
void *allocate_array(size_t count, size_t size);
size_t strlen(const char *);
size_t strnlen(const char *, size_t);
void consume_bytes(const void *source withtok(fixture_readable_span(length)),
	size_t length);
void consume_elements(
	const unsigned *source withtok(fixture_readable_elements(count)),
	size_t count);

void consume_too_many_elements(void)
{
	unsigned value;
	consume_elements(&value, 2); /* memory-contract-expect */
}
void establish_writable(
	void *buffer grant(fixture_writable_span(length)), size_t length);
void unsafe_assume_writable_span(
	void *buffer grant(fixture_writable_span(length)), size_t length);
void unsafe_assume_readable_span(
	const void *buffer grant(fixture_readable_span(length)), size_t length);
void unsafe_assume_disjoint_span(
	void *first grant(fixture_disjoint_span(second, length)),
	const void *second, size_t length);
int maybe_establish_writable(
	void *buffer grant(fixture_writable_span(length)), size_t length);

void unproved_writable_grant(
	void *buffer grant(fixture_writable_span(length)), size_t length)
{
	(void)buffer;
	(void)length;
} /* memory-contract-expect */

void proof_invalidated_by_reassignment(
	void *buffer grant(fixture_writable_span(length)), size_t length)
{
	establish_writable(buffer, length);
	buffer = 0;
} /* memory-contract-expect */

void failed_grant_is_not_available(char *buffer, size_t length)
{
	if (maybe_establish_writable(buffer, length) == 0)
		return;
	memset(buffer, 0, length); /* memory-contract-expect */
}

void unproved_disjoint_grant(
	void *first grant(fixture_disjoint_span(second, length)),
	const void *second, size_t length)
{
	(void)first;
	(void)second;
	(void)length;
} /* memory-contract-expect */

void contracted_copy(char *out withtok(fixture_writable_span(length)),
	const char *in withtok(fixture_readable_span(length)), size_t length);

static void contracted_fill(
	char *out withtok(fixture_writable_span(length)), size_t length)
{
	memset(out, 0, length);
}

void insufficient_contracted_suffix(
	char *out withtok(fixture_writable_span(capacity)), size_t capacity,
	size_t offset, size_t length)
{
	if (offset <= capacity && length > capacity - offset)
		memset(out + offset, 0, length); /* memory-contract-expect */
}

struct counted_buffer {
	const char *data withtok(fixture_readable_span(length));
	size_t length;
};

void overread_counted_buffer(const struct counted_buffer *buffer)
{
	consume_bytes(buffer->data, buffer->length + 1); /* memory-contract-expect */
}

struct counted_elements {
	const unsigned *data withtok(fixture_readable_elements(count));
	size_t count;
};

void overread_counted_elements(const struct counted_elements *buffer)
{
	consume_elements(buffer->data, buffer->count + 1); /* memory-contract-expect */
}

void copy_unrestricted_parameters(
	char *destination withtok(fixture_writable_span(length)),
	const char *source withtok(fixture_readable_span(length)), size_t length)
{
	memcpy(destination, source, length); /* memory-contract-expect */
}

void copy_restrict_alias(
	char *restrict destination withtok(fixture_writable_span(length)),
	size_t length)
{
	char *alias = destination;
	memcpy(destination, alias, length); /* memory-contract-expect */
}

void copy_to_unproven_fresh_allocation(
	const char *source withtok(fixture_readable_span(length)), size_t length)
{
	char *destination = allocate_unknown_extent(length);
	if (!destination) return;
	memcpy(destination, source, length); /* memory-contract-expect */
}

struct fixture_record {
	int first;
	int second;
};

void overfill_typed_object(struct fixture_record *record)
{
	memset(record, 0, sizeof *record + 1); /* memory-contract-expect */
}

void overfill_typed_member(struct fixture_record *record)
{
	memset(&record->second, 0, sizeof record->second + 1); /* memory-contract-expect */
}

void movable_path_axiom(char *buffer, size_t length, int use_local)
{
	char local[8];
	if (use_local) {
		if (length > sizeof local)
			return;
		buffer = local;
	}
	unsafe_assume_writable_span(buffer, length); /* memory-contract-expect */
}

void violate_contracts(char *text)
{
	char source[4], destination[4];
	(void)text;
	contracted_copy(destination, source, 8); /* memory-contract-expect */
}

/* Only this caller violates the contract.  Once diagnosed, the assumed
 * exact-region span must prevent a duplicate report in contracted_fill's
 * inlined body, even though destination + 2 is an interior region. */
void violate_inline_contract(void)
{
	char destination[4];
	contracted_fill(destination + 2, 3); /* memory-contract-expect */
}

void oversized(void)
{
	char source[4], destination[4];
	memcpy(destination, source, 8); /* memory-contract-expect */
}

void opaque(void *buffer, size_t length)
{
	memset(buffer, 0, length); /* memory-contract-expect */
}

/* Manual proof calls are migration scaffolding.  Once the allocation's
 * dynamic extent already proves the same span, retaining the axiom must be
 * diagnosed so implementation bodies converge on inferred contracts. */
void redundant_heap_axiom(size_t length)
{
	char *buffer = __malloc(length);
	if (!buffer) return;
	unsafe_assume_writable_span(buffer, length); /* memory-contract-expect */
	memset(buffer, 0, length);
}

void redundant_static_axioms(void)
{
	char source[4], destination[4];
	unsafe_assume_readable_span(source, sizeof source); /* memory-contract-expect */
	unsafe_assume_disjoint_span(destination, source, sizeof source); /* memory-contract-expect */
}

void overlapping(void)
{
	char buffer[16];
	memcpy(buffer + 1, buffer, 8); /* memory-contract-expect */
}

/* A genuinely too-small __malloc'd allocation must still be caught once
 * this tree's own allocator family gets a real (as opposed to placeholder)
 * dynamic extent -- the same regression guard 8a56a66 pinned for the
 * sibling ValidPointerChecker's own analogous fix. */
void too_small_heap_allocation(const char *s)
{
	char *d = __malloc(4);
	memcpy(d, s, 8); /* memory-contract-expect */
}

/* A suggestive allocator name is not a contract. */
void undeclared_allocator_extent(size_t length)
{
	char *buffer = opaque_allocator(length);
	if (!buffer) return;
	memset(buffer, 0, length); /* memory-contract-expect */
}

/* Sharing an affine root does not prove the larger expression is larger:
 * unsigned addition wraps, so n == SIZE_MAX allocates zero bytes here. */
void wrapped_allocator_extent(size_t n)
{
	if (n != (size_t)-1) return;
	char *d = __malloc(n + 1);
	if (!d) return;
	memset(d, 0, n); /* memory-contract-expect */
}

void overfill_reassociated_allocation(size_t left, size_t right)
{
	char *buffer = __malloc(left + right);
	if (!buffer) return;
	memset(buffer, 0, right + left + 1); /* memory-contract-expect */
}

void fill_unchecked_allocation_suffix(
	const char *source withtok(fixture_readable_span(right)),
	size_t left, size_t right)
{
	char *buffer = __malloc(left + right);
	if (!buffer) return;
	memcpy(buffer + left, source, right); /* memory-contract-expect */
}

void fill_wrapping_slack_suffix(
	const char *source withtok(fixture_readable_span(right)),
	size_t left, size_t right)
{
	char *buffer = __malloc(left + right + 1);
	if (!buffer) return;
	memcpy(buffer + left, source, right); /* memory-contract-expect */
}

void fill_unguarded_contracted_suffix(
	char *restrict buffer withtok(fixture_writable_span(capacity)),
	size_t capacity,
	const char *source withtok(fixture_readable_span(length)), size_t offset,
	size_t length)
{
	if (offset > capacity) return;
	memcpy(buffer + offset, source, length); /* memory-contract-expect */
}

/* strnlen(s, n)'s contract is looser than strlen(s)'s: if it walked all
 * n bytes without finding a terminator, only those n bytes (not n + 1)
 * are known-safe to read back from s -- reading one byte past that is
 * NOT proven, unlike the strlen()-derived case in safe.c's dup_all(). */
void too_much_from_strnlen(const char *s, size_t n)
{
	size_t l = strnlen(s, n);
	char *d = __malloc(l + 1);
	if (!d) return;
	memcpy(d, s, l + 1); /* memory-contract-expect */
	d[0] = 0;
}

/* Advancing the source without shortening the requested span still reaches
 * one byte beyond what strnlen established. */
void too_much_from_strnlen_suffix(const char *s, size_t n)
{
	size_t l = strnlen(s, n);
	if (l == 0) return;
	consume_bytes(s + 1, l); /* memory-contract-expect */
}

void unchecked_strlen_difference(const char *s, const char *tail)
{
	size_t whole = strlen(s);
	size_t removed = strlen(tail);
	consume_bytes(s, whole - removed); /* memory-contract-expect */
}

void consume_unbounded_prefix(const char *s, size_t requested)
{
	(void)strlen(s);
	consume_bytes(s, requested); /* memory-contract-expect */
}

void overfill_nonstrict_capacity(
	char *buffer withtok(fixture_writable_span(capacity)),
	size_t capacity, size_t used)
{
	if (used <= capacity)
		memset(buffer, 0, used + 1); /* memory-contract-expect */
}

void subtract_without_nonzero_guard(
	char *buffer withtok(fixture_writable_span(capacity)), size_t capacity)
{
	memset(buffer, 0, capacity - 1); /* memory-contract-expect */
}

void consume_wrapping_bounded_prefix(const char *s, size_t requested)
{
	size_t available = strlen(s);
	if (requested > available) return;
	consume_bytes(s, requested - 1); /* memory-contract-expect */
}

/* src/util/patch.c's own `struct linebuf` shape: a pointer field paired
 * with both a readable count (n) and a writable capacity (cap). */
struct fixture_vector {
	unsigned *v withtok(fixture_readable_elements(n))
		withtok(fixture_writable_elements(cap));
	size_t n, cap;
};

/* A helper that grows cap without ever reallocating v to match -- exactly
 * the "helper that reallocates without updating the length field, or vice
 * versa" desync this checker exists to catch.  v's real allocation extent
 * stays sized for the OLD, smaller capacity. */
void grow_vector_forgets_pointer(void)
{
	struct fixture_vector vec;
	unsigned *g = allocate_array(4, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = 4;
	vec.cap = 8;
} /* memory-contract-expect */

/* The opposite desync: v is reallocated to a SMALLER buffer, but cap is
 * left at its old, now-overstated value. */
void shrink_vector_forgets_length(void)
{
	struct fixture_vector vec;
	unsigned *g = allocate_array(8, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = 8;
	unsigned *smaller = allocate_array(2, sizeof *smaller);
	if (!smaller) return;
	vec.v = smaller;
} /* memory-contract-expect */

/* n (the readable-elements pairing, not cap) is pushed past v's real
 * extent directly. */
void push_vector_element_past_cap(void)
{
	struct fixture_vector vec;
	unsigned *g = allocate_array(4, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = 4;
	vec.n = 5;
} /* memory-contract-expect */

/* fields_established (see include/ownership.h's own comment): a helper
 * that trusts its caller to have already established the incoming
 * n/cap/v relationship. */
void grow_established_vector(struct fixture_vector *vec fields_established)
{
	if (vec->n == vec->cap) {
		unsigned newcap = vec->cap ? vec->cap * 2 : 4;
		unsigned *g = allocate_array(newcap, sizeof *g);
		if (!g) return;
		vec->v = g;
		vec->cap = newcap;
	}
	vec->n++;
}

/* The caller-side violation: claims cap=8 without ever allocating v --
 * the precondition genuinely does not hold before this call, and must
 * be caught HERE, not silently trusted (the first marker below). Once
 * inlined, the callee's own vec->n++ (n==cap is false, so growth is
 * skipped entirely) is ALSO independently caught by the ordinary write-
 * time check from the earlier commit, reported at this function's own
 * exit -- two real findings for one root cause, not a duplicate. */
void call_established_vector_unsafely(void)
{
	struct fixture_vector vec;
	vec.v = 0;
	vec.n = 0;
	vec.cap = 8;
	grow_established_vector(&vec); /* memory-contract-expect */
} /* memory-contract-expect */

/* Adversarial twin of tools/lint-memory-contract-fixtures/safe.c's
 * grow_vector_scaled_relation_bounded: the IDENTICAL unscaled relation
 * `need <= cap` is provable via the SAME guard, but nothing bounds cap
 * itself, so `cap * sizeof(*v)` genuinely CAN overflow (e.g. cap == 2^62,
 * sizeof(*v) == 4: `cap * sizeof(*v)` wraps to 0 while `need *
 * sizeof(*v)` need not) -- the no-wrap side obligation
 * MemoryContractZ3Proof::provesScaledAtLeast's own comment requires is
 * NOT satisfiable here, so the scaled inequality must NOT be trusted and
 * this finding must still be reported. */
void grow_vector_scaled_relation_unbounded(size_t cap, size_t need)
{
	struct fixture_vector vec;
	unsigned *g;
	g = allocate_array(cap, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = cap;
	vec.n = 0;
	if (vec.n + need > vec.cap) return;
	vec.n += need;
} /* memory-contract-expect */
