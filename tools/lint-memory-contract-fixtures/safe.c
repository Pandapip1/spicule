/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

typedef __SIZE_TYPE__ size_t;
#include "../../include/ownership.h"

tokdef fixture_readable_span l_unlimited implicit_drop extent_at_least zero_vacuous;
tokdef fixture_writable_span l_unlimited implicit_drop extent_at_least zero_vacuous;
tokdef fixture_disjoint_span l_unlimited implicit_drop disjoint_extent zero_vacuous;
tokdef fixture_readable_elements l_unlimited implicit_drop element_extent zero_vacuous;
tokdef fixture_writable_elements l_unlimited implicit_drop element_extent zero_vacuous;
tokdef fixture_allocation dynamic_storage;

void *memcpy(void *destination withtok(fixture_writable_span(length))
	withtok(fixture_disjoint_span(source, length)),
	const void *source withtok(fixture_readable_span(length)), size_t length);
void *memmove(void *destination withtok(fixture_writable_span(length)),
	const void *source withtok(fixture_readable_span(length)), size_t length);
void *memset(void *destination withtok(fixture_writable_span(length)), int,
	size_t length);
long read(int, void *buffer withtok(fixture_writable_span(length)),
	size_t length);
withtok(fixture_allocation)
withtok(fixture_writable_span(length))
void *__malloc(size_t length);
withtok(fixture_writable_span(length))
void *allocate_bytes(size_t length);
withtok(fixture_writable_span(count * size))
void *allocate_array(size_t count, size_t size);
withtok(fixture_allocation)
withtok(fixture_writable_span(length))
void *allocate_unknown_extent(size_t length);
size_t strlen(const char *);
size_t strnlen(const char *, size_t);
void consume_bytes(const void *source withtok(fixture_readable_span(length)),
	size_t length);
void consume_elements(
	const unsigned *source withtok(fixture_readable_elements(count)),
	size_t count);
void copy_elements(
	unsigned *restrict destination withtok(fixture_writable_elements(count)),
	const unsigned *restrict source withtok(fixture_readable_elements(count)),
	size_t count)
{
	memcpy(destination, source, count * sizeof *destination);
}
void establish_writable(
	void *buffer grant(fixture_writable_span(length)), size_t length);
void establish_readable(
	const void *buffer grant(fixture_readable_span(length)), size_t length);
void establish_disjoint(
	void *first grant(fixture_disjoint_span(second, length)),
	const void *second, size_t length);
void unsafe_assume_writable_span(
	void *buffer grant(fixture_writable_span(length)), size_t length);
void unsafe_assume_readable_span(
	const void *buffer grant(fixture_readable_span(length)), size_t length);
void unsafe_assume_disjoint_span(
	void *first grant(fixture_disjoint_span(second, length)),
	const void *second, size_t length);

void prove_writable(
	void *buffer grant(fixture_writable_span(length)), size_t length)
{
	establish_writable(buffer, length);
}

void prove_disjoint(
	void *first grant(fixture_disjoint_span(second, length)),
	const void *second, size_t length)
{
	establish_disjoint(first, second, length);
}

int prove_writable_if(
	void *buffer grant(fixture_writable_span(length)), size_t length, int okay)
{
	if (!okay)
		return -1;
	establish_writable(buffer, length);
	return 0;
}

int compose_conditional_proof(
	void *buffer grant(fixture_writable_span(length)), size_t length, int okay)
{
	return prove_writable_if(buffer, length, okay);
}

void use_conditional_memory_proof(char *destination, size_t length, int okay)
{
	if (compose_conditional_proof(destination, length, okay) != 0)
		return;
	memset(destination, 0, length);
}

void use_explicit_memory_proofs(char *destination, const char *source,
	size_t length)
{
	prove_writable(destination, length);
	establish_readable(source, length);
	prove_disjoint(destination, source, length);
	memcpy(destination, source, length);
}

/* An opaque caller-provided pointer has no inferred extent.  Its proof is
 * still necessary and therefore must not receive the redundancy warning. */
void use_necessary_manual_proof(char *destination, size_t length)
{
	unsafe_assume_writable_span(destination, length);
	memset(destination, 0, length);
}

void retain_necessary_alias_proofs(char *destination, const char *source,
	size_t length)
{
	unsafe_assume_readable_span(source, length);
	unsafe_assume_disjoint_span(destination, source, length);
}

void granted_array_base_suffix(size_t length, size_t offset)
{
	char storage[32];
	char *base = storage;
	if (length > sizeof storage || offset > length)
		return;
	establish_readable(base, length);
	consume_bytes(base + offset, length - offset);
}

void contracted_copy(char *out withtok(fixture_writable_span(length)),
	const char *in withtok(fixture_readable_span(length)), size_t length)
{
	memcpy(out, in, length);
}

void contracted_suffix(
	char *out withtok(fixture_writable_span(capacity)), size_t capacity,
	size_t offset, size_t length)
{
	if (offset > capacity || length > capacity - offset)
		return;
	memset(out + offset, 0, length);
}

void contracted_product(
	char *out withtok(fixture_writable_span(rows * columns)),
	size_t rows, size_t columns)
{
	memset(out, 0, rows * columns);
}

struct counted_buffer {
	const char *data withtok(fixture_readable_span(length));
	size_t length;
};

void consume_counted_buffer(const struct counted_buffer *buffer)
{
	consume_bytes(buffer->data, buffer->length);
	if (buffer->length >= 2)
		consume_bytes(buffer->data + 2, buffer->length - 2);
}

struct counted_elements {
	const unsigned *data withtok(fixture_readable_elements(count));
	size_t count;
};

void consume_counted_elements(const struct counted_elements *buffer)
{
	consume_elements(buffer->data, buffer->count);
}

void consume_counted_element_bytes(const struct counted_elements *buffer)
{
	consume_bytes(buffer->data, buffer->count * sizeof *buffer->data);
}

struct fixture_record {
	int first;
	int second;
};

void fill_typed_object(struct fixture_record *record)
{
	memset(record, 0, sizeof *record);
}

void satisfy_contracts(void)
{
	char source[8], destination[8];
	contracted_copy(destination, source, sizeof source);
}

/* A user function that merely shares a recognized libc name must not make
 * BeginFunction index nonexistent builtin-contract parameters. */
static int send(void)
{
	return 0;
}

int call_shadow_send(void)
{
	return send();
}

void bounded_operations(int fd)
{
	char source[16], destination[16];
	memcpy(destination, source, sizeof source);
	memmove(source + 1, source, 8);
	memset(destination, 0, sizeof destination);
	read(fd, destination, sizeof destination);
}

void copy_restrict_parameters(
	char *restrict destination withtok(fixture_writable_span(length)),
	const char *restrict source withtok(fixture_readable_span(length)),
	size_t length)
{
	memcpy(destination, source, length);
}

void copy_one_restrict_parameter(
	char *restrict destination withtok(fixture_writable_span(length)),
	const char *source withtok(fixture_readable_span(length)), size_t length)
{
	memcpy(destination, source, length);
}

struct fixture_member_buffer {
	char bytes[16];
};

void copy_restrict_members(
	struct fixture_member_buffer *restrict destination,
	const struct fixture_member_buffer *restrict source)
{
	memcpy(destination->bytes, source->bytes, sizeof destination->bytes);
}

void copy_local_restrict_pointer(
	char *storage withtok(fixture_writable_span(length)),
	const char *source withtok(fixture_readable_span(length)),
	size_t length)
{
	char *restrict destination = storage;
	memcpy(destination, source, length);
}

void copy_to_fresh_unknown_allocation(
	const char *source withtok(fixture_readable_span(length)), size_t length)
{
	char *destination = allocate_unknown_extent(length);
	if (!destination) return;
	memcpy(destination, source, length);
}

struct allocated_bytes {
	char value[8];
};

void copy_to_typed_fresh_allocation(
	const char *source withtok(fixture_readable_span(length)), size_t length)
{
	struct allocated_bytes *destination = allocate_unknown_extent(
		sizeof *destination);
	if (!destination || length > sizeof destination->value) return;
	memcpy(destination->value, source, length);
}

void clear_typed_member(struct fixture_record *record)
{
	memset(&record->second, 0, sizeof record->second);
}

/* strndup.c's own shape: this tree's own allocator (__malloc, not the
 * literally-named "malloc" clang's builtin modeling already knows how to
 * give a real dynamic extent) is sized as `l + 1`, and the destination
 * span's length is the same `l` symbol on its own -- the "allocate
 * len+1, write the terminator at len" idiom repeated throughout
 * src/string and src/sh. The SOURCE span (reading `l` bytes from `s`,
 * where `l` came from strnlen(s, n)) is proven by a separate lemma:
 * strnlen's own contract guarantees `s` has at least `l` readable bytes
 * (whether or not it found a real terminator within the first n). */
char *dup_prefix(const char *s, size_t n)
{
	size_t l = strnlen(s, n);
	if (l == (size_t)-1) return 0;
	char *d = __malloc(l + 1);
	if (!d) return 0;
	memcpy(d, s, l);
	d[l] = 0;
	return d;
}

/* A length established at the base also proves the corresponding shortened
 * span after advancing the pointer by the same number of bytes. */
void copy_strnlen_suffix(const char *s, size_t n)
{
	size_t l = strnlen(s, n);
	if (l == 0) return;
	consume_bytes(s + 1, l - 1);
}

void consume_measured_substring(const char *s, size_t n)
{
	const char *substring = s + 2;
	size_t l = strnlen(substring, n);
	consume_bytes(substring, l);
}

void consume_guarded_strlen_difference(const char *s, const char *tail)
{
	size_t whole = strlen(s);
	size_t removed = strlen(tail);
	if (removed > whole) return;
	consume_bytes(s, whole - removed);
}

void consume_strlen_bounded_prefix(const char *s, size_t requested)
{
	size_t available = strlen(s);
	if (requested > available) return;
	consume_bytes(s, requested);
}

void consume_conditional_string_prefix(const char *s, size_t requested)
{
	size_t available = strlen(s);
	size_t selected = requested < available ? requested : available;
	consume_bytes(s, selected);
}

void fill_strict_capacity(
	char *buffer withtok(fixture_writable_span(capacity)),
	size_t capacity, size_t used)
{
	if (used < capacity) memset(buffer, 0, used + 1);
}

void fill_nonzero_shorter(
	char *buffer withtok(fixture_writable_span(capacity)), size_t capacity)
{
	if (capacity) memset(buffer, 0, capacity - 1);
}

void consume_shorter_bounded_prefix(const char *s, size_t requested)
{
	size_t available = strlen(s);
	if (requested == 0 || requested > available) return;
	consume_bytes(s, requested - 1);
}

/* xstrdup's own shape, duplicated across src/glob/glob.c,
 * src/sh/execute.c, src/sh/parse.c, and src/wordexp/wordexp.c (and
 * src/string/strdup.c itself): the allocation and the memcpy length are
 * the SAME compound expression (`n`, itself `strlen(s) + 1`) on both
 * sides, and the source span is proven because strlen(s)'s own
 * byte-count contract guarantees `s` has at least strlen(s) bytes plus
 * its terminator -- exactly `n` bytes. `s` is a string literal, not a
 * parameter, so this stays focused on the MemoryContract span lemma:
 * a string literal. */
char *dup_all(void)
{
	const char *s = "example";
	size_t n = strlen(s) + 1;
	char *p = __malloc(n);
	if (!p) return 0;
	memcpy(p, s, n);
	return p;
}

/* Return extents are declaration-driven, not tied to allocator spellings. */
void declaration_driven_allocator(size_t length)
{
	char *buffer = allocate_bytes(length);
	if (!buffer) return;
	memset(buffer, 0, length);
}

void declaration_driven_array_allocator(size_t count, size_t size)
{
	char *buffer = allocate_array(count, size);
	if (!buffer) return;
	memset(buffer, 0, count * size);
}

void fill_reassociated_allocation(size_t left, size_t right)
{
	char *buffer = __malloc(left + right);
	if (!buffer) return;
	memset(buffer, 0, right + left);
}

void fill_checked_allocation_suffix(
	const char *source withtok(fixture_readable_span(right)),
	size_t left, size_t right)
{
	size_t total = left + right;
	if (total < left) return;
	char *buffer = __malloc(total);
	if (!buffer) return;
	memcpy(buffer + left, source, right);
}

void fill_checked_slack_suffix(
	const char *source withtok(fixture_readable_span(right)),
	size_t left, size_t right)
{
	if (right == (size_t)-1) return;
	size_t total = left + right + 1;
	if (total <= left) return;
	char *buffer = __malloc(total);
	if (!buffer) return;
	memcpy(buffer + left, source, right);
}

void fill_guarded_contracted_suffix(
	char *restrict buffer withtok(fixture_writable_span(capacity)),
	size_t capacity,
	const char *source withtok(fixture_readable_span(length)), size_t offset,
	size_t length)
{
	if (offset > capacity) return;
	size_t remaining = capacity - offset;
	if (length > remaining) return;
	memcpy(buffer + offset, source, length);
}

void fill_strictly_guarded_contracted_suffix(
	char *restrict buffer withtok(fixture_writable_span(capacity)),
	size_t capacity,
	const char *source withtok(fixture_readable_span(length)), size_t offset,
	size_t length)
{
	if (offset >= capacity) return;
	size_t remaining = capacity - offset;
	if (length >= remaining) return;
	memcpy(buffer + offset, source, length);
}

/* `l <= cap` is a relation between two DISTINCT symbolic expressions, not
 * a direct concrete-int range on `l` itself -- checkBranchCondition
 * records it in ProvenLessEqual precisely because the range constraint
 * manager (and therefore SValBuilder::getMaxValue(), the fast path
 * sameSymbolSpanProven tries first) cannot represent a fact about one
 * symbol in terms of another. Only combining that relation with `cap`'s
 * own concrete range fact (`cap <= 1000`) proves `l + 1` cannot wrap
 * size_t when sizing the allocation below; the coarse per-symbol
 * getMaxValue() check can only ever see `l`'s own (here: unconstrained)
 * range and so cannot discharge this side condition -- only the Z3
 * fallback in MemoryContractZ3Proof, which asserts both facts together,
 * can. `cap` is read again after the copy so it remains live (and its
 * range constraint un-reaped) at the memcpy site, matching how a real
 * capacity value would ordinarily still be used afterward. */
size_t fill_z3_bounded_allocation(
	const char *source withtok(fixture_readable_span(l)), size_t l,
	size_t cap)
{
	if (cap > 1000) return 0;
	if (l > cap) return 0;
	char *d = __malloc(l + 1);
	if (!d) return 0;
	memcpy(d, source, l);
	return cap - l;
}

/* src/util/patch.c's own `struct linebuf` shape: a pointer field paired
 * with both a readable count (n, the number of elements actually in use)
 * and a writable capacity (cap, the real allocation size in elements). */
struct fixture_vector {
	unsigned *v withtok(fixture_readable_elements(n))
		withtok(fixture_writable_elements(cap));
	size_t n, cap;
};

/* src/util/patch.c's own pointer-then-length ordering: `lb->v = g;
 * lb->cap = newcap;` are two separate statements, not one atomic update.
 * Both settle within this function body's one block, so the deferred
 * field-span check (checkPostStmt<CompoundStmt>) only judges cap against
 * v's real DynamicExtent once both writes have actually landed -- not on
 * the (still-consistent, since cap hasn't grown yet) intermediate state
 * right after `vec.v = g;` alone. */
void grow_vector_pointer_first(void)
{
	struct fixture_vector vec;
	unsigned *g = allocate_array(4, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = 4;
	vec.n = 0;
}

/* src/glob/glob.c's own opposite ordering: `out.n = out.cap =
 * pglob->gl_pathc;` is written before `out.v = __malloc(...)`.  The
 * length field settles first this time, but the deferred check still
 * only fires once both fields have landed at the end of the block, so
 * the ordering itself does not matter to the proof. */
void grow_vector_length_first(void)
{
	struct fixture_vector vec;
	vec.cap = 4;
	unsigned *g = allocate_array(4, sizeof *g);
	if (!g) return;
	vec.v = g;
}

/* A read-count push that never exceeds the just-established capacity. */
void push_vector_element(void)
{
	struct fixture_vector vec;
	unsigned *g = allocate_array(4, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = 4;
	vec.n = 0;
	vec.n = 1;
}

/* fields_established (see include/ownership.h's own comment): a helper
 * that takes an ALREADY-consistent vector and grows it further. Its own
 * standalone analysis (no visible caller, e.g. --analyze's own per-
 * function entry point) has to trust the incoming n/cap/v relationship
 * to judge its OWN internal growth fairly -- exactly src/util/patch.c's
 * apply_section/apply_ed_section's own outbuf shape. */
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

/* The caller-side half of the same contract: genuinely establishing the
 * invariant (a freshly zeroed vector: 0 <= 0) before calling a
 * fields_established parameter is provably sufficient. */
void call_established_vector_safely(void)
{
	struct fixture_vector vec;
	vec.v = 0;
	vec.n = 0;
	vec.cap = 0;
	grow_established_vector(&vec);
}

/* Mirrors src/util/patch.c's linebuf_insert_block()/src/glob/glob.c's
 * pv_push()/comp_push(): once `cap`'s own allocation (here allocate_array,
 * real code's __util_reallocarray/__malloc) establishes v's real
 * DynamicExtent as `cap * sizeof(*v)`, a growth guard's FALSE branch
 * (folded here to an early return on the TRUE branch, to keep this
 * fixture to the single path that matters) records only the UNSCALED
 * relation `need <= cap` via checkBranchCondition/ProvenLessEqual -- but
 * the real obligation flushRecordSpanObligations poses is the ELEMENT-
 * SIZE-SCALED `need * sizeof(*v) <= DynamicExtent(v)`. An explicit prior
 * bound on cap (mirroring src/internal/libc.h's own
 * __array_next_capacity's `maximum = (size_t)-1 / element_size; if
 * (current > maximum) return 0;` check) is what makes `cap *
 * sizeof(*v)` genuinely provable not to overflow -- see
 * MemoryContractZ3Proof::provesScaledAtLeast's own comment
 * (tools/clang/MemoryContractChecker.cpp) for exactly why that side
 * proof, not just the unscaled relation alone, is required before the
 * scaled inequality can be trusted. tools/lint-memory-contract-
 * fixtures/unsafe.c's grow_vector_scaled_relation_unbounded is the
 * adversarial twin: the IDENTICAL unscaled relation, but with no such
 * bound on cap, so the no-wrap side obligation is genuinely
 * unsatisfiable and the finding must still be reported. */
void grow_vector_scaled_relation_bounded(size_t cap, size_t need)
{
	struct fixture_vector vec;
	unsigned *g;
	if (cap > 1000000000u) return;
	g = allocate_array(cap, sizeof *g);
	if (!g) return;
	vec.v = g;
	vec.cap = cap;
	vec.n = 0;
	if (vec.n + need > vec.cap) return;
	vec.n += need;
}
