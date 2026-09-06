/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

__SIZE_TYPE__ strlen(
	const char * __attribute__((annotate("withtok:null_terminated"))));
__SIZE_TYPE__ wcslen(
	const __WCHAR_TYPE__ * __attribute__((annotate("withtok:null_terminated"))));

__SIZE_TYPE__ inclusive_sentinel_length(const char *s)
{
	__SIZE_TYPE__ length = strlen(s);
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) {
	}
	return i;
}

__SIZE_TYPE__ propagated_inclusive_sentinel_length(const char *s)
{
	__SIZE_TYPE__ length = strlen(s);
	__SIZE_TYPE__ copy = length;
	__SIZE_TYPE__ i;
	for (i = 0; i <= copy; i++) {
	}
	return i;
}

__SIZE_TYPE__ reversed_inclusive_sentinel_length(const char *s)
{
	__SIZE_TYPE__ length = strlen(s);
	__SIZE_TYPE__ i;
	for (i = 0; length >= i; i++) {
	}
	return i;
}

__SIZE_TYPE__ inclusive_wide_sentinel_length(const __WCHAR_TYPE__ *s)
{
	__SIZE_TYPE__ length = wcslen(s);
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) {
	}
	return i;
}

unsigned strict_bound(unsigned n)
{
	unsigned i;
	for (i = 0; i < n; i++) {
	}
	return i;
}

unsigned affine_strict_bound(unsigned n)
{
	unsigned i;
	for (i = 0; i + 2 < n; i++) {
	}
	return i;
}

unsigned conjunctive_bound(unsigned n, int stop)
{
	unsigned i;
	for (i = 0; i < n && !stop; ++i) {
	}
	return i;
}

unsigned inclusive_constant_bound(void)
{
	unsigned i;
	for (i = 0; i <= 60; i++) {
	}
	return i;
}

int inclusive_countdown(void)
{
	int i;
	for (i = 8; i >= 0; i--) {
	}
	return i;
}

int signed_nonunit_step(int n)
{
	int i;
	for (i = 0; i <= n; i += 3) {
	}
	return i;
}

static unsigned stable_file_bound = 8;

unsigned stable_file_bound_loop(void)
{
	unsigned i;
	for (i = 0; i < stable_file_bound; i++) {
	}
	return i;
}

unsigned sentinel_pointer(const unsigned char *p)
{
	const unsigned char *start = p;
	while (*p != 0)
		p++;
	return (unsigned)(p - start);
}

unsigned sentinel_pointer_variable_step(const unsigned char *p)
{
	const unsigned char *start = p;
	while (*p != 0)
		p += (unsigned)*p + 1;
	return (unsigned)(p - start);
}

size_t sentinel_index(const unsigned char *p)
{
	size_t i = 0;
	while (p[i])
		i = i + 1;
	return i;
}

unsigned narrow_index_with_explicit_bound(const unsigned char *p,
	unsigned char n)
{
	unsigned char i = 0;
	while (i < n && p[i])
		i++;
	return i;
}

int pure_byte_predicate(int) __attribute__((pure));
int const_byte_predicate(int) __attribute__((const));

size_t sentinel_index_through_pure_predicate(const unsigned char *p)
{
	size_t i = 0;
	while (pure_byte_predicate(p[i]))
		i++;
	return i;
}

const unsigned char *sentinel_pointer_through_pure_predicate(
	const unsigned char *p)
{
	while (pure_byte_predicate(*p))
		p++;
	return p;
}

const unsigned char *sentinel_pointer_through_const_predicate(
	const unsigned char *p)
{
	while (const_byte_predicate(*p))
		p++;
	return p;
}

unsigned bounded_index_through_pure_predicate(const unsigned char *p,
	unsigned n)
{
	unsigned i = 0;
	while (i < n && pure_byte_predicate(p[i]))
		i++;
	return i;
}

struct cursor_accessor {
	const char **v;
	size_t n;
	size_t i;
};

static const char *cursor_peek(struct cursor_accessor *c)
{
	return c->i < c->n ? c->v[c->i] : (void *)0;
}

/* cursor_peek()'s own bound comparison (c->i < c->n) is entirely inside
 * its body; the caller only ever passes the cursor itself.  Proving this
 * terminates requires inlining cursor_peek() into the condition. */
size_t truthy_call_wrapped_bound(struct cursor_accessor *c)
{
	while (cursor_peek(c))
		c->i++;
	return c->i;
}

struct byte_scanner {
	const unsigned char *src;
	size_t len;
	size_t pos;
};

static int scanner_peek(struct byte_scanner *s)
{
	return s->pos < s->len ? (unsigned char)s->src[s->pos] : -1;
}

/* Same call-wrapped bound as truthy_call_wrapped_bound(), but the
 * accessor signals "nothing left" with an explicit sentinel comparison
 * (`!= -1`) rather than relying on pointer truthiness. */
size_t compared_call_wrapped_bound(struct byte_scanner *s)
{
	while (scanner_peek(s) != -1)
		s->pos++;
	return s->pos;
}

unsigned countdown(unsigned n)
{
	while (n)
		--n;
	return n;
}

unsigned radix_countdown(unsigned n)
{
	while (n)
		n /= 10;
	return n;
}

unsigned radix_countdown_above_one(unsigned n)
{
	while (n > 1)
		n /= 10;
	return n;
}

unsigned radix_countdown_at_least_two(unsigned n)
{
	while (2 <= n)
		n /= 10;
	return n;
}

unsigned assigned_radix_countdown(unsigned n)
{
	while (n)
		n = n / 10;
	return n;
}

unsigned shifted_countdown(unsigned n)
{
	while (n)
		n >>= 3;
	return n;
}

unsigned explicit_cast_bound(unsigned n)
{
	unsigned long i;
	for (i = 0; i < (unsigned long)n; i++) {
	}
	return (unsigned)i;
}

int signed_countdown(int n)
{
	while (n)
		n--;
	return n;
}

int signed_radix_countdown(int n)
{
	while (n != 0)
		n /= 10;
	return n;
}

unsigned chunked_countdown(unsigned n)
{
	while (n >= 3)
		n -= 3;
	return n;
}

unsigned sizeof_chunked_countdown(unsigned n)
{
	for (; n >= sizeof(unsigned); n -= sizeof(unsigned)) {
	}
	return n;
}

struct counter {
	unsigned n;
};

void opaque_exit_call(void);

unsigned member_countdown(struct counter *counter)
{
	while (counter->n)
		counter->n--;
	return counter->n;
}

unsigned member_countdown_call_only_on_exit(struct counter *counter, int stop)
{
	while (counter->n) {
		counter->n--;
		if (stop) {
			opaque_exit_call();
			return counter->n;
		}
	}
	return counter->n;
}

unsigned member_unconditional_countdown(struct counter *counter)
{
	for (;;) {
		unsigned value;
		if (counter->n == 0) {
			opaque_exit_call();
			return counter->n;
		}
		counter->n--;
		value = counter->n;
		if (value & 1) continue;
	}
}

int signed_unconditional_countdown(int n)
{
	for (;;) {
		if (!n) break;
		n--;
	}
	return n;
}

int opaque_dynamic_step(void);

/* The transition slice must quantify this per-iteration value.  Treating it
 * as an unchanged header-state slot would silently strengthen the relation. */
unsigned transition_ir_havocs_transient(unsigned n)
{
	while (n > 0) {
		int transient = opaque_dynamic_step();
		(void)transient;
		n--;
	}
	return n;
}

/* The existing rank proof may ignore this call because n does not escape.
 * The general transition IR must nevertheless label the path unsupported
 * until the shared effect algebra can supply an exact call summary. */
unsigned transition_ir_marks_opaque_effect_unsupported(unsigned n)
{
	while (n > 0) {
		opaque_exit_call();
		n--;
	}
	return n;
}

unsigned _BitInt(3) literal_finite_nonmonotonic(unsigned _BitInt(3) value)
{
	while (value != 0) {
		if (value == 1)
			value = 2;
		else if (value == 2)
			value = 3;
		else
			value = 0;
	}
	return value;
}

signed _BitInt(8) literal_signed_ub_terminal(signed _BitInt(8) value)
{
	for (;;)
		value += (signed _BitInt(8))1;
}

unsigned char literal_multiple_backedges(unsigned char value)
{
	while (value != 0) {
		if (value == 1) {
			value = 2;
			continue;
		}
		value = 0;
	}
	return value;
}

signed char literal_signed_widening_boundary(signed char value)
{
	while (value < 0)
		value++;
	return value;
}

unsigned char literal_unsigned_widening_boundary(unsigned char value)
{
	while (value == 255)
		value = 0;
	return value;
}

__UINT32_TYPE__ spacer_finite_nonmonotonic_u32(__UINT32_TYPE__ value)
{
	while (value != 0) {
		if (value == 1)
			value = 2;
		else if (value == 2)
			value = 3;
		else
			value = 0;
	}
	return value;
}

__UINT32_TYPE__ spacer_wide_terminating(__UINT32_TYPE__ value)
{
	while (value != 0) {
		if (value == 1)
			value = 0;
		else
			value--;
	}
	return value;
}

int spacer_wide_defined_descent(int value)
{
	for (;;) {
		if (value == 0)
			return value;
		value -= 2;
	}
}

__UINT32_TYPE__ spacer_multiple_backedges_u32(__UINT32_TYPE__ value)
{
	while (value != 0) {
		if (value == 1) {
			value = 2;
			continue;
		}
		value = 0;
	}
	return value;
}

int guarded_dynamic_countdown(int n)
{
	while (n > 0) {
		opaque_exit_call();
		int step = opaque_dynamic_step();
		if (step <= 0 || step > n) return n;
		n -= step;
	}
	return n;
}

unsigned guarded_mixed_dynamic_countdown(unsigned n)
{
	while (n > 0) {
		int step = opaque_dynamic_step();
		if (step <= 0 || (unsigned)step > n) return n;
		n -= (unsigned)step;
	}
	return n;
}

__SIZE_TYPE__ clamped_dynamic_countdown(__SIZE_TYPE__ n)
{
	while (n) {
		__SIZE_TYPE__ step = n < 32 ? n : 32;
		n -= step;
	}
	return n;
}

__SIZE_TYPE__ reversed_clamped_dynamic_countdown(__SIZE_TYPE__ n)
{
	while (n != 0) {
		__SIZE_TYPE__ step = 16 > n ? n : 16;
		n -= step;
	}
	return n;
}

__SIZE_TYPE__ sizeof_clamped_dynamic_countdown(__SIZE_TYPE__ n)
{
	while (n > 0) {
		__SIZE_TYPE__ step = n < sizeof(unsigned long)
			? n : sizeof(unsigned long);
		n -= step;
	}
	return n;
}

__SIZE_TYPE__ clamped_countdown_across_condition_call(__SIZE_TYPE__ n)
{
	while (n) {
		__SIZE_TYPE__ step = n < 32 ? n : 32;
		if (opaque_dynamic_step()) opaque_exit_call();
		n -= step;
	}
	return n;
}

unsigned clamped_countdown_wider_choice(unsigned n)
{
	while (n) {
		unsigned step = n < (__SIZE_TYPE__)32 ? n : (__SIZE_TYPE__)32;
		n -= step;
	}
	return n;
}

unsigned inclusive_clamped_countdown(unsigned n)
{
	while (n) {
		unsigned step = n <= 32 ? n : 32;
		n -= step;
	}
	return n;
}

struct byte_cursor {
	unsigned char next;
};

unsigned char member_byte_rank_call_only_on_exit(struct byte_cursor *cursor,
	unsigned char total, int skip)
{
	while (cursor->next < total) {
		cursor->next++;
		if (skip) continue;
		opaque_exit_call();
		return cursor->next;
	}
	return cursor->next;
}

struct restricted_byte_cursor {
	unsigned char next;
};

struct disjoint_byte_state {
	unsigned char next;
};

unsigned char restricted_member_call_not_receiving_base(
	struct restricted_byte_cursor *restrict cursor, unsigned char total,
	struct disjoint_byte_state *other, int skip)
{
	while (cursor->next < total) {
		cursor->next++;
		other->next = 0;
		opaque_exit_call();
		if (skip) continue;
	}
	return cursor->next;
}

int signed_extra_progress(int n, int skip)
{
	int i;
	for (i = 0; i < n; i++) {
		if (skip)
			i++;
	}
	return i;
}

unsigned two_variable_increment(unsigned n)
{
	unsigned i, remaining;
	for (i = 0, remaining = n; i < n; i++, remaining--) {
	}
	return remaining;
}

unsigned condition_countdown(unsigned n)
{
	unsigned sum = 0;
	while (n-- > 0)
		sum++;
	return sum;
}

unsigned progress_on_every_backedge(unsigned n, int choose)
{
	unsigned i = 0;
	while (i < n) {
		if (choose) {
			i++;
			continue;
		}
		i++;
	}
	return i;
}

unsigned progress_or_exit(unsigned n, int stop)
{
	unsigned i = 0;
	while (i < n) {
		if (stop)
			break;
		i++;
	}
	return i;
}

unsigned progress_in_both_expression_arms(unsigned n, int choose)
{
	unsigned i = 0;
	while (i < n)
		choose ? i++ : ++i;
	return i;
}

unsigned paired_merge_rank(unsigned a, unsigned a_end, unsigned b,
	unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) {
		if (choose)
			a++;
		else
			b++;
	}
	return a + b;
}

unsigned guarded_recursion(unsigned n)
{
	if (n)
		return guarded_recursion(n - 1);
	return 0;
}

unsigned guarded_else_recursion(unsigned n)
{
	if (!n)
		return 0;
	else
		return guarded_else_recursion(n - 1);
}

/* A recursive-descent parser's cursor struct: ps is passed unchanged by
 * pointer at every call (no scalar argument shrinks), but scan_group()'s
 * own dominating "sc->p++" before its self-call is the real progress --
 * see fieldProgressRelation() in TotalityChecker.cpp. scan_mark()'s call
 * in between is a harmless distraction: it never touches ->p. */
struct scan_cursor {
	const char *p;
	int depth;
};

static void scan_mark(struct scan_cursor *sc, int op)
{
	if (op < 0)
		sc->depth = op;
}

static void scan_group(struct scan_cursor *sc)
{
	if (*sc->p == '(') {
		sc->p++;
		scan_mark(sc, 1);
		scan_group(sc);
	}
}

struct vec {
	unsigned n;
	unsigned *v;
};

void free(void *);
void __free(void *);

struct owned_vec {
	unsigned n;
	void **v;
};

unsigned member_bound_arrow(struct vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
	}
	return i;
}

unsigned member_bound_dot(struct vec v)
{
	unsigned i;
	for (i = 0; i < v.n; i++) {
	}
	return i;
}

unsigned member_bound_while(struct vec *p)
{
	unsigned i = 0;
	while (i < p->n) {
		if (p->v[i] == 0)
			return i;
		i++;
	}
	return i;
}

unsigned member_bound_across_free(struct owned_vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++)
		free(p->v[i]);
	return i;
}

unsigned member_bound_across_internal_free(struct owned_vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++)
		__free(p->v[i]);
	return i;
}

static __SIZE_TYPE__ stable_unsigned_step(__SIZE_TYPE__ remaining)
{
	return remaining ? 1 : 0;
}

__SIZE_TYPE__ guarded_unsigned_distance_ascent(__SIZE_TYPE__ end)
{
	__SIZE_TYPE__ i = 0;
	while (i < end) {
		__SIZE_TYPE__ step = stable_unsigned_step(end - i);
		if (!step) return i;
		if (step > end - i) return i;
		i += step;
	}
	return i;
}

static __PTRDIFF_TYPE__ stable_signed_step(__SIZE_TYPE__ remaining)
{
	return remaining ? 1 : 0;
}

__SIZE_TYPE__ guarded_signed_distance_ascent(__SIZE_TYPE__ end)
{
	__SIZE_TYPE__ i = 0;
	while (i < end) {
		__PTRDIFF_TYPE__ step = stable_signed_step(end - i);
		if (step <= 0) return i;
		if ((__SIZE_TYPE__)step > end - i) return i;
		i += (__SIZE_TYPE__)step;
	}
	return i;
}

static void change_live_unsigned_bound(unsigned *bound)
{
	if (*bound)
		(*bound)--;
}

unsigned unit_rank_with_live_bound(unsigned *bound)
{
	unsigned i;
	for (i = 0; i < *bound; i++)
		change_live_unsigned_bound(bound);
	return i;
}

int signed_unit_rank_with_live_bound(int *bound)
{
	int i;
	for (i = -4; i < *bound; i++)
		if (*bound > 0)
			(*bound)--;
	return i;
}

void opaque_affine_callback(void);
int opaque_affine_predicate(void);

__SIZE_TYPE__ guarded_affine_ascent(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) {
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ guarded_affine_callback_ascent(__SIZE_TYPE__ i,
	__SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) {
		child = 2 * i + 1;
		if (child + 1 < n && opaque_affine_predicate())
			child++;
		opaque_affine_callback();
		i = child;
	}
	return i;
}

__SIZE_TYPE__ guarded_affine_continue_after_progress(__SIZE_TYPE__ i,
	__SIZE_TYPE__ n, int skip)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) {
		child = 2 * i + 1;
		i = child;
		if (skip)
			continue;
	}
	return i;
}

unsigned char promoted_byte_unit_rank(unsigned char bound)
{
	unsigned char i;
	for (i = 0; i < bound; i++) {
	}
	return i;
}

unsigned char byte_rank_with_fitting_wide_constant(void)
{
	unsigned char i;
	for (i = 0; i < 200U; i++) {
	}
	return i;
}

signed char signed_byte_rank_with_fitting_constant(void)
{
	signed char i;
	for (i = -2; i < 100L; i++) {
	}
	return i;
}

unsigned reversed_unit_upper_bound(unsigned bound)
{
	unsigned i;
	for (i = 0; bound > i; i++) {
	}
	return i;
}

unsigned inclusive_below_maximum(void)
{
	unsigned char i;
	for (i = 0; i <= 254; i++) {
	}
	return i;
}

unsigned inclusive_nonnegative_signed_constant(void)
{
	unsigned i;
	for (i = 0; i <= 5; i++) {
	}
	return i;
}

void opaque_exit_path_call(void);

unsigned exit_path_call_and_rank_change(unsigned bound, int stop)
{
	unsigned i;
	for (i = 0; i < bound; i++) {
		if (stop) {
			opaque_exit_path_call();
			i = bound;
			return i;
		}
	}
	return i;
}

unsigned reused_rank_only_before_return(unsigned bound, unsigned inner,
	int stop)
{
	unsigned i;
	for (i = 0; i < bound; i++) {
		if (stop) {
			for (i = 0; i < inner; i++) {
			}
			return i;
		}
	}
	return i;
}

unsigned halving_interval(unsigned n, unsigned key)
{
	while (n) {
		unsigned half = n / 2;
		if (key > half)
			n -= half + 1;
		else
			n = half;
	}
	return n;
}

unsigned bounded_interval(unsigned lo, unsigned hi, unsigned key)
{
	while (lo < hi) {
		unsigned mid = lo + (hi - lo) / 2;
		if (key < mid)
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

int interval_compare(unsigned key, unsigned mid);

unsigned interval_with_comparator(unsigned lo, unsigned hi, unsigned key)
{
	while (lo < hi) {
		unsigned mid = lo + (hi - lo) / 2;
		if (interval_compare(key, mid) < 0)
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

unsigned interval_reused_only_on_exit(unsigned lo, unsigned hi,
	unsigned inner, int stop)
{
	while (lo < hi) {
		unsigned mid = lo + (hi - lo) / 2;
		if (stop) {
			while (lo < inner)
				lo++;
			return lo;
		}
		if (mid & 1)
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

__SIZE_TYPE__ geometric_unsigned_growth(__SIZE_TYPE__ initial,
	__SIZE_TYPE__ need)
{
	__SIZE_TYPE__ cap = initial ? initial : 8;
	while (cap < need) {
		if (cap > (__SIZE_TYPE__)-1 / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

int geometric_signed_growth(int initial, int need)
{
	int cap = initial;
	if (cap < 32)
		cap = 32;
	while (cap < need) {
		if (cap > __INT_MAX__ / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

__SIZE_TYPE__ geometric_exit_assignment(__SIZE_TYPE__ initial,
	__SIZE_TYPE__ need)
{
	__SIZE_TYPE__ cap = initial ? initial : 8;
	while (cap < need) {
		if (cap > (__SIZE_TYPE__)-1 / 2) {
			cap = need;
			break;
		}
		cap *= 2;
	}
	return cap;
}

void geometric_opaque(void);

unsigned geometric_call_with_closed_locals(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) {
		if (cap > (unsigned)-1 / 2)
			return cap;
		geometric_opaque();
		cap = cap * 2;
	}
	return cap;
}

unsigned constant_stride_three(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) {
	}
	return i;
}

unsigned constant_stride_reversed(unsigned bound)
{
	unsigned i;
	for (i = 0; bound > i; i += 3) {
	}
	return i;
}

unsigned constant_stride_multiple_bound(unsigned source)
{
	unsigned bound = source * 4;
	unsigned i;
	for (i = 0; i < bound; i += 4) {
	}
	return i;
}

unsigned constant_stride_literal_bound(void)
{
	unsigned i;
	for (i = 0; i < 100; i += 7) {
	}
	return i;
}

unsigned constant_stride_for_continue(unsigned bound, int skip)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) {
		if (skip)
			continue;
		geometric_opaque();
	}
	return i;
}

static const char *positive_stride_leaf(const char *p, __SIZE_TYPE__ stride)
{
	while (*p)
		p += stride;
	return p;
}

static const char *positive_stride_forward(const char *p,
	__SIZE_TYPE__ stride)
{
	return positive_stride_leaf(p, stride);
}

const char *positive_stride_root(const char *p)
{
	return positive_stride_forward(p, sizeof(unsigned));
}

const char *positive_stride_cast_root(const char *p)
{
	return positive_stride_forward(p, (int)sizeof(unsigned));
}

static const char *positive_stride_assignment_leaf(const char *p,
	unsigned stride)
{
	while (*p)
		p = p + stride;
	return p;
}

const char *positive_stride_assignment_root(const char *p)
{
	return positive_stride_assignment_leaf(p, 2);
}

static const char *positive_stride_cycle_b(const char *, unsigned, unsigned);

static const char *positive_stride_cycle_a(const char *p, unsigned stride,
	unsigned remaining)
{
	while (*p)
		p += stride;
	if (remaining)
		return positive_stride_cycle_b(p, stride, remaining - 1);
	return p;
}

static const char *positive_stride_cycle_b(const char *p, unsigned stride,
	unsigned remaining)
{
	while (*p)
		p += stride;
	if (remaining)
		return positive_stride_cycle_a(p, stride, remaining - 1);
	return p;
}

const char *positive_stride_cycle_root(const char *p, unsigned remaining)
{
	return positive_stride_cycle_a(p, 1, remaining);
}

static int inferred_readonly_leaf(unsigned char c)
{
	return c != 0;
}

static int inferred_readonly_scalar(unsigned char c)
{
	int copy = c;
	copy &= 0x7f;
	return inferred_readonly_leaf((unsigned char)copy);
}

unsigned inferred_readonly_scalar_bound(const unsigned char *p, unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_readonly_scalar(p[i]))
		i++;
	return i;
}

static int inferred_readonly_pointer(const unsigned char *p, unsigned i)
{
	return p[i] != 0;
}

unsigned inferred_readonly_pointer_bound(const unsigned char *p, unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_readonly_pointer(p, i))
		i++;
	return i;
}

struct safe_pointer_member_cursor {
	const char *p;
};

static int pointer_member_readonly(
	const struct safe_pointer_member_cursor *cursor)
{
	return *cursor->p != 0;
}

const char *pointer_member_body_exit(
	struct safe_pointer_member_cursor *cursor)
{
	for (;;) {
		if (!pointer_member_readonly(cursor)) return cursor->p;
		cursor->p++;
	}
}

const char *pointer_member_positive_skip(
	struct safe_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running)
		cursor->p += 2;
	return cursor->p;
}

const char *pointer_member_descent(
	struct safe_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running)
		cursor->p--;
	return cursor->p;
}

const char *local_pointer_without_sentinel(const char *p, int keep_running)
{
	while (keep_running)
		p++;
	return p;
}

const char *local_pointer_after_unsigned_span(const char *p, unsigned span,
	int keep_running)
{
	while (keep_running) {
		p += span;
		p++;
	}
	return p;
}

const char *local_pointer_before_unsigned_span(const char *p, unsigned span,
	int keep_running)
{
	while (keep_running) {
		p++;
		p += span;
	}
	return p;
}

const char *guarded_unsigned_pointer_step(const char *p, unsigned step,
	int keep_running)
{
	while (keep_running) {
		unsigned used = step;
		if (!used) break;
		p += used;
	}
	return p;
}

unsigned forward_goto_countdown(unsigned n, int fail)
{
	while (n > 0) {
		if (fail) goto out;
		n--;
	}
out:
	return n;
}

unsigned multiple_forward_goto_countdown(unsigned n, int first, int second)
{
	while (n > 0) {
		if (first) goto first_exit;
		if (second) goto second_exit;
		n--;
	}
first_exit:
	return n;
second_exit:
	return n;
}

const char *switch_pointer_progress(const char *p, int arm)
{
	while (*p) {
		switch (arm) {
		case 0:
			p++;
			break;
		case 1:
		case 2:
			p += 2;
			break;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_pointer_fallthrough(const char *p, int arm)
{
	while (*p) {
		switch (arm) {
		case 0:
			arm = 1;
			/* fall through */
		case 1:
			p++;
			break;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_pointer_continue(const char *p, int arm)
{
	while (*p) {
		switch (arm) {
		case 0:
			p++;
			continue;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_empty_sentinel_exit(const char *p, int arm)
{
	while (*p) {
		switch (arm) {
		case 0:
			p++;
			break;
		case 1:
			p = (const char *)"";
			break;
		default:
			return p;
		}
	}
	return p;
}

unsigned switch_scalar_progress(unsigned i, unsigned limit, int arm)
{
	while (i < limit) {
		switch (arm) {
		case 0:
			i++;
			break;
		default:
			return i;
		}
	}
	return i;
}

int signed_body_finite_domain(int i, int keep_running)
{
	for (;;) {
		if (!keep_running) return i;
		i++;
	}
}

int signed_body_descent(int i, int keep_running)
{
	while (keep_running)
		i--;
	return i;
}

long write(int, const void *, __SIZE_TYPE__);

__SIZE_TYPE__ z3_guarded_write_progress(int fd, const char *buf,
	__SIZE_TYPE__ len)
{
	__SIZE_TYPE__ off = 0;
	while (off < len) {
		long written = write(fd, buf + off, len - off);
		if (written <= 0 || (__SIZE_TYPE__)written > len - off)
			return off;
		off += (__SIZE_TYPE__)written;
	}
	return off;
}

/* A condensed version of src/util/m4.c's own ev_primary()/ev_unary()
 * operator-precedence chain -- the real-world shape a full-tree
 * totality survey found unprovable across ~1470 recursion edges despite
 * fieldProgressRelation() already existing, and which turned out to be
 * three separate, general blind spots rather than one:
 *
 *   1. eval_unary() calling itself as `int r = eval_unary(ev);` --
 *      a fresh local's own initializer, not a plain assignment to an
 *      already-declared one. A CallExpr nested there has that VarDecl
 *      itself as its immediate AST parent, not a Stmt (a declarator's
 *      initializer has no Stmt node of its own), which used to make
 *      precedingStatements() return empty and the dominating `ev->p++`
 *      right next to it invisible.
 *   2. eval_primary()'s and eval_unary()'s own calls to eval_ws() in
 *      between an established witness and the recursive call that
 *      relies on it: eval_ws() may or may not actually consume
 *      anything (it depends on whether the input has leading
 *      whitespace right there), so it is neither a witness itself nor,
 *      under the OLD "prove exactly unchanged or bail" TolerateAdvances
 *      rule, tolerable filler -- even though "never moves backward" is
 *      all the proof actually needs from it.
 *   3. eval_primary()'s digit branch: `long v = strtol(ev->p, &end,
 *      0); ev->p = end;` is neither a `+=`-shaped step nor reachable
 *      through safeFieldAdvance()'s witness shapes at all, so it used
 *      to read as an arbitrary, adversarial write to ev->p -- poisoning
 *      every OTHER caller's witness search that transitively called
 *      through eval_primary(), which is all of them.
 *
 * See TotalityChecker.cpp's toleratedPointerReassign(),
 * precedingStatements()'s VarDecl-initializer climb, and
 * fieldProgressRelation()'s own comment on why tolerating a recognized
 * forward-or-unchanged write even with no witness in hand is sound. */
long strtol(const char *, char **
	__attribute__((annotate("qual:endptr_advances"))), int);

struct eval_cursor {
	const char *p;
};

static void eval_ws(struct eval_cursor *ev)
{
	while (*ev->p == ' ')
		ev->p++;
}

static int eval_unary(struct eval_cursor *ev);

static int eval_primary(struct eval_cursor *ev)
{
	eval_ws(ev);
	if (*ev->p == '(') {
		ev->p++;
		int v = eval_unary(ev);
		eval_ws(ev);
		if (*ev->p == ')')
			ev->p++;
		return v;
	}
	if (*ev->p >= '0' && *ev->p <= '9') {
		char *end;
		long v = strtol(ev->p, &end, 0);
		ev->p = end;
		return (int)v;
	}
	if (*ev->p)
		ev->p++;
	return 0;
}

static int eval_unary(struct eval_cursor *ev)
{
	eval_ws(ev);
	if (*ev->p == '-') {
		ev->p++;
		int r = eval_unary(ev);
		return -r;
	}
	return eval_primary(ev);
}
