/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

struct node {
	struct node *next;
};

__SIZE_TYPE__ untrusted_sentinel_length(const char *);

__SIZE_TYPE__ inclusive_untrusted_length(const char *s)
{
	__SIZE_TYPE__ length = untrusted_sentinel_length(s);
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

__SIZE_TYPE__ strlen(
	const char * __attribute__((annotate("withtok:null_terminated"))));

__SIZE_TYPE__ wcslen(const __WCHAR_TYPE__ *);

__SIZE_TYPE__ missing_terminator_contract(const __WCHAR_TYPE__ *s)
{
	__SIZE_TYPE__ length = wcslen(s);
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

__SIZE_TYPE__ indirect_sentinel_length(const char *s)
{
	__SIZE_TYPE__ (*scan)(const char *) = strlen;
	__SIZE_TYPE__ length = scan(s);
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

__SIZE_TYPE__ length_plus_one(const char *s)
{
	__SIZE_TYPE__ length = strlen(s) + 1;
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

__SIZE_TYPE__ mutated_length_snapshot(const char *s)
{
	__SIZE_TYPE__ length = strlen(s);
	__SIZE_TYPE__ i;
	length++;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

void mutate_size(__SIZE_TYPE__ *);

__SIZE_TYPE__ aliased_length_snapshot(const char *s)
{
	__SIZE_TYPE__ length = strlen(s);
	__SIZE_TYPE__ i;
	mutate_size(&length);
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

static __SIZE_TYPE__ global_length_snapshot;

__SIZE_TYPE__ global_sentinel_length(const char *s)
{
	__SIZE_TYPE__ i;
	global_length_snapshot = strlen(s);
	for (i = 0; i <= global_length_snapshot; i++) { /* totality-expect */
	}
	return i;
}

__SIZE_TYPE__ volatile_sentinel_length(const char *s)
{
	volatile __SIZE_TYPE__ length = strlen(s);
	__SIZE_TYPE__ i;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

unsigned short narrowed_sentinel_length(const char *s)
{
	__SIZE_TYPE__ raw = strlen(s);
	unsigned short length = raw;
	unsigned short i;
	for (i = 0; i <= length; i++) { /* totality-expect */
	}
	return i;
}

void unconditional_loop(void)
{
	for (;;) { /* totality-expect */
	}
}

unsigned wrapping_step(unsigned n)
{
	unsigned i;
	for (i = 0; i < n; i += 2) { /* totality-expect */
	}
	return i;
}

unsigned inclusive_type_maximum(void)
{
	unsigned i;
	for (i = 0; i <= ~0u; i++) { /* totality-expect */
	}
	return i;
}

unsigned disjunctive_bound(unsigned n, int keep_running)
{
	unsigned i;
	for (i = 0; i < n || keep_running; i++) { /* totality-expect */
	}
	return i;
}

unsigned moving_bound(unsigned n)
{
	unsigned i = 0;
	while (i < n) { /* totality-expect */
		i++;
		n++;
	}
	return i;
}

unsigned escaped_rank(unsigned n)
{
	unsigned i = 0;
	unsigned *alias = &i;
	while (i < n) { /* totality-expect */
		i++;
		(*alias)--;
	}
	return i;
}

unsigned conditional_progress(unsigned n, int choose)
{
	unsigned i = 0;
	while (i < n) { /* totality-expect */
		if (choose)
			i++;
	}
	return i;
}

unsigned short_circuit_progress(unsigned n, int choose)
{
	unsigned i = 0;
	while (i < n) { /* totality-expect */
		choose && i++;
	}
	return i;
}

unsigned conditional_expression_progress(unsigned n, int choose)
{
	unsigned i = 0;
	while (i < n) { /* totality-expect */
		choose ? i++ : 0;
	}
	return i;
}

unsigned cancelled_for_increment(unsigned n)
{
	unsigned i;
	for (i = 0; i < n; i++) { /* totality-expect */
		i--;
	}
	return i;
}

unsigned unsigned_extra_progress_can_wrap(unsigned n)
{
	unsigned i;
	for (i = 0; i < n; i++) { /* totality-expect */
		i++;
	}
	return i;
}

unsigned division_by_one_does_not_progress(unsigned n)
{
	while (n) { /* totality-expect */
		n /= 1;
	}
	return n;
}

unsigned division_guard_admits_zero(unsigned n)
{
	while (n < 2) { /* totality-expect */
		n /= 2;
	}
	return n;
}

unsigned division_disequality_admits_zero(unsigned n)
{
	while (n != 1) { /* totality-expect */
		n /= 2;
	}
	return n;
}

unsigned nonunit_countdown_can_wrap(unsigned n)
{
	while (n) { /* totality-expect */
		n -= 2;
	}
	return n;
}

unsigned mismatched_guarded_steps(unsigned n, int choose)
{
	while (n >= 3) { /* totality-expect */
		if (choose)
			n -= 3;
		else
			n -= 5;
	}
	return n;
}

unsigned cancelled_comma_increment(unsigned n)
{
	unsigned i;
	for (i = 0; i < n; i++, i--) { /* totality-expect */
	}
	return i;
}

unsigned cancelled_condition_countdown(unsigned n)
{
	while (n-- > 0) { /* totality-expect */
		n++;
	}
	return n;
}

void floating_condition_countdown(double n)
{
	while (n-- > 0) { /* totality-expect */
	}
}

struct node *possibly_circular(struct node *node)
{
	while (node) { /* totality-expect */
		node = node->next;
	}
	return node;
}

unsigned unguarded_recursion(unsigned n)
{
	return unguarded_recursion(n - 1); /* totality-expect */
}

const unsigned char *unguarded_pointer_recursion(const unsigned char *p)
{
	return unguarded_pointer_recursion(p + 1); /* totality-expect */
}

/* Same cursor-struct shape as safe.c's scan_group(), minus its one
 * dominating "sc->p++": no field of the unchanged sc argument ever
 * advances, so this stays exactly as unproved as it was before
 * fieldProgressRelation() existed. */
struct scan_cursor_unguarded {
	const char *p;
};

static void scan_group_unguarded(struct scan_cursor_unguarded *sc)
{
	if (*sc->p == '(')
		scan_group_unguarded(sc); /* totality-expect */
}

/* Same shape again, but the dominating advance is followed by an
 * untracked reset to an earlier position before the self-call --
 * bodyMayWriteField() must still catch this as interference even though
 * safeFieldAdvance() already approved an earlier statement as the
 * witness for this exact call. */
struct scan_cursor_reset {
	const char *p;
	const char *start;
};

static void scan_group_reset(struct scan_cursor_reset *sc)
{
	if (*sc->p == '(') {
		sc->p++;
		sc->p = sc->start;
		scan_group_reset(sc); /* totality-expect */
	}
}

struct vec {
	unsigned n;
	unsigned *v;
};

void mutate_vec(struct vec *p);
void free(void *);
void *realloc(void *, __SIZE_TYPE__);

unsigned member_bound_mutated_in_body(struct vec *p)
{
	/* The bound may move on a continuing path: strict same-domain `<`
	 * still makes a TYPE_MAX backedge impossible for local unit rank i. */
	unsigned i;
	for (i = 0; i < p->n; i++) {
		p->n++;
	}
	return i;
}

unsigned member_bound_escapes_to_call(struct vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
		mutate_vec(p);
	}
	return i;
}

unsigned member_bound_across_realloc(struct vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
		(void)realloc(p->v, 16);
	}
	return i;
}

unsigned member_bound_address_taken(struct vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
		(void)&p->n;
	}
	return i;
}

struct ascent_alias_vec {
	unsigned bound;
	unsigned *alias;
};

static unsigned pointer_member_alias_step(struct ascent_alias_vec *p,
	unsigned remaining)
{
	*p->alias = p->bound + 1;
	return remaining ? 1 : 0;
}

unsigned ascent_with_pointer_member_alias(struct ascent_alias_vec *p)
{
	unsigned i = 0;
	while (i < p->bound) { /* totality-expect */
		unsigned step = pointer_member_alias_step(p, p->bound - i);
		if (!step || step > p->bound - i) return i;
		i += step;
	}
	return i;
}

unsigned ascent_allows_zero(unsigned end, unsigned step)
{
	unsigned i = 0;
	while (i < end) { /* totality-expect */
		if (step > end - i) return i;
		i += step;
	}
	return i;
}

unsigned ascent_allows_oversize(unsigned end, unsigned step)
{
	unsigned i = 0;
	while (i < end) { /* totality-expect */
		if (!step) return i;
		i += step;
	}
	return i;
}

unsigned member_bound_base_reseated(struct vec *p, struct vec *q)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
		p = q;
	}
	return i;
}

unsigned mismatched_member_rank(struct vec *tested, struct vec *changed)
{
	while (tested->n) { /* totality-expect */
		changed->n--;
	}
	return tested->n;
}

unsigned wrapping_pointer_step(const unsigned char *p, unsigned step)
{
	while (*p) { /* totality-expect */
		p += step + 1;
	}
	return *p;
}

unsigned narrow_sentinel_index_wrap(const unsigned char *p)
{
	unsigned char i = 0;
	while (p[i]) { /* totality-expect */
		i++;
	}
	return i;
}

unsigned narrow_sentinel_direct_mutation(unsigned char *p)
{
	unsigned char i = 0;
	while (p[i]) { /* totality-expect */
		/* With an initially valid 256-byte string whose last byte is NUL,
		 * this erases the terminator before it is observed. */
		p[255] = 1;
		i++;
	}
	return i;
}

unsigned narrow_sentinel_alias_mutation(unsigned char *p)
{
	unsigned char *alias = p;
	unsigned char i = 0;
	while (p[i]) { /* totality-expect */
		alias[255] = 1;
		i++;
	}
	return i;
}

void mutate_sentinel(unsigned char *p);

unsigned narrow_sentinel_call_mutation(unsigned char *p)
{
	unsigned char i = 0;
	while (p[i]) { /* totality-expect */
		mutate_sentinel(p);
		i++;
	}
	return i;
}

int impure_byte_predicate(int);
int pure_byte_predicate(int) __attribute__((pure));

const unsigned char *sentinel_through_impure_predicate(
	const unsigned char *p)
{
	while (impure_byte_predicate(*p)) { /* totality-expect */
		p++;
	}
	return p;
}

unsigned pure_predicate_without_object_rank(unsigned i)
{
	while (pure_byte_predicate((int)i)) { /* totality-expect */
		i++;
	}
	return i;
}

unsigned char narrow_sentinel_through_pure_predicate(
	const unsigned char *p)
{
	unsigned char i = 0;
	while (pure_byte_predicate(p[i])) { /* totality-expect */
		i++;
	}
	return i;
}

__SIZE_TYPE__ skipping_sentinel_through_pure_predicate(
	const unsigned char *p)
{
	__SIZE_TYPE__ i = 0;
	while (pure_byte_predicate(p[i])) { /* totality-expect */
		i += 2;
	}
	return i;
}

__SIZE_TYPE__ pure_argument_resets_rank(const unsigned char *p)
{
	__SIZE_TYPE__ i = 0;
	while (pure_byte_predicate(p[i = 0])) { /* totality-expect */
		i++;
	}
	return i;
}

const unsigned char *pure_sentinel_rank_reset(const unsigned char *p,
	const unsigned char *start)
{
	while (pure_byte_predicate(*p)) { /* totality-expect */
		p++;
		p = start;
	}
	return p;
}

const unsigned char *pure_sentinel_continue_without_progress(
	const unsigned char *p, int skip)
{
	while (pure_byte_predicate(*p)) { /* totality-expect */
		if (skip) continue;
		p++;
	}
	return p;
}

unsigned narrow_unsigned_strict_bound(unsigned long n)
{
	unsigned char i = 0;
	while (i < n) { /* totality-expect */
		i++;
	}
	return i;
}

unsigned aliased_dereferenced_bound(unsigned *bound, unsigned *alias)
{
	unsigned i = 0;
	while (i < *bound) { /* totality-expect */
		i++;
		(*alias)++;
	}
	return i;
}

unsigned volatile_dereferenced_bound(volatile unsigned *bound)
{
	unsigned i = 0;
	while (i < *bound) { /* totality-expect */
		i++;
	}
	return i;
}

unsigned volatile_member_rank(volatile struct vec *p)
{
	while (p->n) { /* totality-expect */
		p->n--;
	}
	return p->n;
}

unsigned volatile_member_base(struct vec * volatile p)
{
	while (p->n) { /* totality-expect */
		p->n--;
	}
	return p->n;
}

unsigned volatile_member_bound(volatile struct vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
	}
	return i;
}

void opaque_mutation(void);
int opaque_predicate(void);

int signed_division_fixed_point(int n)
{
	while (n > -100) { /* totality-expect */
		n /= 10;
	}
	return n;
}

unsigned division_zero_fixed_point(unsigned n, const unsigned char *table)
{
	while (table[n]) { /* totality-expect */
		n /= 2;
	}
	return n;
}

unsigned shift_zero_fixed_point(unsigned n, const unsigned char *table)
{
	while (table[n]) { /* totality-expect */
		n >>= 1;
	}
	return n;
}

unsigned member_bound_across_opaque_call(struct vec *p)
{
	unsigned i;
	for (i = 0; i < p->n; i++) {
		opaque_mutation();
	}
	return i;
}

unsigned member_rank_across_opaque_call(struct vec *p)
{
	while (p->n) { /* totality-expect */
		opaque_mutation();
		p->n--;
	}
	return p->n;
}

unsigned member_rank_call_before_continue(struct vec *p, int call)
{
	while (p->n) { /* totality-expect */
		p->n--;
		if (call) {
			opaque_mutation();
			continue;
		}
	}
	return p->n;
}

unsigned member_decrement_before_guard(struct vec *p)
{
	for (;;) { /* totality-expect */
		p->n--;
		if (p->n == 0) return p->n;
	}
}

unsigned member_guard_bypassed(struct vec *p, int bypass)
{
	for (;;) { /* totality-expect */
		if (bypass) continue;
		if (p->n == 0) return p->n;
		p->n--;
	}
}

unsigned member_guard_without_progress(struct vec *p, int skip)
{
	for (;;) { /* totality-expect */
		if (p->n == 0) return p->n;
		if (skip) continue;
		p->n--;
	}
}

int signed_nonunit_after_zero_guard(int n)
{
	/* Even values reach zero.  Odd values have only a finite defined prefix
	 * before signed UB; Spacer proves that no defined backedge cycle exists. */
	for (;;) {
		if (n == 0) return n;
		n -= 2;
	}
}

int dynamic_countdown_allows_zero(int n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step > n) return n;
		n -= step;
	}
	return n;
}

unsigned paired_rank_can_stall(unsigned a, unsigned a_end, unsigned b,
	unsigned b_end, int choose, int stuck)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else if (stuck)
			continue;
		else
			b++;
	}
	return a + b;
}

unsigned paired_rank_can_retreat(unsigned a, unsigned a_end, unsigned b,
	unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else {
			b++;
			a--;
		}
	}
	return a + b;
}

unsigned paired_rank_can_wrap_one_component(unsigned a, unsigned a_end,
	unsigned b, unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose) {
			a++;
			a++;
		} else {
			b++;
		}
	}
	return a + b;
}

static void paired_rank_sink(unsigned value)
{
	(void)value;
}

unsigned paired_rank_nested_repeated_progress(unsigned a, unsigned a_end,
	unsigned b, unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			paired_rank_sink((a++, a++));
		else
			b++;
	}
	return a + b;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunevaluated-expression"
unsigned paired_rank_unevaluated_progress(unsigned a, unsigned a_end,
	unsigned b, unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			(void)sizeof(a++);
		else
			b++;
	}
	return a + b;
}
#pragma clang diagnostic pop

unsigned paired_rank_builtin_unevaluated_progress(unsigned a,
	unsigned a_end, unsigned b, unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			(void)__builtin_constant_p(a++);
		else
			b++;
	}
	return a + b;
}

unsigned paired_rank_condition_resets_component(unsigned a, unsigned a_end,
	unsigned b, unsigned b_end, int choose)
{
	unsigned *alias = &a;
	while (a < a_end && b < b_end && ((*alias = 0), 1)) { /* totality-expect */
		if (choose)
			a++;
		else
			b++;
	}
	return a + b;
}

unsigned paired_rank_transitive_alias_reset(unsigned a, unsigned a_end,
	unsigned b, unsigned b_end, int choose)
{
	unsigned *alias = &a;
	unsigned **indirect = &alias;
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else
			b++;
		**indirect = 0;
	}
	return a + b;
}

unsigned paired_rank_disjunctive_bound(unsigned a, unsigned a_end,
	unsigned b, unsigned b_end, int choose)
{
	while (a < a_end || b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else
			b++;
	}
	return a + b;
}

unsigned paired_rank_affine_wrap(unsigned char a, unsigned char a_end,
	unsigned char b, unsigned char b_end, int choose)
{
	int offset = -1;
	while (a + offset < a_end && b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else
			b++;
	}
	return (unsigned)a + b;
}

unsigned paired_rank_mutable_bound(unsigned a, unsigned a_end, unsigned b,
	unsigned b_end, int choose)
{
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose) {
			a++;
			a_end++;
		} else {
			b++;
		}
	}
	return a + b;
}

static unsigned paired_global_end;
static unsigned *paired_global_end_alias = &paired_global_end;

unsigned paired_rank_global_bound_alias(unsigned a, unsigned b,
	unsigned b_end, int choose)
{
	while (a < paired_global_end && b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else
			b++;
		*paired_global_end_alias = a + 1;
	}
	return a + b;
}

unsigned paired_rank_local_bound_transitive_alias(unsigned a,
	unsigned a_end, unsigned b, unsigned b_end, int choose)
{
	unsigned *alias = &a_end;
	unsigned **indirect = &alias;
	while (a < a_end && b < b_end) { /* totality-expect */
		if (choose)
			a++;
		else
			b++;
		**indirect = a + 1;
	}
	return a + b;
}

int dynamic_countdown_allows_negative(int n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step == 0 || step > n) return n;
		n -= step;
	}
	return n;
}

int dynamic_countdown_allows_oversize(int n)
{
	while (n > 0) {
		int step = opaque_predicate();
		if (step <= 0) return n;
		n -= step;
	}
	return n;
}

int dynamic_countdown_missing_branch(int n, int skip)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step <= 0 || step > n) return n;
		if (skip) continue;
		n -= step;
	}
	return n;
}

int dynamic_countdown_conditional_update(int n, int update)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step <= 0 || step > n) return n;
		if (update) n -= step;
	}
	return n;
}

void opaque_rank_mutation(int *n);

int transition_ir_havoc_can_bypass_progress(int n)
{
	while (n > 0) { /* totality-expect */
		int transient = opaque_predicate();
		if (transient)
			n--;
	}
	return n;
}

unsigned char literal_promoted_uint8_cycle(unsigned char value)
{
	for (;;) { /* totality-expect */
		value++;
	}
}

unsigned char literal_toggle_cycle(unsigned char value)
{
	while (value < 2) { /* totality-expect */
		value = 1 - value;
	}
	return value;
}

unsigned char literal_havoc_cycle(unsigned char value)
{
	while (value != 0) { /* totality-expect */
		if (opaque_predicate())
			value = 0;
	}
	return value;
}

int literal_const_choice(void) __attribute__((const));

unsigned char literal_havoced_return(unsigned char value)
{
	while (value != 0) { /* totality-expect */
		value = (unsigned char)literal_const_choice();
	}
	return value;
}

unsigned _BitInt(2)
literal_nondeterministic_cycle(unsigned _BitInt(2) value,
	unsigned _BitInt(1) stay)
{
	while (value != 3) { /* totality-expect */
		if (stay)
			continue;
		value++;
	}
	return value;
}

unsigned short literal_cap_rejection(unsigned short value)
{
	while (value != 0) { /* totality-expect */
		if (value == 1)
			value = 2;
		else if (value == 2)
			value = 3;
		else
			value = 0;
	}
	return value;
}

signed char literal_signed_narrowing_cycle(signed char value)
{
	while (value != 0) { /* totality-expect */
		value = (signed char)(value + 128);
	}
	return value;
}

__UINT32_TYPE__ spacer_toggle_cycle_u32(__UINT32_TYPE__ value)
{
	while (value < 2) { /* totality-expect */
		value = 1 - value;
	}
	return value;
}

__UINT32_TYPE__ spacer_modular_cycle_u32(__UINT32_TYPE__ value)
{
	for (;;) { /* totality-expect */
		value++;
	}
}

__UINT32_TYPE__ spacer_nondeterministic_cycle_u32(
	__UINT32_TYPE__ value, unsigned _BitInt(1) stay)
{
	while (value != 0) { /* totality-expect */
		if (stay)
			continue;
		value = 0;
	}
	return value;
}

__UINT32_TYPE__ spacer_projected_memory_state_rejected(
	__UINT32_TYPE__ value, const unsigned *choice)
{
	while (value != 0) { /* totality-expect */
		if (*choice)
			value = 0;
	}
	return value;
}

unsigned spacer_unsupported_call_rejected(unsigned value)
{
	while (value != 0) { /* totality-expect */
		if (opaque_predicate())
			value = 0;
	}
	return value;
}

int dynamic_countdown_escaped_rank(int n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step <= 0 || step > n) return n;
		opaque_rank_mutation(&n);
		n -= step;
	}
	return n;
}

unsigned dynamic_cast_without_positive_guard(unsigned n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if ((unsigned)step > n) return n;
		n -= (unsigned)step;
	}
	return n;
}

unsigned char dynamic_narrowing_cast(unsigned char n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step <= 0 || (unsigned char)step > n) return n;
		n -= (unsigned char)step;
	}
	return n;
}

int dynamic_step_changed_after_guard(int n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step <= 0 || step > n) return n;
		step = opaque_predicate();
		n -= step;
	}
	return n;
}

int dynamic_rank_changed_after_guard(int n)
{
	while (n > 0) { /* totality-expect */
		int step = opaque_predicate();
		if (step <= 0 || step > n) return n;
		n += opaque_predicate();
		n -= step;
	}
	return n;
}

unsigned clamped_countdown_condition_unrelated(unsigned n, int keep)
{
	while (keep) { /* totality-expect */
		unsigned step = n < 32 ? n : 32;
		n -= step;
	}
	return n;
}

int signed_clamped_countdown(int n)
{
	while (n) { /* totality-expect */
		int step = n < 32 ? n : 32;
		n -= step;
	}
	return n;
}

unsigned max_instead_of_min_countdown(unsigned n)
{
	while (n) { /* totality-expect */
		unsigned step = n < 32 ? 32 : n;
		n -= step;
	}
	return n;
}

unsigned mismatched_clamp_countdown(unsigned n)
{
	while (n) { /* totality-expect */
		unsigned step = n < 32 ? n : 16;
		n -= step;
	}
	return n;
}

unsigned zero_clamp_countdown(unsigned n)
{
	while (n) { /* totality-expect */
		unsigned step = n < 1 ? n : 0;
		n -= step;
	}
	return n;
}

unsigned narrowed_clamp_countdown(unsigned n)
{
	while (n) { /* totality-expect */
		unsigned char step = n < 256 ? (unsigned char)n : 255;
		n -= step;
	}
	return n;
}

unsigned mutated_clamp_countdown(unsigned n, int change)
{
	while (n) { /* totality-expect */
		unsigned step = n < 32 ? n : 32;
		if (change) step = 0;
		n -= step;
	}
	return n;
}

unsigned bypassed_clamp_countdown(unsigned n, int skip)
{
	while (n) { /* totality-expect */
		unsigned step = n < 32 ? n : 32;
		if (skip) continue;
		n -= step;
	}
	return n;
}

void mutate_unsigned_rank(unsigned *n);

unsigned aliased_clamp_countdown(unsigned n)
{
	while (n) { /* totality-expect */
		unsigned step = n < 32 ? n : 32;
		mutate_unsigned_rank(&n);
		n -= step;
	}
	return n;
}

unsigned aliased_clamp_step(unsigned n)
{
	while (n) { /* totality-expect */
		unsigned step = n < 32 ? n : 32;
		mutate_unsigned_rank(&step);
		n -= step;
	}
	return n;
}

unsigned member_zero_branch_can_fall_through(struct vec *p, int stop)
{
	for (;;) { /* totality-expect */
		if (p->n == 0 && stop) return p->n;
		p->n--;
	}
}

struct byte_cursor {
	unsigned char next;
};

unsigned char member_byte_rank_call_before_continue(struct byte_cursor *cursor,
	unsigned char total, int call)
{
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		if (call) {
			opaque_mutation();
			continue;
		}
	}
	return cursor->next;
}

struct restricted_byte_cursor {
	unsigned char next;
};

extern void opaque_cursor_call(struct restricted_byte_cursor *);

unsigned char nonrestricted_member_call_not_receiving_base(
	struct restricted_byte_cursor *cursor, unsigned char total)
{
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		opaque_mutation();
	}
	return cursor->next;
}

unsigned char restricted_member_direct_alias_reset(
	struct restricted_byte_cursor *restrict cursor, unsigned char total)
{
	struct restricted_byte_cursor *alias = cursor;
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		alias->next = 0;
	}
	return cursor->next;
}

unsigned char restricted_member_indirect_alias_reset(
	struct restricted_byte_cursor *restrict cursor, unsigned char total)
{
	struct restricted_byte_cursor *alias = cursor;
	struct restricted_byte_cursor **indirect = &alias;
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		(*indirect)->next = 0;
	}
	return cursor->next;
}

unsigned char restricted_member_call_receives_base(
	struct restricted_byte_cursor *restrict cursor, unsigned char total)
{
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		opaque_cursor_call(cursor);
	}
	return cursor->next;
}

unsigned char restricted_member_call_receives_alias(
	struct restricted_byte_cursor *restrict cursor, unsigned char total)
{
	struct restricted_byte_cursor *alias = cursor;
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		opaque_cursor_call(alias);
	}
	return cursor->next;
}

unsigned char restricted_member_bound_changes(
	struct restricted_byte_cursor *restrict cursor, unsigned char total)
{
	while (cursor->next < total) { /* totality-expect */
		cursor->next++;
		total++;
	}
	return cursor->next;
}

unsigned char restricted_member_can_wrap_at_maximum(
	struct restricted_byte_cursor *restrict cursor, unsigned char total)
{
	while (cursor->next <= total) { /* totality-expect */
		cursor->next++;
		opaque_mutation();
	}
	return cursor->next;
}

unsigned char restricted_member_early_continue(
	struct restricted_byte_cursor *restrict cursor, unsigned char total,
	int skip)
{
	while (cursor->next < total) { /* totality-expect */
		if (skip) continue;
		cursor->next++;
		opaque_mutation();
	}
	return cursor->next;
}

unsigned member_rank_with_condition_call(struct vec *p)
{
	while (p->n && opaque_predicate()) { /* totality-expect */
		p->n--;
	}
	return p->n;
}

static unsigned file_bound = 8;
static unsigned file_remaining = 8;
static unsigned *escaped_bound;

unsigned file_bound_across_opaque_call(void)
{
	unsigned i;
	for (i = 0; i < file_bound; i++) {
		opaque_mutation();
	}
	return i;
}

unsigned file_rank_across_opaque_call(void)
{
	while (file_remaining) { /* totality-expect */
		opaque_mutation();
		file_remaining--;
	}
	return file_remaining;
}

unsigned escaped_scalar_bound_across_opaque_call(unsigned bound)
{
	unsigned i = 0;
	escaped_bound = &bound;
	while (i < bound) { /* totality-expect */
		opaque_mutation();
		i++;
	}
	return i;
}

unsigned char byte_rank_wider_bound(__SIZE_TYPE__ bound)
{
	unsigned char i;
	for (i = 0; i < bound; i++) { /* totality-expect */
	}
	return i;
}

unsigned inclusive_unit_rank_can_wrap(unsigned bound)
{
	unsigned i;
	for (i = 0; i <= bound; i++) { /* totality-expect */
	}
	return i;
}

unsigned inclusive_negative_constant_wraps(void)
{
	unsigned i;
	for (i = 0; i <= -1; i++) { /* totality-expect */
	}
	return i;
}

unsigned inclusive_runtime_signed_bound(int bound)
{
	unsigned i;
	for (i = 0; i <= bound; i++) { /* totality-expect */
	}
	return i;
}

unsigned reversed_inclusive_runtime_signed_bound(int bound)
{
	unsigned i;
	for (i = 0; bound >= i; i++) { /* totality-expect */
	}
	return i;
}

unsigned inclusive_narrow_signed_bound(signed char bound)
{
	unsigned i;
	for (i = 0; i <= bound; i++) { /* totality-expect */
	}
	return i;
}

unsigned repeated_unit_increment(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i++, i++) { /* totality-expect */
	}
	return i;
}

unsigned continuing_rank_reset(unsigned bound, int reset)
{
	unsigned i;
	for (i = 0; i < bound; i++) { /* totality-expect */
		if (reset)
			i = 0;
	}
	return i;
}

void callback_changes_rank(unsigned *rank);

unsigned callback_rank_mutation(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i++) { /* totality-expect */
		callback_changes_rank(&i);
	}
	return i;
}

unsigned reused_rank_in_continuing_inner_loop(unsigned bound, unsigned inner,
	int reuse)
{
	unsigned i;
	for (i = 0; i < bound; i++) { /* totality-expect */
		if (reuse)
			for (i = 0; i < inner; i++) {
			}
	}
	return i;
}

unsigned char byte_rank_mixed_signed_bound(int bound)
{
	unsigned char i;
	for (i = 0; i < bound; i++) { /* totality-expect */
	}
	return i;
}

unsigned short narrow_rank_runtime_wide_bound(unsigned bound)
{
	unsigned short i;
	for (i = 0; i < bound; i++) { /* totality-expect */
	}
	return i;
}

int signed_rank_unsigned_domain(unsigned bound)
{
	int i;
	/* A signed overflow leaves defined C execution, so this pre-existing
	 * signed-rank proof does not need the unsigned same-domain lemma. */
	for (i = 0; i < bound; i++) {
	}
	return i;
}

unsigned nonunit_upper_bound(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 2) { /* totality-expect */
	}
	return i;
}

static unsigned global_unit_rank;

unsigned nonlocal_unit_rank(unsigned bound)
{
	for (global_unit_rank = 0; global_unit_rank < bound; /* totality-expect */
	     global_unit_rank++) {
		opaque_mutation();
	}
	return global_unit_rank;
}

unsigned nested_goto_skips_exit(unsigned bound, unsigned inner, int reuse)
{
	unsigned i;
	for (i = 0; i < bound; i++) { /* totality-expect */
		if (reuse) {
			for (i = 0; i < inner; i++)
				goto keep_going;
			return i;
		}
keep_going:
		;
	}
	return i;
}

unsigned statement_expression_skips_progress(unsigned bound, int reset)
{
	unsigned i;
	for (i = 0; i < bound; i++) { /* totality-expect */
		(void)({
			if (reset) {
				i = 0;
				continue;
			}
			0;
		});
	}
	return i;
}

unsigned interval_one_branch_unchanged(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (left)
			hi = mid;
	}
	return lo;
}

unsigned interval_one_branch_grows(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (left)
			hi = mid;
		else
			lo = mid + 2;
	}
	return lo;
}

unsigned interval_overflowing_midpoint(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = (lo + hi) / 2;
		if (left)
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

void callback_changes_bounds(unsigned *lo, unsigned *hi);

unsigned interval_callback_mutation(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		callback_changes_bounds(&lo, &hi);
		if (left)
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

unsigned interval_alias_reset(unsigned lo, unsigned hi, int left)
{
	unsigned *alias = &lo;
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (left)
			hi = mid;
		else
			lo = mid + 1;
		*alias = 0;
	}
	return lo;
}

unsigned interval_continue_before_update(unsigned lo, unsigned hi, int skip)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (skip)
			continue;
		lo = mid + 1;
	}
	return lo;
}

unsigned interval_goto_skips_update(unsigned lo, unsigned hi, int skip)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (skip)
			goto next;
		lo = mid + 1;
next:
		;
	}
	return lo;
}

unsigned interval_low_can_stall(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (left)
			hi = mid;
		else
			lo = mid;
	}
	return lo;
}

unsigned interval_high_can_stall(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (left)
			hi = mid + 1;
		else
			lo = mid + 1;
	}
	return lo;
}

unsigned interval_midpoint_mutated(unsigned lo, unsigned hi, int left)
{
	while (lo < hi) { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		mid++;
		if (left)
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

unsigned halving_wrong_divisor(unsigned n, int left)
{
	while (n) { /* totality-expect */
		unsigned half = n / 3;
		if (left)
			n = half;
		else
			n -= half + 1;
	}
	return n;
}

unsigned halving_repeated_update(unsigned n, int left)
{
	while (n) { /* totality-expect */
		unsigned half = n / 2;
		if (left)
			n = half;
		else
			n -= half + 1;
		n = half;
	}
	return n;
}

unsigned interval_do_while_first_iteration(unsigned lo, unsigned hi, int left)
{
	do { /* totality-expect */
		unsigned mid = lo + (hi - lo) / 2;
		if (left)
			hi = mid;
		else
			lo = mid + 1;
	} while (lo < hi);
	return lo;
}

void mutate_affine_value(__SIZE_TYPE__ *);

__SIZE_TYPE__ affine_overflow_fixed_point(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i <= n) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ affine_without_half_guard(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ affine_inclusive_half_guard(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i <= n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ affine_do_while_not_pretested(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	do { /* totality-expect */
		child = 2 * i + 1;
		i = child;
	} while (i < n / 2);
	return i;
}

__SIZE_TYPE__ affine_rank_reset(__SIZE_TYPE__ i, __SIZE_TYPE__ n, int reset)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
		if (reset)
			i = 0;
	}
	return i;
}

__SIZE_TYPE__ escaped_affine_rank(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
		mutate_affine_value(&i);
	}
	return i;
}

__SIZE_TYPE__ affine_child_reset(__SIZE_TYPE__ i, __SIZE_TYPE__ n,
	int reset)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		if (reset)
			child = 0;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ escaped_affine_child(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		mutate_affine_value(&child);
		i = child;
	}
	return i;
}

__SIZE_TYPE__ mutable_affine_bound(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
		n++;
	}
	return i;
}

__SIZE_TYPE__ escaped_affine_bound(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
		mutate_affine_value(&n);
	}
	return i;
}

__SIZE_TYPE__ callback_mutates_affine_rank(__SIZE_TYPE__ i,
	__SIZE_TYPE__ n, void (*callback)(__SIZE_TYPE__ *))
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
		callback(&i);
	}
	return i;
}

__SIZE_TYPE__ alternate_affine_multiplier(__SIZE_TYPE__ i,
	__SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 3 * i + 1;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ alternate_affine_addend(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 2;
		i = child;
	}
	return i;
}

unsigned short promoted_affine_type(unsigned short i, unsigned short n)
{
	unsigned short child;
	while (i < n / 2) { /* totality-expect */
		child = (unsigned short)(2 * i + 1);
		i = child;
	}
	return i;
}

__SIZE_TYPE__ repeated_affine_update(__SIZE_TYPE__ i, __SIZE_TYPE__ n)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

long signed_affine_negative_domain(long i, long n)
{
	long child;
	while (i < n / 2) { /* totality-expect */
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

__SIZE_TYPE__ affine_early_continue(__SIZE_TYPE__ i, __SIZE_TYPE__ n,
	int skip)
{
	__SIZE_TYPE__ child;
	while (i < n / 2) { /* totality-expect */
		if (skip)
			continue;
		child = 2 * i + 1;
		i = child;
	}
	return i;
}

unsigned geometric_missing_overflow_guard(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		cap *= 2;
	}
	return cap;
}

unsigned geometric_guard_too_high(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2 + 1)
			return cap;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_reversed_guard(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap <= (unsigned)-1 / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_zero_rank(unsigned need)
{
	unsigned cap = 0;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

int geometric_negative_signed_rank(int need)
{
	int cap = -1;
	while (cap < need) { /* totality-expect */
		if (cap > __INT_MAX__ / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

signed char geometric_narrow_signed_rank(signed char initial,
	signed char need)
{
	signed char cap = initial;
	if (cap < 8)
		cap = 8;
	while (cap < need) { /* totality-expect */
		if (cap > __SCHAR_MAX__ / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

void geometric_change(unsigned *p);

unsigned geometric_bound_callback(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		geometric_change(&need);
		cap *= 2;
	}
	return cap;
}

unsigned geometric_rank_callback(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		geometric_change(&cap);
		cap *= 2;
	}
	return cap;
}

unsigned geometric_bound_reset(unsigned initial, unsigned need, int reset)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		if (reset)
			need = (unsigned)-1;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_rank_reset(unsigned initial, unsigned need, int reset)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		if (reset)
			cap = 1;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_continue_bypass(unsigned initial, unsigned need, int skip)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (skip)
			continue;
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_repeated_doubling(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 2;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_saturating_formula(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		cap = cap > (unsigned)-1 / 2 ? (unsigned)-1 : cap * 2;
	}
	return cap;
}

unsigned geometric_stalling_formula(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 1;
	}
	return cap;
}

unsigned geometric_guard_does_not_exit(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			cap = 1;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_guard_after_doubling(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		cap *= 2;
		if (cap > (unsigned)-1 / 2)
			return cap;
	}
	return cap;
}

unsigned geometric_conditional_doubling(unsigned initial, unsigned need,
	int grow)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		if (grow)
			cap *= 2;
	}
	return cap;
}

unsigned geometric_nested_doubling(unsigned initial, unsigned need, int grow)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		while (grow) /* totality-expect */
			cap *= 2;
	}
	return cap;
}

static unsigned geometric_global_need;

unsigned geometric_global_bound_call(unsigned initial)
{
	unsigned cap = initial ? initial : 8;
	while (cap < geometric_global_need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		opaque_mutation();
		cap *= 2;
	}
	return cap;
}

unsigned geometric_do_while(unsigned initial, unsigned need)
{
	unsigned cap = initial ? initial : 8;
	do { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 2;
	} while (cap < need);
	return cap;
}

unsigned geometric_truncated_initializer(unsigned initial, unsigned need,
	unsigned long long wide)
{
	unsigned cap = initial ? initial : wide;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_volatile_initializer(volatile unsigned initial,
	unsigned need)
{
	unsigned cap = initial ? initial : 8;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

unsigned geometric_transitive_bound_alias(unsigned initial, unsigned need,
	int reset)
{
	unsigned cap = initial ? initial : 8;
	unsigned *first = &need;
	unsigned *second = first;
	while (cap < need) { /* totality-expect */
		if (cap > (unsigned)-1 / 2)
			return cap;
		if (reset)
			*second = (unsigned)-1;
		cap *= 2;
	}
	return cap;
}

int geometric_mixed_signed_initializer(int initial, int need)
{
	int cap = initial;
	if (cap < (unsigned)-1)
		cap = 8;
	while (cap < need) { /* totality-expect */
		if (cap > __INT_MAX__ / 2)
			return cap;
		cap *= 2;
	}
	return cap;
}

void stride_change(unsigned *value);

unsigned constant_stride_wrap(void)
{
	unsigned i;
	for (i = 0; i < (unsigned)-1; i += 2) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_inclusive(unsigned bound)
{
	unsigned i;
	for (i = 0; i <= bound; i += 3) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_zero(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 0) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_negative(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += -3) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_dynamic(unsigned bound, unsigned stride)
{
	unsigned i;
	for (i = 0; i < bound; i += stride) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_wrong_guard(unsigned bound)
{
	unsigned i;
	for (i = 0; i != bound; i += 3) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_bound_alias(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) { /* totality-expect */
		stride_change(&bound);
	}
	return i;
}

unsigned constant_stride_rank_alias(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) { /* totality-expect */
		stride_change(&i);
	}
	return i;
}

unsigned constant_stride_bound_reset(unsigned bound, int reset)
{
	unsigned i;
	for (i = 0; i < bound; i += 2) { /* totality-expect */
		if (reset)
			bound = (unsigned)-1;
	}
	return i;
}

unsigned constant_stride_continue_bypass(unsigned bound, int skip)
{
	unsigned i = 0;
	while (i < bound) { /* totality-expect */
		if (skip)
			continue;
		i += 3;
	}
	return i;
}

unsigned constant_stride_repeated(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) { /* totality-expect */
		i += 3;
	}
	return i;
}

unsigned constant_stride_nonzero_start(void)
{
	unsigned i;
	for (i = 1; i < (unsigned)-1; i += 3) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_nonpower_product(unsigned source)
{
	unsigned bound = source * 6;
	unsigned i;
	for (i = 0; i < bound; i += 6) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_changed_product(unsigned source, int reset)
{
	unsigned bound = source * 4;
	unsigned i;
	if (reset)
		bound = (unsigned)-1;
	for (i = 0; i < bound; i += 4) { /* totality-expect */
	}
	return i;
}

static unsigned constant_stride_global_bound;

unsigned constant_stride_global_callback(void)
{
	unsigned i;
	for (i = 0; i < constant_stride_global_bound; i += 3) { /* totality-expect */
		opaque_mutation();
	}
	return i;
}

unsigned constant_stride_mixed_bound(unsigned long long bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_wide_step(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += (unsigned long long)3) { /* totality-expect */
	}
	return i;
}

unsigned constant_stride_goto_bypasses_zero(void)
{
	unsigned i = 1;
	goto inside;
	for (i = 0; i < (unsigned)-1; i += 3) { /* totality-expect */
inside:
		;
	}
	return i;
}

unsigned constant_stride_inline_asm(unsigned bound)
{
	unsigned i;
	for (i = 0; i < bound; i += 3) { /* totality-expect */
		__asm__ volatile("" : "+r"(i));
	}
	return i;
}

unsigned constant_stride_case_bypasses_zero(unsigned select)
{
	unsigned i = 1;
	switch (select) {
		for (i = 0; i < (unsigned)-1; i += 3) { /* totality-expect */
		case 1:
			;
		}
	}
	return i;
}

unsigned constant_stride_default_bypasses_zero(unsigned select)
{
	unsigned i = 1;
	switch (select) {
		for (i = 0; i < (unsigned)-1; i += 3) { /* totality-expect */
		default:
			;
		}
	}
	return i;
}

static const char *zero_stride_leaf(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *zero_stride_root(const char *p)
{
	return zero_stride_leaf(p, 0);
}

static const char *mixed_stride_leaf(const char *p, int stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *mixed_stride_root(const char *p, int zero)
{
	mixed_stride_leaf(p, 1);
	return mixed_stride_leaf(p, zero ? 0 : -1);
}

static const char *address_taken_stride_leaf(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *(*address_taken_stride_pointer)(const char *, unsigned) =
	address_taken_stride_leaf;

const char *address_taken_stride_root(const char *p)
{
	return address_taken_stride_leaf(p, 1);
}

const char *address_taken_stride_indirect(const char *p)
{
	return address_taken_stride_pointer(p, 1);
}

const char *external_stride_leaf(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

static const char *missing_stride_calls(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

__SIZE_TYPE__ unevaluated_stride_call(const char *p)
{
	return sizeof(missing_stride_calls(p, 1));
}

static const char *cycle_stride_b(const char *, unsigned);

static const char *cycle_stride_a(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return cycle_stride_b(p, stride); /* totality-expect */
}

static const char *cycle_stride_b(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return cycle_stride_a(p, stride); /* totality-expect */
}

static const char *narrow_stride_leaf(const char *p, unsigned char stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *narrow_stride_root(const char *p)
{
	return narrow_stride_leaf(p, (unsigned char)256);
}

static const char *mutated_stride_leaf(const char *p, unsigned stride)
{
	stride = 0;
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *mutated_stride_root(const char *p)
{
	return mutated_stride_leaf(p, 1);
}

static const char *aliased_stride_leaf(const char *p, unsigned stride)
{
	unsigned *alias = &stride;
	*alias = 0;
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *aliased_stride_root(const char *p)
{
	return aliased_stride_leaf(p, 1);
}

static const char *used_stride_leaf(const char *p, unsigned stride)
	__attribute__((used));

static const char *used_stride_leaf(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *used_stride_root(const char *p)
{
	return used_stride_leaf(p, 1);
}

static const char *alias_attribute_stride_leaf(const char *p,
	unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

extern __typeof__(alias_attribute_stride_leaf) alias_attribute_stride_entry
	__attribute__((alias("alias_attribute_stride_leaf")));

const char *alias_attribute_stride_root(const char *p)
{
	return alias_attribute_stride_leaf(p, 1);
}

static const char *weakref_stride_leaf(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

static __typeof__(weakref_stride_leaf) weakref_stride_entry
	__attribute__((weakref("weakref_stride_leaf")));

const char *weakref_stride_root(const char *p)
{
	return weakref_stride_leaf(p, 1);
}

static const char *asm_stride_leaf(const char *p, unsigned stride)
{
	__asm__("" : "+r"(stride));
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *asm_stride_root(const char *p)
{
	return asm_stride_leaf(p, 1);
}

static const char *narrow_forward_stride_leaf(const char *p,
	unsigned char stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

static const char *narrow_forward_stride_mid(const char *p, unsigned stride)
{
	return narrow_forward_stride_leaf(p, stride);
}

const char *narrow_forward_stride_root(const char *p)
{
	return narrow_forward_stride_mid(p, 1);
}

static const char *narrow_expression_stride_leaf(const char *p,
	unsigned stride)
{
	while (*p) { /* totality-expect */
		p += (unsigned char)stride;
	}
	return p;
}

const char *narrow_expression_stride_root(const char *p)
{
	return narrow_expression_stride_leaf(p, 256);
}

static const char *forward_mutation_leaf(const char *p, unsigned stride)
{
	while (*p) { /* totality-expect */
		p += stride;
	}
	return p;
}

static const char *forward_mutation_mid(const char *p, unsigned stride)
{
	stride = 0;
	return forward_mutation_leaf(p, stride);
}

const char *forward_mutation_root(const char *p)
{
	return forward_mutation_mid(p, 1);
}

static unsigned positive_unsigned_skip_leaf(unsigned limit, unsigned stride)
{
	unsigned i = 0;
	while (i < limit) { /* totality-expect */
		i += stride;
	}
	return i;
}

unsigned positive_unsigned_skip_root(unsigned limit)
{
	return positive_unsigned_skip_leaf(limit, 2);
}

static const char *positive_stride_without_sentinel_leaf(const char *p,
	unsigned stride, int keep_running)
{
	/* Pointer arithmetic itself exhausts the finite source object before it
	 * can cycle, even without a sentinel load. */
	while (keep_running) {
		p += stride;
	}
	return p;
}

const char *positive_stride_without_sentinel_root(const char *p,
	int keep_running)
{
	return positive_stride_without_sentinel_leaf(p, 1, keep_running);
}

int stride_impure_condition(void);

static const char *condition_stride_leaf(const char *p, unsigned stride)
{
	while (stride_impure_condition() && *p) { /* totality-expect */
		p += stride;
	}
	return p;
}

const char *condition_stride_root(const char *p)
{
	return condition_stride_leaf(p, 1);
}

static const char *goto_stride_leaf(const char *p, unsigned stride, int skip)
{
	while (*p) { /* totality-expect */
		if (skip)
			goto bypass_stride;
		p += stride;
bypass_stride:
		skip = !skip;
	}
	return p;
}

const char *goto_stride_root(const char *p, int skip)
{
	return goto_stride_leaf(p, 1, skip);
}

static const char *switch_stride_leaf(const char *p, unsigned stride, int arm)
{
	while (*p) { /* totality-expect */
		switch (arm) {
		case 1:
			p += stride;
		}
	}
	return p;
}

const char *switch_stride_root(const char *p, int arm)
{
	return switch_stride_leaf(p, sizeof(char), arm);
}

static int inferred_writer(unsigned *rank)
{
	*rank = 0;
	return 1;
}

unsigned inferred_writer_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_writer(&i)) { /* totality-expect */
		i++;
	}
	return i;
}

static int inferred_alias_writer(unsigned *rank)
{
	unsigned *alias = rank;
	*alias = 0;
	return 1;
}

unsigned inferred_alias_writer_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_alias_writer(&i)) { /* totality-expect */
		i++;
	}
	return i;
}

static unsigned inferred_global;

static int inferred_global_writer(void)
{
	inferred_global++;
	return 1;
}

unsigned inferred_global_writer_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_global_writer()) { /* totality-expect */
		i++;
	}
	return i;
}

static volatile unsigned inferred_volatile;

static int inferred_volatile_reader(void)
{
	return inferred_volatile != 0;
}

unsigned inferred_volatile_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_volatile_reader()) { /* totality-expect */
		i++;
	}
	return i;
}

static int inferred_asm_reader(unsigned value)
{
	__asm__ volatile("" : "+r"(value));
	return value != 0;
}

unsigned inferred_asm_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_asm_reader(i)) { /* totality-expect */
		i++;
	}
	return i;
}

int inferred_unknown_reader(unsigned);

unsigned inferred_unknown_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_unknown_reader(i)) { /* totality-expect */
		i++;
	}
	return i;
}

static int (*inferred_callback)(unsigned);

static int inferred_indirect_reader(unsigned value)
{
	return inferred_callback(value);
}

unsigned inferred_indirect_condition(unsigned n)
{
	unsigned i = 0;
	while (i < n && inferred_indirect_reader(i)) { /* totality-expect */
		i++;
	}
	return i;
}

struct unsafe_pointer_member_cursor {
	const char *p;
};

extern void mutate_pointer_member(void);

const char *pointer_member_unknown_call(
	struct unsafe_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running) { /* totality-expect */
		cursor->p++;
		mutate_pointer_member();
	}
	return cursor->p;
}

static void (*pointer_member_callback)(void);

const char *pointer_member_indirect_call(
	struct unsafe_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running) { /* totality-expect */
		cursor->p++;
		pointer_member_callback();
	}
	return cursor->p;
}

const char *pointer_member_copied_base_backtrack(
	struct unsafe_pointer_member_cursor *cursor, int keep_running)
{
	struct unsafe_pointer_member_cursor *alias = cursor;
	while (keep_running) { /* totality-expect */
		cursor->p++;
		alias->p--;
	}
	return cursor->p;
}

const char *pointer_member_copied_base_reset(
	struct unsafe_pointer_member_cursor *cursor, const char *start,
	int keep_running)
{
	struct unsafe_pointer_member_cursor *alias = cursor;
	while (keep_running) { /* totality-expect */
		cursor->p++;
		alias->p = start;
	}
	return cursor->p;
}

const char *pointer_member_direct_backtrack(
	struct unsafe_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running) { /* totality-expect */
		cursor->p++;
		cursor->p--;
	}
	return cursor->p;
}

const char *pointer_member_base_switch(
	struct unsafe_pointer_member_cursor *cursor,
	struct unsafe_pointer_member_cursor *other, int keep_running)
{
	while (keep_running) { /* totality-expect */
		cursor->p++;
		cursor = other;
	}
	return cursor->p;
}

const char *pointer_member_early_continue(
	struct unsafe_pointer_member_cursor *cursor, int keep_running, int skip)
{
	while (keep_running) { /* totality-expect */
		if (skip) continue;
		cursor->p++;
	}
	return cursor->p;
}

const char *pointer_member_alternating_backedges(
	struct unsafe_pointer_member_cursor *cursor, int keep_running, int reverse)
{
	while (keep_running) { /* totality-expect */
		if (reverse) cursor->p--;
		else cursor->p++;
	}
	return cursor->p;
}

const char *pointer_member_asm_mutation(
	struct unsafe_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running) { /* totality-expect */
		cursor->p++;
		__asm__ volatile("" : "+r"(cursor->p));
	}
	return cursor->p;
}

struct volatile_pointer_member_cursor {
	const char *volatile p;
};

const char *pointer_member_volatile(
	struct volatile_pointer_member_cursor *cursor, int keep_running)
{
	while (keep_running) { /* totality-expect */
		cursor->p++;
	}
	return cursor->p;
}

const char *integer_reconstituted_pointer(const char *p, int keep_running)
{
	while (keep_running) { /* totality-expect */
		p = (const char *)((__UINTPTR_TYPE__)p + 1);
	}
	return p;
}

const char *local_pointer_net_zero(const char *p, int keep_running)
{
	while (keep_running) { /* totality-expect */
		p++;
		p--;
	}
	return p;
}

const char *local_pointer_dynamic_cancellation(const char *p, int step,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		p++;
		p += step;
	}
	return p;
}

unsigned scalar_dynamic_then_unit_wrap(unsigned i, unsigned step,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		i += step;
		i++;
	}
	return i;
}

const char *unguarded_unsigned_pointer_step(const char *p, unsigned step,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		p += used;
	}
	return p;
}

const char *late_guarded_unsigned_pointer_step(const char *p, unsigned step,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		p += used;
		if (!used) break;
	}
	return p;
}

const char *continuing_zero_unsigned_pointer_step(const char *p,
	unsigned step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		if (!used) continue;
		p += used;
	}
	return p;
}

const char *mutated_guarded_unsigned_pointer_step(const char *p,
	unsigned step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		if (!used) break;
		used = 0;
		p += used;
	}
	return p;
}

extern void mutate_guarded_step(unsigned *);

const char *aliased_guarded_unsigned_pointer_step(const char *p,
	unsigned step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		if (!used) break;
		mutate_guarded_step(&used);
		p += used;
	}
	return p;
}

const char *bypassed_guarded_unsigned_pointer_step(const char *p,
	unsigned step, int keep_running, int skip)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		if (skip) continue;
		if (!used) break;
		p += used;
	}
	return p;
}

const char *cancelled_guarded_unsigned_pointer_ascent(const char *p,
	unsigned step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		if (!used) break;
		p += used;
		p -= used;
	}
	return p;
}

const char *cancelled_guarded_unsigned_pointer_descent(const char *p,
	unsigned step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		unsigned used = step;
		if (!used) break;
		p -= used;
		p += used;
	}
	return p;
}

const char *signed_guarded_pointer_step(const char *p, int step,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		int used = step;
		if (!used) break;
		p += used;
	}
	return p;
}

unsigned goto_internal_label_bypasses_countdown(unsigned n, int skip)
{
	while (n > 0) { /* totality-expect */
		if (skip) goto again;
		n--;
	again:
		;
	}
	return n;
}

unsigned goto_backward_label_bypasses_countdown(unsigned n, int skip)
{
again:
	while (n > 0) { /* totality-expect */
		if (skip) goto again;
		n--;
	}
	return n;
}

unsigned goto_forward_then_reenters_countdown(unsigned n, int fail,
	int repeat)
{
again:
	while (n > 0) { /* totality-expect */
		if (fail) goto out;
		n--;
	}
out:
	if (repeat) goto again;
	return n;
}

unsigned indirect_goto_bypasses_countdown(unsigned n, int skip)
{
	void *target = &&out;
	while (n > 0) { /* totality-expect */
		if (skip) goto *target;
		n--;
	}
out:
	return n;
}

const char *local_pointer_copied_dynamic_cancellation(const char *p,
	int step, int keep_running)
{
	int copy = step;
	while (keep_running) { /* totality-expect */
		p++;
		p += copy;
	}
	return p;
}

const char *local_pointer_dynamic_descent_cancellation(const char *p,
	int step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		p--;
		p -= step;
	}
	return p;
}

const char *local_pointer_literal_cancellation(const char *p,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		p++;
		p += -1;
	}
	return p;
}

const char *local_pointer_alternating(const char *p, int keep_running,
	int reverse)
{
	while (keep_running) { /* totality-expect */
		if (reverse) p--;
		else p++;
	}
	return p;
}

const char *local_pointer_object_switch(const char *p, const char *other,
	int keep_running, int switch_object)
{
	while (keep_running) { /* totality-expect */
		p++;
		if (switch_object) p = other;
	}
	return p;
}

const char *pointer_member_condition_alias_reset(
	struct unsafe_pointer_member_cursor *cursor, const char *start)
{
	struct unsafe_pointer_member_cursor *alias = cursor;
	while ((alias->p = start), *cursor->p) { /* totality-expect */
		cursor->p++;
	}
	return cursor->p;
}

const char *local_pointer_condition_reset(const char *p, const char *start,
	int keep_running)
{
	while ((p = start), keep_running) { /* totality-expect */
		p++;
	}
	return p;
}

const char *switch_case_without_progress(const char *p, int arm)
{
	while (*p) { /* totality-expect */
		switch (arm) {
		case 0:
			p++;
			break;
		case 1:
			break;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_continue_without_progress(const char *p, int arm)
{
	while (*p) { /* totality-expect */
		switch (arm) {
		case 0:
			p++;
			break;
		case 1:
			continue;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_fallthrough_bypasses_progress(const char *p, int arm)
{
	while (*p) { /* totality-expect */
		switch (arm) {
		case 0:
			p++;
		case 1:
			break;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_empty_sentinel_then_reset(const char *p,
	const char *start, int arm)
{
	while (*p) { /* totality-expect */
		switch (arm) {
		case 0:
			p++;
			break;
		case 1:
			p = (const char *)"";
			p = start;
			break;
		default:
			return p;
		}
	}
	return p;
}

const char *switch_empty_not_terminating_or(const char *p, int keep,
	int arm)
{
	while (*p || keep) { /* totality-expect */
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

const char *switch_empty_wrong_polarity(const char *p, int arm)
{
	while (!*p) { /* totality-expect */
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

const char *switch_nested_case_bypass(const char *p, int arm, int guard)
{
	while (*p) { /* totality-expect */
		switch (arm) {
		case 0:
			if (guard) {
				p++;
		case 1:
				break;
			}
			break;
		default:
			return p;
		}
	}
	return p;
}

unsigned switch_repeated_unsigned_progress(unsigned i, unsigned limit,
	int arm)
{
	while (i < limit) { /* totality-expect */
		switch (arm) {
		case 0:
			i++;
			i++;
			break;
		default:
			return i;
		}
	}
	return i;
}

unsigned unsigned_body_wrap(unsigned i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i++;
	}
	return i;
}

signed char promoted_signed_char_wrap(signed char i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i++;
	}
	return i;
}

short promoted_signed_short_wrap(short i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i += 3;
	}
	return i;
}

struct narrow_signed_bitfield {
	int value : 2;
};

int promoted_signed_bitfield_wrap(struct narrow_signed_bitfield *p,
	int keep_running)
{
	while (keep_running) { /* totality-expect */
		p->value++;
	}
	return p->value;
}

int signed_unsigned_compound_cycle(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i += 2147483648u;
	}
	return i;
}

int signed_unsigned_unit_compound_cycle(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i += 1u;
	}
	return i;
}

int signed_unsigned_assignment_cycle(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i = i + 2147483648u;
	}
	return i;
}

int signed_unsigned_unit_assignment_cycle(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i = i + 1u;
	}
	return i;
}

int signed_unary_then_unsigned_cycle(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i++;
		i += 1u;
	}
	return i;
}

int signed_body_unsigned_increment_cycle(int i, int keep_running)
{
	for (; keep_running; i += 1u) { /* totality-expect */
		i++;
	}
	return i;
}

enum unsigned_step_constant {
	UNSIGNED_STEP = 2147483648u
};

int signed_unsigned_enum_cycle(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i += UNSIGNED_STEP;
	}
	return i;
}

int signed_body_dynamic_step(int i, int step, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i += step;
	}
	return i;
}

int signed_body_reset(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i++;
		i = 0;
	}
	return i;
}

int signed_body_alternating(int i, int reverse, int keep_running)
{
	while (keep_running) { /* totality-expect */
		if (reverse) i--;
		else i++;
	}
	return i;
}

int signed_body_early_continue(int i, int skip, int keep_running)
{
	while (keep_running) { /* totality-expect */
		if (skip) continue;
		i++;
	}
	return i;
}

int signed_body_condition_reset(int i, int keep_running)
{
	while ((i = 0), keep_running) { /* totality-expect */
		i++;
	}
	return i;
}

int signed_body_asm(int i, int keep_running)
{
	while (keep_running) { /* totality-expect */
		i++;
		__asm__ volatile("" : "+r"(i));
	}
	return i;
}

long write(int, const void *, __SIZE_TYPE__);
long write_without_contract(int, const void *, __SIZE_TYPE__);

__SIZE_TYPE__ z3_unbounded_result_can_wrap(int fd, const char *buf,
	__SIZE_TYPE__ len)
{
	__SIZE_TYPE__ off = 0;
	while (off < len) { /* totality-expect */
		long written = write_without_contract(fd, buf + off, len - off);
		if (written <= 0) return off;
		off += (__SIZE_TYPE__)written;
	}
	return off;
}

__SIZE_TYPE__ z3_progress_bypass(int fd, const char *buf,
	__SIZE_TYPE__ len, int bypass)
{
	__SIZE_TYPE__ off = 0;
	while (off < len) { /* totality-expect */
		long written = write(fd, buf + off, len - off);
		if (written <= 0) return off;
		if (bypass) continue;
		off += (__SIZE_TYPE__)written;
	}
	return off;
}

__SIZE_TYPE__ z3_progress_cancelled(int fd, const char *buf,
	__SIZE_TYPE__ len)
{
	__SIZE_TYPE__ off = 0;
	while (off < len) { /* totality-expect */
		long written = write(fd, buf + off, len - off);
		if (written <= 0) return off;
		off += (__SIZE_TYPE__)written;
		off -= (__SIZE_TYPE__)written;
	}
	return off;
}

unsigned z3_unsupported_sort_is_unproved(unsigned i, double limit)
{
	while ((double)i < limit) { /* totality-expect */
		i++;
	}
	return i;
}

/* Soundness regressions for the three general fixes paired with this
 * file's safe.c eval_cursor chain (precedingStatements()'s
 * VarDecl-initializer climb, toleratedPointerReassign(), and always
 * tolerating a recognized forward-or-unchanged write even with no
 * witness in hand -- see fieldProgressRelation()'s own comment). None
 * of the three is a witness by itself; each one must still leave a
 * call genuinely lacking any real advance exactly as unproved as
 * before. */
long strtol(const char *, char **
	__attribute__((annotate("qual:endptr_advances"))), int);

/* The precedingStatements() VarDecl-initializer climb now finds
 * "int r = eval_declare_and_call_no_advance(ev);"'s enclosing
 * DeclStmt -- but there is no dominating advance anywhere in this
 * function for it to find there, so the climb fixing precedingStatements()
 * must not, by itself, manufacture a witness out of nothing. */
struct eval_cursor_no_advance {
	const char *p;
};

static int eval_declare_and_call_no_advance(struct eval_cursor_no_advance *ev)
{
	if (*ev->p == '(') {
		int r = eval_declare_and_call_no_advance(ev); /* totality-expect */
		return r;
	}
	return 0;
}

/* Same establishing-call shape as safe.c's eval_primary() digit branch,
 * but the value committed into mine->p was read from a DIFFERENT
 * cursor's own field (other->p), not mine->p's own current value --
 * toleratedPointerReassign() requires the establishing call's first
 * argument to read exactly Base->Field, precisely so a value with no
 * relationship to the field actually being reassigned cannot be
 * laundered as a safe advance just by sitting next to a real
 * endptr_advances call. */
struct eval_cursor_pair {
	const char *p;
};

static int eval_swapped_endptr(struct eval_cursor_pair *mine,
	struct eval_cursor_pair *other)
{
	char *end;
	long v = strtol(other->p, &end, 0);
	mine->p = end;
	if (v)
		return eval_swapped_endptr(mine, other); /* totality-expect */
	return 0;
}

/* toleratedPointerReassign() is deliberately never itself a witness (the
 * standard leaves *endptr == the input pointer, unchanged, on a
 * completely failed conversion) -- a function whose ONLY field write
 * anywhere is this idiom, with no other dominating advance, must stay
 * unproved even though nothing here is adversarial either. */
struct eval_cursor_only_endptr {
	const char *p;
};

static int eval_only_endptr(struct eval_cursor_only_endptr *ev)
{
	char *end;
	long v = strtol(ev->p, &end, 0);
	ev->p = end;
	if (v)
		return eval_only_endptr(ev); /* totality-expect */
	return 0;
}
