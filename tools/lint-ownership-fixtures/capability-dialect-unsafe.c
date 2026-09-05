/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "capability-dialect-fixture.h"

void macro_lock_without_token(void)
{
	dialect_mutex_t mutex;
	dialect_mutex_lock(&mutex); /* ownership-expect: dialect-capability-missing */
}

void use_string_without_evidence(void)
{
	char text[8];
	dialect_use_string(text); /* ownership-expect: dialect-string-missing */
}

void uncontracted_elements_are_not_evidence(int count, char **values)
	__attribute__((nonnull(2)))
{
	if (count > 0)
		dialect_use_string(values[0]); /* ownership-expect: uncontracted-element */
}

void out_of_range_element_is_not_evidence(
	int count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)))
{
	dialect_use_string(values[count]); /* ownership-expect: element-at-extent */
}

void negative_element_is_not_evidence(
	int count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)))
{
	if (count > 0)
		dialect_use_string(values[-1]); /* ownership-expect: negative-element */
}

void rebound_aggregate_is_not_evidence(
	int count,
	char **values elements_withtok(dialect_terminated, count), char **other)
	__attribute__((nonnull(2)))
{
	values = other;
	if (count > 0)
		dialect_use_string(values[0]); /* ownership-expect: rebound-aggregate */
}

void written_element_is_not_evidence(
	int count,
	char **values elements_withtok(dialect_terminated, count), char *other)
	__attribute__((nonnull(2)))
{
	if (count <= 0)
		return;
	values[0] = other;
	dialect_use_string(values[0]); /* ownership-expect: written-element */
}

void alias_written_element_is_not_evidence(
	int count,
	char **values elements_withtok(dialect_terminated, count), char *other)
	__attribute__((nonnull(2)))
{
	char **alias = values;

	if (count <= 0)
		return;
	alias[0] = other;
	dialect_use_string(values[0]); /* ownership-expect: alias-written-element */
}

void unknown_mutate_vector(char **values);

void unknown_mutable_call_havocs_elements(
	int count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)))
{
	if (count <= 0)
		return;
	unknown_mutate_vector(values);
	dialect_use_string(values[0]); /* ownership-expect: unknown-element-havoc */
}

void converted_index_is_conservatively_unproved(
	int count, unsigned index,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(3)))
{
	if (count > 0 && index < (unsigned)count)
		dialect_use_string(values[index]); /* ownership-expect: converted-element-index */
}

void out_of_range_wide_element_is_not_evidence(
	unsigned long long count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)))
{
	dialect_use_string(values[count]); /* ownership-expect: wide-element-at-extent */
}

/* Same-width, different-signedness twin: "unsigned long long count" vs.
 * a "long long index" -- same 64 bits, but a genuine signedness
 * mismatch the checker's width/signedness comparison must still
 * reject, proving the fix compares BOTH properties, not just width. */
void signedness_mismatched_wide_index_is_not_evidence(
	unsigned long long count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)))
{
	long long i = 0;

	if (count > 0)
		dialect_use_string(values[i]); /* ownership-expect: wide-signedness-mismatch */
}

void use_string_after_invalidation(void)
{
	char text[8];
	dialect_mark_terminated(text);
	dialect_invalidate_string(text);
	dialect_use_string(text); /* ownership-expect: dialect-string-dropped */
}

extern const char *runtime_string;

void mutable_string_literal_table_is_not_evidence(unsigned i)
{
	static const char *table[] = { "first", "second" };

	if (i < sizeof table / sizeof table[0])
		dialect_use_string(table[i]); /* ownership-expect: dialect-mutable-string-table */
}

void mixed_string_literal_table_is_not_evidence(unsigned i)
{
	const char *const table[] = { "literal", runtime_string };

	if (i < sizeof table / sizeof table[0])
		dialect_use_string(table[i]); /* ownership-expect: dialect-mixed-string-table */
}

void partial_string_literal_table_is_not_evidence(unsigned i)
{
	static const char *const table[2] = { "literal" };

	if (i < sizeof table / sizeof table[0])
		dialect_use_string(table[i]); /* ownership-expect: dialect-partial-string-table */
}

void mutable_string_literal_member_table_is_not_evidence(unsigned i)
{
	struct entry { const char *name; int value; };
	static struct entry table[] = { { "first", 1 }, { "second", 2 } };

	if (i < sizeof table / sizeof table[0])
		dialect_use_string(table[i].name); /* ownership-expect: dialect-mutable-string-member-table */
}

void mixed_string_literal_member_table_is_not_evidence(unsigned i)
{
	struct entry { const char *name; int value; };
	const struct entry table[] = {
		{ "literal", 1 }, { runtime_string, 2 }
	};

	if (i < sizeof table / sizeof table[0])
		dialect_use_string(table[i].name); /* ownership-expect: dialect-mixed-string-member-table */
}

void terminated_suffix_does_not_prove_prefix(void)
{
	char text[8];
	dialect_mark_terminated(text + 4);
	dialect_use_string(text); /* ownership-expect: dialect-string-exact-region */
}

void parameterized_token_length_mismatch(void)
{
	char text[8];
	dialect_mark_span(text, 4);
	dialect_use_span(text, 8); /* ownership-expect: dialect-span-length */
}

void relational_token_pointer_mismatch(void)
{
	char left[8], first[8], second[8];
	dialect_mark_disjoint(left, first, sizeof left);
	dialect_use_disjoint(left, second, sizeof left); /* ownership-expect: dialect-span-relation */
}

void dialect_bad_clear_span(
	void *data drop(dialect_span(length)), size_t length)
{
	(void)data;
	(void)length;
} /* ownership-expect: dialect-parameterized-drop-proof */

void dialect_bad_clear_string(char *text drop(dialect_terminated))
{
	(void)text;
} /* ownership-expect: dialect-string-drop-proof */
