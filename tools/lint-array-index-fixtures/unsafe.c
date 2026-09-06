/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

int unguarded_unsigned(unsigned int index)
{
	int values[4] = { 1, 2, 3, 4 };
	return values[index]; /* array-index-expect */
}

int unguarded_signed(int index)
{
	int values[4] = { 1, 2, 3, 4 };
	return values[index]; /* array-index-expect */
}

int off_by_one(unsigned int index)
{
	int values[4] = { 1, 2, 3, 4 };
	if (index > 4)
		return 0;
	return values[index]; /* array-index-expect */
}

int late_guard(unsigned int index)
{
	int values[4] = { 1, 2, 3, 4 };
	int result = values[index]; /* array-index-expect */
	if (index >= 4)
		return 0;
	return result;
}

int negative_only_guard(int index)
{
	int values[4] = { 1, 2, 3, 4 };
	if (index < 0)
		return 0;
	return values[index]; /* array-index-expect */
}

/* An elements_withtok(token, argc) contract bounds argv to argc elements,
 * not argc+1 -- the same off-by-one an unannotated array would still be
 * caught for.  contractElementCount()'s second proof route must reject
 * this exactly as the primary DynamicExtent route already would, proving
 * the new contract-reading path does not loosen what still counts as
 * unproven. */
int argv_off_by_one(
	int argc,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	return (int)(argv[argc] != 0); /* array-index-expect */
}

/* The contract names argc as the bound for argv; an index compared only
 * against an unrelated parameter must stay unproven even though argv now
 * carries a declared element count. */
int argv_unrelated_bound(
	int argc, int limit,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	int i;
	int total = 0;
	for (i = 0; i < limit; i++)
		total += (int)(argv[i] != 0); /* array-index-expect */
	return total;
}

/* A plain, unannotated char* carries no null-terminated contract at all --
 * confirms the new proof route only ever fires off a real, declared
 * withtok(null_terminated)/elements_withtok(null_terminated, ...) fact, and
 * never treats an arbitrary char* as null-terminated just because it looks
 * like one. */
int plain_pointer_index_zero(char *p)
{
	return p[0]; /* array-index-expect */
}

/* withtok(null_terminated) proves s's own extent is at least one element,
 * which is exactly enough for s[0] -- but proves nothing at all about
 * s[1] on its own: a length-0-or-1 string makes this a REAL out-of-bounds
 * read, and it must stay flagged with no guard present. */
int direct_null_terminated_unguarded_index_one(
	const char *s __attribute__((annotate("withtok:null_terminated"))))
{
	return s[1]; /* array-index-expect */
}

/* A branch that exists on the same path, but proves nothing about a[0]'s
 * own value, must not be mistaken for the dominating guard the m4.c-style
 * idiom relies on: this checker must trace the SPECIFIC symbol a branch
 * narrowed, not merely "some branch happened before this subscript". */
int direct_null_terminated_unrelated_guard(
	int flag, const char *a __attribute__((annotate("withtok:null_terminated"))))
{
	if (flag != 0)
		return a[1]; /* array-index-expect */
	return 0;
}

/* argv[argc] is only guaranteed NULL by POSIX, not a valid null-terminated
 * string -- elements_withtok(null_terminated, argc) covers argv[0..argc)
 * only. Trusting a's content here would trust a slot the contract makes no
 * promise about; the SAME "i < argc" reproof the direct argv[i] subscript
 * needs must also gate whether a's OWN content is trusted. */
int argv_content_out_of_bound(
	int argc,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	char *a = argv[argc]; /* array-index-expect */
	return a[0]; /* array-index-expect */
}

/* The argv-shaped analog of direct_null_terminated_unguarded_index_one:
 * proving a's content is null-terminated (via i < argc) says nothing about
 * a[0]'s own value, so a[1] must still be rejected with no guard on it. */
int argv_content_unguarded_index_one(
	int argc,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	int i;
	int total = 0;
	for (i = 0; i < argc; i++) {
		char *a = argv[i];
		total += a[1]; /* array-index-expect */
	}
	return total;
}
