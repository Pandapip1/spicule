/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

int fixed_constant(void)
{
	int values[4] = { 1, 2, 3, 4 };
	return values[3];
}

int guarded_unsigned(unsigned int index)
{
	int values[4] = { 1, 2, 3, 4 };
	if (index >= 4)
		return 0;
	return values[index];
}

int guarded_signed(int index)
{
	int values[4] = { 1, 2, 3, 4 };
	if (index < 0 || index >= 4)
		return 0;
	return values[index];
}

int bounded_loop(void)
{
	int values[4] = { 1, 2, 3, 4 };
	int total = 0;
	unsigned int index;
	for (index = 0; index < 4; index++)
		total += values[index];
	return total;
}

/* A plain incoming pointer parameter has no DynamicExtent this checker can
 * ever derive on its own -- the allocation backing it happened somewhere
 * this translation unit cannot see.  elements_withtok(token, extent_param)
 * is the same declared element-count contract include/ownership.h already
 * attaches to every argc/argv-shaped utility entry point; contractElementCount()
 * reads it as a second, independent bound.  This proves what a same-statement
 * "i < argc"-style guard already established in the source, the way
 * src/internal/util.h's real __util_*_main declarations do. */
int argv_style_loop(
	int argc,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	int i;
	int total = 0;
	for (i = 0; i < argc; i++)
		total += (int)(argv[i] != 0);
	return total;
}

/* include/string.h's withtok(null_terminated) -- the same per-parameter
 * trust boundary TotalityChecker.cpp's nullTerminatedParameter() already
 * reads off strlen/wcslen's own declaration -- guarantees s's own extent is
 * at least one element (the terminator, if nothing else), so index 0 needs
 * no guard at all. */
int direct_null_terminated_index_zero(
	const char *s __attribute__((annotate("withtok:null_terminated"))))
{
	return s[0];
}

/* Index 1 is NOT axiomatic the way index 0 is: it is only in bounds once a
 * real, dominating branch has established byte 0 is nonzero. A plain
 * `if (s[0] == 0) return 0;` guard, taken on its false edge, is exactly
 * that branch. */
int direct_null_terminated_guarded_index_one(
	const char *s __attribute__((annotate("withtok:null_terminated"))))
{
	if (s[0] == 0)
		return 0;
	return s[1];
}

/* src/util/m4.c's own real option-parsing idiom (see m4.c's parse of
 * argv[i], `if (a[0] != '-' || a[1] == 0) break;`): `a[1]` is only ever
 * evaluated once the `||`'s left operand `a[0] != '-'` has tested false,
 * i.e. once a[0] == '-' -- a concrete, nonzero byte. This is the exact
 * repeating shape a large fraction of the tree's real array-index findings
 * reduce to. */
int direct_null_terminated_option_style(
	const char *a __attribute__((annotate("withtok:null_terminated"))))
{
	if (a[0] != '-' || a[1] == 0)
		return 0;
	return 1;
}

/* The argv-shaped analog of the two direct cases above: `char *a =
 * argv[i]` where argv carries elements_withtok(null_terminated, argc).
 * POSIX guarantees every argv[i] with i in [0, argc) is itself a valid,
 * finite, null-terminated C string, so the SAME index-0/guarded-index-1
 * reasoning applies to a's own content once i is proven in that range --
 * proven here by the loop guard, the same "i < argc" fact
 * contractElementCount() already proves for the argv[i] subscript itself. */
int argv_content_option_style(
	int argc,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	int i;
	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		if (a[0] != '-' || a[1] == 0)
			break;
	}
	return i;
}

int argv_content_index_zero(
	int argc,
	char **argv __attribute__((annotate("elements_withtok:null_terminated:argc"))))
{
	int i;
	int total = 0;
	for (i = 0; i < argc; i++) {
		char *a = argv[i];
		total += a[0];
	}
	return total;
}
