/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* Self-contained, like every fixture in this file's sibling
 * lint-*-fixtures directories: spells out the raw annotate() text rather
 * than including ownership.h, so this fixture builds with no extra -I
 * flag under lint.sh's own bare `clang-18 --analyze ... "$fixture"`
 * invocation. */
#define integer_sentinel(value) \
	__attribute__((annotate("qual:integer_sentinel=" #value)))
#define long_sentinel(value) \
	__attribute__((annotate("qual:long_sentinel=" #value)))

integer_sentinel(-1)
long parse_duration(const char *text);

long_sentinel(-1)
long parse_offset(const char *text);

static int not_sentinel(long value)
{
	return value != -1;
}

int guarded_not_equal_cast(const char *text)
{
	long value = parse_duration(text);
	if (value != -1)
		return (int)value;
	return 0;
}

long guarded_range_arithmetic(const char *text)
{
	long value = parse_duration(text);
	if (value >= 0)
		return value + 1;
	return 0;
}

long guarded_via_helper(const char *text)
{
	long value = parse_duration(text);
	if (not_sentinel(value))
		return value * 2;
	return 0;
}

int guarded_index(const char *text, int *table)
{
	long value = parse_duration(text);
	if (value != -1)
		return table[value];
	return 0;
}

long guarded_long_sentinel(const char *text)
{
	long value = parse_offset(text);
	if (value != -1)
		return value - 1;
	return 0;
}

int guarded_parameter(long value integer_sentinel(-1))
{
	if (value != -1)
		return (int)value;
	return 0;
}

long guarded_division(const char *text)
{
	long value = parse_duration(text);
	if (value != -1)
		return 100 / value;
	return 0;
}
