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

int unguarded_cast(const char *text)
{
	long value = parse_duration(text);
	return (int)value; /* integer-sentinel-expect */
}

long unguarded_arithmetic(const char *text)
{
	long value = parse_duration(text);
	return value + 1; /* integer-sentinel-expect */
}

int unguarded_index(const char *text, int *table)
{
	long value = parse_duration(text);
	return table[value]; /* integer-sentinel-expect */
}

long insufficient_guard(const char *text)
{
	long value = parse_duration(text);
	if (value != -2) /* rules out the wrong literal */
		return value * 2; /* integer-sentinel-expect */
	return 0;
}

long unguarded_long_sentinel(const char *text)
{
	long value = parse_offset(text);
	return value - 1; /* integer-sentinel-expect */
}

int unguarded_parameter(long value integer_sentinel(-1))
{
	return (int)value; /* integer-sentinel-expect */
}

long unguarded_division(const char *text)
{
	long value = parse_duration(text);
	return 100 / value; /* integer-sentinel-expect */
}
