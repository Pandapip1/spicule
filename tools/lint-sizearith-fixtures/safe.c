/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

typedef __SIZE_TYPE__ size_t;
typedef unsigned short USHORT;
#define __US_MAX_WCHARS ((size_t)32766)
#define USHRT_MAX 65535
void *malloc(size_t);
void *calloc(size_t, size_t);
void *reallocarray(void *, size_t, size_t);
int __size_mul_checked(size_t, size_t, size_t *);
int __array_next_capacity(size_t, size_t, size_t, size_t, size_t, size_t *);

void *checked_allocation(size_t count)
{
	size_t bytes;
	if (!__size_mul_checked(count, sizeof(int), &bytes)) return 0;
	return malloc(bytes);
}

void *counted_reallocation(void *p, size_t count)
{
	return reallocarray(p, count, sizeof(int));
}

void *counted_allocation(size_t count)
{
	return calloc(count, sizeof(int));
}

size_t checked_growth(size_t cap)
{
	size_t next;
	return __array_next_capacity(cap, cap, 1, 8, sizeof(int), &next) ? next : 0;
}

void *fixed_object(void)
{
	int *p;
	return malloc(sizeof *p);
}

size_t proved_growth(size_t cap)
{
	if (cap > (size_t)-1 / 2) { return 0; }
	return cap * 2;
}

const char *noncode_is_ignored(void)
{
	/* malloc(count + 1); cap *= 2; (ULONG)length */
	return "realloc(p, cap * sizeof(int))";
}

USHORT guarded_ushort_narrowing(size_t length)
{
	if (length > 0xffffu) return 0;
	return (USHORT)length;
}

USHORT macro_guarded_ushort_narrowing(size_t length)
{
	if (length > __US_MAX_WCHARS) return 0;
	return (USHORT)length;
}

USHORT limit_guarded_ushort_narrowing(size_t length)
{
	if (length > USHRT_MAX) return 0;
	return (USHORT)length;
}

USHORT decimal_guarded_ushort_narrowing(size_t length)
{
	if (length > 65535) return 0;
	return (USHORT)length;
}

USHORT proved_ushort_narrowing(size_t length)
{
	if (length > 0xffffu) return 0;
	return (USHORT)length;
}

size_t ushort_type_width(void)
{
	return sizeof(USHORT);
}

/* A ternary's '?' and ':' each start a fresh sub-expression: the '*'
 * right after '?' below dereferences out_size (unary), it does not
 * multiply the previous branch's operand (there is no previous
 * branch -- this is the condition itself, but the same shape recurs
 * with a real preceding operand whenever the true-branch also derefs
 * a pointer). Not allocation arithmetic at all. */
void *ternary_dereference_is_not_multiplication(size_t *out_size)
{
	return malloc(*out_size ? *out_size : 1);
}
