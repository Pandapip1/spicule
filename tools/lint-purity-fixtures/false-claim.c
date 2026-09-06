/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Every function below is wrongly marked __attribute__((pure)) -- each
 * documents one real violation class from the checklist a genuine pure
 * claim has to clear. A wrong pure claim is a real correctness bug: it
 * licenses the compiler to eliminate, reorder, or coalesce calls the
 * program actually depends on. */

#include "../../include/ownership.h"

/* 1. errno. */
int *__errno_location(void);
int bad_errno(int x) __attribute__((pure));
int bad_errno(int x)
{
	if (x < 0) {
		*__errno_location() = 22; /* purity-expect */
		return -1;
	}
	return x;
}

/* 2. write through a pointer argument. */
int bad_pointer_write(int *out, int x) __attribute__((pure));
int bad_pointer_write(int *out, int x)
{
	*out = x; /* purity-expect */
	return x;
}

/* 3. I/O. */
io_operation
long read(int fd, void *buf, unsigned long n);
int bad_io(int fd) __attribute__((pure));
int bad_io(int fd)
{
	char buf[1];
	return (int)read(fd, buf, 1); /* purity-expect */
}

/* 4. mutable global/static read. */
static int counter;
int bad_global_read(void) __attribute__((pure));
int bad_global_read(void)
{
	return counter; /* purity-expect */
}

/* 5. impure callee (transitively, not in bad_callee's own body). */
static int helper(int x)
{
	static int seen;
	seen += x;
	return seen;
}
int bad_callee(int x) __attribute__((pure));
int bad_callee(int x)
{
	return helper(x); /* purity-expect */
}

/* 6. locking. */
typedef struct mutex mutex_t;
int pthread_mutex_lock(mutex_t *);
int pthread_mutex_unlock(mutex_t *);
int bad_lock(mutex_t *m, int x) __attribute__((pure));
int bad_lock(mutex_t *m, int x)
{
	pthread_mutex_lock(m); /* purity-expect */
	x = x + 1;
	pthread_mutex_unlock(m);
	return x;
}

/* 7. call through a function pointer -- cannot be proven pure. */
typedef int (*fn_t)(int);
int bad_indirect(fn_t f, int x) __attribute__((pure));
int bad_indirect(fn_t f, int x)
{
	return f(x); /* purity-expect */
}

/* 8. volatile access -- a real, required-by-the-standard observable
 * side effect regardless of whether the storage is a parameter. */
int bad_volatile(volatile int *p) __attribute__((pure));
int bad_volatile(volatile int *p)
{
	return *p; /* purity-expect */
}

/* 9. inline assembly -- opaque to this analysis, so never trusted. */
int bad_asm(int x) __attribute__((pure));
int bad_asm(int x)
{
	int y;
	__asm__ __volatile__("mov %1, %0" : "=r"(y) : "r"(x)); /* purity-expect */
	return y;
}

/* 10. memset() is only trusted through a stack-local destination
 * (see safe.c's zero_and_check()) -- writing through a parameter pointer
 * via memset() is exactly as real a violation as a direct assignment. */
void *memset(void *, int, unsigned long);
int bad_memset_write(int *out, unsigned long n) __attribute__((pure));
int bad_memset_write(int *out, unsigned long n)
{
	memset(out, 0, n); /* purity-expect */
	return (int)n;
}

/* 11. a subscript write is only trusted through a genuine local array
 * object (see safe.c's build_bitset()) -- writing through a *parameter*
 * array/pointer via subscript is exactly as real a violation as `*out = x`
 * (case 2 above), regardless of the `[]` spelling. */
int bad_array_param_write(int *out, int i, int v) __attribute__((pure));
int bad_array_param_write(int *out, int i, int v)
{
	out[i] = v; /* purity-expect */
	return v;
}

/* 12. The analyzer-only ownership primitive is trusted by exact name, not
 * as a blanket exception for similarly named functions. */
void __ownership_string_mutated(void *);
int bad_ownership_name(int *p) __attribute__((pure));
int bad_ownership_name(int *p)
{
	__ownership_string_mutated(p); /* purity-expect */
	return *p;
}
