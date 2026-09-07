/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Every publicly-declared function below is genuinely pure and already
 * annotated as such; this fixture must produce zero *false-claim* findings.
 * The one exception is is_even()/is_odd() further down, which are
 * deliberately left unmarked (mirroring fnmatch.c's own file-static
 * helpers, which 08449f1's commit message explains were intentionally
 * left unmarked too) specifically to exercise the checker's real
 * cross-function call-cycle path from a false-claim check's perspective,
 * not just the already-marked-callee trust shortcut -- so each of them
 * still produces its own, expected, *candidate* finding. */

typedef struct { int value; int bad; } tagged_t;

/* Pure arithmetic over the arguments only. */
int add(int a, int b) __attribute__((pure));
int add(int a, int b) { return a + b; }

/* Struct-by-value return -- the sched.c/locale.c pure-core-plus-thin-
 * impure-wrapper split pattern, minus the wrapper (the core alone). */
tagged_t compute(int policy) __attribute__((pure));
tagged_t compute(int policy)
{
	tagged_t r = { 0, 0 };
	if (policy < 0) { r.bad = 1; return r; }
	r.value = policy * 2;
	return r;
}

/* Read-only through a pointer argument -- exactly how memcmp/strcmp work. */
int first_byte(const char *p) __attribute__((pure));
int first_byte(const char *p) { return (int)p[0]; }

/* Read of a const global table -- the strerror() shape. */
static const int table[4] = { 1, 2, 3, 4 };
int lookup(int index) __attribute__((pure));
int lookup(int index) { return table[index]; }

/* Calling an already-proven-pure function in the same translation unit. */
int add_twice(int a, int b) __attribute__((pure));
int add_twice(int a, int b) { return add(a, b) + add(a, b); }

/* Calling a trusted bootstrap primitive without dereferencing its result:
 * the call itself has no observable side effect, matching __teb()'s real
 * body (a raw fs:/gs:-relative register read, opaque but side-effect-free)
 * -- see src/internal/{i386,x86_64}/teb.c. */
void *__teb(void);
int has_teb(void) __attribute__((pure));
int has_teb(void) { return __teb() != 0; }

/* Analyzer-only ownership proof calls erase to no-ops in ordinary builds.
 * Their abstract token effect is not a runtime side effect and therefore
 * does not invalidate a surrounding compiler purity claim. */
void unsafe_assume_string_terminated(const void *);
int prove_terminated(const char *p) __attribute__((pure));
int prove_terminated(const char *p)
{
	unsafe_assume_string_terminated(p);
	return *p;
}

/* Direct self-recursion, no other side effect anywhere in the cycle --
 * the fnm_match() shape (src/fnmatch/fnmatch.c): the recursive call is not
 * itself a violation, only a concrete disqualifier found while walking the
 * body would be. */
int count_down(int n) __attribute__((pure));
int count_down(int n) { return n <= 0 ? 0 : 1 + count_down(n - 1); }

/* Mutual recursion between two static, deliberately UNMARKED helpers,
 * reached only through a single already-marked-pure public entry point --
 * the real fnmatch()/fnm_match() shape (src/fnmatch/fnmatch.c). Because
 * neither helper is marked, parity()'s call into is_even() cannot take the
 * hasPureOrConstAttr() trust shortcut -- it must go through
 * computePurity()'s InProgress cycle-optimism path for real, which is
 * exactly the path being regression-tested here. Each helper is itself
 * genuinely pure but unmarked, so each also produces its own, expected,
 * *candidate* finding (see is_even/is_odd below). */
static int is_even(int n);
static int is_odd(int n) { return n == 0 ? 0 : is_even(n - 1); } /* purity-expect */
static int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); } /* purity-expect */
int parity(int n) __attribute__((pure));
int parity(int n) { return is_even(n); }

/* memset() on a stack-local scratch buffer that never escapes -- the
 * strcspn()/strspn() shape (src/string/strcspn.c, strspn.c): a real write,
 * but invisible to any caller. */
void *memset(void *, int, unsigned long);
int zero_and_check(int index) __attribute__((pure));
int zero_and_check(int index)
{
	char scratch[16];
	memset(scratch, 0, sizeof scratch);
	return scratch[index & 15] == 0;
}

/* Direct subscript writes into a stack-local array object -- the
 * strcspn()/strspn() BITOP macro's real shape (`byteset[i] |= bit`,
 * src/string/strcspn.c, strspn.c): a real write, but to storage that can
 * never be reassigned to alias anything else, so still invisible to any
 * caller. */
int build_bitset(const char *s) __attribute__((pure));
int build_bitset(const char *s)
{
	unsigned char seen[32] = { 0 };
	for (; *s; s++)
		seen[(unsigned char)*s / 8] |= 1 << (*s % 8);
	return seen[0];
}
