/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "allocator-fixture.h"

size_t strcspn(const char *, const char *);
size_t strspn(const char *, const char *);
/* Deliberately `unsigned short`, NOT whatever clang's own builtin
 * wchar_t happens to be on the host running this fixture -- this is
 * ntlibc's own real `wchar_t` typedef (each arch/'s bits/alltypes.h.in's
 * `TYPEDEF unsigned short wchar_t`, kept 2 bytes on every arch this
 * tree builds for), and the whole point of wide_scan_return_value_
 * extent_is_trusted below is to prove trackScanExtent() uses THIS
 * type's real size, not ASTContext::getWCharType()'s. */
typedef unsigned short wchar_t;
size_t wcsspn(const wchar_t *, const wchar_t *);
long strtol(const char *, char **, int);
long getline(char **, size_t *, void *);

int local_object(void)
{
	int value = 7;
	int *pointer = &value;
	return *pointer;
}

int allocated_object(void)
{
	int result;
	int *pointer = malloc(sizeof *pointer);
	if (!pointer)
		return 0;
	*pointer = 9;
	result = *pointer;
	free(pointer);
	return result;
}

int bounded_array(void)
{
	int values[3] = {1, 2, 3};
	return values[2];
}

int static_string(void)
{
	return "valid"[1];
}

/* A null-checked pointer *parameter* -- ntlibc's single most common
 * pointer shape, used pervasively for borrowed buffers, structs, and
 * caller-owned objects the callee never allocated and never frees. Once
 * nonnull is proven (the check above), this checker has no further
 * *provable* liveness fact to demand: it never observed this symbol pass
 * through its own allocator/deallocator tracking (OwnershipChecker) at
 * all, so there is no positive evidence to weigh either way, only the
 * ordinary shape of a trusted borrow from the caller. Requiring proof
 * beyond nonnull-ness here is not requiring something merely unproven,
 * it is requiring something structurally unprovable by any per-function
 * analysis: no code on the callee side can ever establish that a value
 * whose provenance crosses a call boundary was not freed by code this
 * analysis never sees. Before the checker stopped treating "not seen by
 * my own allocator tracking" as "known freed", this one shape alone
 * accounted for the majority of ntlibc.ValidPointer findings tree-wide. */
int opaque_borrow(int *pointer)
{
	if (!pointer)
		return 0;
	return *pointer;
}

/* __errno_location() is declared (include/errno.h) `returns_nonnull`:
 * it always returns a valid pointer to the calling thread's own storage
 * and is never permitted to return NULL -- errno itself is `#define
 * errno (*__errno_location())`, so this exact shape is behind
 * essentially every `errno = ...` and `if (errno)` in the tree. Pinned
 * here (mirroring the real header's attribute, since this fixture does
 * not include it) so a regression in
 * ValidPointerChecker::isAlwaysNonNull is caught locally instead of
 * silently reappearing as ~440 findings tree-wide. */
extern int *__errno_location(void) __attribute__((returns_nonnull));

int errno_is_always_valid(void)
{
	return *__errno_location();
}

/* A fixed-size static array with an explicit bounds guard immediately
 * before the write. The guard proves the index in bounds directly; the
 * generic byte-extent machinery below (getDynamicExtentWithOffset)
 * turns that same fact into a compound "extent_of_slots_in_bytes minus
 * index*sizeof(*slots)" expression the constraint solver generally
 * cannot simplify back down to the plain "index < CAP" comparison it
 * started as, so this pattern -- among the most common in systems code:
 * a static table plus a bounds-checked counter -- was reported as
 * unproven even though the bound was checked one line above.
 * arrayIndexProvenInBounds() asks the solver the exact question the
 * guard itself answered instead. Deliberately `unsigned`: an
 * *unconstrained signed* counter needs a separate, real proof that it
 * cannot be negative too (a whole-file invariant -- "only ever
 * incremented from a zero-initialized static, never decremented past
 * it" -- that no single function can see, and getting it wrong would
 * hide a genuine buffer-underflow shape), so arrayIndexProvenInBounds()
 * only fires unconditionally for `unsigned`, where "not negative" is
 * true by type and only the upper bound needs checking; a signed
 * counter still requires provable non-negativity, exactly like
 * src/exit/exit.c's own `static int nhandlers` remains unresolved by
 * this fix (see the commit message for the fuller accounting). */
static void (*slots[8])(void);
static unsigned nslots;

int bounded_table_push(void (*f)(void))
{
	if (nslots >= 8)
		return -1;
	slots[nslots++] = f;
	return 0;
}

/* __teb() (src/internal/libc.h, declared `returns_nonnull`) and the
 * global __peb it bootstraps are NT's own OS-guaranteed-present
 * per-thread/per-process control blocks: every live thread has a TEB
 * (read via a two-instruction segment-register access, not something
 * application code can ever observe as absent), and __peb is set from
 * it, unconditionally, before anything else in the program runs
 * (crt/crt1.c's __libc_start_main), never reassigned or cleared
 * afterward. Pinned here (mirroring the real header's attribute, since
 * this fixture does not include it) so a regression in
 * ValidPointerChecker::isAlwaysNonNull/isAlwaysNonNullGlobal is caught
 * locally instead of silently reappearing as ~14 findings tree-wide
 * (dlfcn's __peb->ImageBaseAddress, every NT malloc/free/realloc's
 * __peb->ProcessHeap, ...). */
typedef struct { void *ImageBaseAddress; } *PPEB_FIXTURE;
extern PPEB_FIXTURE __teb(void) __attribute__((returns_nonnull));
PPEB_FIXTURE __peb;

/* Each tests its own mechanism in isolation: teb_is_always_valid never
 * touches __peb, so it cannot pass merely because assigning __peb from
 * __teb()'s already-proven-nonnull return would locally taint __peb too
 * -- and peb_is_always_valid dereferences __peb with no preceding
 * assignment or check anywhere in the function, so it can only pass via
 * isAlwaysNonNullGlobal recognising the global's own identity. */
void *teb_is_always_valid(void)
{
	return __teb()->ImageBaseAddress;
}

void *peb_is_always_valid(void)
{
	return __peb->ImageBaseAddress;
}

/* The process child table is initialized to a fixed seed array and its only
 * replacement is published after a checked allocation.  It is never cleared,
 * so the checker may trust this one reserved global's cross-TU invariant. */
struct __child { int pid; };
static struct __child child_seed[4];
struct __child *__children = child_seed;

int child_table_is_always_valid(void)
{
	return __children[0].pid;
}

/* GCC/Clang's `nonnull` attribute is the C ecosystem's own standard way
 * to say a pointer parameter is required, not optional -- real compilers
 * already diagnose a provably-NULL argument at the call site under
 * -Wnonnull. Trusting it here (ValidPointerChecker::checkBeginFunction)
 * means an ordinary parameter dereferenced with no in-function guard is
 * no longer unconditionally flagged once its own header truthfully
 * states the function's real contract -- unlike a blanket relaxation of
 * every unchecked parameter (which would also silence pointer-unsafe.c's
 * nullable_pointer, a genuine unguarded-dereference shape this checker
 * must keep catching), this only trusts parameters this project has
 * itself explicitly annotated. */
int nonnull_attribute_is_trusted(int *pointer) __attribute__((nonnull(1)));
int nonnull_attribute_is_trusted(int *pointer)
{
	return *pointer;
}

/* strto* guarantees that a supplied end pointer receives either the input
 * pointer itself or a pointer to the first unconverted byte within that same
 * nonnull string.  The generic analyzer invalidates `end` across the call but
 * does not know that the fresh value is necessarily nonnull; pin the
 * ValidPointer checkPostCall summary that supplies this standard contract. */
int string_conversion_end_pointer_is_nonnull(const char *text)
    __attribute__((nonnull(1)));
int string_conversion_end_pointer_is_nonnull(const char *text)
{
	char *end;
	(void)strtol(text, &end, 10);
	return *end;
}

/* On success getline writes a nonnull buffer containing the returned byte
 * count followed by a NUL.  This checks both facts: pointer validity and the
 * return-value-derived dynamic extent. */
int line_input_result_bounds_the_buffer(void *stream)
    __attribute__((nonnull(1)));
int line_input_result_bounds_the_buffer(void *stream)
{
	char *line = 0;
	size_t capacity = 0;
	long length = getline(&line, &capacity, stream);
	if (length < 0)
		return 0;
	return line[length];
}

/* clang's own dynamic-extent tracking for an allocator's return value only
 * fires for a handful of literally-named standard functions -- confirmed
 * empirically: `malloc(n)` gets a real, usable dynamic extent, but
 * `__malloc(n)` -- the name every allocation inside this tree's OWN code
 * actually goes through -- does not, leaving ValidPointerChecker with
 * nothing but an unconstrained SymbolExtent placeholder for every buffer
 * this codebase allocates through its own internal entry point.
 * OwnershipChecker::allocationSizeInBytes fixes this by setting the real
 * extent itself, straight from the real size argument, for its own whole
 * allocator family. A concrete, fixed offset into a concrete-sized
 * allocation (not the same-symbol pattern below) pins that this checker's
 * OWN extent-setting is what makes this provable now, not the pointer's
 * static type or any other pre-existing relaxation. */
char *heap_allocation_extent_is_trusted(void)
{
	char *buffer = __malloc(8);
	if (!buffer) return 0;
	buffer[3] = 'x';
	return buffer;
}

/* The single most common "allocate len+1, write the terminator at len"
 * idiom throughout this tree (src/string/strndup.c's real body is the
 * concrete case this mirrors: `d = malloc(l+1); ...; d[l] = 0;`). The
 * generic byte-extent machinery computes extent_of_d (itself `l + 1`, a
 * compound expression once __malloc's real size argument is tracked, see
 * heap_allocation_extent_is_trusted above) MINUS the access offset (`l`),
 * but clang's range-based constraint solver does not fold "(S + 1) - S"
 * down to the literal 1 for two separately-built compound expressions
 * that merely happen to share a root symbol -- confirmed empirically
 * while developing sameSymbolExtentProvenInBounds: even an explicit
 * evalBinOp + assume() on that exact subtraction cannot refute "too
 * small". This is the shape that function exists to prove directly,
 * bypassing the solver's own inability to cancel it. */
char *same_symbol_extent_cancels(size_t n)
{
	char *d = __malloc(n + 1);
	if (!d) return 0;
	d[n] = 0;
	return d;
}

/* The generalization one level up from same_symbol_extent_cancels: an
 * allocation sized from the SUM of two or more independent length
 * symbols, indexed by an expression that reuses ALL of them -- a
 * name-then-value idiom loosely mirroring src/env/setenv.c's real body
 * (`s = malloc(l1 + l2 + 2); ...`). The write cannot be related to the
 * allocation by pointer-identity of a single shared symbol the way
 * same_symbol_extent_cancels's `d[n]` can -- it needs the linear-term
 * decomposition linearExtentProvenInBounds() adds to actually cancel --
 * but it is still a ZERO-MARGIN match: `l1 + 1 + l2` and the extent's
 * own `l1 + l2 + 2` reduce to the identical closed-form expression
 * (differing only by the trailing `+ 1` this access itself needs), so
 * the comparison is reflexive and safe under wraparound regardless of
 * l1/l2's actual values. tools/lint-ownership-fixtures/pointer-unsafe.c's
 * linear_combination_extent_leftover_term_not_provably_bounded is the
 * adversarial twin: the SAME allocation, but a write that leaves a real
 * (unsigned, exact-arithmetic-only) margin instead of an exact match,
 * which is NOT safe and must still be reported -- see
 * linearExtentProvenInBounds's own block comment in OwnershipChecker.cpp
 * for the confirmed wraparound counterexample. */
char *linear_combination_extent_cancels(size_t l1, size_t l2)
{
	char *s = __malloc(l1 + l2 + 2);
	if (!s) return 0;
	s[l1 + 1 + l2] = 0;
	return s;
}

/* getDynamicExtent() always answers in bytes, but a non-byte element
 * array's own index is naturally in ELEMENTS -- src/env/setenv.c's `ne =
 * realloc(__environ, sizeof(char *) * (n + 2)); ...; ne[n + 1] = 0;` is
 * the real body this mirrors. linearExtentProvenInBounds() peels the
 * `sizeof(char *) * (...)` factor off the extent expression before
 * applying the same zero-margin cancellation same_symbol_extent_cancels/
 * linear_combination_extent_cancels above already exploit (`n + 1` here
 * against a peeled extent of `n + 2`, needing exactly one more element,
 * same shape as those). tools/lint-ownership-fixtures/pointer-unsafe.c's
 * element_width_leftover_margin_not_provably_bounded is the adversarial
 * twin: `ne[n] = s;` on this SAME allocation, one element short of the
 * full extent -- a real margin through the element-width peel, not an
 * exact match, and NOT safe for the identical wraparound reason. */
char **element_width_is_peeled(char **environ, size_t n, char *s)
{
	char **ne = realloc(environ, sizeof(char *) * (n + 2));
	if (!ne) return 0;
	ne[n + 1] = 0;
	return ne;
}

/* GCC/Clang's `returns_nonnull` attribute is the return-value
 * counterpart of `nonnull` on a parameter -- the standard way a
 * function states "this never returns NULL" as part of its own real
 * contract. Trusting it here (OwnershipChecker::isAlwaysNonNull, the
 * same mechanism __errno_location/__teb/localeconv are themselves
 * declared with above) means a call result dereferenced with no
 * in-function guard is no longer unconditionally flagged once its own
 * header truthfully states the contract -- src/string/strchr.c's real
 * `char *r = strchrnul(s, c); return *(unsigned char *)r == ...;` is
 * the motivating case (strchrnul is marked returns_nonnull for
 * exactly this reason). */
char *always_nonnull_helper(const char *s, int c) __attribute__((returns_nonnull));
char *always_nonnull_helper(const char *s, int c)
{
	(void)c;
	return (char *)s;
}

char *returns_nonnull_attribute_is_trusted(const char *s, int c)
{
	char *r = always_nonnull_helper(s, c);
	return *r ? r : 0;
}

/* OwnershipChecker::isScanExtentFunction/trackScanExtent: nothing in
 * clang's own builtin summaries relates a NUL-terminated-string scan's
 * return value to the dynamic extent of the pointer it scanned, the
 * same gap allocationSizeInBytes closes for this tree's own __malloc
 * family above. src/string/strsep.c's real body -- `end = s +
 * strcspn(s, sep); if (*end) *end++ = 0;` -- is the concrete case this
 * mirrors: strcspn(s, sep) cannot return without having read s[L]
 * itself (whichever of "hit a byte in sep" or "hit the NUL" is what
 * stopped it), so the region s points to has to have at least L+1
 * bytes, even though s is a plain borrowed parameter this function
 * never allocated and has no other extent information about at all. */
char *scan_return_value_extent_is_trusted(char *s, const char *sep)
{
	char *end;
	if (!s)
		return 0;
	end = s + strcspn(s, sep);
	if (*end)
		*end = 0;
	return end;
}

/* src/string/strtok.c's/strtok_r.c's real body -- `s += strspn(s,
 * sep); if (!*s) ...` -- the strspn() twin of the strcspn() case
 * above: strspn(s, accept) equally cannot return without having read
 * s[L] itself (the first byte NOT in accept, or the NUL), so the same
 * "L scanned plus one more" bound holds. */
int strspn_return_value_extent_is_trusted(char *s, const char *accept)
{
	if (!s)
		return 0;
	s += strspn(s, accept);
	return *s;
}

/* src/string/wcstok.c's real body -- `s += wcsspn(s, sep); if (!*s)
 * ...` -- the wide-scanner twin of strspn_return_value_extent_is_trusted
 * above, pinning that trackScanExtent()'s byte multiplier is read off
 * the scanned argument's OWN pointee type (this file's `wchar_t`,
 * `unsigned short`, deliberately declared above to differ in size from
 * whatever clang's builtin wchar_t is on the host compiling this
 * fixture) rather than ASTContext::getWCharType() -- a real regression
 * during this fix's own development: using getWCharType() proved this
 * exact shape fine when the two happened to agree in size and left it
 * reported the moment they did not (see trackScanExtent's own comment
 * for the full account). */
int wide_scan_return_value_extent_is_trusted(wchar_t *s, const wchar_t *accept)
{
	if (!s)
		return 0;
	s += wcsspn(s, accept);
	return *s;
}

/* A "write two copies of an n-byte value back to back, then terminate"
 * idiom (allocate exactly enough for both copies plus a NUL, then write
 * the terminator at the doubled offset). The extent is `n + n + 1` -- an
 * additive tree collectLinearTerms() decomposes fine, accumulating the
 * repeated symbol `n` into coefficient 2 -- but the terminator's index is
 * written as the semantically equal, structurally different `2 * n`: a
 * BO_Mul node collectLinearTerms() cannot decompose at all, so it folds
 * the whole node in as one opaque term keyed by ITS OWN pointer identity,
 * which can never cancel against a plain occurrence of the symbol `n` on
 * the other side. That is exactly the "cancels opaque subexpressions only
 * by raw pointer/AST-node identity, not semantic equality" gap named in
 * linearExtentProvenInBounds's own comments: the ad hoc prover reports
 * "not proven" here. z3ExtentProvenInBounds proves it directly instead --
 * `n + n + 1 == 2 * n + 1` is exact ring arithmetic, true for every value
 * of `n` including under unsigned wraparound, since doubling and self-
 * addition are bit-identical modulo 2^width. */
char *doubled_extent_via_multiplication_index(size_t n)
{
	char *d = __malloc(n + n + 1);
	if (!d) return 0;
	d[2 * n] = 0;
	return d;
}
