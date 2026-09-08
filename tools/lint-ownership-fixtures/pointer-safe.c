/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "allocator-fixture.h"

size_t strcspn(const char *, const char *);
size_t strspn(const char *, const char *);
/* Deliberately `unsigned short`, NOT whatever clang's own builtin
 * wchar_t happens to be on the host running this fixture -- this is
 * spicule's own real `wchar_t` typedef (each arch/'s bits/alltypes.h.in's
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

/* A null-checked pointer *parameter* -- spicule's single most common
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
 * accounted for the majority of spicule.ValidPointer findings tree-wide. */
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

/* unsafe_assume_pointer_nonnull(): the leaf axiom src/internal/
 * ownership_stubs.h declares for exactly this gap, pinned end to end
 * here the way every other axiom in this file is. struct argv_slice
 * mirrors src/util/test.c's real struct texpr (`char **v`, sliced out of
 * argv and never reassigned within the accessor) and src/util/find.c's
 * byte-for-byte identical struct find_ctx: a struct field holding a
 * `char **` array that is genuinely always live by construction (it
 * always traces back to a real argv), read back out through the
 * struct's own accessor via a MemberExpr immediately followed by an
 * ArraySubscriptExpr. No existing withtok(readable_elements(...))/
 * elements_withtok(...) annotation on this field makes
 * ValidPointerChecker::checkPointerExpression's native
 * isNonNull()-based proof treat that read's *own* value as nonnull: a
 * struct field read yields a fresh, unconstrained symbol every time it
 * is evaluated, and this project's other grant()/consume() token
 * annotations operate on a wholly separate state map (see
 * CapabilityTokenChecker) that checkPointerExpression's native-
 * constraint proof never consults -- confirmed by
 * struct_field_array_element_is_flagged_without_the_axiom below, the
 * identical shape with the unsafe_assume_pointer_nonnull() call removed,
 * which still reports.
 *
 * The element index is deliberately the literal 0, not a second struct
 * field the way test.c's real `t->v[t->i]` reads it: indexing by a
 * runtime-computed field would *also* need a genuine dynamic-extent
 * proof for slice->v's own allocation (a completely separate, harder
 * gap this axiom does not claim to close -- checkLocation's own extent
 * check has no leniency for a symbolic array offset with no established
 * extent, only for a fixed one), and mixing that unresolved, unrelated
 * finding into this fixture would no longer isolate the ONE fact this
 * axiom exists to prove. A literal, fixed offset keeps this fixture
 * "safe" in the same narrow sense opaque_borrow/local_object above are:
 * every OTHER proof obligation this access carries is already trusted
 * by the type ("dereference extent is not proven sufficient" grants a
 * fixed offset the same "trust the type" leniency it already grants
 * opaque_borrow's own implicit *pointer), leaving nonnull-ness the one
 * remaining, genuinely open question -- exactly the one this axiom
 * answers. */
struct argv_slice { char **v; size_t i; };

#ifdef __clang_analyzer__
void unsafe_assume_pointer_nonnull(const void *object);
#else
#define unsafe_assume_pointer_nonnull(object) ((void)0)
#endif

char *struct_field_array_element_nonnull_axiom_is_trusted(
    struct argv_slice *slice) __attribute__((nonnull(1)));
char *struct_field_array_element_nonnull_axiom_is_trusted(
    struct argv_slice *slice)
{
	unsafe_assume_pointer_nonnull(slice->v);
	return slice->v[0];
}

/* null_terminated implies nonnull, asserted once at the point the token is
 * GRANTED rather than at every later dereference (OwnershipChecker.cpp's
 * tokenImpliesNonNull and its three grant-point consumers:
 * AggregateElementTokenChecker::checkBeginFunction/checkPostStmt and
 * CapabilityTokenChecker::checkBeginFunction -- plus ValidPointerChecker's
 * own by-name mirrors of those same three grant points,
 * parameterGrantsNullTerminatedScalar/elementProvenNullTerminated/
 * isStringTerminatedAxiom, needed because that checker never shares a
 * pass with the CapabilityToken family; see isPointerNonNullAxiom's own
 * comment). Before this fix, each case below needed its own manual
 * unsafe_assume_pointer_nonnull()/unsafe_assume_string_terminated() restatement
 * the way struct_field_array_element_nonnull_axiom_is_trusted above still
 * does for the genuinely unrelated struct-field-capture shape. */
tokdef null_terminated l_unlimited implicit_drop string_literal;

void unsafe_assume_string_terminated(const void * grant(null_terminated));

/* A scalar withtok(null_terminated) parameter's own nonnull-ness needs no
 * separate axiom or __attribute__((nonnull)). */
int scalar_withtok_null_terminated_needs_no_axiom(
    const char *path withtok(null_terminated))
{
	return path[0] == '/';
}

/* elements_withtok(null_terminated, argc): the aggregate pointer itself
 * (argv) and each in-bounds element (argv[i]) are both nonnull with no
 * separate unsafe_assume_pointer_nonnull() call, directly inside a loop
 * condition/body -- the src/util/find.c __util_find_main() shape this
 * fixture mirrors. */
int elements_withtok_array_and_element_need_no_axiom(
    int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 0;
	while (i < argc) {
		if (argv[i][0] == '-') break;
		i++;
	}
	return i;
}

/* The manual unsafe_assume_string_terminated() axiom itself also proves
 * nonnull, with no separate unsafe_assume_pointer_nonnull() call. */
int string_terminated_axiom_also_proves_nonnull(const char *p)
{
	unsafe_assume_string_terminated(p);
	return p[0] == '/';
}

/* dirname()/basename() (src/misc/dirname.c, src/misc/basename.c) always
 * return a live, NUL-terminated string for any input, recognized by name
 * in ValidPointerChecker (returnsNullTerminatedString) -- no manual
 * restatement needed at the call site. */
char *dirname(char *s);
char *basename(char *s);

int dirname_result_needs_no_restatement(char *path)
{
	char *d = dirname(path);
	return d[0] == '/';
}

int basename_result_needs_no_restatement(char *path)
{
	char *b = basename(path);
	return b[0] == '/';
}

/* snprintf()/vsnprintf() NUL-terminate their destination whenever the size
 * argument is provably nonzero (src/stdio/printf.c's vxprintf_mem: `if
 * (cap) { ...; s[pos] = 0; }`) -- proven here via sizeof, the overwhelmingly
 * common real case (snprintfSizeProvenNonzero's own comment). */
int snprintf(char *s, size_t n, const char *fmt, ...) __attribute__((nonnull(3)));

int snprintf_with_proven_nonzero_size_needs_no_restatement(void)
{
	char buf[64];
	snprintf(buf, sizeof buf, "%s", "hi");
	return buf[0] == 'h';
}

/* src/internal/fd.c's __fd_install()/__fd_get(): a successful install's own
 * return value, when passed to __fd_get() with nothing in between that
 * could invalidate the slot, is guaranteed to find it -- ValidPointer
 * Checker's own by-name PendingInstalledFd tracking (isFdInstall/isFdGet/
 * fdGetArgProvenLive) proves this without a manual
 * unsafe_assume_pointer_nonnull() restatement, closing the gap
 * src/socket/{socket,accept,socketpair}.c (commit 3dd52b7a) previously had
 * to work around by hand at every call site. */
struct __fd { int state; };
int __fd_install(void *handle, unsigned flags, int type);
struct __fd *__fd_get(int fd);
void __plat_close(void *handle);

int fd_get_after_successful_install_needs_no_restatement(void *handle)
{
	int fd = __fd_install(handle, 0, 0);
	if (fd < 0) { __plat_close(handle); return -1; }
	struct __fd *f = __fd_get(fd);
	f->state = 1;
	return fd;
}

/* The same idiom, but the fd's own symbol reaches __fd_get() through a
 * plain copy to a second local (`newfd = fd; ... __fd_get(newfd)`) rather
 * than the install call's own immediate LHS -- confirming the proof
 * follows the SYMBOL, not the specific variable spelling the install call
 * happened to assign to (dup.c-style plumbing might reasonably do this). */
int fd_get_after_install_through_copied_local_needs_no_restatement(void *handle)
{
	int fd = __fd_install(handle, 0, 0);
	int newfd;
	struct __fd *f;
	if (fd < 0) { __plat_close(handle); return -1; }
	newfd = fd;
	f = __fd_get(newfd);
	f->state = 2;
	return newfd;
}

/* spicule.RedundantPointerAxiom (OwnershipChecker.cpp's
 * RedundantPointerAxiomChecker, tools/lint.sh's opt-in `pointeraxiom`
 * stage) audits the two axioms above the way spicule.MemoryContract
 * already audits unsafe_assume_readable_span/unsafe_assume_writable_span:
 * a restatement of a fact the analysis can already prove without it is
 * dead scaffolding left behind by a checker improvement that closed the
 * gap at its point of origin.
 *
 * The pointer-axiom-* expectation tags below belong to
 * tools/lint-pointer-axiom.py's own fixture gate, not to
 * tools/lint-ownership.py's -- exactly the split the opt-in
 * spicule.ResourceLeak checker's own resource-leak tag already has.
 * Every case below is otherwise a genuine "safe" case: none of them has
 * any ValidPointer finding of its own.
 *
 * The negative half of this audit's proof obligation is
 * struct_field_array_element_nonnull_axiom_is_trusted above -- the
 * struct-held array element whose axiom is still the only thing proving
 * that read nonnull, and which therefore must NOT be flagged here.
 * pointer-unsafe.c's struct_field_array_element_is_flagged_without_the_
 * axiom is the standing proof that it really is load-bearing. */

/* __attribute__((nonnull)) already asserts this parameter at entry
 * (ValidPointerChecker::checkBeginFunction), on every path, so the
 * restatement proves nothing new. */
int nonnull_parameter_axiom_is_redundant(char *p) __attribute__((nonnull(1)));
int nonnull_parameter_axiom_is_redundant(char *p)
{
	unsafe_assume_pointer_nonnull(p); /* ownership-expect: pointer-axiom-redundant */
	return p[0];
}

/* A local object's own address is nonnull by construction; no axiom of
 * any kind was ever needed for it. */
int address_of_local_axiom_is_redundant(void)
{
	int value = 7;
	unsafe_assume_pointer_nonnull(&value); /* ownership-expect: pointer-axiom-redundant */
	return value;
}

/* withtok(null_terminated) grants both halves of what
 * unsafe_assume_string_terminated() would grant -- the token itself
 * (CapabilityTokenChecker::checkBeginFunction) and the nonnull-ness that
 * token implies (parameterGrantsNullTerminatedScalar) -- so this
 * restatement is dead in both passes at once, which is the only
 * condition under which the string axiom is reported at all. */
int withtok_parameter_string_axiom_is_redundant(
    const char *path withtok(null_terminated))
{
	unsafe_assume_string_terminated(path); /* ownership-expect: pointer-axiom-redundant */
	return path[0] == '/';
}

/* An elements_withtok() element -- the argv[i] shape src/util/{cut,ln,
 * mkdir_util,pathchk,rm}.c all have -- is the load-bearing counterexample
 * to that reasoning, and must NOT be flagged. ValidPointer can prove this
 * element nonnull on its own here (elementProvenNullTerminated, the same
 * proof that makes the nonnull axiom on such an element redundant), but
 * the element's null_terminated token does not reach the element's later
 * uses in spicule.CapabilityToken's own pass, so the axiom is still the
 * only thing granting it there: deleting these calls from the five real
 * files above makes spicule.CapabilityToken and spicule.OwnershipType
 * report "required ownership capability token is not held" at the very
 * next use. Nonnull-ness is not evidence about a token grant. */
int elements_withtok_element_string_axiom_is_still_needed(
    int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 0;
	while (i < argc) {
		unsafe_assume_string_terminated(argv[i]);
		i++;
	}
	return i;
}

/* The nonnull axiom on that same element, by contrast, IS redundant:
 * unsafe_assume_pointer_nonnull() has no token effect at all, so the one
 * fact it asserts is the one elementProvenNullTerminated already
 * establishes. */
int elements_withtok_element_nonnull_axiom_is_redundant(
    int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 0;
	while (i < argc) {
		unsafe_assume_pointer_nonnull(argv[i]); /* ownership-expect: pointer-axiom-redundant */
		i++;
	}
	return i;
}

/* An ordinary unannotated parameter's NUL-termination is not something
 * this analysis can derive, so string_terminated_axiom_also_proves_nonnull
 * above stays unflagged even though the axiom's nonnull half is
 * self-fulfilling: the token half is still the only thing granting
 * null_terminated there. The same is true here, with the nonnull half
 * additionally proven by a real guard -- a path fact, which never
 * licenses removing a token grant. */
int guarded_string_axiom_is_not_flagged(const char *p)
{
	if (!p)
		return 0;
	unsafe_assume_string_terminated(p);
	return p[0] == '/';
}

/* A guard proves this parameter nonnull on the path that reaches the
 * axiom, but says nothing about the paths that do not, so the axiom is
 * reported as narrowable rather than dead -- the same distinction
 * MemoryContractChecker draws between "is redundant" and "can be
 * narrowed" for its own span axioms. */
int guarded_nonnull_axiom_can_be_narrowed(char *p)
{
	if (!p)
		return 0;
	unsafe_assume_pointer_nonnull(p); /* ownership-expect: pointer-axiom-narrowable */
	return p[0];
}
