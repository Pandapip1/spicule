/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

long same_array_difference(int *items) { return &items[3] - &items[1]; }

int same_array_order(int *items) { return items < items + 1; }

void *null_pointer(void) { return (void *)0; }

/* A compile-time-constant integer cast to a pointer type is a
 * deliberate, source-visible sentinel (NT's own pseudo-handle
 * convention, SIG_DFL/SIG_IGN/SIG_ERR, MAP_FAILED, and the invalid
 * nl_catd/iconv_t/sem_t markers all take this shape) -- see
 * PointerProvenanceChecker.cpp's isConstantSentinel(). */
void *constant_sentinel(void) { return (void *)(long)-1; }

/* Pointer -> integer -> (mask/offset) -> pointer, the alignment idiom
 * used by posix_memalign()/align16()/mman.c's page-range clamps --
 * see derivesFromPointer(). */
void *alignment_roundtrip(void *p) {
  return (void *)(((unsigned long)p + 15) & ~15UL);
}

/* A conditional expression choosing between two such round trips (the
 * shape mman.c's `lo = a > b ? a : b`-style range clamp takes once its
 * operands are cast through uintptr_t). */
void *alignment_roundtrip_conditional(void *a, void *b) {
  unsigned long ia = (unsigned long)a, ib = (unsigned long)b;
  return (void *)(ia > ib ? ia : ib);
}

/* strchr()'s return shares provenance with its first argument by
 * contract (a "needle in haystack" function -- see checkPostCall());
 * the two are the same object even though the call is opaque to this
 * checker (no strchr() definition is visible to a --analyze pass over
 * one file). */
/* strchr(), inlined rather than `#include <string.h>`: these fixtures
 * compile with no include path (see marked_unprovable_cast()'s comment
 * below), so this must not depend on a header actually resolving -- see
 * clang's own resource-dir, which is what `<string.h>` would otherwise
 * come from. */
char *strchr(const char *, int);
long needle_in_haystack(const char *s) {
  const char *dot = strchr(s, '.');
  return dot ? dot - s : -1;
}

/* strto*'s endptr output is either the input pointer or a later pointer in
 * the same array by contract, even though the opaque call gives the stored
 * value a fresh analyzer symbol. */
/* strtol(), inlined for the same reason strchr() is above. */
long strtol(const char *, char **, int);
long conversion_end_in_input(const char *s) {
  char *end;
  (void)strtol(s, &end, 10);
  return end - s;
}

static const char *skip_digits(const char *p) {
  if (*p < '0' || *p > '9')
    return 0;
  while (*p >= '0' && *p <= '9')
    ++p;
  return p;
}

long static_cursor_return(const char *s) {
  const char *end = skip_digits(s);
  return end ? end - s : -1;
}

#define returns_element_of(registry) \
  __attribute__((annotate("ntlibc_relation_returns_element_of:" #registry)))
#define parameter_element_of(index, registry) \
  __attribute__((annotate("ntlibc_relation_parameter_element_of:" #index ":" #registry)))

static int *safe_registry;
static int *safe_registry_lookup(unsigned i) returns_element_of(safe_registry);
static int *safe_registry_lookup(unsigned i) {
  return &safe_registry[i];
}

static long safe_registry_index(int *p)
    parameter_element_of(0, safe_registry);
static long safe_registry_index(int *p) { return p - safe_registry; }

/* An opaque call may change an element's contents, but receives only the
 * element pointer and cannot rebind the file-static registry pointer. */
void mutate_element_contents(int *);
long registry_relation_survives_content_mutation(unsigned i) {
  int *p = safe_registry_lookup(i);
  mutate_element_contents(p);
  return safe_registry_index(p);
}

/* unsafe_assume_valid_pointer(expr) -- src/internal/unsafe_pointer.h's
 * real marker, inlined here since these fixtures compile with no
 * include path (matching this file's own inlined
 * returns_element_of/parameter_element_of macros above). See
 * PointerProvenanceChecker.cpp's isUnsafeAssumeValidPointer() for how
 * it is recognised, and unsafe.c's unmarked_cast_still_flagged() for
 * proof this does not blanket-loosen the checker. */
#ifdef __clang_analyzer__
#define unsafe_assume_valid_pointer(expr) \
  (__extension__({ \
    __typeof__(expr) __ntlibc_unsafe_ptr__ \
      __attribute__((annotate("ntlibc_unsafe_assume_valid_pointer"))) \
      = (expr); \
    __ntlibc_unsafe_ptr__; \
  }))
#else
#define unsafe_assume_valid_pointer(expr) (expr)
#endif

/* A marked integer-to-pointer conversion with no provable pointer
 * derivation anywhere in this file -- the same shape as the real
 * marked call sites in src/ (a raw syscall or kernel-populated value
 * with no base/len pair anywhere to prove from) -- must be resolved,
 * not flagged. */
void *marked_unprovable_cast(unsigned long value) {
  return unsafe_assume_valid_pointer((void *)value);
}

/* unsafe_assume_shared_provenance(expr) -- src/internal/unsafe_pointer.h's
 * other real marker, inlined here for the same reason
 * unsafe_assume_valid_pointer() is above. See
 * PointerProvenanceChecker.cpp's isUnsafeAssumeSharedProvenance() for how
 * it is recognised, and unsafe.c's unmarked_subtraction_still_flagged()
 * for proof this does not blanket-loosen the checker. */
#ifdef __clang_analyzer__
#define unsafe_assume_shared_provenance(expr) \
  (__extension__({ \
    __typeof__(expr) __ntlibc_unsafe_shared_prov__ \
      __attribute__((annotate("ntlibc_unsafe_assume_shared_provenance"))) \
      = (expr); \
    __ntlibc_unsafe_shared_prov__; \
  }))
#else
#define unsafe_assume_shared_provenance(expr) (expr)
#endif

/* A marked pointer subtraction between two unrelated arrays -- the same
 * shape as the real marked call sites in src/ (two pointers a caller
 * contract asserts are the same object, with no base/len pair in this
 * function to prove it from) -- must be resolved, not flagged. */
long marked_unprovable_difference(int *left, int *right) {
  return unsafe_assume_shared_provenance(left - right);
}
