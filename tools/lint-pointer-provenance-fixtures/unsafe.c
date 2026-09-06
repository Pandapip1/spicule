/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

long different_array_difference(int *left, int *right) {
  return left - right; /* pointer-provenance-expect */
}

int different_array_order(int *left, int *right) {
  return left < right; /* pointer-provenance-expect */
}

int *integer_pointer(unsigned long address) {
  return (int *)address; /* pointer-provenance-expect */
}

/* checkPostCall's strchr() alias must not bleed across unrelated
 * buffers: subtracting a strchr() result from a *different* string is
 * still two unrelated objects, not the same "needle in haystack" pair,
 * and must stay flagged. */
/* strchr(), inlined rather than `#include <string.h>` -- same reason as
 * safe.c's identical inlined declaration: these fixtures compile with no
 * include path. */
char *strchr(const char *, int);
long different_haystack_difference(const char *s, const char *other) {
  const char *dot = strchr(s, '.');
  return dot ? dot - other : -1; /* pointer-provenance-expect */
}


/* A strto* end pointer shares provenance only with that call's own input. */
/* strtol(), inlined for the same reason strchr() is above. */
long strtol(const char *, char **, int);
long conversion_end_from_different_input(const char *s, const char *other) {
  char *end;
  (void)strtol(s, &end, 10);
  return end - other; /* pointer-provenance-expect */
}

/* Reassigning end after conversion must discard the conversion contract. */
long overwritten_conversion_end(const char *s, const char *other) {
  char *end;
  (void)strtol(s, &end, 10);
  end = (char *)other;
  return end - s; /* pointer-provenance-expect */
}

/* An arbitrary output-pointer function has no strto* provenance contract. */
void parse_number(const char *, char **);
long untrusted_end_output(const char *s) {
  char *end;
  parse_number(s, &end);
  return end - s; /* pointer-provenance-expect */
}

/* Named kernel/loader ABI exceptions require both their audited source file
 * and function name; merely reusing a name elsewhere grants nothing. */
void *shmat(unsigned long address) {
  return (void *)address; /* pointer-provenance-expect */
}
void *raw_brk(unsigned long address) {
  return (void *)address; /* pointer-provenance-expect */
}
void *load_object(unsigned long address) {
  return (void *)address; /* pointer-provenance-expect */
}

static const char *mixed_cursor_return(const char *p, const char *other,
                                       int choose) {
  return choose ? p + 1 : other;
}
long mixed_cursor_origin(const char *p, const char *other, int choose) {
  return mixed_cursor_return(p, other, choose) - p; /* pointer-provenance-expect */
}

static const char *reset_cursor(const char *p, const char *other) {
  p = other;
  return p;
}
long reset_cursor_origin(const char *p, const char *other) {
  return reset_cursor(p, other) - p; /* pointer-provenance-expect */
}

static void replace_cursor(const char **p, const char *other) { *p = other; }
static const char *aliased_cursor(const char *p, const char *other) {
  replace_cursor(&p, other);
  return p;
}
long aliased_cursor_origin(const char *p, const char *other) {
  return aliased_cursor(p, other) - p; /* pointer-provenance-expect */
}

static const char *integer_cursor(const char *p, unsigned long delta) {
  unsigned long bits = (unsigned long)p;
  bits += delta;
  return (const char *)bits;
}
long integer_cursor_origin(const char *p, unsigned long delta) {
  return integer_cursor(p, delta) - p; /* pointer-provenance-expect */
}

const char *external_cursor(const char *p);
long external_cursor_origin(const char *p) {
  return external_cursor(p) - p; /* pointer-provenance-expect */
}

typedef const char *(*cursor_fn)(const char *);
long indirect_cursor_origin(cursor_fn fn, const char *p) {
  return fn(p) - p; /* pointer-provenance-expect */
}

#define returns_element_of(registry) \
  __attribute__((annotate("ntlibc_relation_returns_element_of:" #registry)))
#define parameter_element_of(index, registry) \
  __attribute__((annotate("ntlibc_relation_parameter_element_of:" #index ":" #registry)))

static int *contract_registry;
static int *other_registry;

static int *wrong_registry_return(unsigned i)
    returns_element_of(contract_registry);
static int *wrong_registry_return(unsigned i) {
  return &other_registry[i]; /* pointer-provenance-expect */
}
long exercise_wrong_registry_return(unsigned i) {
  return wrong_registry_return(i) != 0;
}

static long contract_consumer(int *p)
    parameter_element_of(0, contract_registry);
static long contract_consumer(int *p) { return p - contract_registry; }

long wrong_registry_argument(unsigned i) {
  return contract_consumer(&other_registry[i]); /* pointer-provenance-expect */
}

static int *contract_lookup(unsigned i) returns_element_of(contract_registry);
static int *contract_lookup(unsigned i) { return &contract_registry[i]; }

long rebound_registry_argument(unsigned i, int *replacement) {
  int *p = contract_lookup(i);
  contract_registry = replacement;
  return contract_consumer(p); /* pointer-provenance-expect */
}

static int *reset_registry;
static long reset_consumer(int *p, int *other)
    parameter_element_of(0, reset_registry);
static long reset_consumer(int *p, int *other) {
  p = other;
  return p - reset_registry; /* pointer-provenance-expect */
}
long exercise_reset_consumer(unsigned i, int *other) {
  return reset_consumer(&reset_registry[i], other);
}

static int *escaped_registry;
static long escaped_consumer(int *p)
    parameter_element_of(0, escaped_registry);
static long escaped_consumer(int *p) {
  return p - escaped_registry; /* pointer-provenance-expect */
}
int **escape_registry_storage(void) { return &escaped_registry; }
long exercise_escaped_consumer(unsigned i) {
  return escaped_consumer(&other_registry[i]);
}

static int *address_taken_registry;
static long address_taken_consumer(int *p)
    parameter_element_of(0, address_taken_registry);
static long address_taken_consumer(int *p) {
  return p - address_taken_registry; /* pointer-provenance-expect */
}
typedef long (*registry_consumer_fn)(int *);
registry_consumer_fn expose_consumer(void) { return address_taken_consumer; }
long exercise_address_taken_consumer(unsigned i) {
  return address_taken_consumer(&other_registry[i]);
}

/* unsafe_assume_valid_pointer(expr) -- same inlined marker as safe.c's
 * copy (fixtures compile with no include path); see that file's
 * marked_unprovable_cast() for proof the marker actually suppresses
 * the one cast it wraps. */
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

/* The marker resolves only the one cast it is applied to. An unmarked,
 * otherwise-identical integer-to-pointer conversion of the very same
 * parameter, in the very same function, right next to a marked one,
 * must still be flagged -- proving this is not a blanket loosening of
 * the checker for the whole function, the translation unit, or even
 * the one source variable the marked cast happens to be assigned to. */
void *unmarked_cast_still_flagged(unsigned long value) {
  void *marked = unsafe_assume_valid_pointer((void *)value);
  void *unmarked = (void *)value; /* pointer-provenance-expect */
  return marked ? marked : unmarked;
}

/* The marker wraps a constant sentinel -- the exact shape safe.c's own
 * constant_sentinel() already proves safe with no marker at all (see
 * isConstantSentinel()). The checker's ordinary logic would have
 * cleared this cast whether or not the marker was ever applied, so the
 * marker covers no real gap here: this must produce the distinct
 * "marker is redundant" diagnostic (reportRedundantMarker(), routed
 * through isMarkerRedundant()/isProvenByOrdinaryLogic()), not the
 * normal "unproven" finding, and not silent acceptance either. */
void *redundant_marker_constant_sentinel(void) {
  return unsafe_assume_valid_pointer((void *)(long)-1); /* pointer-provenance-expect */
}

/* unsafe_assume_shared_provenance(expr) -- same inlined marker as safe.c's
 * copy; see that file's marked_unprovable_difference() for proof the
 * marker actually suppresses the one subtraction it wraps. */
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

/* The marker resolves only the one subtraction it is applied to. An
 * unmarked, otherwise-identical pointer subtraction of the very same
 * parameters, right next to a marked one, must still be flagged -- the
 * same non-blanket-loosening property unmarked_cast_still_flagged()
 * above proves for unsafe_assume_valid_pointer(). */
long unmarked_subtraction_still_flagged(int *left, int *right) {
  long marked = unsafe_assume_shared_provenance(left - right);
  long unmarked = left - right; /* pointer-provenance-expect */
  return marked + unmarked;
}

/* The marker wraps a subtraction between two pointers into the SAME
 * array -- the exact shape safe.c's own same_array_difference() already
 * proves safe with no marker at all. The marker covers no real gap
 * here: this must produce the "marker is redundant" diagnostic, not the
 * normal "unproven" finding, and not silent acceptance either. */
long redundant_marker_same_array(int *items) {
  return unsafe_assume_shared_provenance(&items[3] - &items[1]); /* pointer-provenance-expect */
}

/* A loop-carried counterpart to redundant_marker_same_array() above,
 * exercising PointerProvenanceChecker.cpp's whole-function accumulation
 * (recordSharedProvenanceMarkerObservation()/checkEndAnalysis()) rather
 * than just isProvenSharedProvenance()'s single-path AST shape: p is
 * re-derived from items on every loop iteration the analyzer explores,
 * including any iteration reached only after the analyzer's bounded loop
 * widening gives up tracking i as a concrete value, so every explored
 * path that reaches the marker resolves p's region back to items's own.
 * Unlike dn_expand.c's/parse.c's/timer.c's real, still-necessary uses of
 * this marker (loop-carried pointers where widening genuinely loses the
 * region on SOME but not all explored paths -- see
 * recordSharedProvenanceMarkerObservation()'s own comment), this loop
 * must still report "marker is redundant" once every explored path has
 * been accounted for: proof that accumulating across paths does not, by
 * itself, make a genuinely-provable-everywhere marker look necessary. */
long redundant_marker_loop_same_array(int *items, int count) {
  long total = 0;
  int *p = items;
  int i;
  for (i = 0; i < count; i++) {
    total += unsafe_assume_shared_provenance(p - items); /* pointer-provenance-expect */
    p++;
  }
  return total;
}
