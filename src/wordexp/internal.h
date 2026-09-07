/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private glue between this directory's few translation units. Nothing
 * here is part of spicule's public surface or shared with any other
 * directory -- src/internal/libc.h is the place for that, and neither
 * of the pieces declared below belongs there: each is a single-purpose
 * helper only wordexp.c itself calls, split into its own file purely
 * because the parsing/evaluation logic involved (a C-expression
 * evaluator; a subprocess-and-pipe dance) is substantial enough to
 * clutter wordexp.c's own single left-to-right scan if inlined there.
 */
#ifndef WORDEXP_INTERNAL_H
#define WORDEXP_INTERNAL_H

#include <wordexp.h>

/* src/wordexp/arith.c: evaluate `expr` (a NUL-terminated string already
 * extracted from between a "$((" and its matching "))", not including
 * either delimiter) as the POSIX arithmetic expression XBD 2.6.4
 * describes -- signed long arithmetic, ISO C 6.5 operator semantics
 * minus sizeof/++/--/control-flow, with a bare identifier or a $NAME
 * reference read from/assigned to via getenv()/setenv() (this
 * implementation's only notion of a "shell variable"). On success
 * returns 0 with *result holding the value; on failure returns a
 * WRDE_* code (see arith.c's own header comment for exactly which, and
 * why no dedicated WRDE_ code exists for "bad arithmetic" so WRDE_SYNTAX
 * does double duty). flags is the flags wordexp() itself was called
 * with -- only WRDE_UNDEF is consulted (an undefined variable inside
 * the expression is worth 0 unless the caller asked to be told).
 *
 * result is required: `*result = arith_comma(&a);` in arith.c's own
 * body runs before any error check, on every call, regardless of
 * whether evaluation ultimately succeeds. expr is NOT marked: this
 * function only ever assigns it into struct arith's own `p` field
 * (`a.p = expr;`), never dereferences it directly itself -- every
 * actual dereference happens through that field, inside arith.c's own
 * recursive-descent functions, which is where that requirement is
 * expressed instead (see arith.c's own struct arith *a parameters). */
int __wordexp_arith(const char *expr, long *result, int flags)
    __attribute__((nonnull(2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
