/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The `-t tablist` grammar shared, verbatim, between expand(1p) and
 * unexpand(1p) -- XCU expand(1p) OPTIONS: "tablist ... If a single
 * number is given, tabs shall be set that number of column positions
 * apart instead of the default 8 ... [if multiple,] the application
 * shall ensure that it consists of a list of two or more positive
 * decimal integers, separated by <blank> or <comma> characters, in
 * ascending order."  unexpand(1p)'s own -t bullet is the identical
 * grammar for the identical option-argument (and its own DESCRIPTION
 * adds: "When -t is specified, the presence or absence of the -a option
 * shall be ignored; conversion shall not be limited to the processing
 * of leading <blank> characters" -- unexpand.c's own code applies that
 * rule, not this parser).
 *
 * Declared in a header of its own rather than folded into
 * src/internal/util.h's flat function list, unlike src/util/cp.c's
 * __util_copy_regular_file() and friends: those take and return plain
 * types util.h's callers already see, where struct tablist itself (not
 * just the three functions over it) is what expand.c/unexpand.c need,
 * and util.h has no struct definitions of its own to extend -- a
 * forward declaration there would still send both callers here for the
 * real definition, so this file is the one honest place for both.  Real,
 * non-trivial grammar (comma/blank splitting, strict-ascending
 * validation, single-number vs list disambiguation) genuinely shared by
 * two callers, not copied, is what earns it a declaration anywhere
 * rather than being duplicated in both -- the same bar src/internal/
 * util.h's own cp/mv/rm section states for its three.
 *
 * This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard and its own declarations
 * so they cannot collide with user code.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_UTIL_TABLIST_H
#define _NTLIBC_UTIL_TABLIST_H

#include <stddef.h>

/* Either a single repeat interval (tab stops at every `interval`
 * columns: 1, 1+interval, 1+2*interval, ...) or an explicit strictly-
 * ascending list of column numbers -- never both.  `interval` is 0 when
 * `stops`/`nstops` are the live members, so a caller can tell them apart
 * with one comparison. */
struct tablist {
	int interval;
	long *stops;
	size_t nstops;
};

/* Parses expand(1p)/unexpand(1p)'s shared -t grammar out of `spec`.
 * Returns 0 and fills *out on success; -1 (out untouched) on anything
 * that grammar does not define: an empty spec, a non-digit, a value
 * <= 0, or a list that is not strictly ascending -- refused rather than
 * silently reordered or clamped, this project's usual rule for a
 * grammar with no defined fallback. */
int __util_tablist_parse(const char *spec, struct tablist *out) __attribute__((nonnull(1, 2)));

/* Releases stops[] (a no-op, safely, for the single-interval case where
 * it is already NULL). */
void __util_tablist_free(struct tablist *tl) __attribute__((nonnull(1)));

/* The column a <tab> typed at 1-based column `col` lands on: the
 * smallest tab-stop column strictly greater than `col`.  Always exists
 * for a single-interval tablist; returns 0 for an explicit list once
 * `col` is at or past its last entry, meaning "no further stop" --
 * expand(1p)'s own words for that case: "the <tab> shall be replaced by
 * a single <space>". */
long __util_tablist_next_stop(const struct tablist *tl, long col) __attribute__((nonnull(1)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
