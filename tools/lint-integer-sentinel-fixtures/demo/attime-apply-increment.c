/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT a wired-in regression fixture (lint.sh's fixture loop only globs
 * tools/lint-integer-sentinel-fixtures/*.c directly, not this demo/
 * subdirectory) -- this is a one-off, isolated demonstration that
 * ntlibc.IntegerSentinel has real teeth against a real bug SHAPE, requested
 * by the mechanism's own design task. It is a byte-for-byte structural copy
 * of src/util/attime.c's own static apply_increment()/maybe_increment()
 * (as they exist in this tree today, unmodified), with exactly one line
 * added: `integer_sentinel(-1)` on apply_increment's own declaration,
 * documenting the (time_t)-1 convention its body already uses twice
 * (localtime_r() failure, and the closing unreachable default).
 *
 * Investigation for this task could not find an already-fixed-today commit
 * whose defect reduces to "one literal scalar sentinel unchecked before
 * arithmetic/cast/index" -- src/util/timeout.c's real parse_duration()
 * defect (commit 1c4fc3b2) turned out to be a floating-point
 * finiteness/range precondition (NaN/+inf both evade a plain "v < 0"
 * check), which is categorically outside what integer_sentinel(value)
 * covers by design (see include/ownership.h's own comment: the proof goes
 * through SValBuilder::makeIntVal, which has no IEEE-754 equality
 * semantics); crontime.c/csplit.c/dd.c/attime.c's OWN already-fixed
 * increment-count bug are all range-or-overflow bugs (a broader, different
 * obligation a future excluded_range()-shaped token would cover, not this
 * one). This file instead reproduces the exact-fit shape found while
 * auditing that same bug class: apply_increment() genuinely returns a
 * literal (time_t)-1 sentinel, and its one real caller in the current tree,
 * maybe_increment(), forwards that return value without ever checking it --
 * exactly the "unchecked scalar sentinel reaches further use" shape this
 * checker exists to flag. Whether -1 is reachable in practice (localtime_r()
 * failing on a real base time) was not independently confirmed; this file
 * demonstrates the MECHANISM's finding on the exact real code shape, not a
 * confirmed live CVE, and nothing under src/ was modified for it. */

typedef long time_t;

#define integer_sentinel(value) \
	__attribute__((annotate("qual:integer_sentinel=" #value)))

struct tm { int tm_mon; int tm_year; int tm_isdst; };
int localtime_r(const time_t *, struct tm *);
time_t mktime(struct tm *);

enum period { P_MINUTE, P_HOUR, P_DAY, P_WEEK, P_MONTH, P_YEAR };

/* Verbatim shape of src/util/attime.c's own apply_increment(), with only
 * integer_sentinel(-1) added to its declaration. */
integer_sentinel(-1)
static time_t apply_increment(time_t base, long n, enum period p)
{
	switch (p) {
	case P_MINUTE: return base + n * 60;
	case P_HOUR:   return base + n * 3600;
	case P_DAY:    return base + n * 86400;
	case P_WEEK:   return base + n * 7 * 86400;
	case P_MONTH:
	case P_YEAR: {
		struct tm tmv;
		if (!localtime_r(&base, &tmv)) return (time_t)-1;
		if (p == P_MONTH) tmv.tm_mon += (int)n;
		else tmv.tm_year += (int)n;
		tmv.tm_isdst = -1;
		return mktime(&tmv);
	}
	}
	return (time_t)-1;
}

/* Verbatim shape of src/util/attime.c's own maybe_increment(), trimmed to
 * just the two call sites that forward apply_increment()'s return value
 * with no check -- the real file's own word-parsing/strtol() plumbing
 * around them is irrelevant to this checker and omitted. Neither `return`
 * here is itself flagged, correctly: a bare pass-through is not yet an
 * arithmetic/cast/index USE, so nothing unsound has happened on this
 * statement alone. The point of keeping the wrapper (rather than calling
 * apply_increment() directly from seconds_until below) is to prove the
 * tracked value survives being forwarded through an ordinary, unmarked
 * helper -- ntlibc.IntegerSentinel's checkPostCall only tags a value at the
 * exact call to a marked function, so this only stays flagged downstream
 * because Clang's own inliner substitutes maybe_increment_plus()'s body at
 * its call site, carrying the identical tracked symbol through; a helper
 * too large for the analyzer's default inlining budget would silently
 * break this chain, a real, honest limit of a single-TU, symbolic-execution
 * analysis (see this checker's own top-of-class comment for the design
 * trade-off, and this task's final report for why this is called out
 * explicitly rather than left implicit). */
static time_t maybe_increment_next(enum period p, time_t base)
{
	return apply_increment(base, 1, p);
}

static time_t maybe_increment_plus(long v, enum period p, time_t base)
{
	return apply_increment(base, v, p);
}

/* Downstream use further reinforcing why an unchecked -1 here is a real
 * hazard, not a harmless pass-through: the real caller chain (attime.c's
 * __attime_parse -> its own arithmetic against "now") eventually casts or
 * compares this exact value the same way. This is the one line this demo
 * actually expects ntlibc.IntegerSentinel to flag. */
int seconds_until(time_t deadline, time_t now)
{
	time_t incremented = maybe_increment_plus(3, P_DAY, deadline);
	return (int)(incremented - now); /* integer-sentinel-expect */
}

/* maybe_increment_next()'s own call site, included only to show the same
 * "next month"/"next year" path (n=1, calendar arithmetic) reaches the
 * checker too -- localtime_r() failing on a real base time is the one
 * concrete way apply_increment() actually returns -1 rather than a
 * computed value. */
int seconds_until_next(enum period p, time_t base, time_t now)
{
	time_t incremented = maybe_increment_next(p, base);
	return (int)(incremented - now); /* integer-sentinel-expect */
}

/* Positive control: the real, correct fix for this shape (check the
 * sentinel before using the value further) silences the checker on the
 * exact same call chain -- proving the two findings above come from a real
 * missing check, not from an unconditional "any call to apply_increment is
 * flagged" rule. */
int seconds_until_guarded(time_t deadline, time_t now)
{
	time_t incremented = maybe_increment_plus(3, P_DAY, deadline);
	if (incremented == (time_t)-1)
		return -1;
	return (int)(incremented - now);
}
