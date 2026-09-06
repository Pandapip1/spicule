/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fixtures for ntlibc.SizeCast's pointer-difference extension (see
 * tools/clang/SizeCastChecker.cpp's CastZ3Proof::
 * provesPointerDifferenceRepresentable() and the mismatched-width
 * SymSymExpr case its own translate() gained alongside it): a pointer
 * difference cast to an unsigned type is safe once Z3 can show the two
 * pointers are ordered (subtrahend <= minuend) from a real, path-sensitive
 * guard, reusing the identical CastZ3BranchFact/getConstraintMap machinery
 * relational.c already exercises for plain integers -- just applied to the
 * SymExpr shape RegionStore's own element-offset arithmetic produces for
 * `end - p` once both pointers resolve to a comparable offset into the
 * same base region. */

typedef unsigned long fixture_size;

/* forward_cursor is exactly the shape found in man.c's man_builtin_pager()
 * and awk_run.c's awk_format(): a fixed `end` pointer and a cursor `p`
 * advanced by a narrower-typed (here `int`) offset before the two are
 * compared and subtracted -- the width mismatch between the offset's own
 * type (int) and the buffer-size type (fixture_size) is exactly what
 * CastZ3Proof::translate()'s SymSymExpr case could not previously combine,
 * and `len` has no upper bound of its own, so provesRepresentable()'s
 * ordinary truncate-through-ptrdiff_t-then-re-widen path cannot rule out a
 * spurious sign-bit wraparound for a hypothetically huge buffer either --
 * only provesPointerDifferenceRepresentable()'s untruncated comparison
 * proves this. */
fixture_size forward_cursor(const char *start, fixture_size len, int n)
{
	const char *p = start, *end = start + len;
	if (n < 1 || n > 100) return 0;
	p = p + n;
	if (p < end)
		return (fixture_size)(end - p);
	return 0;
}

/* Adversarial twin of forward_cursor: the guard that would establish
 * ordering is missing, so n could exceed len and the cast must stay
 * flagged -- confirms the extension only removes a finding it can
 * actually prove, never the mere presence of a pointer subtraction between
 * two same-buffer pointers on its own. */
fixture_size unordered_cursor(const char *start, fixture_size len, int n)
{
	const char *p = start, *end = start + len;
	p = p + n;
	return (fixture_size)(end - p); /* cast-range-expect */
}

/* Adversarial twin of forward_cursor: `end` and `p` are two unrelated
 * pointer parameters, not both derived from one common buffer -- even a
 * `p < end` guard between them carries no real ordering guarantee this
 * extension may trust, since Clang's own analyzer cannot (and must not)
 * relate two entirely independent symbolic regions this way either.
 * (Clang's own RangeConstraintManager already proves this specific shape
 * representable on its own, independent of this extension entirely, via
 * the ordinary assumeInclusiveRange() check checkPreStmt runs before ever
 * reaching CastZ3Proof -- confirmed unchanged on the unmodified checker --
 * so unlike the other two fixtures below this one is not itself a
 * regression probe for the new machinery; it stays here as a record of
 * that fact.) */
fixture_size unrelated_buffers(const char *end, const char *p)
{
	if (p < end)
		return (fixture_size)(end - p);
	return 0;
}

/* A second near-miss, structurally closer to forward_cursor than
 * unrelated_buffers above: two INDEPENDENTLY-advanced cursors/ends from
 * two DIFFERENT buffers, each individually shaped like forward_cursor's
 * own provably-safe pair (an ElementRegion cursor compared and subtracted
 * against a same-shaped end pointer). This stays flagged for a second,
 * independent reason on top of checkPreStmt's own explicit
 * MemRegion::getBaseRegion() equality guard: comparing pointers into two
 * unrelated objects with `<` is itself undefined behavior in C, and
 * Clang's own SValBuilder already refuses to produce a usable relational
 * fact for it (confirmed directly: this fixture stays flagged even with
 * checkPreStmt's SameBaseRegion check deliberately removed, because
 * provesPointerDifferenceRepresentable() still cannot discharge the
 * obligation without one). The explicit getBaseRegion() guard is kept
 * anyway as this class's own principled, independently-verifiable
 * invariant -- a checker's soundness should rest on an explicit check it
 * controls, not on incidentally never reaching the unsound case because
 * some other part of the engine happens to decline first. */
fixture_size unrelated_cursors(const char *a, const char *b,
                               fixture_size blen, int n)
{
	const char *pa = a;
	const char *endb = b + blen;
	pa = pa + n;
	if (pa < endb)
		return (fixture_size)(endb - pa); /* cast-range-expect */
	return 0;
}
