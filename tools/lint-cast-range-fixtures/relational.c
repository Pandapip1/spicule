/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fixtures for spicule.SizeCast's CastZ3Proof extension (see
 * tools/clang/SizeCastChecker.cpp's CastZ3Engine/CastZ3Proof/
 * CastZ3BranchFact): a same-domain relational guard between two live
 * symbols, combined with an independent bound on the second symbol,
 * entails a real bound on the first that expressionInterval()/
 * symbolInterval()'s plain interval arithmetic cannot derive on its own. */

typedef unsigned short fixture_word;

/* bounded_by_room is exactly the shape CastZ3Proof exists for: `value` has
 * no bound of its own anywhere in this function, but `room`'s guard
 * (room <= 1000) together with the `value < room` branch taken to reach
 * this cast entails value < 1000, which fits fixture_word.  Proving this
 * needs a fact relating two live symbols -- CastZ3Engine::translate()'s
 * SymSymExpr case, fed by eval::Assume via CastZ3BranchFact -- not a
 * concrete literal bound on value alone. */
fixture_word bounded_by_room(unsigned int value, unsigned int room)
{
	if (room > 1000) return 0;
	return value < room ? (fixture_word)value : (fixture_word)room;
}

/* Adversarial twin of bounded_by_room: room carries no independent bound
 * at all, so `value < room` alone still permits both value and room up to
 * UINT_MAX.  Both branches of the same cast must still be reported --
 * confirms the extension only removes a finding it can actually prove,
 * never the mere presence of a relational guard on its own. */
fixture_word unguarded_room(unsigned int value, unsigned int room)
{
	return value < room ? (fixture_word)value : (fixture_word)room; /* cast-range-expect */
}
