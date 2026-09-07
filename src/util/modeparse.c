/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See modeparse.h for the grammar this implements and the documented
 * gap (X/s/t/permcopy are not supported -- refused, not approximated).
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "modeparse.h"
#include "util.h"
#include "ownership_stubs.h" /* __ownership_pointer_nonnull(): parse_clause() advances *pp forward from a nonnull spec, through a T** out-parameter the checker cannot trace back to a nonnull constraint on c */

static int is_octal_digit(char c) { return c >= '0' && c <= '7'; }

/* who-class index order used throughout this file: user, group, other. */
static const int class_shift[3] = { 6, 3, 0 };
static const unsigned class_bit[3] = { 1, 2, 4 }; /* matches the wholist below */

/* Applies one `op perm` action, already parsed, to every who-class named
 * by `effwho` (a combination of the class_bit[] values above).
 * `mask_who` carries the class_bit()s for which perm must still be
 * filtered by the caller's umask -- set for every class when the clause
 * had no explicit who (chmod(1p)'s umask rule, quoted in modeparse.h),
 * clear otherwise. */
static void apply_action(mode_t *cur, unsigned effwho, unsigned mask_who, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                          char op, unsigned perm, mode_t umask_bits)
{
	int i;
	for (i = 0; i < 3; i++) {
		mode_t p, classmask;
		if (!(effwho & class_bit[i])) continue;
		p = (mode_t)perm;
		if (mask_who & class_bit[i])
			p &= ~((umask_bits >> class_shift[i]) & 7u);
		p = (mode_t)(p << class_shift[i]);
		classmask = (mode_t)(7 << class_shift[i]);
		switch (op) {
		case '+': *cur |= p; break;
		case '-': *cur &= ~p; break;
		case '=': *cur = (mode_t)((*cur & ~classmask) | p); break;
		default: break; /* unreachable: caller only passes +/-/= */
		}
	}
}

/* One `[who...] (op [perm...])+` clause, starting at *pp. Returns 0 and
 * advances *pp past the clause (to the next ',' or the terminating NUL)
 * on success, -1 (with no diagnostic of its own -- the caller has `spec`
 * for a better message) if the clause is malformed. */
static int parse_clause(const char **pp, mode_t *cur, mode_t umask_bits)
{
	const char *c = *pp;
	unsigned who = 0;
	int any_who = 0;
	unsigned effwho, mask_who;

	for (; *c == 'u' || *c == 'g' || *c == 'o' || *c == 'a'; c++) {
		any_who = 1;
		switch (*c) {
		case 'u': who |= 1u; break;
		case 'g': who |= 2u; break;
		case 'o': who |= 4u; break;
		case 'a': who |= 1u | 2u | 4u; break;
		default: break; /* unreachable: loop condition already restricts *c to u/g/o/a */
		}
	}
	if (*c != '+' && *c != '-' && *c != '=') return -1;

	effwho = any_who ? who : (1u | 2u | 4u);
	mask_who = any_who ? 0u : (1u | 2u | 4u);

	while (*c == '+' || *c == '-' || *c == '=') {
		char op = *c++;
		unsigned perm = 0;
		for (; *c == 'r' || *c == 'w' || *c == 'x'; c++) {
			switch (*c) {
			case 'r': perm |= 4u; break;
			case 'w': perm |= 2u; break;
			case 'x': perm |= 1u; break;
			default: break; /* unreachable: loop condition already restricts *c to r/w/x */
			}
		}
		apply_action(cur, effwho, mask_who, op, perm, umask_bits);
	}
	*pp = c;
	return 0;
}

int __util_parse_mode(const char *prog, const char *spec, mode_t base, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                       mode_t umask_bits, mode_t *out)
{
	if (!*spec) goto bad;

	if (is_octal_digit(*spec)) {
		/* chmod(1p): an octal number "formed by OR-ing together"
		 * the desired bits -- taken to mean the whole operand must
		 * be octal digits, up to the 4 that reach S_ISUID/S_ISGID/
		 * S_ISVTX as well as the permission bits. */
		char *end;
		unsigned long v = strtoul(spec, &end, 8);
		if (*end || v > 07777ul) goto bad;
		*out = (mode_t)v;
		return 0;
	}

	{
		mode_t cur = base;
		const char *c = spec;
		for (;;) {
			if (parse_clause(&c, &cur, umask_bits) < 0) goto bad;
			/* parse_clause() only ever advances *pp forward from its
			 * own nonnull starting value (never sets it NULL), but
			 * that fact does not survive the T** out-parameter back
			 * to this caller's own analysis. */
			__ownership_pointer_nonnull(c);
			if (*c == ',') { c++; continue; }
			if (*c == 0) break;
			goto bad;
		}
		*out = cur & 07777;
		return 0;
	}

bad:
	__util_diagf("%s: invalid mode: '%s'\n", prog, spec);
	return -1;
}

// NOLINTEND(misc-include-cleaner)
