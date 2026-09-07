/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Table shapes for src/internal/unicode_tables.c (generated data) and
 * src/internal/unicode_data.c (hand-written lookups over that data).
 * Kept separate from the generated file itself so regenerating the
 * tables (tools/gen-unicode-tables.py) never needs to touch this header.
 */
#ifndef SPICULE_UNICODE_TABLES_H
#define SPICULE_UNICODE_TABLES_H

#include <stddef.h>

/* A closed interval [lo, hi] of Unicode code points, both inclusive.
 * Every table below is sorted ascending by lo and non-overlapping --
 * tools/gen-unicode-tables.py's coalesce() guarantees that on
 * generation, so lookup can binary-search it. */
struct unicode_range {
	unsigned short lo, hi;
};

/* A single code point's simple case mapping: from maps to to. Sorted
 * ascending by from for binary search; every entry has from != to (an
 * identity mapping carries no information, so the generator drops it). */
struct unicode_casepair {
	unsigned short from, to;
};

#define UNICODE_TABLE(name) \
	extern const struct unicode_range name[]; \
	extern const size_t name##_count

UNICODE_TABLE(unicode_alpha_ranges);     /* Alphabetic */
UNICODE_TABLE(unicode_upper_ranges);     /* Uppercase */
UNICODE_TABLE(unicode_lower_ranges);     /* Lowercase */
UNICODE_TABLE(unicode_digit_ranges);     /* General_Category = Nd */
UNICODE_TABLE(unicode_space_ranges);     /* White_Space */
UNICODE_TABLE(unicode_cntrl_ranges);     /* General_Category = Cc */
UNICODE_TABLE(unicode_xdigit_ranges);    /* Hex_Digit */
UNICODE_TABLE(unicode_blank_ranges);     /* Zs union {TAB} */
UNICODE_TABLE(unicode_notprint_ranges);  /* Cc+Cf+Cs+Co+Cn+Zl+Zp */
UNICODE_TABLE(unicode_combining_ranges); /* Mn+Me (wcwidth 0-width set) */
UNICODE_TABLE(unicode_wide_ranges);      /* East_Asian_Width W or F */

#undef UNICODE_TABLE

extern const struct unicode_casepair unicode_toupper_pairs[];
extern const size_t unicode_toupper_pairs_count;
extern const struct unicode_casepair unicode_tolower_pairs[];
extern const size_t unicode_tolower_pairs_count;

#endif
