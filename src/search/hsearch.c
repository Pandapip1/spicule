/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * hcreate/hsearch/hdestroy: one process-wide open-addressing hash
 * table, exactly as hcreate.html specifies -- "Only one hash table may
 * be active at a time." hdestroy() frees the table's own bookkeeping
 * only; ENTRY.key/.data are the caller's, never touched here (same
 * rule tdelete()/tsearch.c's free_subtree() follows for tree nodes).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <search.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct slot {
	char *key;	/* NULL: empty; (char *)-1 unused here, no tombstones needed (no delete op) */
	void *data;
	unsigned long h;
	int used;
};

static struct slot *table;
static size_t table_size;

/* FNV-1a: fine for short C-string keys, deliberately wraps mod 2^32
 * (unsigned arithmetic, not UB) -- __wraps documents that instead of
 * letting -fsanitize=unsigned-integer-overflow flag it as accidental. */
/* s is dereferenced unconditionally: `while (*s)` evaluates it at
 * least once regardless of content, and this file's one real call
 * site (`hash_str(item.key)`) always passes a real ENTRY key, never a
 * value that could legitimately be null. */
__wraps static unsigned long hash_str(const char *s) __attribute__((nonnull(1)));
__wraps static unsigned long hash_str(const char *s)
{
	unsigned long h = 2166136261UL;
	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 16777619UL;
	}
	return h;
}

int hcreate(size_t nel)
{
	size_t cap;

	if (table) hdestroy();

	/* hcreate.html RETURN VALUE: "shall return 0 if it cannot allocate
	 * sufficient space for the table".
	 *
	 * The padding below is `nel + nel/2 + 8` in size_t, and that
	 * arithmetic WRAPS for a large enough nel -- silently producing a
	 * tiny capacity that calloc() then satisfies easily, so hcreate()
	 * reported success for a table that could not come close to holding
	 * nel entries.  Measured before this check: hcreate((SIZE_MAX/3)*2 +
	 * 2) returned 1 and the 11th ENTER returned NULL -- ten slots
	 * reported as sufficient for 1.2e19 entries.  That is exactly the
	 * case the RETURN VALUE clause exists to report, so the wrap turned
	 * a required failure into a false success.
	 *
	 * Refusing up front is the fix rather than checking after the fact,
	 * because after the wrap there is nothing left to detect: the sum is
	 * a perfectly ordinary small number.  calloc() cannot cover this
	 * either -- it guards its OWN multiply (m > SIZE_MAX/n) and is handed
	 * an already-wrapped cap.
	 *
	 * The bound is stated so it cannot itself overflow: dividing first,
	 * never adding first.  [ENOMEM] is hcreate.html's one listed error
	 * ("may fail"), and is the honest description of a request whose
	 * table could never be allocated. */
	if (nel > (((size_t)-1 - 8) / 3) * 2) { errno = ENOMEM; return 0; }
	/* "may be adjusted upward" -- pad for load factor, keep it a
	 * comfortable margin above nel so linear probing stays cheap. */
	cap = nel + nel / 2 + 8;
	table = calloc(cap, sizeof *table);
	if (!table) return 0;
	table_size = cap;
	return 1;
}

void hdestroy(void)
{
	free(table);
	table = NULL;
	table_size = 0;
}

/* table[i] below is a disclosed, deliberately unmarked residual, not
 * an oversight: table is a file-static global, not a parameter of
 * this function at all (hsearch() takes item by value and action, no
 * pointer parameter table could describe) -- the same "global-array
 * residual, not expressible via nonnull" class d24fe86's own commit
 * already established for src/env/setenv.c's putenv_strings[i] and
 * src/thread/{children,fork,wait}.c's __children[i]. `if (!table)
 * return NULL;` right above IS the real guard; the intervening
 * hash_str() call between it and this loop's own table[i] access is
 * enough for a conservative interprocedural analysis to no longer
 * trust that a global's value survived an opaque call, which is a
 * different, structural limitation from an actual missing check. */
ENTRY *hsearch(ENTRY item, ACTION action)
{
	unsigned long h;
	size_t i, start, size, remaining;

	/* table_size is published and cleared with table.  Check both halves of
	 * that invariant here so the modulo below is locally protected even if a
	 * future initialization path is changed incompletely. */
	if (!table || !table_size) return NULL;
	size = table_size;

	h = hash_str(item.key);
	start = h % size;
	/* Linear probing visits each slot exactly once before the table is
	 * full. The decrement lives in the loop's own increment clause, not
	 * the condition (`remaining-- > 0` used to spell it, and wrapped
	 * size_t 0 to SIZE_MAX on the exiting check -- defined by C99
	 * 6.2.5p9 and discarded the instant the loop exited, so never a
	 * memory-safety defect, but exactly what INTSAN
	 * (-fsanitize=unsigned-integer-overflow, tools/asan-build.sh, fatal
	 * for library code) exists to flag -- GitHub issues #9/#10, a
	 * 9th ENTER into an already-full 8-slot table via
	 * fuzz/fuzz_search.c). Spelled this way, the decrement only ever
	 * runs on a `remaining` already known to be >= 1. */
	for (i = start, remaining = size; remaining > 0;
	     remaining--, i = (i + 1) % size) {
		if (!table[i].used) {
			if (action != ENTER) return NULL;
			table[i].key = item.key;
			table[i].data = item.data;
			table[i].h = h;
			table[i].used = 1;
			return (ENTRY *)&table[i];
		}
		if (table[i].h == h && strcmp(table[i].key, item.key) == 0)
			return (ENTRY *)&table[i];	/* ENTER on a hit: leave existing data alone */
	}

	return NULL;	/* table full */
}

// NOLINTEND(misc-include-cleaner)
