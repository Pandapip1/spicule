/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See src/util/tablist.h for what this grammar is and why it lives here
 * rather than duplicated in src/util/expand.c and src/util/unexpand.c.
 */
#include <stdlib.h>
#include "tablist.h"
#include "util.h"
#include "ownership_stubs.h" /* __ownership_pointer_nonnull() */

int __util_tablist_parse(const char *spec, struct tablist *out)
{
	long *stops = NULL;
	size_t n = 0, cap = 0;
	const char *p = spec;

	if (!*spec) return -1;

	while (*p) {
		char *end;
		long v;

		while (*p == ',' || *p == ' ' || *p == '\t') p++;
		if (!*p) break;

		if (*p < '0' || *p > '9') { free(stops); return -1; }
		v = strtol(p, &end, 10);
		if (end == p || v <= 0) { free(stops); return -1; }
		p = end;
		if (*p && *p != ',' && *p != ' ' && *p != '\t') { free(stops); return -1; }

		/* "in ascending order" -- strict, so a repeated or out-of-order
		 * value is refused rather than silently deduplicated or sorted. */
		if (n && stops[n - 1] >= v) { free(stops); return -1; }

		if (n == cap) {
			size_t newcap;
			long *tmp;
			if (!__util_array_capacity(cap, n, 1, 8, sizeof *stops, &newcap)) { free(stops); return -1; }
			tmp = __util_reallocarray(stops, newcap, sizeof *stops);
			if (!tmp) { free(stops); return -1; }
			stops = tmp;
			cap = newcap;
		}
		stops[n++] = v;
	}
	if (n == 0) { free(stops); return -1; }

	if (n == 1) {
		/* "If a single number is given, tabs shall be set that number
		 * of column positions apart" -- the interval case, not a
		 * one-entry explicit list. */
		out->interval = (int)stops[0];
		out->stops = NULL;
		out->nstops = 0;
		free(stops);
	} else {
		out->interval = 0;
		out->stops = stops;
		out->nstops = n;
	}
	return 0;
}

void __util_tablist_free(struct tablist *tl)
{
	free(tl->stops);
	tl->stops = NULL;
	tl->nstops = 0;
}

long __util_tablist_next_stop(const struct tablist *tl, long col)
{
	if (tl->interval > 0) {
		long i = tl->interval;
		/* Smallest multiple-of-i-plus-1 strictly greater than col --
		 * see this file's header for the column convention (col is
		 * the 1-based column the next character would occupy). */
		return ((col - 1) / i + 1) * i + 1;
	}
	{
		size_t k;
		/* interval == 0 here, so this is the explicit-list case, where
		 * __util_tablist_parse always paired a live stops[] allocation
		 * with nstops > 0 (see struct tablist's own comment) -- a fact
		 * this checker can't trace across the two functions. */
		__ownership_pointer_nonnull(tl->stops);
		for (k = 0; k < tl->nstops; k++)
			if (tl->stops[k] > col) return tl->stops[k];
		return 0;
	}
}
