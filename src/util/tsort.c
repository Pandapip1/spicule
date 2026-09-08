/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tsort(1p): `tsort [file]`.  "The standard input (or a single file
 * operand) shall consist of pairs of items (non-empty strings)
 * separated by <blank> characters ... Pairs of different items
 * indicate ordering.  Pairs of identical items indicate presence, but
 * not ordering."  Output: "a totally ordered list of items consistent
 * with [that] partial ordering", one item per line.
 *
 * An odd number of whitespace-separated tokens is malformed input (the
 * pairs don't close) and is refused with a diagnostic and a nonzero
 * exit rather than silently dropping the trailing token.
 *
 * ALGORITHM: Kahn's algorithm (repeatedly output any node with no
 * remaining unsatisfied predecessor, then drop its outgoing edges) --
 * chosen specifically because it makes cycle detection fall out for
 * free: standard textbook proof is that Kahn's algorithm empties the
 * whole graph if and only if the graph is acyclic, so "nodes remain but
 * none has indegree zero" *is* "there is a cycle", not a heuristic
 * approximation of one.  XCU does not constrain which valid ordering to
 * pick when more than one exists (nothing in tsort(1p) says so, and
 * nothing here claims to match any particular real implementation's tie
 * -break) -- this file breaks ties by node-discovery order (the order
 * each name was first seen in the input), which is simply whichever
 * deterministic choice Kahn's algorithm's ready-queue naturally makes
 * with a FIFO, not a claim that this is *the* required order.
 *
 * CYCLE DIAGNOSTIC: real XCU tsort(1p) text is silent on the exact
 * wording (its own EXTENDED DESCRIPTION only requires that "The
 * standard error shall be used only for diagnostic messages"), but a
 * cycle is unambiguously an error case per plain reading of "totally
 * ordered list ... consistent with a partial ordering" -- an input with
 * a cycle has no such ordering to produce.  This file stops Kahn's
 * algorithm the moment it stalls (rather than looping forever waiting
 * for a zero-indegree node that will never appear), reports every
 * still-unresolved node by name on stderr, and exits nonzero; whatever
 * prefix was already validly ordered has already been written to
 * stdout by that point and is left there rather than un-written, since
 * it is a real, correct partial answer and not part of the cycle.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "util.h"
#include "ownership_stubs.h"

/* name/succ withtok(heap_allocated): lets AllocationLifetimeChecker see
 * get_or_add()'s and add_edge()'s stores into these fields as owning
 * moves, not leaks; freed once in __util_tsort_main()'s cleanup loop. */
struct node {
	char *name withtok(heap_allocated);
	size_t indeg;
	int *succ withtok(heap_allocated);
	size_t nsucc, cap;
	int done;
};

static struct node *nodes withtok(heap_allocated); /* same reason, for get_or_add()'s `nodes = g` */
static size_t nnodes, nodecap;

static int find_node(const char *name withtok(null_terminated))
{
	size_t i;
	for (i = 0; i < nnodes; i++) {
		/* nodes[i].name has no field-level withtok spelling to carry
		 * "always populated via strdup() in get_or_add()"; restated by
		 * hand through a local, since restating it directly on the
		 * global-reachable field would be re-widened away before
		 * strcmp() below ever saw it. */
		char *nm = nodes[i].name;
		unsafe_assume_string_terminated(nm);
		if (!strcmp(nm, name)) return (int)i;
	}
	return -1;
}

static int get_or_add(const char *name withtok(null_terminated))
{
	int idx = find_node(name);
	if (idx >= 0) return idx;

	if (nnodes >= nodecap) {
		size_t newcap;
		struct node *g;
		if (!__util_array_capacity(nodecap, nnodes, 1, 64, sizeof *nodes, &newcap)) return -1;
		g = __util_reallocarray(nodes, newcap, sizeof *nodes);
		if (!g) return -1;
		nodes = g;
		nodecap = newcap;
	}
	nodes[nnodes].name = strdup(name);
	nodes[nnodes].indeg = 0;
	nodes[nnodes].succ = 0;
	nodes[nnodes].nsucc = 0;
	nodes[nnodes].cap = 0;
	nodes[nnodes].done = 0;
	return (int)nnodes++;
}

static int add_edge(int a, int b)
{
	if (nodes[a].nsucc >= nodes[a].cap) {
		size_t newcap;
		int *g;
		if (!__util_array_capacity(nodes[a].cap, nodes[a].nsucc, 1, 8,
		    sizeof *nodes[a].succ, &newcap)) return -1;
		g = __util_reallocarray(nodes[a].succ, newcap, sizeof *nodes[a].succ);
		if (!g) return -1;
		nodes[a].succ = g;
		nodes[a].cap = newcap;
	}
	nodes[a].succ[nodes[a].nsucc++] = b;
	nodes[b].indeg++;
	return 0;
}

withtok(heap_allocated)
static char *slurp(FILE *f, size_t *outlen)
{
	size_t cap = 65536, len = 0;
	char *buf = malloc(cap);
	size_t got;

	if (!buf) return 0;
	for (;;) {
		if (len == cap) {
			size_t newcap;
			if (!__util_array_capacity(cap, len, 1, 65536, 1, &newcap)) {
				free(buf); return 0;
			}
			{
				char *g = realloc(buf, newcap);
				if (!g) { free(buf); return 0; }
				buf = g;
				cap = newcap;
			}
		}
		unsafe_assume_writable_span(buf + len, cap - len);
		got = fread(buf + len, 1, cap - len, f);
		len += got;
		if (got == 0) break;
	}
	*outlen = len;
	return buf;
}

int __util_tsort_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	FILE *f = stdin;
	int have_file = 0;
	char *buf;
	size_t len, pos = 0;
	char **tok = 0;
	size_t ntok = 0, tokcap = 0;
	size_t i;
	int cycle;
	size_t queue_head, ready_count;

	if (argc > 2) {
		__util_diagf("tsort: too many operands\n");
		return 1;
	}
	if (argc == 2) {
		/* restate argv[1]'s null-termination at this now-in-range
		 * index; the checker can't derive it from argc == 2 alone. */
		unsafe_assume_string_terminated(argv[1]);
		if (!strcmp(argv[1], "-")) {
			f = stdin;
		} else {
			f = fopen(argv[1], "r");
			if (!f) { __util_diagf("tsort: %s: %s\n", argv[1], strerror(errno)); return 1; }
			have_file = 1;
		}
	}

	buf = slurp(f, &len);
	if (!buf) {
		int saved = errno ? errno : ENOMEM;
		/* Allocation/read failure is primary; close only releases the input. */
		if (have_file) (void)fclose(f);
		errno = saved;
		__util_diagf("tsort: out of memory\n");
		return 1;
	}
	if (have_file && fclose(f) != 0) { free(buf); return 1; }

	/* Tokenize on runs of whitespace. */
	while (pos < len) {
		size_t start;
		while (pos < len && isspace((unsigned char)buf[pos])) pos++;
		if (pos >= len) break;
		start = pos;
		while (pos < len && !isspace((unsigned char)buf[pos])) pos++;
		if (ntok >= tokcap) {
			size_t newcap;
			char **g;
			if (!__util_array_capacity(tokcap, ntok, 1, 64, sizeof *tok, &newcap)) {
				__util_diagf("tsort: out of memory\n"); free((void *)tok); free(buf); return 1;
			}
			g = (char **)__util_reallocarray((void *)tok, newcap, sizeof *tok);
			if (!g) { __util_diagf("tsort: out of memory\n"); free((void *)tok); free(buf); return 1; }
			tok = g;
			tokcap = newcap;
		}
		buf[pos] = 0; /* pos <= len; slurp()'s cap is always > len at EOF, so
		                 a write at buf[len] is still inside the allocation. */
		tok[ntok++] = buf + start;
		pos++;
	}

	if (ntok % 2) {
		__util_diagf("tsort: odd number of tokens (%lu) -- input is not pairs\n", (unsigned long)ntok);
		free((void *)tok);
		free(buf);
		return 1;
	}

	for (i = 0; i < ntok / 2; i++) {
		int a, b;
		/* Each tok[] entry was NUL-terminated in the tokenizing loop
		 * above; re-proven here for get_or_add()'s withtok(null_terminated)
		 * parameter at this call site. */
		unsafe_assume_string_terminated(tok[2 * i]);
		unsafe_assume_string_terminated(tok[2 * i + 1]);
		a = get_or_add(tok[2 * i]);
		b = get_or_add(tok[2 * i + 1]);
		if (a < 0 || b < 0) { __util_diagf("tsort: out of memory\n"); free((void *)tok); free(buf); return 1; }
		if (a != b && add_edge(a, b) < 0) {
			__util_diagf("tsort: out of memory\n"); free((void *)tok); free(buf); return 1;
		}
	}
	free((void *)tok);
	free(buf);

	{
		int *queue = __util_mallocarray(nnodes ? nnodes : 1, sizeof *queue);
		size_t qtail = 0;
		size_t n, remaining;

		if (!queue && nnodes) { __util_diagf("tsort: out of memory\n"); return 1; }

		for (n = 0; n < nnodes; n++)
			if (nodes[n].indeg == 0) queue[qtail++] = (int)n;

		queue_head = 0;
		ready_count = 0;
		for (remaining = nnodes; remaining > 0; remaining--) {
			int cur;
			size_t s;
			if (queue_head >= qtail) break; /* stalled: a cycle remains */
			cur = queue[queue_head++];
			ready_count++;
			nodes[cur].done = 1;
			printf("%s\n", nodes[cur].name);
			for (s = 0; s < nodes[cur].nsucc; s++) {
				int nb = nodes[cur].succ[s];
				/* Each node's indegree reaches zero at most once, so
				 * qtail can never exceed nnodes here. */
				if (--nodes[nb].indeg == 0) queue[qtail++] = nb;
			}
		}
		free(queue);
	}

	cycle = ready_count < nnodes;
	if (cycle) {
		size_t n;
		__util_diagf("tsort: cycle in input; unresolved:");
		for (n = 0; n < nnodes; n++)
			if (!nodes[n].done) __util_diagf(" %s", nodes[n].name);
		__util_diagf("\n");
	}

	for (i = 0; i < nnodes; i++) {
		free(nodes[i].name);
		free(nodes[i].succ);
	}
	free(nodes);

	return cycle ? 1 : 0;
}
