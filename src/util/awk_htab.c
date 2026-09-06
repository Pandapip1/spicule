/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The chained string-keyed hash table src/util/awk_priv.h's own header
 * comment on struct awk_htab describes (global variables, array
 * storage, open streams, the dynamic-regex cache). FNV-1a is used for
 * the hash purely for its simplicity and even bit distribution across
 * short identifier-shaped keys -- awk programs are not adversarial
 * input in the way a network-facing hash table's keys might be, so
 * nothing here defends against deliberately colliding keys.
 */
#include <stdlib.h>
#include <string.h>
#include <features.h>
#include "awk_priv.h"
#include "util.h"

/* `h *= 16777619u` is an intentional, correct multiplicative overflow
 * (wraparound) -- FNV-1a's whole definition is modular arithmetic over
 * size_t's own range, the same "this specific arithmetic wraparound is
 * intentional" case src/search/hsearch.c's own hash_str() and
 * src/stdlib/rand48.c's step() both mark __wraps for, so this is too
 * (this project's INTSAN lint policy would otherwise flag the multiply
 * as an unannotated, and therefore suspicious, overflow). */
__wraps static size_t fnv1a(const char *s)
{
	size_t h = 2166136261u;
	while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
	return h;
}

void awk_htab_init(struct awk_htab *t)
{
	t->buckets = NULL;
	t->nbuckets = 0;
	t->count = 0;
}

static int rehash(struct awk_htab *t)
	__arith_nonzero_field_on_success(0, nbuckets)
{
	size_t newn;
	struct awk_hnode **nb;
	size_t i;

	if (t->nbuckets > (size_t)-1 / 2) return 0;
	newn = t->nbuckets ? t->nbuckets * 2 : 16;
	nb = calloc(newn, sizeof *nb); // NOLINT(bugprone-sizeof-expression) -- nb is awk_hnode**, *nb is awk_hnode*, the array holds pointers

	if (!nb) return 0;
	for (i = 0; i < t->nbuckets; i++) {
		struct awk_hnode *n = t->buckets[i];
		while (n) {
			struct awk_hnode *next = n->next;
			size_t bi = fnv1a(n->key) % newn;
			n->next = nb[bi];
			nb[bi] = n;
			n = next;
		}
	}
	free(t->buckets);
	t->buckets = nb;
	t->nbuckets = newn;
	return 1;
}

void *awk_htab_get(struct awk_htab *t, const char *key)
{
	struct awk_hnode *n;
	if (!t->nbuckets) return NULL;
	n = t->buckets[fnv1a(key) % t->nbuckets];
	for (; n; n = n->next) if (!strcmp(n->key, key)) return n->val;
	return NULL;
}

void **awk_htab_getp(struct awk_htab *t, const char *key)
{
	struct awk_hnode *n;
	size_t bi;

	if (t->nbuckets) {
		bi = fnv1a(key) % t->nbuckets;
		for (n = t->buckets[bi]; n; n = n->next)
			if (!strcmp(n->key, key)) return &n->val;
	}
	/* Grow when the table would exceed a load factor of ~1.0 (or does
	 * not exist yet) -- checked before insertion, not after, so the
	 * new node always lands in the post-grow bucket layout. */
	if (!t->nbuckets || t->count + 1 > t->nbuckets) {
		if (!rehash(t)) return NULL;
	}
	n = malloc(sizeof *n);
	if (!n) return NULL;
	{
		size_t keybytes;
		if (!__util_size_add(strlen(key), 1, &keybytes)) { free(n); return NULL; }
		n->key = malloc(keybytes);
	}
	if (!n->key) { free(n); return NULL; }
	strcpy(n->key, key); // NOLINT(clang-analyzer-security.insecureAPI.strcpy) -- n->key was just sized to strlen(key)+1 immediately above
	n->val = NULL;
	bi = fnv1a(key) % t->nbuckets;
	n->next = t->buckets[bi];
	t->buckets[bi] = n;
	t->count++;
	return &n->val;
}

void awk_htab_del(struct awk_htab *t, const char *key, void (*free_val)(void *))
{
	struct awk_hnode **pp;
	size_t bi;

	if (!t->nbuckets) return;
	bi = fnv1a(key) % t->nbuckets;
	pp = &t->buckets[bi];
	while (*pp) {
		if (!strcmp((*pp)->key, key)) {
			struct awk_hnode *dead = *pp;
			*pp = dead->next;
			if (free_val) free_val(dead->val);
			free(dead->key);
			free(dead);
			t->count--;
			return;
		}
		pp = &(*pp)->next;
	}
}

void awk_htab_free(struct awk_htab *t, void (*free_val)(void *))
{
	size_t i;
	for (i = 0; i < t->nbuckets; i++) {
		struct awk_hnode *n = t->buckets[i];
		while (n) {
			struct awk_hnode *next = n->next;
			if (free_val) free_val(n->val);
			free(n->key);
			free(n);
			n = next;
		}
	}
	free(t->buckets);
	t->buckets = NULL;
	t->nbuckets = 0;
	t->count = 0;
}

void awk_hiter_init(struct awk_hiter *it, struct awk_htab *t)
{
	it->t = t;
	it->bi = 0;
	it->n = NULL;
}

struct awk_hnode *awk_hiter_next(struct awk_hiter *it)
{
	if (it->n && it->n->next) { it->n = it->n->next; return it->n; }
	for (; it->bi < it->t->nbuckets; it->bi++) {
		if (it->t->buckets[it->bi]) {
			it->n = it->t->buckets[it->bi];
			it->bi++;
			return it->n;
		}
	}
	return NULL;
}
