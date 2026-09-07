/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tsearch/tfind/tdelete/twalk: an unbalanced binary search tree.  POSIX
 * does not require any particular balancing (tsearch.html DESCRIPTION
 * only promises the comparator's total order is respected), so a plain
 * BST is a conforming implementation; worst case O(n) per operation on
 * already-sorted input, same as glibc's documented behaviour before it
 * grew red-black balancing as a non-standard extra.
 *
 * Node layout: struct node's first member is the key pointer, so a
 * struct node * can be handed back to the caller reinterpreted as a
 * "pointer to a pointer to key" (void **) per tsearch.html's return
 * value wording -- *result yields the stored key, matching glibc/BSD
 * behaviour that programs written against this API rely on.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <search.h>
#include <stdlib.h>

struct node {
	const void *key;
	struct node *left, *right;
};

void *tsearch(const void *key, void **rootp, int (*compar)(const void *, const void *))
{
	struct node **p;

	if (!rootp) return NULL;

	p = (struct node **)rootp;
	while (*p) {
		int c = compar(key, (*p)->key);
		if (c == 0) return *p;
		p = c < 0 ? &(*p)->left : &(*p)->right;
	}

	*p = malloc(sizeof **p);
	if (!*p) return NULL;
	(*p)->key = key;
	(*p)->left = (*p)->right = NULL;
	return *p;
}

void *tfind(const void *key, void *const *rootp, int (*compar)(const void *, const void *))
{
	struct node *n;

	if (!rootp) return NULL;
	n = *(struct node *const *)rootp;
	while (n) {
		int c = compar(key, n->key);
		if (c == 0) return n;
		n = c < 0 ? n->left : n->right;
	}
	return NULL;
}

/* Recursively free a subtree's nodes without touching caller key storage
 * (tdelete.html says nothing about freeing keys -- they are the
 * application's, same contract as hdestroy() below). */
// NOLINTNEXTLINE(misc-no-recursion) -- the operation intentionally follows the caller-provided binary-tree height
static void free_subtree(struct node *n)
{
	if (!n) return;
	free_subtree(n->left);
	free_subtree(n->right);
	free(n);
}

void *tdelete(const void *__restrict key, void **__restrict rootp,
	      int (*compar)(const void *, const void *))
{
	struct node **p, *parent, *target;

	if (!rootp) return NULL;

	parent = NULL;
	p = (struct node **)rootp;
	for (;;) {
		if (!*p) return NULL;	/* not found */
		{
			int c = compar(key, (*p)->key);
			if (c == 0) break;
			parent = *p;
			p = c < 0 ? &(*p)->left : &(*p)->right;
		}
	}

	target = *p;
	if (target->left && target->right) {
		/* Two children: splice in the in-order predecessor (the
		 * rightmost node of the left subtree) in target's place,
		 * then delete that predecessor node from where it was. */
		struct node **pp = &target->left;
		struct node *pred;
		while ((*pp)->right) pp = &(*pp)->right;
		pred = *pp;
		*pp = pred->left;	/* unlink pred (it has no right child) */
		pred->left = target->left;
		pred->right = target->right;
		*p = pred;
	} else {
		*p = target->left ? target->left : target->right;
	}
	free(target);

	/* "a pointer to the parent of the deleted node" -- parent, from
	 * the search above, is exactly the node whose child link was just
	 * rewritten. "... or an unspecified non-null pointer if the
	 * deleted node was the root node" -- rootp itself qualifies. */
	if (!parent) return (void *)rootp;
	return parent;
}

// NOLINTNEXTLINE(misc-no-recursion) -- the operation intentionally follows the caller-provided binary-tree height
static void trecurse(struct node *n, void (*action)(const void *, VISIT, int), int depth)
{
	if (!n->left && !n->right) {
		action(n, leaf, depth);
		return;
	}
	action(n, preorder, depth);
	if (n->left) trecurse(n->left, action, depth + 1);
	action(n, postorder, depth);
	if (n->right) trecurse(n->right, action, depth + 1);
	action(n, endorder, depth);
}

void twalk(const void *root, void (*action)(const void *, VISIT, int))
{
	if (root) trecurse((struct node *)root, action, 0);
}

// NOLINTEND(misc-include-cleaner)
