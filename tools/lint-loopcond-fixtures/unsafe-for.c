/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Each `for` loop below folds an incidental, data-dependent bail-out
 * condition into its own header via `&&`, alongside a genuine structural
 * bound -- exactly the pattern this checker exists to catch. The fix in
 * both cases is the same: keep the range/cursor bound as the for-loop's
 * own condition, and move the flag check into an explicit
 * `if (...) break;` inside the loop body. */

struct node { struct node *next; int value; };

/* 1. Range bound `i < max_attempts` compounded with an incidental
 * success flag `!success` -- the maintainer's own flagship example. */
int retry_up_to(int (*attempt)(void), int max_attempts)
{
	int i;
	int success = 0;
	for (i = 0; i < max_attempts && !success; i++) { /* loopcond-expect */
		success = attempt();
	}
	return success;
}

/* 2. Cursor-vs-NULL bound `p` compounded with an incidental
 * search-found flag `!matched`. */
struct node *find_matching(struct node *head, int target)
{
	struct node *p;
	int matched = 0;
	for (p = head; p && !matched; p = p->next) { /* loopcond-expect */
		if (p->value == target) matched = 1;
	}
	return matched ? p : (void *)0;
}
