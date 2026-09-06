/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Every loop below is either a plain single-condition header (out of
 * scope for this checker -- it only looks at compound `&&`/`||`
 * headers), a compound header whose leaves are ALL structural, or a loop
 * that already uses the encouraged pattern: an explicit `if (...) break;`
 * in the body instead of folding a second condition into the header. */

#include <stddef.h>

struct node { struct node *next; int value; };

int page_lock_state(void *m, size_t first);

/* Plain range scan: single condition, not compound -- never in scope. */
int sum_range(const int *arr, size_t n)
{
	int total = 0;
	size_t i;
	for (i = 0; i < n; i++) total += arr[i];
	return total;
}

/* Linked-list traversal to NULL: single condition (bare pointer cursor
 * test), not compound -- never in scope. */
int list_length(const struct node *head)
{
	int n = 0;
	const struct node *p;
	for (p = head; p; p = p->next) n++;
	return n;
}

/* Fixed-count loop: single condition -- never in scope. */
void retry_fixed(void (*step)(void))
{
	int i;
	for (i = 0; i < 3; i++) step();
}

/* Dual-range scan: BOTH leaves of the compound condition are structural
 * comparisons (i against len, steps against len) -- no incidental flag,
 * so this is a legitimate compound header and must not be flagged. */
int dual_bound(const int *arr, size_t len)
{
	size_t i, steps;
	int total = 0;
	for (i = 0, steps = 0; i < len && steps < len; steps++) {
		total += arr[i];
		i++;
	}
	return total;
}

/* Bounded sentinel scan: `i < n` is a comparison (Bound) and
 * `buf[i] != '\0'` is also a comparison (Bound) -- checking content
 * under the cursor to find a terminator is a structural "reached the end
 * of the structure" test, not an incidental flag. Must not be flagged. */
size_t bounded_strnlen(const char *buf, size_t n)
{
	size_t i;
	for (i = 0; i < n && buf[i] != '\0'; i++) ;
	return i;
}

/* A bare call whose own arguments mention the same variable the other
 * leaf's comparison is about reads as "check content at the cursor", not
 * as an independent flag -- must not be flagged. */
size_t first_unlocked(void *m, size_t first, size_t npages)
{
	size_t n;
	for (n = 0; first + n < npages && !page_lock_state(m, first + n); n++) ;
	return n;
}

/* The ENCOURAGED pattern for a data-dependent early exit from an
 * otherwise clean range loop: the secondary condition is an explicit
 * `if (...) break;` in the body, not folded into the for-loop's own
 * header. This must not be flagged -- it is exactly what the unsafe
 * fixtures' findings should be turned into. */
int linear_search(const int *arr, size_t n, int target)
{
	size_t i;
	int found = -1;
	for (i = 0; i < n; i++) {
		if (arr[i] == target) {
			found = (int)i;
			break;
		}
	}
	return found;
}

/* A while loop whose real driver is a single data-dependent condition,
 * with no secondary cap at all: single condition, not compound -- never
 * in scope, and exactly the shape a `while` loop exists for. */
int retry_until_success(int (*attempt)(void))
{
	int success = 0;
	while (!success) success = attempt();
	return success;
}

/* The bounded-copy idiom this tree's strncmp/strncat/wcsncpy/wmemcmp
 * family all share: a bare countdown `n` compounded with a cursor
 * dereference `*s`. `n` is NOT a boolean flag -- it is decremented in
 * the loop body, which is this checker's own evidence that a bare
 * non-pointer identifier is a remaining-budget counter (structural)
 * rather than a flag (incidental). Must not be flagged. */
char *bounded_copy(char *d, const char *s, unsigned long n)
{
	char *a = d;
	while (n && *s) {
		*d = *s;
		d++;
		s++;
		n--;
	}
	*d = 0;
	return a;
}

/* The ENCOURAGED pattern for a while loop that also needs a safety cap:
 * the cap is an explicit `if (...) break;` in the body, not `&&`'d into
 * the while's own header. Must not be flagged. */
int retry_with_cap(int (*attempt)(void), int max_attempts)
{
	int success = 0;
	int attempts = 0;
	while (!success) {
		success = attempt();
		if (++attempts >= max_attempts) break;
	}
	return success;
}
