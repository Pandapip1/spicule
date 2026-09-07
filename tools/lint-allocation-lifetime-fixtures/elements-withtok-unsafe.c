/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "stubs.h"

int populate(char **out elements_withtok(heap_allocated, n), size_t n);

/* Same call-boundary contract as elements-withtok-safe.c's use_populate(),
 * but this path only ever reads (and thereby takes ownership of) element
 * 0 and never frees it -- caught exactly like any other tracked
 * allocation this checker already knows how to prove leaks, once
 * elements_withtok mints the obligation for it in the first place. */
int leaks_one_element(char **arr, size_t n)
{
	size_t i = 0;
	if (n == 0)
		return -1;
	if (populate(arr, n))
		return -1;
	char *first = arr[i];
	(void)first;
	return 0; /* allocation-lifetime-expect: elements_withtok caller-side element leak */
}
