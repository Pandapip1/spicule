/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The read-only *attribute* a name can be given by the `readonly`
 * special built-in (XCU 2.14, readonly(1p)), kept apart from its value.
 *
 * Every assignment is already a setenv() into the real `environ`
 * (builtin.c's bi_export()), but environ has no per-entry "further
 * assignment must fail" flag, so the read-only *set* -- independent of
 * whether a name currently has a value -- gets its own small array here,
 * the same shape param.c uses for state with no home in environ.
 *
 * There is no unmark: `unset` is the only thing that would need one, and
 * it's unimplemented (script.c's unimplemented_builtins). A mark is
 * therefore permanent for the process's life, matching readonly(1p): once
 * read-only, a name must error on any later readonly or assignment.
 */
#include <string.h>
#include "libc.h"
#include "sh.h"

/* NUL-terminated names, __malloc'd; names[i] is never freed or
 * reordered once appended, since nothing here ever removes one. */
static char **names;
static size_t count;
static size_t cap;

static size_t find(const char *name)
{
	size_t i;
	for (i = 0; i < count; i++)
		if (strcmp(names[i], name) == 0) return i;
	return count;
}

int __sh_readonly_is(const char *name)
{
	return find(name) < count;
}

int __sh_readonly_mark(const char *name)
{
	size_t len;
	char *dup;

	if (find(name) < count) return 0;

	len = strlen(name) + 1;
	dup = __malloc(len);
	if (!dup) return -1;
	memcpy(dup, name, len);

	if (count == cap) {
		size_t ncap = 8, bytes;
		char **nv = 0;
		if ((!cap || __size_mul_checked(cap, 2, &ncap)) &&
		    __size_mul_checked(ncap, sizeof *nv, &bytes))
			nv = (char **)__malloc(bytes);
		if (!nv) { __free(dup); return -1; }
		memcpy((void *)nv, (const void *)names, count * sizeof *nv);
		__free((void *)names);
		names = nv;
		cap = ncap;
	}
	names[count++] = dup;
	return 0;
}

size_t __sh_readonly_count(void)
{
	return count;
}

/* Returns NULL out-of-range rather than asserting, as __sh_param_get() does
 * (param.c) -- a defensive answer, not a contract callers rely on. */
const char *__sh_readonly_name(size_t i)
{
	return i < count ? names[i] : 0;
}
