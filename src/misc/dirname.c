/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <libgen.h>
#include "ownership_stubs.h"

#define ISSEP(c) ((c) == '/' || (c) == '\\')

__wraps char *dirname(char *s)
{
	size_t i, start = 0;
	if (!s || !*s) return (char *)".";
	/* s is non-NULL here, and dirname()'s own POSIX contract requires a
	 * real NUL-terminated string -- true by that public API contract, not
	 * otherwise visible to the checker across this function's own call
	 * boundary (the same shape src/stat/stat.c's fstatat() and
	 * src/dlfcn/linux/plat_dlfcn.c's __plat_dlopen() use for their own
	 * path parameters). Stating this via withtok(null_terminated) instead
	 * would cascade into every dirname()/basename() caller tree-wide. */
	unsafe_assume_string_terminated(s);
	if (((unsigned)(s[0] | 32) - 'a') < 26u && s[1] == ':') start = 2;
	i = strlen(s) - 1;
	/* Strip trailing separators, but keep a root. */
	for (; i > start && ISSEP(s[i]); i--);
	if (i == start && ISSEP(s[i])) {
		/* "/" or "C:\" (possibly repeated): already the root. */
		s[start+1] = 0;
		return s;
	}
	if (i < start) {
		/* "C:" alone: the drive's current directory. */
		return s;
	}
	/* Skip the last component. */
	for (; i > start && !ISSEP(s[i]); i--);
	if (i == start) {
		if (ISSEP(s[i])) {
			/* "/foo" -> "/"; "C:/foo" -> "C:/" */
			s[start+1] = 0;
		} else if (start) {
			/* "C:foo" -> "C:" */
			s[start] = 0;
		} else {
			/* "foo" -> "." */
			return (char *)".";
		}
		return s;
	}
	/* Strip the separators before the last component too. */
	for (; i > start && ISSEP(s[i]); i--);
	if (i == start && ISSEP(s[i])) {
		s[start+1] = 0;
		return s;
	}
	s[i+1] = 0;
	return s;
}

// NOLINTEND(misc-include-cleaner)
