/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <libgen.h>

#define ISSEP(c) ((c) == '/' || (c) == '\\')

__wraps char *basename(char *s)
{
	size_t i, start = 0;
	if (!s || !*s) return (char *)".";
	/* A drive prefix is not part of the last component. */
	if (((unsigned)(s[0] | 32) - 'a') < 26u && s[1] == ':') start = 2;
	i = strlen(s) - 1;
	for (; i > start && ISSEP(s[i]); i--) s[i] = 0;
	if (i == start && ISSEP(s[i])) {
		/* "C:\" or "/": the root. */
		s[start+1] = 0;
		return s + start;
	}
	if (i < start) return (char *)".";  /* "C:" alone */
	for (; i > start && !ISSEP(s[i-1]); i--);
	return s + i;
}

// NOLINTEND(misc-include-cleaner)
