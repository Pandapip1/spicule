/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdlib.h>
#include <string.h>
#include "ownership_stubs.h"

int getsubopt(char **opt, char *const *keys, char **val)
{
	char *s = *opt; /* getsubopt(3p)'s own contract: *optionp is a string */
	size_t i;

	__ownership_string_terminated(s);
	*val = 0;
	*opt = strchr(s, ',');
	if (*opt) *(*opt)++ = 0;
	else *opt = s + strlen(s);

	for (i = 0; keys[i]; i++) {
		__ownership_string_terminated(keys[i]); /* each keys[] entry is a string, same contract as *optionp */
		size_t l = strlen(keys[i]);
		if (strncmp(keys[i], s, l)) continue; // NOLINT(bugprone-suspicious-string-compare) -- any nonzero result intentionally skips a nonmatching key prefix
		/* s[l] is in-bounds: strncmp above matched l non-NUL keys[i]
		 * bytes, so s has no NUL before index l. Not expressible in
		 * this checker's vocabulary (needs strncmp's return value
		 * tied to s's own extent), left open. */
		if (s[l] == '=') *val = s + l + 1;
		else if (s[l]) continue;
		return (int)i;
	}
	*val = s;
	return -1;
}
