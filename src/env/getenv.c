/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdlib.h>
#include <string.h>
#include "libc.h"
#include "ownership_stubs.h"

/* Windows environment names are case-insensitive, and a program asking
 * for "PATH" must find "Path", which is how Windows spells it.
 *
 * entry/name are both required: __env_find's only caller of this helper
 * already checked *entry truthy (the loop's own `*entry` condition) before
 * passing it as entry, and name is __env_find's own now-nonnull parameter
 * (see src/internal/libc.h). */
static int name_eq(const char *entry, const char *name, size_t name_length)
    __attribute__((nonnull(1, 2)));
static int name_eq(const char *entry, const char *name, size_t name_length) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t i;
	for (i = 0; i < name_length; i++) {
		int a = (unsigned char)entry[i], b = (unsigned char)name[i];
		if (!a) return 0;
		if (a >= 'a' && a <= 'z') a -= 32;
		if (b >= 'a' && b <= 'z') b -= 32;
		if (a != b) return 0;
	}
	return entry[name_length] == '=';
}

char **__env_find(const char *name, size_t l)
{
	char **e;
	if (!__environ) return 0;
	for (e = __environ; *e; e++)
		if (name_eq(*e, name, l)) return e;
	return 0;
}

withtok(null_terminated)
char *getenv(const char *name withtok(null_terminated))
{
	size_t l = strcspn(name, "=");
	char **e;
	char *result;
	if (!l || name[l]) return 0;
	e = __env_find(name, l);
	result = e ? *e + l + 1 : 0;
	if (result) unsafe_assume_string_terminated(result);
	return result;
}
