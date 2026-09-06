/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libc.h"


/* Strings put in the environment by setenv/putenv are ours to free; the
 * ones crt1 built are too, since all of them were malloc'd.  Strings
 * given to putenv belong to the caller and are tracked so that they are
 * never freed. */
static char **putenv_strings;
static size_t nputenv;

/* s is required: both call sites below pass *e straight from
 * __env_find's return, which is only ever a slot this file's own
 * name_eq-driven search already found truthy (`*e`, i.e. non-null). */
static int is_putenv(char *s) __attribute__((nonnull(1)));
/* putenv_strings[i] is a disclosed, deliberately unmarked residual:
 * putenv_strings is a file-static global, not a parameter of this
 * function at all (is_putenv() takes only s, already required above)
 * -- the same "global-array residual, not expressible via nonnull"
 * class d24fe86's own commit already established for this exact
 * array (and src/thread/{children,fork,wait}.c's __children[i]). */
static int is_putenv(char *s)
{
	size_t i;
	for (i = 0; i < nputenv; i++) if (putenv_strings[i] == s) return 1;
	return 0;
}

static size_t env_count(void)
{
	size_t n = 0;
	if (__environ) while (__environ[n]) n++;
	return n;
}

int __putenv(char *s, size_t l, char *owned)
{
	char **e = __env_find(s, l);
	if (e) {
		if (!is_putenv(*e)) free(*e);
		*e = s;
	} else {
		size_t n = env_count(), total;
		if (!__size_add_checked(n, 2, &total)) {
			errno = ENOMEM;
			free(owned);
			return -1;
		}
		char **ne = (char **)reallocarray((void *)__environ, total, sizeof(char *));
		if (!ne) { free(owned); return -1; }
		ne[n] = s;
		ne[n+1] = 0;
		__environ = ne;
	}
	(void)owned;
	return 0;
}

int setenv(const char *name, const char *value, int overwrite)
{
	size_t l1, l2, total;
	char *s;
	if (!name) { errno = EINVAL; return -1; }
	l1 = strcspn(name, "=");
	if (!l1 || name[l1]) { errno = EINVAL; return -1; }
	if (!overwrite && getenv(name)) return 0;
	l2 = strlen(value);
	if (!__size_add_checked(l1, l2, &total) ||
	    !__size_add_checked(total, 2, &total)) { errno = ENOMEM; return -1; }
	s = malloc(total);
	if (!s) return -1;
	memcpy(s, name, l1);
	s[l1] = '=';
	memcpy(s + l1 + 1, value, l2 + 1);
	return __putenv(s, l1, s);
}

int putenv(char *s)
{
	size_t l = strcspn(s, "="), total;
	char **np;
	if (!l || !s[l]) return unsetenv(s);
	if (!__size_add_checked(nputenv, 1, &total)) return -1;
	np = (char **)reallocarray((void *)putenv_strings, total, sizeof(char *));
	if (!np) return -1;
	putenv_strings = np;
	putenv_strings[nputenv++] = s;
	return __putenv(s, l, 0);
}

int unsetenv(const char *name)
{
	size_t l, remaining;
	if (!name) { errno = EINVAL; return -1; }
	l = strcspn(name, "=");
	if (!l || name[l]) { errno = EINVAL; return -1; }
	/* Each pass removes one entry, so the initial environment size is an
	 * exact upper bound even when an inherited environment contains the
	 * same name more than once. */
	for (remaining = env_count(); remaining > 0; remaining--) {
		char **p = __env_find(name, l);
		if (!p) break;
		if (!is_putenv(*p)) free(*p);
		do {
			p[0] = p[1];
			p++;
		} while (*p);
	}
	return 0;
}

/* Restored per test/libc-test-expected.txt's "env" row: musl's libc-test
 * functional/env.c calls clearenv() directly, so this XSI function is a
 * real consumer after all (see 49b8099, which removed it for having
 * none at the time). */
int clearenv(void)
{
	char **e;
	if (__environ) {
		for (e = __environ; *e; e++) if (!is_putenv(*e)) free(*e);
		__environ[0] = 0;
	}
	return 0;
}
