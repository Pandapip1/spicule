/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * scandir, and the two comparators dirent.h advertises for it, built
 * entirely on opendir/readdir + qsort: nothing here talks to NT
 * directly.  Each surviving entry is copied into a malloc'd block sized
 * to its actual name, not a full struct dirent, the way musl does it.
 */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <dirent.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libc.h"

/* Casting compar itself to qsort_r's comparator type and calling it that
 * way is UB (C99 6.3.2.3p8) and traps under -fsanitize=function; this
 * adapter has the type qsort_r actually calls and reinterprets the
 * arguments instead, an ordinary object-pointer conversion. */
static int scandir_cmp(const void *a, const void *b, void *arg) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int (*compar)(const struct dirent **, const struct dirent **) = arg;
	return compar((const struct dirent **)a, (const struct dirent **)b);
}

int scandir(const char *path, struct dirent ***res,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **))
{
	DIR *dp;
	struct dirent *d, **list = 0;
	size_t n = 0, cap = 0, i;

	dp = opendir(path);
	if (!dp) return -1;

	errno = 0;
	while ((d = readdir(dp))) {
		struct dirent *copy;
		size_t copylen, namelen;

		/* Validate the producer's fixed-size name member before either
		 * this function or an application filter is allowed to traverse it. */
		namelen = strnlen(d->d_name, sizeof d->d_name);
		if (namelen == sizeof d->d_name) { errno = EIO; goto fail; }
		if (filter && !filter(d)) continue;

		if (n == cap) {
			size_t newcap, newbytes;
			if (!__array_next_capacity(cap, n, 1, 16,
			    sizeof *list, &newcap)) { errno = ENOMEM; goto fail; } // NOLINT(bugprone-sizeof-expression) -- list is dirent**, *list is dirent*, the array holds pointers
			newbytes = newcap * sizeof *list; // NOLINT(bugprone-sizeof-expression) -- already proven <= SIZE_MAX by __array_next_capacity's own element_size bound above
			struct dirent **nl = (struct dirent **)__malloc(newbytes);
			if (!nl) goto fail;
			if (list) memcpy((void *)nl, (const void *)list, n * sizeof *nl); // NOLINT(bugprone-sizeof-expression)
			__free((void *)list);
			list = nl;
			cap = newcap;
		}

		copylen = offsetof(struct dirent, d_name) + namelen + 1;
		copy = __malloc(copylen);
		if (!copy) goto fail;
		copy->d_ino = d->d_ino;
		copy->d_off = d->d_off;
		copy->d_reclen = d->d_reclen;
		copy->d_type = d->d_type;
		memcpy(copy->d_name, d->d_name, namelen);
		copy->d_name[namelen] = 0;
		list[n++] = copy;
	}
	if (errno) goto fail;
	if (closedir(dp) < 0) {
		int e = errno;
		for (i = 0; i < n; i++) __free(list[i]);
		__free((void *)list);
		errno = e;
		return -1;
	}

	/* list is struct dirent **, so *list is a pointer and sizeof *list is
	 * deliberately a pointer size: the array being sorted holds pointers,
	 * not structs. */
	/* NOLINTNEXTLINE(bugprone-sizeof-expression) */
	if (compar) qsort_r((void *)list, n, sizeof *list, scandir_cmp, (void *)compar);
	*res = list;
	return (int)n;

fail:
	{
		int e = errno ? errno : ENOMEM;
		for (i = 0; i < n; i++) __free(list[i]);
		__free((void *)list);
		(void)closedir(dp);
		errno = e;
		return -1;
	}
}

int alphasort(const struct dirent **a, const struct dirent **b)
{
	return strcmp((*a)->d_name, (*b)->d_name);
}

int versionsort(const struct dirent **a, const struct dirent **b)
{
	return strverscmp((*a)->d_name, (*b)->d_name);
}
