/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

/* This front door only handles the __VFS_ROOT/__VFS_DEV overlay special
 * cases (portable bookkeeping, same split as chdir.c's __vfs_cwd_set())
 * and getcwd.html's buf/size contract -- NULL buf mallocs exactly what's
 * needed, size 0 with non-NULL buf is EINVAL, a result that won't fit is
 * ERANGE. What "current directory" means on this backend is entirely
 * __plat_getcwd()'s job (src/unistd/{nt,linux}/plat_unistd.c). */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_unistd.h"
#include "ownership_stubs.h"

withtok(heap_allocated)
char *getcwd(char *buf withtok(heap_allocated), size_t size)
{
	char tmp[4096 * 3];
	size_t len;
	ssize_t r;
	int vfs = __vfs_cwd_get();
	if (vfs == __VFS_ROOT || vfs == __VFS_DEV) {
		const char *path = vfs == __VFS_ROOT ? "/" : "/dev";
		/* Both arms are string literals; the checker's literal
		 * recognition doesn't reach through the ternary assignment. */
		unsafe_assume_string_terminated(path);
		len = strlen(path);
		if (!buf) {
			if (!size) size = len + 1;
			if (len + 1 > size) { errno = ERANGE; return 0; }
			buf = malloc(size);
			if (!buf) return 0;
		} else if (!size) { errno = EINVAL; return 0; }
		else if (len + 1 > size) { errno = ERANGE; return 0; }
		memcpy(buf, path, len + 1);
		return buf;
	}

	r = __plat_getcwd(tmp, sizeof tmp);
	if (r < 0) return 0;
	len = (size_t)r;
	if (!buf) {
		if (!size) size = len + 1;
		if (len + 1 > size) { errno = ERANGE; return 0; }
		buf = malloc(size);
		if (!buf) return 0;
	} else if (!size) {
		errno = EINVAL; return 0;
	} else if (len + 1 > size) {
		errno = ERANGE; return 0;
	}
	for (size_t i = 0; i <= len; i++) buf[i] = tmp[i];
	return buf;
}

withtok(heap_allocated)
char *get_current_dir_name(void)
{
	return getcwd(0, 0);
}

// NOLINTEND(misc-include-cleaner)
