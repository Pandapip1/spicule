/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Resolving a program name for execvp.
 *
 * A name with a directory part (a '/', a '\\', or a drive letter) is
 * taken as-is; __spawn reports ENOENT if it does not exist. Otherwise
 * each PATH directory is tried with the name, then with ".exe" appended
 * (what Windows expects, and what a Linux candidate never needs but
 * costs only one extra failed access() to rule out). PATH's separator
 * (';' on NT, since ':' appears in every absolute entry like
 * "C:\Windows"; ':' on Linux) and join character ('\\' vs '/') are both
 * platform-specific; an empty entry means the current directory.
 *
 * A candidate needs both access(X_OK) (backed by $LXMOD) and
 * __is_program() below (first two bytes "MZ" or "#!", the latter one of
 * the two historical script-detection strategies exec.html APPLICATION
 * USAGE names). XBD 8.3 requires only "an executable file ... with
 * appropriate execution permissions" and names no mechanism for probing
 * it; musl's execvp() confirms access() was never required, since it
 * just execve()s each candidate instead -- not viable here, since NT
 * process creation isn't cheap the way a failed execve() on a fork()ed
 * child is. MSVCRT splits the same two questions across separate pages
 * (PATH search order vs. execute-bit checks) for the same reason.
 *
 * Content sniffing stays out of stat(): needed once per PATH candidate
 * here, not on every stat() of every file. Cygwin's noacl fallback
 * sniffs inside stat() instead, paying the open+read on every call with
 * no cache (hence `ls -l` being documented as slow there); the fix is
 * keeping the sniff out of stat() (src/stat/stat.c), not adding a cache
 * here.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include "libc.h"
#include "plat_process.h"

/* Can NT start this file, or is it a script something else can run?
 *
 * FILE_NON_DIRECTORY_FILE matters as much as the two-byte sniff: without
 * it, an empty program name appended to a PATH entry ("C:\Windows\")
 * opens the *directory* and the search accepts it (test/POSIX-COVERAGE.md,
 * exec group, bug 1).
 *
 * FILE_OPEN_NO_RECALL and the RECALL_ON_* attribute checks keep this
 * from waking a cloud-backed placeholder: a OneDrive-style provider
 * fetches the whole file on open/first-read, so blind sniffing could
 * pull megabytes over a network just to look at two bytes. A placeholder
 * (or any other failure) is answered "no" without being read; a caller
 * who knows better can still reach __spawn directly with a path. */
int __is_program(const char *path)
{
	return __plat_is_program(path);
}

static int has_dir(const char *name)
{
	if (strchr(name, '/') || strchr(name, '\\')) return 1;
	if (((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && name[1] == ':') return 1;
	return 0;
}

withtok(heap_allocated)
static char *try_dir(const char *dir, size_t dlen, const char *name)
{
	size_t nlen = strlen(name);
	size_t total;
	char *p;
	int need_separator;
#if defined(__linux__)
	static const char join[] = "/";
#else
	static const char join[] = "\\";
#endif

	if (dlen > INT_MAX || !__size_add_checked(dlen, nlen, &total) ||
	    !__size_add_checked(total, 6, &total)) {
		errno = ENOMEM;
		return 0;
	}
	p = malloc(total); // NOLINT(clang-analyzer-optin.taint.TaintedAlloc)
	if (!p) return 0;
	need_separator = dlen && dir[dlen - 1] != '/' && dir[dlen - 1] != '\\';
	snprintf(p, total, "%.*s%s%s", (int)dlen, dir,
	    need_separator ? join : "", name);
	dlen += (size_t)need_separator;
	if (access(p, X_OK) == 0 && __is_program(p)) return p;
	snprintf(p + dlen + nlen, 5, ".exe");
	if (access(p, X_OK) == 0 && __is_program(p)) return p;
	free(p);
	return 0;
}

withtok(heap_allocated) __attribute__((nonnull(1)))
char *__find_program(const char *name, int use_path)
{
	const char *path, *p;
	char *r;
#if defined(__linux__)
	static const char psep[] = ":";
#else
	static const char psep[] = ";";
#endif
	/* The empty string must be rejected before the PATH loop: it has no
	 * directory part, so has_dir() would otherwise send it through
	 * try_dir(), which appends nothing to a PATH entry and produces just
	 * `<entry>/` -- the directory itself. __is_program() also refuses
	 * directories, but a shall-fail clause shouldn't rest on an open
	 * flag two functions away; musl rejects the empty string up front
	 * too. */
	if (!name[0]) { errno = ENOENT; return 0; }
	if (!use_path || has_dir(name)) {
		size_t n = strlen(name) + 1;
		r = malloc(n);
		if (r) memcpy(r, name, n);
		return r;
	}
	path = getenv("PATH");
	if (!path) path = "";
	p = path;
	for (;;) {
		size_t len = strcspn(p, psep);
		r = try_dir(p, len, name);
		if (r) return r;
		p += len;
		if (!*p) break;
		p++;
	}
	errno = ENOENT;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
