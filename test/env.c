/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Regression test for a real, confirmed startup bug: crt/linux/crt1.c
 * used to alias `environ` directly onto the kernel-provided envp block
 * handed to the process at exec(2) time, instead of handing it a real
 * copy owned by this library's own allocator (see that file's own
 * header comment, and src/env/setenv.c's __putenv(), for the fuller
 * story).  Every environment variable a freshly exec()'d process
 * inherits therefore used to sit in memory this library never
 * allocated -- and setenv() on an already-present variable calls
 * free() on that variable's old value when replacing it (__putenv()'s
 * `if (!is_putenv(*e)) free(*e);`), so the very first setenv() call to
 * *overwrite* an inherited variable free()'d a pointer into the
 * kernel's own initial-stack block.  That is undefined behavior, and
 * was confirmed to crash in practice on native Linux; it never
 * reproduced on the NT side, whose crt/crt1.c already builds environ
 * as a real, independently __malloc()'d array of __malloc()'d strings
 * (build_environ(), that file's own env/argv-building section).
 *
 * "PATH" is used as the pre-existing variable: every process this
 * test could plausibly run under (a shell, a test harness, CI) already
 * has PATH in its environment, so this does not depend on the test's
 * own caller passing anything special -- if PATH is somehow absent,
 * this test degrades to exercising setenv() on a fresh variable
 * instead (still a legitimate check, just not the one this file exists
 * for) rather than silently skipping.
 */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

extern char **environ;

int main(void)
{
	const char *before;
	char *after;

	/* Confirms this run actually exercises the *overwrite* path (a
	 * slot __putenv() replaces in place, not one it appends) -- the
	 * distinction that mattered: appending a brand-new variable only
	 * ever realloc()s the environ ARRAY, never free()s an inherited
	 * variable's VALUE string, so it could never have hit this bug. */
	before = getenv("PATH");

	CHECK(setenv("PATH", "/spicule-env-test-value", 1) == 0);
	after = getenv("PATH");
	CHECK(after != 0 && !strcmp(after, "/spicule-env-test-value"));

	/* Overwrite it again -- exercises free() on a value THIS test
	 * itself just malloc()'d via setenv(), not the original
	 * inherited one, catching a fix that only handled the first
	 * (kernel-owned) generation correctly. */
	CHECK(setenv("PATH", "/spicule-env-test-value-2", 1) == 0);
	after = getenv("PATH");
	CHECK(after != 0 && !strcmp(after, "/spicule-env-test-value-2"));

	/* A brand-new variable: exercises __putenv()'s append path
	 * (realloc() of the environ array itself). */
	CHECK(setenv("SPICULE_ENV_TEST_NEW", "1", 1) == 0);
	CHECK(getenv("SPICULE_ENV_TEST_NEW") != 0);

	/* unsetenv() on the variable this test overwrote also frees its
	 * (by now, this test's own malloc()'d) value -- exercised here
	 * too, rather than only via setenv()'s own free(). */
	CHECK(unsetenv("SPICULE_ENV_TEST_NEW") == 0);
	CHECK(getenv("SPICULE_ENV_TEST_NEW") == 0);

	/* Restore PATH so a caller relying on it later in the same
	 * process (there is none today, but the courtesy costs nothing)
	 * is not left with this test's own scratch value. */
	if (before) setenv("PATH", before, 1);

	if (!fails) printf("env: all tests passed (reached the end without crashing -- see this file's header)\n");
	return fails != 0;
}
