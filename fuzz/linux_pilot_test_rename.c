/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * rename()/renameat() front-door smoke test -- NOT part of spicule, same
 * standing as fuzz/linux_pilot_test_open.c. Calls the REAL src/stdio/
 * misc.c front door (rename()/renameat()), not a raw syscall standing
 * in for it -- proving __plat_rename()'s path-resolution refactor
 * (src/internal/plat_stdio.h, src/stdio/nt/plat_stdio.c,
 * src/stdio/linux/plat_stdio.c) end to end.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "libc.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);

#define SYS_unlinkat 35
#define SYS_mkdirat  34
#define AT_FDCWD_LX (-100)

/* src/stdio/misc.c is linked here as a whole object (not pulled by need
 * from a .a archive), so GNU ld resolves EVERY undefined reference in
 * it regardless of --gc-sections -- the same "the linker still needs a
 * real symbol even for an unreached branch" situation this project's
 * other Linux-pilot harnesses (fuzz/linux_pilot_harness_fs.c's own
 * banner) already document. This test calls only rename()/renameat(),
 * never tmpfile()/popen(), so both stand-ins below are never actually
 * invoked -- their bodies exist purely to satisfy the symbol table. */
FILE *__file_new(int fd, int flags) { (void)fd; (void)flags; return 0; }
int __spawn(const char *path, char *const argv[], char *const envp[])
{
	(void)path; (void)argv; (void)envp;
	return -1;
}
/* popen()'s own real "sh" lookup (src/stdio/misc.c, added by "Add a
 * real Linux implementation of system() and popen()" after this file
 * was last touched -- a real, previously-hidden gap CI never reached).
 * src/process/find_program.c's real __find_program() needs malloc(),
 * access() and __plat_is_program() (src/process/linux/plat_process.c)
 * -- a whole PATH-search subsystem well past this rename()/renameat()
 * pilot's own scope to stand up just for a popen() call this test never
 * makes. Same stand-in shape as __file_new()/__spawn() above: a NULL
 * "not found" is honest here too (real __find_program() also returns
 * NULL when nothing on PATH matches), and popen()'s own `if (!shell)
 * pid = -1;` guard is what actually executes if this is ever reached
 * at runtime, which it never is. */
char *__find_program(const char *name, int use_path)
{
	(void)name; (void)use_path;
	return 0;
}

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

static void cleanup(void)
{
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-a", 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-b", 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-dir/inner", 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-dir", (long)0x200 /* AT_REMOVEDIR */);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-dir2", (long)0x200 /* AT_REMOVEDIR */);
}

int main(void)
{
	cleanup();

	/* --- plain rename() of a real file --- */
	{
		int fd = open("/tmp/spicule-linux-rename-a", O_CREAT | O_WRONLY, 0644);
		CHECK(fd >= 0, "open() of the source file for rename() succeeded");
		if (fd >= 0) CHECK(close(fd) == 0, "close() succeeded");

		CHECK(rename("/tmp/spicule-linux-rename-a", "/tmp/spicule-linux-rename-b") == 0,
		      "rename() through the real front door succeeded");
		{
			int fd2 = open("/tmp/spicule-linux-rename-a", O_RDONLY);
			CHECK(fd2 == -1 && errno == ENOENT, "the old name is really gone after rename()");
		}
		{
			int fd2 = open("/tmp/spicule-linux-rename-b", O_RDONLY);
			CHECK(fd2 >= 0, "the new name really exists after rename()");
			if (fd2 >= 0) close(fd2);
		}
	}

	/* --- renameat() with real dirfds --- */
	{
		int dfd, dfd2, r;
		syscall(SYS_mkdirat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-dir", 0755L);
		syscall(SYS_mkdirat, (long)AT_FDCWD_LX, (long)"/tmp/spicule-linux-rename-dir2", 0755L);
		dfd = open("/tmp/spicule-linux-rename-dir", O_RDONLY | O_DIRECTORY);
		dfd2 = open("/tmp/spicule-linux-rename-dir2", O_RDONLY | O_DIRECTORY);
		CHECK(dfd >= 0 && dfd2 >= 0, "open()ing both real directories for renameat() succeeded");

		r = openat(dfd, "inner", O_CREAT | O_WRONLY, 0644);
		CHECK(r >= 0, "openat(dfd, \"inner\", O_CREAT) succeeded");
		if (r >= 0) close(r);

		CHECK(renameat(dfd, "inner", dfd2, "moved") == 0,
		      "renameat() with two real dirfds through the real front door succeeded");
		{
			int check = openat(dfd2, "moved", O_RDONLY);
			CHECK(check >= 0, "the file really moved into the second real directory");
			if (check >= 0) close(check);
		}
		if (dfd >= 0) close(dfd);
		if (dfd2 >= 0) close(dfd2);
	}

	/* --- rename() onto a directory where types mismatch: ENOTDIR --- */
	{
		int fd = open("/tmp/spicule-linux-rename-b", O_CREAT | O_WRONLY, 0644);
		if (fd >= 0) close(fd);
		CHECK(rename("/tmp/spicule-linux-rename-dir", "/tmp/spicule-linux-rename-b") == -1 &&
		      (errno == ENOTDIR || errno == EISDIR || errno == EEXIST),
		      "rename() of a directory onto an existing non-directory fails with a type-mismatch errno");
	}

	/* --- rename() of a directory into its own descendant: EINVAL --- */
	{
		int r = rename("/tmp/spicule-linux-rename-dir2", "/tmp/spicule-linux-rename-dir2/sub");
		CHECK(r == -1 && errno == EINVAL, "rename() of a directory into its own descendant fails EINVAL");
	}

	/* --- rename() of a nonexistent source: ENOENT --- */
	{
		int r = rename("/tmp/spicule-linux-rename-does-not-exist", "/tmp/spicule-linux-rename-x");
		CHECK(r == -1 && errno == ENOENT, "rename() of a missing source fails ENOENT");
	}

	cleanup();

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
