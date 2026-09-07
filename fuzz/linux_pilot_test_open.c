/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * open()/openat() front-door smoke test -- NOT part of spicule, same
 * standing as every other fuzz/linux_pilot_test_*.c file.
 *
 * Unlike every earlier Linux-pilot test, this one calls the REAL
 * src/fcntl/open.c front door (open()/openat()/creat()) itself, not a
 * raw openat(2) syscall standing in for it -- open()'s own path
 * resolution was refactored (src/internal/plat_fcntl.h's __plat_open())
 * so the NT-specific VFS-overlay/__ntpath_at() machinery moved into
 * src/fcntl/nt/plat_fcntl.c's own backend body, leaving src/fcntl/
 * open.c a genuinely portable front door for the first time. This test
 * is the proof: every check below exercises open()/openat() for real.
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "libc.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

#define SYS_unlinkat 35
#define SYS_mkdirat  34
#define AT_FDCWD_LX (-100)

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

int main(void)
{
	int fd, fd2, dfd;
	const char path[] = "/tmp/spicule-linux-open-test-file";
	const char dirpath[] = "/tmp/spicule-linux-open-test-dir";
	const char nested[] = "/tmp/spicule-linux-open-test-dir/inner";
	const char msg[] = "real open() front door on linux";
	char buf[64];

	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)path, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)nested, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)dirpath, (long)0x200 /* AT_REMOVEDIR */);

	/* --- O_CREAT|O_EXCL: the real front door, real mode bits --- */
	fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0640);
	CHECK(fd >= 0, "open(O_CREAT|O_EXCL) created a new file through the real front door");
	if (fd < 0) return 1;

	{
		struct stat st;
		CHECK(fstat(fd, &st) == 0, "fstat() on the newly opened fd succeeded");
		CHECK((st.st_mode & 07777) == 0640, "the real mode bits (0640) were set natively, no $LXMOD needed");
		CHECK(!S_ISDIR(st.st_mode), "the new file is not reported as a directory");
	}

	/* --- O_CREAT|O_EXCL again: must fail EEXIST --- */
	{
		int fd3 = open(path, O_CREAT | O_EXCL | O_RDWR, 0640);
		CHECK(fd3 == -1 && errno == EEXIST, "open(O_CREAT|O_EXCL) on an existing file fails EEXIST");
	}

	/* --- write()/read() through the real fd the real open() handed back --- */
	CHECK(write(fd, msg, sizeof msg - 1) == (ssize_t)(sizeof msg - 1), "write() through the real open()'d fd succeeded");
	CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek() back to start succeeded");
	memset(buf, 0, sizeof buf);
	CHECK(read(fd, buf, sizeof msg - 1) == (ssize_t)(sizeof msg - 1), "read() through the real open()'d fd succeeded");
	CHECK(memcmp(buf, msg, sizeof msg - 1) == 0, "content round-tripped correctly");
	CHECK(close(fd) == 0, "close() succeeded");

	/* --- openat() with a real dirfd, not AT_FDCWD --- */
	syscall(SYS_mkdirat, (long)AT_FDCWD_LX, (long)dirpath, 0755L);
	dfd = open(dirpath, O_RDONLY | O_DIRECTORY);
	CHECK(dfd >= 0, "open(O_DIRECTORY) on a real directory succeeded");
	if (dfd >= 0) {
		struct stat st;
		CHECK(fstat(dfd, &st) == 0 && S_ISDIR(st.st_mode), "fstat() on the directory fd reports S_ISDIR");

		fd2 = openat(dfd, "inner", O_CREAT | O_WRONLY, 0600);
		CHECK(fd2 >= 0, "openat(realdirfd, \"inner\", O_CREAT) created a file relative to a real dirfd");
		if (fd2 >= 0) CHECK(close(fd2) == 0, "close() of the fd-relative file succeeded");

		CHECK(close(dfd) == 0, "close() of the directory fd succeeded");
	}

	/* --- open() on a directory WITHOUT O_DIRECTORY: POSIX-legal --- */
	{
		int fd4 = open(dirpath, O_RDONLY);
		CHECK(fd4 >= 0, "open() on a directory without O_DIRECTORY succeeds (POSIX-legal)");
		if (fd4 >= 0) {
			struct stat st;
			CHECK(fstat(fd4, &st) == 0 && S_ISDIR(st.st_mode),
			      "fstat() still reports S_ISDIR even though O_DIRECTORY was not passed -- *typeout was decided correctly");
			CHECK(close(fd4) == 0, "close() succeeded");
		}
	}

	/* --- open() on a nonexistent path without O_CREAT: ENOENT --- */
	{
		int fd5 = open("/tmp/spicule-linux-open-test-does-not-exist", O_RDONLY);
		CHECK(fd5 == -1 && errno == ENOENT, "open() on a missing path fails ENOENT");
	}

	/* --- creat() --- */
	{
		const char creatpath[] = "/tmp/spicule-linux-open-test-creat";
		syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)creatpath, 0L);
		int fd6 = creat(creatpath, 0600);
		CHECK(fd6 >= 0, "creat() succeeded");
		if (fd6 >= 0) CHECK(close(fd6) == 0, "close() of the creat()'d fd succeeded");
		syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)creatpath, 0L);
	}

	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)nested, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)dirpath, (long)0x200 /* AT_REMOVEDIR */);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)path, 0L);

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
