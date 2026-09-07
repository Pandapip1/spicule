/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux dirent pilot smoke test -- NOT part of spicule, same standing as
 * fuzz/linux_pilot_test_fs.c and fuzz/linux_pilot_test_open.c.
 *
 * Exercises the REAL spicule public entry points opendir()/readdir()/
 * closedir() (src/dirent/{opendir,readdir,closedir}.c) and getdents()
 * (src/dirent/getdents.c), statically linked here against the real
 * open()/openat() front door (src/fcntl/open.c) and the new
 * src/dirent/linux/plat_dirent.c backend -- running as a real, native
 * aarch64 Linux process on this host, no Wine, no emulation. This is
 * the pilot the interface redesign (src/internal/plat_dirent.h's
 * __plat_dir_decode_one()) exists to make possible: earlier pilots
 * (linux_pilot_test_fs.c) could compile src/dirent/linux/plat_dirent.c
 * but never call it, because the front doors it would have talked to
 * still hardcoded NT's own FILE_ID_BOTH_DIR_INFORMATION.
 *
 * Test fixture: a real directory containing three real files of
 * distinct names and one real subdirectory, created here with raw
 * syscalls (mkdirat/openat/close -- not through spicule's own front
 * doors, so this test's fixture setup does not depend on the very code
 * under test). Every one of those names is confirmed present, with the
 * correct d_type, via an order-independent set comparison (directory
 * enumeration order is never guaranteed) -- once through readdir(), and
 * a second time, independently, through getdents() on a raw fd from
 * open().
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include "libc.h"

extern int printf(const char *, ...);
extern int snprintf(char *, size_t, const char *, ...);
extern int strcmp(const char *, const char *);

#define SYS_mkdirat  34
#define SYS_openat   56
#define SYS_close    57
#define SYS_unlinkat 35
#define AT_FDCWD_LX     (-100)
#define AT_REMOVEDIR_LX 0x200
#define O_CREAT_LX      0100
#define O_WRONLY_LX     01

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

/* A local raw syscall trampoline, deliberately NOT `extern long
 * syscall(long, ...)`: see the errno-collapsing bug this project has
 * hit repeatedly (src/mman/linux/plat_mem.c's own banner, and every
 * other Linux plat_*.c file's identical raw_syscall()) -- glibc's own
 * exported syscall() translates the raw kernel -errno convention into
 * -1-with-its-own-errno, which is not what this file's own error
 * checks below assume. Test fixture setup has no comparable dependency
 * on that translation the way a fork-based lock-conflict test would,
 * but there is no reason to reintroduce a known pitfall into new code
 * just because this particular use would not have been visibly broken
 * by it. */
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static const char *TESTDIR = "/tmp/spicule-linux-pilot-test-dirent";

struct expect {
	const char *name;
	unsigned char type;
	int seen;
};

static struct expect expected[] = {
	{ ".",        DT_DIR, 0 },
	{ "..",       DT_DIR, 0 },
	{ "alpha.txt",DT_REG, 0 },
	{ "beta.dat", DT_REG, 0 },
	{ "gamma",    DT_REG, 0 },
	{ "subdir1",  DT_DIR, 0 },
};
#define NEXPECT (sizeof expected / sizeof expected[0])

static void reset_expected(void)
{
	size_t i;
	for (i = 0; i < NEXPECT; i++) expected[i].seen = 0;
}

/* Records one observed (name, type) against the expected set -- the
 * order-independent comparison every readdir()-shaped interface needs,
 * since directory enumeration order is never guaranteed by POSIX. */
static void observe(const char *name, unsigned char type, const char *via)
{
	size_t i;
	char msg[256];
	for (i = 0; i < NEXPECT; i++) {
		if (strcmp(expected[i].name, name)) continue;
		expected[i].seen = 1;
		snprintf(msg, sizeof msg, "%s: \"%s\" has the expected d_type (%u)", via, name, (unsigned)type);
		CHECK(type == expected[i].type, msg);
		return;
	}
	snprintf(msg, sizeof msg, "%s: unexpected extra entry \"%s\" (harmless if the host tmpdir has other content, else a real bug)", via, name);
	printf("note - %s\n", msg);
}

static void check_all_seen(const char *via)
{
	size_t i;
	for (i = 0; i < NEXPECT; i++) {
		char msg[256];
		snprintf(msg, sizeof msg, "%s: saw expected entry \"%s\"", via, expected[i].name);
		CHECK(expected[i].seen, msg);
	}
}

static void make_file(const char *path)
{
	long fd = raw_syscall(SYS_openat, AT_FDCWD_LX, (long)path,
	                      (long)(O_CREAT_LX | O_WRONLY_LX), 0644L, 0L, 0L);
	if (fd < 0) { printf("FAIL - raw openat() fixture setup for %s (errno=%ld)\n", path, -fd); failures++; return; }
	raw_syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);
}

int main(void)
{
	char path[256];
	long r;

	/* --- fixture setup: raw syscalls only, independent of the code
	 * under test --- */
	r = raw_syscall(SYS_mkdirat, AT_FDCWD_LX, (long)TESTDIR, 0755L, 0L, 0L, 0L);
	CHECK(r == 0 || (is_sys_error(r) && -r == 17 /* EEXIST, harmless rerun */), "raw mkdirat() created the test directory");

	snprintf(path, sizeof path, "%s/alpha.txt", TESTDIR); make_file(path);
	snprintf(path, sizeof path, "%s/beta.dat", TESTDIR); make_file(path);
	snprintf(path, sizeof path, "%s/gamma", TESTDIR); make_file(path);
	snprintf(path, sizeof path, "%s/subdir1", TESTDIR);
	r = raw_syscall(SYS_mkdirat, AT_FDCWD_LX, (long)path, 0755L, 0L, 0L, 0L);
	CHECK(r == 0, "raw mkdirat() created the test subdirectory");
	printf("ok   - fixture: %s with alpha.txt, beta.dat, gamma, subdir1\n", TESTDIR);

	/* --- opendir()/readdir()/closedir(), the real front doors --- */
	{
		DIR *dp;
		struct dirent *d;
		int n = 0;

		reset_expected();
		dp = opendir(TESTDIR);
		CHECK(dp != 0, "opendir() on the real test directory succeeded");
		if (dp) {
			errno = 0;
			while ((d = readdir(dp))) {
				observe(d->d_name, d->d_type, "readdir()");
				n++;
			}
			CHECK(errno == 0, "readdir() loop ran to end-of-directory, not an error (errno reset to 0 before the loop)");
			CHECK(n > 0, "readdir() returned at least one real entry");
			check_all_seen("readdir()");
			printf("     (readdir() saw %d total entries)\n", n);
			CHECK(closedir(dp) == 0, "closedir() succeeded");
		}
	}

	/* --- getdents(), directly on a raw fd from the real open() --- */
	{
		int fd;
		unsigned char buf[4096];
		int n;

		reset_expected();
		fd = open(TESTDIR, O_RDONLY | O_DIRECTORY);
		CHECK(fd >= 0, "open(O_DIRECTORY) on the real test directory succeeded");
		if (fd >= 0) {
			n = getdents(fd, (struct dirent *)buf, sizeof buf);
			CHECK(n > 0, "getdents() on the directory fd returned real data");
			if (n > 0) {
				size_t pos = 0, count = 0;
				while (pos + sizeof(struct dirent) <= (size_t)n) {
					struct dirent *d = (struct dirent *)(buf + pos);
					observe(d->d_name, d->d_type, "getdents()");
					count++;
					if (!d->d_reclen) break; /* defensive; never 0 in practice
					                          * -- see readdir.c's own banner:
					                          * d_reclen is always
					                          * sizeof(struct dirent) here. */
					pos += d->d_reclen;
				}
				printf("     (getdents() decoded %zu entries from %d bytes)\n", count, n);
				check_all_seen("getdents()");
			}
			CHECK(close(fd) == 0, "close() of the directory fd succeeded");
		}
	}

	/* --- cleanup: raw syscalls only --- */
	snprintf(path, sizeof path, "%s/alpha.txt", TESTDIR); raw_syscall(SYS_unlinkat, AT_FDCWD_LX, (long)path, 0L, 0L, 0L, 0L);
	snprintf(path, sizeof path, "%s/beta.dat", TESTDIR); raw_syscall(SYS_unlinkat, AT_FDCWD_LX, (long)path, 0L, 0L, 0L, 0L);
	snprintf(path, sizeof path, "%s/gamma", TESTDIR); raw_syscall(SYS_unlinkat, AT_FDCWD_LX, (long)path, 0L, 0L, 0L, 0L);
	snprintf(path, sizeof path, "%s/subdir1", TESTDIR); raw_syscall(SYS_unlinkat, AT_FDCWD_LX, (long)path, (long)AT_REMOVEDIR_LX, 0L, 0L, 0L);
	raw_syscall(SYS_unlinkat, AT_FDCWD_LX, (long)TESTDIR, (long)AT_REMOVEDIR_LX, 0L, 0L, 0L);

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
