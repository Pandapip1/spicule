/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * stat-family front-door smoke test -- NOT part of spicule, same standing
 * as every other fuzz/linux_pilot_test_*.c file.
 *
 * Like fuzz/linux_pilot_test_open.c (the open()/openat() pilot that
 * proved commit ce4763c's path-resolution refactor for __plat_open()),
 * this calls the REAL src/stat/{chmod,mkdir,stat,statvfs,utimensat}.c
 * front doors themselves -- chmod()/fchmod()/fchmodat(), mkdir()/
 * mkdirat(), stat()/lstat()/fstat()/fstatat(), statvfs()/fstatvfs(),
 * utimensat() -- not raw syscalls standing in for them. Those five
 * front doors used to build an NT-only `struct __ntpath` themselves via
 * __ntpath_at()/__vfs_resolve_at() before ever reaching
 * src/internal/plat_stat.h; that coupling is gone (see plat_stat.h's
 * own updated banner and src/stat/linux/plat_stat.c's), so this test is
 * the proof for the stat family the same way linux_pilot_test_open.c
 * was the proof for open().
 *
 * A handful of raw syscalls (via this file's own extern syscall(),
 * satisfied by fuzz/linux_pilot_harness_fs.c's real trampoline) are
 * used only for setup/teardown/oracle checks that are not themselves
 * under test: umask(2) (pinned to 0 so every mode-bit assertion below
 * is deterministic regardless of the host shell's own umask -- see
 * src/stat/linux/plat_stat.c's own banner on why spicule's own umask()
 * has no effect on this backend at all), openat(2)/close(2)/unlinkat(2)/
 * symlinkat(2) for building/tearing down fixtures, exactly the same
 * split linux_pilot_test_open.c already uses.
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include "libc.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);

#define SYS_openat    56
#define SYS_close     57
#define SYS_unlinkat  35
#define SYS_symlinkat 36
#define SYS_umask     166

#define AT_FDCWD_LX    (-100)
#define AT_REMOVEDIR_LX 0x200

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

/* Installs a REAL raw fd (opened via a raw syscall, not through any
 * spicule front door) into spicule's own fd table, exactly the boxing
 * __plat_open() itself uses (src/fcntl/linux/plat_fcntl.c:
 * `*out = (__plat_handle_t)(long)(fd + 1)`) -- so mkdirat()/fstatat()
 * below can be handed a real spicule dirfd that resolve_dirfd() unboxes
 * back to the same real fd. */
static int install_real_fd(int real_fd, int type)
{
	return __fd_install((__plat_handle_t)(long)(real_fd + 1), 0, type);
}

int main(void)
{
	const char dirpath[]   = "/tmp/spicule-linux-statfam-dir";
	const char subpath[]   = "/tmp/spicule-linux-statfam-dir/sub";
	const char filepath[]  = "/tmp/spicule-linux-statfam-file";
	const char linkpath[]  = "/tmp/spicule-linux-statfam-link";
	struct stat st;
	struct statvfs vfs;
	long rawfd;
	int ntdirfd;

	/* Deterministic mode bits: every chmod()/mkdir() assertion below
	 * compares against the EXACT requested mode, which only holds if
	 * the real kernel umask is 0. */
	syscall(SYS_umask, 0L);

	/* Clean slate. */
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)subpath, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)dirpath, (long)AT_REMOVEDIR_LX);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)filepath, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)linkpath, 0L);

	/* ---- mkdir()/mkdirat(), stat(): real directory creation ---- */
	CHECK(mkdir(dirpath, 0751) == 0, "mkdir() created a real directory through the real front door");
	CHECK(stat(dirpath, &st) == 0, "stat() on the new directory succeeded");
	CHECK(S_ISDIR(st.st_mode), "stat() reports S_ISDIR on the new directory");
	CHECK((st.st_mode & 07777) == 0751, "stat() reports the exact requested mode bits (0751), umask pinned to 0");

	{
		int r2 = mkdir(dirpath, 0700);
		CHECK(r2 == -1 && errno == EEXIST, "mkdir() on an existing path fails EEXIST");
	}

	/* mkdirat() against a REAL spicule dirfd (not AT_FDCWD): proves
	 * resolve_dirfd() unboxes an installed fd correctly. */
	/* O_RDONLY alone, deliberately NOT spicule's own O_DIRECTORY here: a
	 * raw syscall needs the REAL kernel flag value, and spicule's own
	 * O_DIRECTORY does not match it (see src/fcntl/linux/plat_fcntl.c's
	 * own banner for exactly this pre-existing include/fcntl.h bug,
	 * found the same way this test found it the first time it was
	 * tried here: openat() on a real directory failing unexpectedly).
	 * Real Linux happily opens a directory with plain O_RDONLY, so
	 * O_DIRECTORY buys nothing for this fixture anyway. */
	rawfd = syscall(SYS_openat, (long)AT_FDCWD_LX, (long)dirpath, (long)O_RDONLY, 0L);
	CHECK(rawfd >= 0, "raw openat() of the directory (fixture, not under test) succeeded");
	ntdirfd = install_real_fd((int)rawfd, __FD_DIR);
	CHECK(ntdirfd >= 0, "installing the real dirfd into spicule's own fd table succeeded");
	CHECK(mkdirat(ntdirfd, "sub", 0700) == 0, "mkdirat(realntfd, \"sub\", 0700) created a directory relative to a real spicule dirfd");

	/* fstatat() against the same real dirfd, exercising resolve_dirfd()
	 * a second, independent way. */
	CHECK(fstatat(ntdirfd, "sub", &st, 0) == 0, "fstatat(realntfd, \"sub\", ...) succeeded");
	CHECK(S_ISDIR(st.st_mode), "fstatat() via a real dirfd reports S_ISDIR on the new subdirectory");
	CHECK((st.st_mode & 07777) == 0700, "fstatat() via a real dirfd reports the exact requested mode (0700)");
	syscall(SYS_close, rawfd, 0L, 0L, 0L, 0L, 0L); /* the raw fd, closed via the raw syscall directly --
	                     * `rawfd` is never an spicule fd-table index, so spicule's own close() (not even
	                     * linked into this test) would be the wrong call here. The __fds[] entry
	                     * installed above is simply abandoned, matching this pilot's fixture-teardown
	                     * style elsewhere. */

	/* ---- chmod()/fchmod()/stat()/fstat(): real file, real mode bits ---- */
	rawfd = syscall(SYS_openat, (long)AT_FDCWD_LX, (long)filepath, (long)(O_CREAT | O_WRONLY), 0600L);
	CHECK(rawfd >= 0, "raw openat(O_CREAT) building the file fixture succeeded");
	syscall(SYS_close, rawfd, 0L, 0L, 0L, 0L, 0L);

	CHECK(chmod(filepath, 0640) == 0, "chmod() on the real file succeeded");
	CHECK(stat(filepath, &st) == 0 && S_ISREG(st.st_mode), "stat() confirms the file is a regular file");
	CHECK((st.st_mode & 07777) == 0640, "stat() confirms chmod()'s exact mode bits (0640) took effect");

	rawfd = syscall(SYS_openat, (long)AT_FDCWD_LX, (long)filepath, (long)O_RDONLY, 0L);
	CHECK(rawfd >= 0, "raw openat() reopening the file for fchmod() succeeded");
	{
		int ntfd = install_real_fd((int)rawfd, __FD_FILE);
		CHECK(ntfd >= 0, "installing the real file fd succeeded");
		CHECK(fchmod(ntfd, 0600) == 0, "fchmod() on the real installed fd succeeded");
		memset(&st, 0, sizeof st);
		CHECK(fstat(ntfd, &st) == 0, "fstat() on the real installed fd succeeded");
		CHECK((st.st_mode & 07777) == 0600, "fstat() confirms fchmod()'s exact mode bits (0600) took effect");
	}
	syscall(SYS_close, rawfd, 0L, 0L, 0L, 0L, 0L);

	/* ---- utimensat(): explicit times, confirmed via a second stat() ---- */
	{
		struct timespec ts[2];
		ts[0].tv_sec = 1000000; ts[0].tv_nsec = 123000000;
		ts[1].tv_sec = 2000000; ts[1].tv_nsec = 456000000;
		CHECK(utimensat(AT_FDCWD, filepath, ts, 0) == 0, "utimensat() with explicit times succeeded");
		memset(&st, 0, sizeof st);
		CHECK(stat(filepath, &st) == 0, "stat() after utimensat() succeeded");
		CHECK(st.st_atim.tv_sec == 1000000 && st.st_atim.tv_nsec == 123000000,
		      "stat() confirms utimensat()'s exact atime took effect");
		CHECK(st.st_mtim.tv_sec == 2000000 && st.st_mtim.tv_nsec == 456000000,
		      "stat() confirms utimensat()'s exact mtime took effect");
	}

	/* ---- fchmodat(AT_SYMLINK_NOFOLLOW): the symlink itself, not its target ---- */
	CHECK(syscall(SYS_symlinkat, (long)filepath, (long)AT_FDCWD_LX, (long)linkpath) == 0,
	      "raw symlinkat() building the symlink fixture succeeded");
	{
		int r = fchmodat(AT_FDCWD, linkpath, 0642, AT_SYMLINK_NOFOLLOW);
		if (r == 0) {
			CHECK(lstat(linkpath, &st) == 0 && S_ISLNK(st.st_mode),
			      "lstat() confirms the fixture is still a symlink after fchmodat(AT_SYMLINK_NOFOLLOW)");
			CHECK((st.st_mode & 07777) == 0642,
			      "lstat() confirms fchmodat(AT_SYMLINK_NOFOLLOW) changed the SYMLINK's own mode (fchmodat2(2) path)");
			memset(&st, 0, sizeof st);
			CHECK(stat(filepath, &st) == 0 && (st.st_mode & 07777) == 0600,
			      "stat() (follows the link) confirms the TARGET's mode is untouched by fchmodat(AT_SYMLINK_NOFOLLOW)");
		} else {
			/* Older kernel, no fchmodat2(2): POSIX explicitly permits
			 * ENOTSUP here -- see src/stat/linux/plat_stat.c's own
			 * banner. Not a failure of this test. */
			CHECK(errno == ENOTSUP, "fchmodat(AT_SYMLINK_NOFOLLOW) without fchmodat2(2) reports ENOTSUP, not silently following the link");
		}
	}

	/* ---- statvfs()/fstatvfs(): real, nonzero block counts ---- */
	memset(&vfs, 0, sizeof vfs);
	CHECK(statvfs("/tmp", &vfs) == 0, "statvfs(\"/tmp\") succeeded");
	CHECK(vfs.f_bsize > 0, "statvfs() reports a nonzero f_bsize");
	CHECK(vfs.f_blocks > 0, "statvfs() reports a nonzero f_blocks (real block count, not NT's honest-zero inode case)");
	CHECK(vfs.f_namemax > 0, "statvfs() reports a nonzero f_namemax");

	/* O_RDONLY alone -- see the earlier openat() fixture's own comment
	 * on why spicule's own O_DIRECTORY is deliberately not used here. */
	rawfd = syscall(SYS_openat, (long)AT_FDCWD_LX, (long)("/tmp"), (long)O_RDONLY, 0L);
	CHECK(rawfd >= 0, "raw openat() of /tmp for fstatvfs() succeeded");
	{
		int ntfd = install_real_fd((int)rawfd, __FD_DIR);
		struct statvfs vfs2;
		memset(&vfs2, 0, sizeof vfs2);
		CHECK(fstatvfs(ntfd, &vfs2) == 0, "fstatvfs() on a real installed dirfd succeeded");
		CHECK(vfs2.f_blocks == vfs.f_blocks, "fstatvfs() and statvfs() agree on the same filesystem's block count");
	}
	syscall(SYS_close, rawfd, 0L, 0L, 0L, 0L, 0L);

	/* Teardown. */
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)linkpath, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)filepath, 0L);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)subpath, (long)AT_REMOVEDIR_LX);
	syscall(SYS_unlinkat, (long)AT_FDCWD_LX, (long)dirpath, (long)AT_REMOVEDIR_LX);

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
