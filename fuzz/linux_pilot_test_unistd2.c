/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux platform pilot smoke test, part two: "the rest of src/unistd" --
 * sleep, getpid, ftruncate, ids, link, fsync, pipe, sysconf, unlink,
 * chdir -- against src/unistd/linux/plat_unistd.c, the same standing as
 * fuzz/linux_pilot_test.c (the original mman/fd-ops pilot) has, exercised
 * the same way: a real, native aarch64 Linux ELF binary on this host, no
 * Wine, no emulation.
 *
 * Two different testing shapes are used below, and which one a given
 * function gets is itself part of what this pilot found:
 *
 *   Through the REAL front door, statically linked unmodified --
 *   src/unistd/{close,read,write,lseek,dup,fsync,pipe,ftruncate,
 *   sysconf,unlink,ids,chdir,link}.c -- for every plat_unistd.h function
 *   whose front door has no NT-only dependency beyond plat_unistd.h
 *   itself.  That turned out to be all but two of them: unlike
 *   src/fcntl/open.c's ORIGINAL shape, none of src/unistd/{unlink,ids,
 *   chdir,link}.c's front doors call __ntpath_at()/__vfs_resolve_at()
 *   themselves any more -- src/unistd/chdir.c's chdir() and
 *   src/unistd/link.c's readlinkat() used to call __vfs_resolve_at()
 *   (src/internal/vfs.c) directly, the same shape of gap open()'s own
 *   front door had, fixed the same way: that call moved behind
 *   __plat_chdir()/__plat_readlink() (src/internal/plat_unistd.h) and
 *   into the NT backend's own function bodies (src/unistd/nt/
 *   plat_unistd.c). This backend's __plat_chdir() below always reports
 *   __VFS_NONE (no overlay on this backend at all -- see
 *   src/unistd/linux/plat_unistd.c's own banner) and __plat_readlink()
 *   needs no vfs pre-check whatsoever, so both front doors now port
 *   directly. See src/unistd/linux/plat_unistd.c's own banner for the
 *   full argument.
 *
 *   Directly against __plat_* -- only for __plat_getppid() and the
 *   sleep.c clock/alarm pair, which have no plat_unistd.h front door to
 *   test through at all here: src/unistd/getpid.c's getpid()/gettid()
 *   read NT's TEB directly (__teb()->ClientId...), never going through
 *   this interface, so getppid()'s own front door cannot be linked into
 *   a freestanding Linux pilot -- the same shape of gap plat_fcntl.h's
 *   banner documents for open(), just landing on getpid()/gettid()
 *   themselves rather than any plat_unistd.h function.
 *
 * fuzz/linux_pilot_harness_unistd2.c supplies the fd table and a handful
 * of other internal helpers these front doors need but that are
 * deliberately not ported here; see its own banner for the full list and
 * why each one.
 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "libc.h"
#include "plat_unistd.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

#define SYS_openat   56
#define SYS_unlinkat 35
#define SYS_mkdirat  34
#define SYS_getppid  173
#define SYS_getcwd    17
#define SYS_close     57
#define SYS_getuid   174
#define SYS_chdir     49
#define AT_FDCWD_RAW (-100)

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

int main(void)
{
	int fd, r;
	char buf[256];

	/* ---- unistd/linux/plat_unistd.c: ftruncate() through the real front door --- */
	{
		long rawfd = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-file",
		                     O_CREAT | O_TRUNC | O_RDWR, 0644L);
		off_t pos;
		CHECK(rawfd >= 0, "raw openat() setup for ftruncate() test succeeded");
		fd = __fd_install((HANDLE)(rawfd + 1), O_RDWR, __FD_FILE);
		CHECK(fd >= 0, "__fd_install() registered the raw fd");

		r = ftruncate(fd, 12345);
		CHECK(r == 0, "ftruncate() grew the file");
		pos = lseek(fd, 0, SEEK_END);
		CHECK(pos == 12345, "lseek(SEEK_END) confirms the grown size");

		r = ftruncate(fd, 10);
		CHECK(r == 0, "ftruncate() shrank the file");
		pos = lseek(fd, 0, SEEK_END);
		CHECK(pos == 10, "lseek(SEEK_END) confirms the shrunk size");

		/* ---- fsync.c: through the real front door --- */
		r = write(fd, "0123456789", 10);
		CHECK(r == 10, "write() before fsync() succeeded");
		CHECK(fsync(fd) == 0, "fsync() on a real file succeeded");
		CHECK(fdatasync(fd) == 0, "fdatasync() on a real file succeeded");

		close(fd);
		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-file", 0);
	}

	/* ---- unistd/linux/plat_unistd.c: pipe()/pipe2() through the real front door, round-tripping real data through write()/read() --- */
	{
		int fds[2];
		ssize_t n;

		CHECK(pipe(fds) == 0, "pipe() created a read/write fd pair");
		n = write(fds[1], "hello-pipe", 10);
		CHECK(n == 10, "write() to the pipe's write end succeeded");
		memset(buf, 0, sizeof buf);
		n = read(fds[0], buf, 10);
		CHECK(n == 10, "read() from the pipe's read end got the full buffer");
		CHECK(memcmp(buf, "hello-pipe", 10) == 0, "pipe data round-tripped intact");
		close(fds[0]);
		close(fds[1]);

		CHECK(pipe2(fds, O_CLOEXEC) == 0, "pipe2(O_CLOEXEC) created a pair");
		close(fds[0]);
		close(fds[1]);
	}

	/* ---- unistd/linux/plat_unistd.c: unlink()/rmdir()/unlinkat() through the real front door --- */
	{
		long rawfd;
		long mk;

		rawfd = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-unlinkme",
		                O_CREAT | O_TRUNC | O_WRONLY, 0644L);
		CHECK(rawfd >= 0, "raw openat() setup for unlink() test succeeded");
		CHECK(unlink("/tmp/spicule-linux-pilot-unistd2-unlinkme") == 0,
		      "unlink() removed the real file");
		/* Confirm it is really gone: re-opening it without O_CREAT must fail. */
		rawfd = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-unlinkme", O_RDONLY);
		CHECK(rawfd < 0, "the unlinked file is really gone");

		mk = syscall(SYS_mkdirat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-dir", 0755L);
		CHECK(mk == 0, "raw mkdirat() setup for rmdir() test succeeded");
		CHECK(rmdir("/tmp/spicule-linux-pilot-unistd2-dir") == 0, "rmdir() removed the real directory");

		mk = syscall(SYS_mkdirat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-dir2", 0755L);
		CHECK(mk == 0, "raw mkdirat() setup for unlinkat(AT_REMOVEDIR) test succeeded");
		CHECK(unlinkat(AT_FDCWD, "/tmp/spicule-linux-pilot-unistd2-dir2", AT_REMOVEDIR) == 0,
		      "unlinkat(AT_REMOVEDIR) removed the real directory");

		/* fd-relative form: unlinkat() against an spicule fd-table dirfd,
		 * proving src/unistd/linux/plat_unistd.c's resolve_dirfd()
		 * really unboxes the fd table's handle rather than only ever
		 * being exercised with the AT_FDCWD sentinel. */
		mk = syscall(SYS_mkdirat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-reldir", 0755L);
		CHECK(mk == 0, "raw mkdirat() setup for fd-relative unlinkat() succeeded");
		{
			/* Deliberately NOT spicule's own O_DIRECTORY here: this is a
			 * raw syscall (like every other setup call in this file),
			 * and spicule's <fcntl.h> O_DIRECTORY (0200000) does not
			 * match the real Linux kernel ABI value (0040000, confirmed
			 * against this host's own <fcntl.h>) the way AT_FDCWD/
			 * O_CLOEXEC/AT_SYMLINK_* do -- plain O_RDONLY is enough to
			 * open a directory for this test's purposes. */
			long dfd = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-reldir",
			                   O_RDONLY);
			int ntdirfd;
			CHECK(dfd >= 0, "raw openat() of the directory for fd-relative unlinkat() succeeded");
			ntdirfd = __fd_install((HANDLE)(dfd + 1), O_RDONLY, __FD_DIR);
			CHECK(ntdirfd >= 0, "__fd_install() registered the directory fd");
			rawfd = syscall(SYS_openat, dfd, "victim", O_CREAT | O_TRUNC | O_WRONLY, 0644L);
			CHECK(rawfd >= 0, "raw openat() created a file inside the directory");
			syscall(SYS_close, rawfd);
			CHECK(unlinkat(ntdirfd, "victim", 0) == 0,
			      "fd-relative unlinkat() removed the file via the fd table's boxed dirfd handle");
			close(ntdirfd);
		}
		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-reldir", AT_REMOVEDIR);
	}

	/* ---- unistd/linux/plat_unistd.c: sysconf() through the real front door --- */
	{
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		long p = sysconf(_SC_PAGESIZE);
		long m = sysconf(_SC_PHYS_PAGES);
		CHECK(n >= 1, "sysconf(_SC_NPROCESSORS_ONLN) reports a plausible CPU count");
		CHECK(p == 4096, "sysconf(_SC_PAGESIZE) reports 4096");
		CHECK(m > 0, "sysconf(_SC_PHYS_PAGES) reports a plausible page count");
		printf("     (nprocessors=%ld phys_pages=%ld ~= %ldMB)\n", n, m, m / 256);
	}

	/* ---- unistd/linux/plat_unistd.c: getuid()/setuid()/pgrp/session/fchownat() through the real front door (src/unistd/ids.c) --- */
	{
		uid_t u = getuid();
		pid_t self, pg;
		CHECK(u == (uid_t)syscall(SYS_getuid), "getuid() matches a raw getuid(2) syscall");
		CHECK(geteuid() == u, "geteuid() agrees with getuid()");
		CHECK(setuid(u) == 0, "setuid() to the current uid succeeds (self-match branch)");
		CHECK(setuid(u ^ 1u) == -1 && errno == EPERM, "setuid() to a foreign uid is EPERM");

		self = getpid();
		pg = getpgrp();
		(void)pg;
		CHECK(setpgrp() == self, "setpgrp() makes this process its own group leader (real setpgid(0,0))");
		CHECK(getpgrp() == self, "getpgrp() now reports this process's own pid");
		CHECK(getpgid(0) == self, "getpgid(0) agrees");
		CHECK(getpgid(self) == self, "getpgid(self) sees the real kernel pgid via __plat_pgrp_is_leader()");

		r = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-chown", O_CREAT | O_TRUNC | O_WRONLY, 0644L);
		CHECK(r >= 0, "raw openat() setup for fchownat() probe succeeded");
		syscall(SYS_close, r);
		CHECK(chown("/tmp/spicule-linux-pilot-unistd2-chown", u, getgid()) == 0,
		      "chown() on an existing file succeeds (probe-only semantics)");
		CHECK(chown("/tmp/spicule-linux-pilot-unistd2-does-not-exist", u, getgid()) == -1 && errno == ENOENT,
		      "chown() on a missing file reports ENOENT via __plat_chown_probe()");
		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-chown", 0);
	}

	/* ---- unistd/linux/plat_unistd.c: __plat_getppid() directly (see this file's banner: getpid()/gettid() have no plat_unistd.h seam at all) --- */
	{
		pid_t pp = __plat_getppid();
		long raw = syscall(SYS_getppid);
		CHECK(pp == (pid_t)raw, "__plat_getppid() matches a raw getppid(2) syscall");
	}

	/* ---- unistd/linux/plat_unistd.c: __plat_time_now()/__plat_alarm_*() directly --- */
	{
		long long t1 = __plat_time_now();
		long long t2 = __plat_time_now();
		CHECK(t1 > 0 && t2 >= t1, "__plat_time_now() is positive and monotonic-ish across two calls");
		CHECK(__plat_alarm_arm(t1 + 10000000LL, 1, 0) == -1,
		      "__plat_alarm_arm() honestly reports 'could not arm' (SIGALRM/timer infra out of scope, see banner)");
		__plat_alarm_cancel();   /* must not crash with nothing armed */
		__plat_alarm_reset_after_fork(); /* must not crash either */
		printf("ok   - __plat_alarm_cancel()/__plat_alarm_reset_after_fork() are safe no-ops\n");
	}

	/* ---- unistd/chdir.c: chdir() through the REAL front door, now that it no longer calls __vfs_resolve_at() itself --- */
	{
		long mk = syscall(SYS_mkdirat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-cwd", 0755L);
		char cwdbuf[256];
		long n;
		CHECK(mk == 0, "raw mkdirat() setup for chdir() test succeeded");
		CHECK(chdir("/tmp/spicule-linux-pilot-unistd2-cwd") == 0, "chdir() succeeded through the real front door");
		memset(cwdbuf, 0, sizeof cwdbuf);
		n = syscall(SYS_getcwd, cwdbuf, sizeof cwdbuf);
		CHECK(n > 0 && !memcmp(cwdbuf, "/tmp/spicule-linux-pilot-unistd2-cwd", strlen("/tmp/spicule-linux-pilot-unistd2-cwd")),
		      "a raw getcwd(2) confirms the real process cwd actually moved");
		CHECK(chdir("/nonexistent-spicule-pilot-path") == -1 && errno == ENOENT,
		      "chdir() to a missing directory fails ENOENT");
		CHECK(chdir("") == -1 && errno == ENOENT,
		      "chdir(\"\") fails ENOENT via the front door's own NUL/empty-string check");
		syscall(SYS_chdir, "/tmp");
		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-cwd", AT_REMOVEDIR);
	}

	/* ---- unistd/link.c: link()/readlink()/symlink() through the REAL front doors, now that readlinkat() no longer calls __vfs_resolve_at() itself --- */
	{
		long rawfd = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-target",
		                     O_CREAT | O_TRUNC | O_WRONLY, 0644L);
		ssize_t n;
		CHECK(rawfd >= 0, "raw openat() setup for link()/symlink() test succeeded");
		syscall(SYS_close, rawfd);

		CHECK(link("/tmp/spicule-linux-pilot-unistd2-target",
		           "/tmp/spicule-linux-pilot-unistd2-hardlink") == 0,
		      "link() created a hard link through the real front door");
		{
			long f1 = syscall(SYS_openat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-hardlink", O_RDONLY);
			CHECK(f1 >= 0, "the hard link opens as a real file");
			if (f1 >= 0) syscall(SYS_close, f1);
		}

		CHECK(symlink("/tmp/spicule-linux-pilot-unistd2-target",
		              "/tmp/spicule-linux-pilot-unistd2-symlink") == 0,
		      "symlink() created a symbolic link through the real front door");
		memset(buf, 0, sizeof buf);
		n = readlink("/tmp/spicule-linux-pilot-unistd2-symlink", buf, sizeof buf);
		CHECK(n == (ssize_t)strlen("/tmp/spicule-linux-pilot-unistd2-target"), "readlink() reports the right length");
		CHECK(!memcmp(buf, "/tmp/spicule-linux-pilot-unistd2-target", (size_t)n),
		      "readlink() content matches the real symlink target");

		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-symlink", 0);
		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-hardlink", 0);
		syscall(SYS_unlinkat, AT_FDCWD_RAW, "/tmp/spicule-linux-pilot-unistd2-target", 0);
	}

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
