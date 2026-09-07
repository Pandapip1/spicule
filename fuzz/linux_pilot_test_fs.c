/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux filesystem-subsystem pilot smoke test -- NOT part of spicule,
 * same standing as fuzz/linux_pilot_test.c (the mman/unistd fd-ops
 * pilot's own test) and fuzz/ntstubs.c's native-build scaffolding.
 *
 * Exercises the REAL spicule public entry points fcntl()/posix_fallocate()
 * (src/fcntl/fcntl.c, fadvise.c), flock() (src/file/flock.c), ioctl()
 * (src/ioctl/ioctl.c), fchmod()/fstat() (src/stat/chmod.c, stat.c), and
 * fstatvfs()/futimens() (src/stat/statvfs.c, utimensat.c), statically
 * linked here, against the five new src/{dirent,fcntl,file,ioctl,stat}/
 * linux/plat_*.c backends -- running as a real, native aarch64 Linux
 * process on this host, no Wine, no emulation.
 *
 * As with the mman/unistd pilot, open() itself is out of scope (its own
 * front door still calls NT-only __ntpath_at() directly -- see
 * src/internal/plat_fcntl.h's own banner), so a raw openat(2) stands in
 * for it, exactly like fuzz/linux_pilot_test.c
 * already does, and the raw fd is registered into spicule's own fd table
 * via __fd_install() the identical way.
 *
 * __plat_dir_read()/__plat_dir_decode_one() (src/dirent/linux/
 * plat_dirent.c) are not exercised here at all: they are real, but this
 * pilot's own fixed fd table (see fuzz/linux_pilot_harness_fs.c) never
 * installs a directory descriptor. See tools/linux-build-dirent.sh for
 * the dedicated pilot that exercises them, through the real
 * src/dirent/{opendir,readdir,getdents,closedir,rewinddir}.c front
 * doors.
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include "libc.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

#define SYS_openat     56
#define SYS_unlinkat   35
#define SYS_clone      220
#define SYS_wait4      260
#define SYS_exit       93
#define SYS_pipe2      59
#define SYS_fcntl_raw  25
#define SYS_flock_raw  32
#define AT_FDCWD_LX    (-100)
#define SIGCHLD_LX     17

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

static const char *TESTFILE = "/tmp/spicule-linux-pilot-test-fs";

/* fork()'s raw shape: clone(SIGCHLD, 0, 0, 0, 0) is the documented
 * "behaves like fork()" idiom on architectures (aarch64 included) that
 * have no dedicated fork(2) syscall number of their own. This relies
 * on fuzz/linux_pilot_harness_fs.c's own real syscall() trampoline
 * (raw aarch64 svc #0) rather than glibc's exported syscall() symbol --
 * see that file's own banner for why: glibc's syscall() translates the
 * raw kernel -errno convention into -1-with-errno-set, which silently
 * broke this file's original lock-conflict checks below (every
 * genuine EAGAIN/EACCES conflict was misreported as a constant, wrong
 * EPERM) until the harness's own trampoline replaced it. */
static long raw_fork(void)
{
	return syscall(SYS_clone, (long)SIGCHLD_LX, (long)0, (long)0, (long)0, (long)0);
}

int main(void)
{
	long rawfd;
	int fd;
	struct stat st;
	struct statvfs vfs;
	struct flock fl;

	rawfd = syscall(SYS_openat, AT_FDCWD_LX, TESTFILE, O_CREAT | O_TRUNC | O_RDWR, 0644L);
	if (rawfd < 0) { printf("FAIL - raw openat setup (errno=%ld)\n", -rawfd); return 1; }
	printf("ok   - raw openat() setup succeeded (raw fd=%ld)\n", rawfd);

	fd = __fd_install((HANDLE)(rawfd + 1), O_RDWR, __FD_FILE);
	CHECK(fd >= 0, "__fd_install() registered the raw fd in spicule's table");
	if (fd < 0) return 1;

	/* --- fcntl/linux/plat_fcntl.c: __plat_lock_probe/set/clear via
	 * the real fcntl(F_GETLK/F_SETLK/F_SETLKW) front door --- */
	{
		memset(&fl, 0, sizeof fl);
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 100;
		CHECK(fcntl(fd, F_GETLK, &fl) == 0, "F_GETLK probe call succeeded");
		CHECK(fl.l_type == F_UNLCK, "F_GETLK probe reports no conflict on an unlocked range");

		fl.l_type = F_WRLCK;
		CHECK(fcntl(fd, F_SETLK, &fl) == 0, "F_SETLK placed an exclusive lock on [0,100)");

		/* Prove the lock is REAL at the kernel level, not just a
		 * successful return code: fork a child that inherits the
		 * same fd (POSIX record locks are owned per-PROCESS, so the
		 * child, despite sharing the fd, is judged as a genuinely
		 * different lock owner) and have it attempt a conflicting
		 * F_SETLK non-blocking. It must observe EAGAIN/EACCES. */
		{
			long pid = raw_fork();
			if (pid == 0) {
				struct flock cfl;
				long r;
				memset(&cfl, 0, sizeof cfl);
				cfl.l_type = F_WRLCK;
				cfl.l_whence = SEEK_SET;
				cfl.l_start = 0;
				cfl.l_len = 100;
				r = syscall(SYS_fcntl_raw, (long)(rawfd), (long)F_SETLK, &cfl);
				syscall(SYS_exit, r < 0 ? (0 - r) : 100);
				return 0; /* unreached */
			}
			CHECK(pid > 0, "fork() for the lock-conflict child succeeded");
			if (pid > 0) {
				int status = 0;
				int code;
				syscall(SYS_wait4, pid, &status, (long)0, (long)0);
				code = (status >> 8) & 0xff;
				CHECK((status & 0x7f) == 0 && (code == 11 /* EAGAIN */ || code == 13 /* EACCES */),
				      "a second process really was refused the conflicting lock -- fcntl() locking is real, not a no-op");
			}
		}

		fl.l_type = F_UNLCK;
		CHECK(fcntl(fd, F_SETLK, &fl) == 0, "F_SETLK(F_UNLCK) cleared the lock");
	}

	/* --- fcntl/linux/plat_fcntl.c: __plat_volume_max_file_size/
	 * __plat_file_extent/__plat_fallocate via the real
	 * posix_fallocate() front door --- */
	{
		int r = posix_fallocate(fd, 0, 8192);
		CHECK(r == 0, "posix_fallocate() reserved 8192 bytes");
		CHECK(fstat(fd, &st) == 0, "fstat() after posix_fallocate() succeeded");
		CHECK(st.st_size >= 8192, "fstat() independently confirms the file really grew to >= 8192 bytes");
	}

	/* --- stat/linux/plat_stat.c: __plat_chmod via the real fchmod()
	 * front door, verified by an independent fstat() --- */
	{
		CHECK(fchmod(fd, 0640) == 0, "fchmod(0640) succeeded");
		CHECK(fstat(fd, &st) == 0, "fstat() after fchmod() succeeded");
		CHECK((st.st_mode & 0777) == 0640,
		      "fstat() independently confirms the permission bits fchmod() set");
		CHECK(S_ISREG(st.st_mode), "fstat() reports a regular file");
	}

	/* --- stat/linux/plat_stat.c: __plat_set_times via the real
	 * futimens() front door, verified by an independent fstat() --- */
	{
		struct timespec ts[2];
		ts[0].tv_sec = 1000000000; ts[0].tv_nsec = 0;   /* 2001-09-09 UTC */
		ts[1].tv_sec = 1234567890; ts[1].tv_nsec = 555000000;
		CHECK(futimens(fd, ts) == 0, "futimens() set explicit access/modification times");
		CHECK(fstat(fd, &st) == 0, "fstat() after futimens() succeeded");
		CHECK(st.st_atim.tv_sec == 1000000000,
		      "fstat() independently confirms the exact atime futimens() set");
		CHECK(st.st_mtim.tv_sec == 1234567890 && st.st_mtim.tv_nsec == 555000000,
		      "fstat() independently confirms the exact mtime (incl. nanoseconds) futimens() set");
	}

	/* --- stat/linux/plat_stat.c: __plat_statvfs via the real
	 * fstatvfs() front door --- */
	{
		CHECK(fstatvfs(fd, &vfs) == 0, "fstatvfs() succeeded");
		CHECK(vfs.f_bsize > 0, "fstatvfs() reports a real nonzero block size");
		CHECK(vfs.f_blocks > 0, "fstatvfs() reports a real nonzero total block count");
		CHECK(vfs.f_namemax > 0, "fstatvfs() reports a real nonzero max filename length");
	}

	/* --- ioctl/linux/plat_ioctl.c: __plat_file_eof_and_pos via the
	 * real ioctl(FIONREAD) front door, on the regular file --- */
	{
		int avail = -1;
		CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek() back to start for the FIONREAD check");
		CHECK(ioctl(fd, FIONREAD, &avail) == 0, "ioctl(FIONREAD) on a regular file succeeded");
		CHECK(avail == (int)st.st_size,
		      "ioctl(FIONREAD) independently agrees with fstat()'s st_size at position 0");
	}

	/* --- ioctl/linux/plat_ioctl.c: __plat_fionread_pipe via the real
	 * ioctl(FIONREAD) front door, on a real pipe --- */
	{
		int pv[2];
		long r = syscall(SYS_pipe2, pv, (long)0);
		CHECK(r == 0, "raw pipe2() setup succeeded");
		if (r == 0) {
			int rfd, wfd, avail = -1;
			const char msg[] = "pipedata";
			rfd = __fd_install((HANDLE)((long)pv[0] + 1), O_RDONLY, __FD_PIPE);
			wfd = __fd_install((HANDLE)((long)pv[1] + 1), O_WRONLY, __FD_PIPE);
			CHECK(rfd >= 0 && wfd >= 0, "__fd_install() registered both pipe ends");
			CHECK(write(wfd, msg, sizeof msg - 1) == (ssize_t)(sizeof msg - 1),
			      "write() into the pipe's write end succeeded");
			CHECK(ioctl(rfd, FIONREAD, &avail) == 0, "ioctl(FIONREAD) on a pipe succeeded");
			CHECK(avail == (int)(sizeof msg - 1),
			      "ioctl(FIONREAD) on the pipe reports exactly the bytes written and not yet read");
			close(rfd);
			close(wfd);
		}
	}

	/* --- file/linux/plat_flock.c: __plat_flock_lock/unlock via the
	 * real flock() front door --- */
	{
		CHECK(flock(fd, LOCK_EX) == 0, "flock(LOCK_EX) succeeded");

		/* Prove it is a real kernel-level whole-file lock: fork a
		 * child that opens an INDEPENDENT file description on the
		 * same path (flock()'s lock lives on the open file
		 * description, not the process, so a fresh open() is what
		 * makes this a genuine second claimant) and attempts
		 * flock(LOCK_EX|LOCK_NB) non-blocking while the parent still
		 * holds it. */
		{
			long pid = raw_fork();
			if (pid == 0) {
				long cfd = syscall(SYS_openat, AT_FDCWD_LX, TESTFILE, O_RDWR, (long)0);
				long r = -1;
				if (cfd >= 0) r = syscall(SYS_flock_raw, cfd, (long)(LOCK_EX | LOCK_NB));
				syscall(SYS_exit, cfd < 0 ? 200 : (r < 0 ? (0 - r) : 100));
				return 0; /* unreached */
			}
			CHECK(pid > 0, "fork() for the flock-conflict child succeeded");
			if (pid > 0) {
				int status = 0;
				int code;
				syscall(SYS_wait4, pid, &status, (long)0, (long)0);
				code = (status >> 8) & 0xff;
				printf("     (flock-conflict child raw status = 0x%x, low7 = %d, exit code = %d; 100 == unexpectedly succeeded, 200 == its own openat failed)\n", status, status & 0x7f, code);
				CHECK((status & 0x7f) == 0 && (code == 11 /* EWOULDBLOCK/EAGAIN */),
				      "a second, independently-opened process really was refused the conflicting flock() -- real, not a no-op");
			}
		}

		CHECK(flock(fd, LOCK_UN) == 0, "flock(LOCK_UN) released the lock");
	}

	CHECK(close(fd) == 0, "close() of the real fd succeeded");
	syscall(SYS_unlinkat, AT_FDCWD_LX, TESTFILE, (long)0);

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
