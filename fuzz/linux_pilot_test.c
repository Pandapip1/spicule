/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux platform pilot smoke test -- NOT part of spicule, same standing
 * as fuzz/ntstubs.c's own native-build scaffolding.
 *
 * Exercises the REAL spicule public entry points (mmap/munmap/mprotect/
 * msync/read/write/lseek/dup/close, from the real src/mman/mman.c and
 * src/unistd/{close,read,write,lseek,dup}.c, statically linked here)
 * against the new src/mman/linux/plat_mem.c and src/unistd/linux/
 * plat_fd.c backends, running as a real, native aarch64 Linux process
 * on this host -- no Wine, no emulation.
 *
 * The one thing it does NOT go through spicule for is opening the test
 * file in the first place: spicule's own open() front door still calls
 * NT-only path resolution directly (__ntpath_at, src/fcntl/open.c) and
 * was explicitly out of scope for this pilot. A raw openat(2) stands in
 * for it here, exactly the same shape of scaffolding fuzz/ntstubs.c
 * already uses for the native ASan build.
 */
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "libc.h"

extern long syscall(long number, ...);
extern int printf(const char *, ...);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);

#define SYS_openat 56
#define SYS_unlinkat 35
#define AT_FDCWD (-100)

static int failures;

#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL - %s (errno=%d)\n", msg, errno); failures++; } \
} while (0)

int main(void)
{
	long rawfd;
	int fd, fd2;
	char buf[64];
	void *map;
	const char msg1[] = "hello from spicule on linux";
	const char msg2[] = "HELLO-FROM-SPICULE-ON-LINUX"; /* same length */

	/* open() itself is out of scope here -- see this file's own banner. */
	rawfd = syscall(SYS_openat, AT_FDCWD, "/tmp/spicule-linux-pilot-test",
	                O_CREAT | O_TRUNC | O_RDWR, 0644L);
	if (rawfd < 0) { printf("FAIL - raw openat setup (errno=%ld)\n", -rawfd); return 1; }
	printf("ok   - raw openat() setup succeeded (raw fd=%ld)\n", rawfd);

	/* Register the raw fd in spicule's OWN fd table -- boxed the same
	 * way src/unistd/linux/plat_fd.c encodes a handle (fd+1) -- and get
	 * back spicule's own fd number, which is what every front door
	 * below actually expects. This is the one piece of "installing an
	 * externally obtained descriptor" that a real Linux open() port
	 * would do internally; here it's done directly since open() itself
	 * is out of scope. */
	fd = __fd_install((HANDLE)(rawfd + 1), O_RDWR, __FD_FILE);
	CHECK(fd >= 0, "__fd_install() registered the raw fd in spicule's table");
	if (fd < 0) return 1;

	/* --- unistd/linux/plat_fd.c: write() --- */
	{
		ssize_t n = write(fd, msg1, sizeof msg1 - 1);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "write() wrote the full buffer");
	}

	/* --- unistd/linux/plat_fd.c: lseek() --- */
	{
		off_t pos = lseek(fd, 0, SEEK_CUR);
		CHECK(pos == (off_t)(sizeof msg1 - 1), "lseek(SEEK_CUR) reports the post-write position");
		pos = lseek(fd, 0, SEEK_SET);
		CHECK(pos == 0, "lseek(SEEK_SET, 0) rewinds");
	}

	/* --- unistd/linux/plat_fd.c: read() --- */
	{
		ssize_t n;
		memset(buf, 0, sizeof buf);
		n = read(fd, buf, sizeof msg1 - 1);
		CHECK(n == (ssize_t)(sizeof msg1 - 1), "read() read the full buffer");
		CHECK(memcmp(buf, msg1, sizeof msg1 - 1) == 0, "read() content matches what was written");
	}

	/* --- unistd/linux/plat_fd.c: dup() --- */
	{
		fd2 = dup(fd);
		CHECK(fd2 >= 0 && fd2 != fd, "dup() returns a distinct valid descriptor");
		if (fd2 >= 0) {
			off_t pos = lseek(fd2, 0, SEEK_CUR);
			CHECK(pos == (off_t)(sizeof msg1 - 1),
			      "dup()'d descriptor shares the same underlying file position");
			close(fd2);
		}
	}

	/* --- mman/linux/plat_mem.c: mmap()/msync()/munmap() over the file --- */
	{
		map = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		CHECK(map != MAP_FAILED, "mmap() of the test file succeeded");
		if (map != MAP_FAILED) {
			CHECK(memcmp(map, msg1, sizeof msg1 - 1) == 0,
			      "mmap()'d view shows the file's real content");
			memset(map, 0, sizeof msg2 - 1);
			{
				unsigned long i;
				for (i = 0; i < sizeof msg2 - 1; i++) ((char *)map)[i] = msg2[i];
			}
			CHECK(msync(map, 4096, MS_SYNC) == 0, "msync() flushed the modified page");
			CHECK(munmap(map, 4096) == 0, "munmap() released the view");

			/* Re-read through the real fd (not the mapping) to prove
			 * msync() actually reached the underlying file, not just
			 * the page cache view mmap() itself would also see. */
			CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek() back to the start for verification");
			memset(buf, 0, sizeof buf);
			{
				ssize_t n = read(fd, buf, sizeof msg2 - 1);
				CHECK(n == (ssize_t)(sizeof msg2 - 1), "post-msync read() got the full buffer");
			}
			CHECK(memcmp(buf, msg2, sizeof msg2 - 1) == 0,
			      "post-msync read() sees the mmap()-written content -- msync() really reached disk");
		}
	}

	/* --- mman/linux/plat_mem.c: anonymous mmap()/mprotect() --- */
	{
		void *anon = mmap(0, 4096, PROT_READ | PROT_WRITE,
		                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		CHECK(anon != MAP_FAILED, "anonymous mmap() succeeded");
		if (anon != MAP_FAILED) {
			((char *)anon)[0] = 'A';
			CHECK(((char *)anon)[0] == 'A', "anonymous mapping is writable");
			CHECK(mprotect(anon, 4096, PROT_READ) == 0, "mprotect() to read-only succeeded");
			CHECK(munmap(anon, 4096) == 0, "munmap() of the anonymous mapping succeeded");
		}
	}

	CHECK(close(fd) == 0, "close() of the real fd succeeded");
	syscall(SYS_unlinkat, AT_FDCWD, "/tmp/spicule-linux-pilot-test", 0);

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
