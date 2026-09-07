/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_dirent.h -- see that header,
 * and src/mman/linux/plat_mem.c's own banner for the raw-syscall
 * discipline this file follows. Supports aarch64, x86_64 and i386 --
 * see the SYS_getdents64/SYS_lseek #if block below for the real,
 * genuinely-different-per-arch numbers.
 *
 * src/dirent/readdir.c's __dirstream_next() and src/dirent/getdents.c's
 * getdents() decode through the backend-neutral __plat_dir_decode_one()
 * rather than hardcoding NT's FILE_ID_BOTH_DIR_INFORMATION, so this
 * backend just needs its own real getdents64(2) plus a decoder for
 * linux_dirent64.
 *
 * linux_dirent64's exact layout (d_ino: u64 @0, d_off: u64 @8, d_reclen:
 * u16 @16, d_type: u8 @18, d_name[]: NUL-terminated @19, chained by
 * d_reclen rather than a NextEntryOffset field) was confirmed against
 * this host with a throwaway oracle program that called the real
 * getdents64(2) syscall and walked the returned bytes, cross-checked
 * against glibc's own <dirent.h> struct dirent64 offsets.
 *
 * d_type's values need NO translation table, unlike NT's FileAttributes:
 * the real kernel's d_type field already uses the exact same numeric
 * convention as dirent.h's own DT_* constants. A directory entry on a
 * filesystem that does not report d_type natively (some network/FUSE
 * filesystems) comes back as DT_UNKNOWN (0) from the kernel itself,
 * passed through unchanged, matching glibc's own readdir() behavior.
 *
 * rewinddir()'s effect (`restart`) has no getdents64(2)-level flag the
 * way NT's RestartScan is a direct argument: Linux directory fds instead
 * expose the same lseek(2) interface a regular file fd does, and
 * lseek(fd, 0, SEEK_SET) is the documented way to rewind a directory
 * stream. One extra syscall versus NT's single combined call, only paid
 * when `restart` is set.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <stddef.h> /* offsetof() -- this file's own __lx_dirent64 _Static_assert below */
#include <string.h>
#include "plat_dirent.h"
#include "ownership_stubs.h"

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * asm-generic/unistd.h; x86_64/i386 confirmed against a real
 * x86_64-linux-gnu glibc's own asm/unistd_64.h/unistd_32.h, two
 * genuinely different tables from aarch64's (and each other), not a
 * fixed offset. i386 has a real, direct getdents64(2) at 220 in this
 * kernel ABI generation -- no legacy getdents(2) fallback needed. */
#if defined(__aarch64__)
#define SYS_getdents64 61
#define SYS_lseek      62
#elif defined(__x86_64__)
#define SYS_getdents64 217
#define SYS_lseek        8
#elif defined(__i386__)
#define SYS_getdents64 220
#define SYS_lseek       19
#else
#error "plat_dirent.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A minimal 6-argument raw syscall: no host libc in the call path --
 * see src/mman/linux/plat_mem.c's banner for why `extern long
 * syscall(long, ...)` is wrong here. Three per-arch bodies, same
 * "own syscall table per file" discipline crt/linux/crt1.c and
 * src/fcntl/linux/plat_fcntl.c already use: aarch64's `svc #0`,
 * x86_64's `syscall`, i386's register-starved `int $0x80`. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
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
#elif defined(__x86_64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#else
#error "plat_dirent.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

ssize_t __plat_dir_read(__plat_handle_t h, void *buf, size_t bufsize, int restart) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; parameter names distinguish roles
{
	int fd = unbox(h);
	long ret;

	if (restart) {
		/* See this file's own banner: lseek(fd, 0, SEEK_SET) is the
		 * real Linux idiom for rewinding a directory stream, there
		 * being no per-call restart flag on getdents64(2) itself. */
		ret = raw_syscall(SYS_lseek, (long)fd, 0L, 0L /* SEEK_SET */, 0L, 0L, 0L);
		if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	}

	ret = raw_syscall(SYS_getdents64, (long)fd, (long)buf, (long)bufsize, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return (ssize_t)ret; /* 0 at end-of-directory already matches
	                      * getdents64(2)'s own convention, unlike NT's
	                      * __plat_dir_read(). */
}

/* The kernel's raw linux_dirent64 -- confirmed field-for-field against
 * this host, see this file's own banner. Declared with a flexible array
 * member (d_name[]) rather than a fixed-size buffer: the compiler's own
 * natural (unpacked) layout for u64/u64/u16/u8/char[] already puts
 * d_name at offset 19 with no padding, matching the real kernel layout
 * exactly, so no explicit packing pragma is needed either.
 *
 * UNLIKE struct stat or struct sigaction elsewhere in this porting
 * series (see src/process/linux/plat_process.c's/src/signal/linux/
 * plat_signal.c's own banners for those two real per-arch layout
 * fights), linux_dirent64 does NOT need a per-arch variant here: the
 * kernel's own fs/readdir.c defines this struct once, shared verbatim
 * by every architecture's getdents64(2) -- not a per-arch uapi/asm/
 * header the way struct stat is. Confirmed by a second, independent
 * real source beyond this file's own single-host oracle: this repo's
 * own third_party/ltp/testcases/kernel/syscalls/getdents/getdents.h
 * (upstream Linux Test Project, itself built and run across many real
 * architectures) declares the identical struct linux_dirent64 -- u64
 * d_ino, s64 d_off, unsigned short d_reclen, unsigned char d_type,
 * char d_name[] -- with no #ifdef per architecture at all. All three
 * of this field set's offsets (0/8/16/18/19) already fall on the
 * natural alignment for every member on every one of aarch64/x86_64/
 * i386 (nothing here needs 8-byte alignment past offset 8), so no
 * arch introduces a padding gap the other two lack either. */
struct __lx_dirent64 { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};
/* This struct's one real ABI-critical invariant, sanity-checked at
 * compile time rather than trusted by inspection alone -- see
 * src/process/linux/plat_process.c's own raw_stat_prefix _Static_assert
 * for the identical discipline (turning silent compiler-padding
 * surprises into a build failure instead of a decode bug): d_name must
 * land at real kernel offset 19 on whichever of the three architectures
 * above this file is compiled for. */
_Static_assert(offsetof(struct __lx_dirent64, d_name) == 19,
               "linux_dirent64 layout mismatch for this architecture");

int __plat_dir_decode_one(const void *buf, size_t buflen, size_t *pos, struct __dirent_raw *out)
{
	const struct __lx_dirent64 *d;
	size_t namecap = sizeof out->name - 1;
	size_t i;

	if (*pos >= buflen) return 0;
	/* `*pos < buflen` above proves this offset is within buf's own real,
	 * getdents64(2)-filled extent. */
	d = (const struct __lx_dirent64 *)((const unsigned char *)buf + *pos);

	/* Zeroed up front so every byte of `out`, including name[] past the
	 * NUL terminator written below, is well-defined: the caller memcpy()s
	 * this whole struct. */
	memset(out, 0, sizeof *out);

	out->ino = (ino_t)d->d_ino;
	out->type = d->d_type; /* already the same DT_* numeric convention as
	                        * dirent.h's own constants; see this file's banner. */

	/* d_name is already NUL-terminated by the kernel, but this is
	 * untrusted kernel-filled memory with no independent length bound
	 * beyond d_reclen itself, so it is copied by hand rather than trusted
	 * to a bare strcpy. */
	for (i = 0; i < namecap && d->d_name[i]; i++)
		out->name[i] = d->d_name[i];
	out->name[i] = 0;

	*pos += d->d_reclen;
	return 1;
}

// NOLINTEND(misc-include-cleaner)
