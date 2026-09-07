/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_mem.h -- the second real
 * backend behind the platform-abstraction seam the NT pilot introduced.
 *
 * Every call here is a single raw Linux syscall via `svc #0`, not any
 * host libc wrapper: this file is compiled under -nostdinc against
 * spicule's OWN generated headers, never glibc's, so both the syscall
 * numbers and the wrapper are declared locally below.
 *
 * NT's reserve/commit split and section-view-vs-anonymous-reservation
 * distinction do not exist on Linux: mmap()/munmap() are already
 * page-granular end to end, so __plat_mem_decommit()/_release()/
 * _unmap_view() are all the identical munmap() call. Likewise
 * __plat_mem_map_file() needs none of the NT backend's EOF-capture/
 * zero-fill-tail workaround (Linux's mmap already zero-fills the partial
 * page past a file's real end natively) or its read-only-section fallback
 * dance, and __plat_mem_flush_view() needs no separate timestamp fix-up
 * after msync() (Linux updates mtime as a normal side effect).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/mman.h>
#include <errno.h>
#include "plat_mem.h"
#include "unsafe_pointer.h"

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * <sys/syscall.h> rather than assumed; x86_64/i386 confirmed against
 * this host's own /nix/store linux-headers asm/unistd_64.h /
 * asm/unistd_32.h. This file's -nostdinc build cannot include the
 * host's own <sys/syscall.h> itself, since it would pull in glibc's
 * conflicting type system alongside spicule's own.
 *
 * i386 uses SYS_mmap2 (192), not the legacy SYS_mmap (90): that old
 * number is not a normal register-passing syscall at all -- it takes
 * ONE pointer argument to a struct {addr,len,prot,flags,fd,offset}
 * packed on the stack, incompatible with every other syscall's plain
 * register-argument convention this file (and every other raw_syscall()
 * in this tree) relies on. mmap2 is the real modern register-based
 * i386 entry point every real libc (glibc, musl) actually uses, with
 * one real ABI difference from mmap()/aarch64's SYS_mmap: its final
 * argument is the offset in fixed 4096-byte units, not bytes --
 * see mmap_off_arg() below, where that unit conversion happens. */
#if defined(__aarch64__)
#define SYS_mmap     222
#define SYS_munmap   215
#define SYS_mprotect 226
#define SYS_msync    227
#define SYS_mlock    228
#define SYS_munlock  229
#elif defined(__x86_64__)
#define SYS_mmap     9
#define SYS_munmap   11
#define SYS_mprotect 10
#define SYS_msync    26
#define SYS_mlock    149
#define SYS_munlock  150
#elif defined(__i386__)
#define SYS_mmap     192 /* really mmap2 -- see this block's own banner */
#define SYS_munmap   91
#define SYS_mprotect 125
#define SYS_msync    144
#define SYS_mlock    150
#define SYS_munlock  151
#else
#error "plat_mem.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A minimal 6-argument raw syscall: no host libc in the call path. NOT
 * `extern long syscall(long, ...)`: that symbol resolves to the HOST's
 * real glibc at link time, which sets glibc's OWN errno on failure
 * rather than the raw kernel -errno this file's translation requires.
 * Three per-arch bodies, same "own syscall table per file" discipline
 * this tree already uses (see src/dirent/linux/plat_dirent.c's own
 * raw_syscall()): aarch64's `svc #0`, x86_64's `syscall`, i386's
 * register-starved `int $0x80`. */
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
#error "plat_mem.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* mmap2(2)'s own offset unit on i386 is a fixed 4096 bytes (documented
 * in mmap2(2), NOT this build's/the target's actual page size --
 * though the two coincide on every arch this tree targets anyway),
 * matching src/mman/mman.c's own MMAP_PAGE=4096u front-door constant
 * exactly: mman.c's mmap() already refuses any `off` that is not a
 * multiple of MMAP_PAGE before __plat_mem_map_file() is ever called,
 * so the shift below never silently drops low bits. aarch64/x86_64's
 * plain mmap(2) instead wants a byte offset, unchanged. */
#if defined(__i386__)
static long mmap_off_arg(off_t off) { return (long)(off >> 12); }
#else
static long mmap_off_arg(off_t off) { return (long)off; }
#endif

/* A raw Linux syscall returns the result on success, or -errno (as an
 * unsigned value in [-4095, -1]) on failure -- the kernel's own ABI
 * convention on every architecture this targets. mmap()'s successful
 * return is a mapped address, which can itself be a huge unsigned
 * value without being an error; the [-4095,-1] window is what
 * distinguishes the two. */
static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

int __plat_mem_reserve(void **base_inout, size_t len, int prot)
{
	/* The PROT_ and MAP_ constants are spicule's own <sys/mman.h>
	 * values, unchanged: they already match the Linux kernel ABI
	 * exactly (confirmed by reading include/sys/mman.h), so unlike
	 * the NT backend's prot_to_page()/prot_to_view() this file needs no
	 * translation table anywhere. */
	/* Anonymous mapping: the offset argument is a fixed literal 0
	 * either way, so it needs no mmap_off_arg() unit conversion --
	 * 0 bytes and 0 pages are the same value. */
	long ret = raw_syscall(SYS_mmap, (long)*base_inout, (long)len, (long)prot,
	                       (long)(MAP_PRIVATE | MAP_ANONYMOUS), -1L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register. */
	*base_inout = unsafe_assume_valid_pointer((void *)ret);
	return 0;
}

int __plat_mem_commit_fixed(void *base, size_t len, int prot)
{
	/* A single MAP_FIXED anonymous mmap() over an address range this
	 * process already reserved atomically discards whatever was there
	 * and hands back fresh zero-filled pages -- mmap.html's MAP_FIXED
	 * "discarded" requirement in one syscall, where the NT backend
	 * needs an explicit decommit-then-commit pair (see its own
	 * comment) because a bare NT commit over already-committed pages
	 * would leave the old bytes in place. */
	long ret = raw_syscall(SYS_mmap, (long)base, (long)len, (long)prot,
	                       (long)(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED), -1L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_decommit(void *base, size_t len)
{
	long ret = raw_syscall(SYS_munmap, (long)base, (long)len, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_release(void *base, size_t len)
{
	long ret = raw_syscall(SYS_munmap, (long)base, (long)len, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_protect(void *addr, size_t len, int prot)
{
	long ret = raw_syscall(SYS_mprotect, (long)addr, (long)len, (long)prot, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_lock(void *addr, size_t len)
{
	long ret = raw_syscall(SYS_mlock, (long)addr, (long)len, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_unlock(void *addr, size_t len)
{
	long ret = raw_syscall(SYS_munlock, (long)addr, (long)len, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_map_file(__plat_handle_t fh, int prot, int flags, off_t off,
                        size_t viewbytes, void **base_inout)
{
	/* fh is this backend's own boxed fd (see src/unistd/linux/plat_fd.c's
	 * banner for the encoding); unbox it the same way that file does. */
	int fd = (int)((long)fh - 1);
	long ret = raw_syscall(SYS_mmap, (long)*base_inout, (long)viewbytes, (long)prot,
	                       (long)((flags & MAP_SHARED) ? MAP_SHARED : MAP_PRIVATE),
	                       (long)fd, mmap_off_arg(off));
	if (is_sys_error(ret)) {
		/* mmap.html has no broader vocabulary for a failed file-backed
		 * mapping than ENOMEM/ENOTSUP -- the same narrowing the NT
		 * backend does, for the same reason (see plat_mem.h). */
		errno = (-ret == ENOMEM) ? ENOMEM : ENOTSUP;
		return -1;
	}
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register. */
	*base_inout = unsafe_assume_valid_pointer((void *)ret);
	return 0;
}

int __plat_mem_unmap_view(void *base, size_t len)
{
	long ret = raw_syscall(SYS_munmap, (long)base, (long)len, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_mem_flush_view(void *addr, size_t len, __plat_handle_t writeback)
{
	long ret;
	(void)writeback; /* Linux's msync() needs no separate handle: it
	                  * operates purely on the mapped address range, and
	                  * already updates the file's mtime as a normal
	                  * side effect -- see this file's own banner. */
	ret = raw_syscall(SYS_msync, (long)addr, (long)len, (long)MS_SYNC, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

// NOLINTEND(misc-include-cleaner)
