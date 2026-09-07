/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * brk()/sbrk() for native Linux: a real program-break, via the real
 * brk(2) syscall. NT has no primitive shaped like brk() at all, so that
 * reasoning stays NT-only; Linux gets real code.
 *
 * Genuinely independent of spicule's own malloc(): src/malloc/linux/
 * plat_malloc.c's __plat_alloc() is built entirely on raw mmap(2)/
 * munmap(2) and never touches the traditional data-segment break, so a
 * caller using brk()/sbrk() directly cannot corrupt, or be corrupted by,
 * this library's own malloc().
 *
 * Linux's raw brk(2) syscall does not use the usual [-4095,-1] "-errno"
 * failure convention every other syscall wrapper in this tree checks with
 * is_sys_error(): it always returns the resulting break address, moved or
 * not, so uniquely among this tree's Linux backends this file has no
 * is_sys_error() at all.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include "unsafe_pointer.h"

/* Linux syscall number -- aarch64 confirmed against this host's own
 * <asm-generic/unistd.h>; x86_64/i386 confirmed against this host's own
 * /nix/store linux-headers asm/unistd_64.h / asm/unistd_32.h, not
 * assumed. */
#if defined(__aarch64__)
#define SYS_brk 214
#elif defined(__x86_64__)
#define SYS_brk 12
#elif defined(__i386__)
#define SYS_brk 45
#else
#error "plat_brk.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A minimal 6-argument raw syscall -- see src/mman/linux/plat_mem.c's
 * banner; this file only ever needs one argument but keeps the same
 * six-slot shape every other Linux backend uses. Three per-arch
 * bodies, same "own syscall table per file" discipline this tree
 * already uses (see src/dirent/linux/plat_dirent.c's own
 * raw_syscall()). */
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
#error "plat_brk.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static void *raw_brk(void *addr)
{
	/* brk(2) returns the (possibly unchanged) break address in a
	 * signed machine-word syscall register; converting that ABI word
	 * to a pointer is the operation this function exists to perform. */
	return unsafe_assume_valid_pointer(
	    (void *)raw_syscall(SYS_brk, (long)addr, 0L, 0L, 0L, 0L, 0L));
}

/* The kernel's own idea of the break, queried once via brk(0) -- a pure
 * query on this syscall's own contract, since passing an address at or
 * below the current break (which 0 always is, on a real Linux process)
 * never moves anything -- and cached afterward, exactly the way
 * glibc's __curbrk and musl's equivalent single-threaded cache both
 * work. */
static void *cur_brk;
static int have_brk;

static void init_brk(void)
{
	if (!have_brk) {
		cur_brk = raw_brk(0);
		have_brk = 1;
	}
}

int brk(void *addr)
{
	void *nb;
	init_brk();
	nb = raw_brk(addr);
	cur_brk = nb;
	/* brk(2)'s own contract: returns the new break on success, the
	 * unchanged (old) break on failure -- "did it actually reach (at
	 * least) where we asked" is the only failure signal there is. */
	if ((uintptr_t)nb < (uintptr_t)addr) { errno = ENOMEM; return -1; }
	return 0;
}

void *sbrk(intptr_t increment)
{
	char *oldbrk;
	uintptr_t base;
	init_brk();
	if (increment == 0) return cur_brk;
	oldbrk = cur_brk;
	/* Same direction-aware overflow check glibc's own sbrk() uses, but
	 * done in uintptr_t rather than on the pointers directly: comparing
	 * pointers formed by an out-of-bounds addition is undefined
	 * behaviour (C99 6.5.6p8), and an optimizer is entitled to assume
	 * that overflow never happens and delete the check. Casting a
	 * signed increment to uintptr_t wraps modulo 2^N (C99 6.3.1.3p2),
	 * matching the pointer arithmetic bit-for-bit while staying inside
	 * defined behaviour throughout. */
	base = (uintptr_t)oldbrk;
	if (increment > 0) {
		if (base + (uintptr_t)increment < base) { errno = ENOMEM; return (void *)-1; }
	} else {
		if (base + (uintptr_t)increment > base) { errno = ENOMEM; return (void *)-1; }
	}
	if (brk(oldbrk + increment) < 0) return (void *)-1;
	return oldbrk;
}

// NOLINTEND(misc-include-cleaner)
