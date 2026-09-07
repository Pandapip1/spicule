/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux's half of src/internal/plat_malloc_generic.h's split: the one
 * thing this platform can supply that the generic allocator cannot --
 * raw, page-granular anonymous memory, via mmap(2)/munmap(2) directly
 * (never the host's syscall(2) wrapper; see src/mman/linux/plat_mem.c's
 * banner for why that collapses every failure's errno to the wrong
 * value). Everything else -- size classes, free lists, the allocation
 * algorithm itself -- lives in that header, written once so a future
 * platform in the same position (no serious heap manager of its own to
 * delegate to, the way src/malloc/nt/plat_malloc.c can) only needs to
 * supply this same small pair of functions, not rewrite the allocator.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "plat_pages.h"
#include "unsafe_pointer.h"

#if defined(__aarch64__)
#define SYS_mmap 222
#define SYS_munmap 215
#elif defined(__x86_64__)
#define SYS_mmap 9
#define SYS_munmap 11
#elif defined(__i386__)
#define SYS_mmap 192  /* mmap2 -- see crt/linux/crt1.c's own SYS_mmap banner */
#define SYS_munmap 91
#else
#error "plat_malloc.c: unsupported architecture"
#endif

#define PROT_READ_LX 0x1
#define PROT_WRITE_LX 0x2
#define MAP_PRIVATE_LX 0x02
#define MAP_ANONYMOUS_LX 0x20

/* Same raw syscall trampoline every Linux backend in this tree defines for
 * itself -- see src/mman/linux/plat_mem.c's banner for why this is never
 * `extern long syscall(long, ...)`. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc #0"
	                 : "+r"(x0)
	                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
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
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

withtok(platform_pages_allocated)
void *__plat_pages_alloc(size_t n)
{
	long ret = raw_syscall(SYS_mmap, 0, (long)n, PROT_READ_LX | PROT_WRITE_LX,
	                       MAP_PRIVATE_LX | MAP_ANONYMOUS_LX, -1L, 0L);
	if (is_sys_error(ret)) return 0;
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register. */
	return unsafe_assume_valid_pointer((void *)ret); /* MAP_ANONYMOUS is always zero-filled by the kernel */
}

void __plat_pages_free(void *p consume(platform_pages_allocated), size_t n)
{
	raw_syscall(SYS_munmap, (long)p, (long)n, 0, 0, 0, 0);
}

#include "plat_malloc_generic.h"

// NOLINTEND(misc-include-cleaner)
