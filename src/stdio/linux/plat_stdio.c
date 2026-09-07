/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_stdio.h -- see that header
 * for the contract __plat_rename() makes, and src/mman/linux/
 * plat_mem.c's banner for the general discipline this file follows
 * (raw syscall(2) via a local `svc #0` trampoline -- NOT `extern long
 * syscall(long, ...)`, which resolves to the host's real glibc at link
 * time in a non-freestanding build and silently discards the real
 * -errno on failure; see plat_mem.c's fix for the full account -- no
 * host libc, -nostdinc against spicule's own headers,
 * aarch64 syscall numbers confirmed against this host's own
 * <sys/syscall.h> as an oracle).
 *
 * This is dramatically simpler than the NT backend (src/stdio/nt/
 * plat_stdio.c): Linux's real renameat(2) already IS POSIX rename's
 * atomic-replace semantics natively, so the NT backend's entire
 * multi-step dance -- resolving both paths, opening `old` to query its
 * attribute-tag type, probing whether `new` exists and what type it
 * is, checking directory-vs-non-directory BEFORE attempting the rename
 * (because NT's own FILE_RENAME_INFORMATION does not enforce POSIX's
 * "neither file is changed on a type-mismatch failure" rule and would
 * silently destroy the victim first), and disambiguating
 * STATUS_ACCESS_DENIED into ENOTEMPTY/EISDIR by the types learned
 * beforehand -- collapses to one syscall here. The kernel already
 * refuses a directory-over-non-directory (or vice versa) rename
 * atomically with the correct errno (ENOTDIR/EISDIR/ENOTEMPTY) BEFORE
 * touching either file, and already refuses renaming a directory into
 * its own descendant (EINVAL) -- src/stdio/nt/plat_stdio.c's own
 * ntpath_is_ancestor() has no portable form worth writing because
 * Linux needs no equivalent check at all.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <errno.h>
#include "libc.h"
#include "plat_stdio.h"

/* Linux syscall number (aarch64 confirmed against this host's own
 * <sys/syscall.h> via a throwaway oracle program, not assumed -- see
 * plat_mem.c's banner for why this file cannot include that header
 * itself; x86_64/i386 confirmed against this host's own /nix/store
 * linux-headers asm/unistd_64.h / asm/unistd_32.h). aarch64 has no
 * plain SYS_rename (the "generic modern ABI" ports dropped every
 * legacy non-*at() syscall) -- only *at() forms exist, which is
 * exactly the shape src/stdio/misc.c's renameat() front door already
 * calls this interface with. x86_64/i386 both still carry a legacy
 * plain SYS_rename, but this file uses SYS_renameat on every arch
 * regardless, matching the *at()-shaped call site uniformly rather
 * than special-casing two of the three arches. */
#if defined(__aarch64__)
#define SYS_renameat 38
#elif defined(__x86_64__)
#define SYS_renameat 264
#elif defined(__i386__)
#define SYS_renameat 302
#else
#error "plat_stdio.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A minimal 6-argument raw syscall: no host libc in the call path at
 * all. Three per-arch bodies, same "own syscall table per file"
 * discipline this tree already uses (see src/dirent/linux/
 * plat_dirent.c's own raw_syscall()): aarch64's `svc #0`, x86_64's
 * `syscall`, i386's register-starved `int $0x80`. */
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
#error "plat_stdio.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* Matches src/unistd/linux/plat_unistd.c's/src/fcntl/linux/
 * plat_fcntl.c's own resolve_dirfd() exactly, duplicated here per this
 * tree's own-syscall-table-per-file discipline: turns spicule's own
 * AT_FDCWD sentinel or fd-table index into what the raw *at() syscalls
 * need. Returns -1 with errno already set (by __fd_get()) only on a
 * bad table index -- never a legitimate result otherwise, since
 * AT_FDCWD is -100 and every unboxed real fd is >= 0. */
static int resolve_dirfd(int dirfd)
{
	struct __fd *f;
	if (dirfd == AT_FDCWD) return AT_FDCWD;
	f = __fd_get(dirfd);
	if (!f) return -1;
	return unbox(f->h);
}

int __plat_rename(int olddirfd, const char *old, int newdirfd, const char *new)
{
	int rold, rnew;
	long ret;

	rold = resolve_dirfd(olddirfd);
	if (rold == -1 && olddirfd != AT_FDCWD) return -1; /* errno already set */
	rnew = resolve_dirfd(newdirfd);
	if (rnew == -1 && newdirfd != AT_FDCWD) return -1;

	ret = raw_syscall(SYS_renameat, (long)rold, (long)old, (long)rnew, (long)new, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

// NOLINTEND(misc-include-cleaner)
