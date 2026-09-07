/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Real Linux backends for the four res*id() calls and euidaccess()/
 * eaccess(), marked "undefined-ok" for NT specifically: NT's single-
 * fixed-identity model has no ruid/euid/suid triple to report and no
 * effective-vs-real access-check distinction. Linux has both for real
 * (setresuid(2)/getresuid(2)/setresgid(2)/getresgid(2), faccessat2(2)'s
 * AT_EACCESS), so this backend implements them.
 *
 * getresuid()/getresgid() ask the kernel directly rather than going
 * through src/unistd/ids.c's own cached getuid()/getgid(), which would
 * give a stale or synthetic answer for the real triple. setresuid()/
 * setresgid() call __ids_creds_cache_invalidate() (src/unistd/ids.c) on
 * success, since they can move this process's real uid/gid out from
 * under that cache.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "libc.h"

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * <asm-generic/unistd.h>; x86_64/i386 confirmed against this host's own
 * /nix/store linux-headers asm/unistd_64.h / asm/unistd_32.h (see
 * plat_mem.c's banner for why these are hardcoded rather than pulled
 * from a host header at build time). faccessat2 is 439 on all three --
 * a post-pidfd_open addition sharing the same cross-arch numbering
 * scheme plat_misc.c's own banner documents for pidfd_open/
 * pidfd_send_signal. setresuid/getresuid/setresgid/getresgid have no
 * i386 16-bit-vs-*32 split the way getuid/setuid etc. do: they were
 * introduced with 32-bit uid_t support already in place, so there is
 * only ever one number per call on every arch. */
#if defined(__aarch64__)
#define SYS_setresuid   147
#define SYS_getresuid   148
#define SYS_setresgid   149
#define SYS_getresgid   150
#define SYS_faccessat2  439
#elif defined(__x86_64__)
#define SYS_setresuid   117
#define SYS_getresuid   118
#define SYS_setresgid   119
#define SYS_getresgid   120
#define SYS_faccessat2  439
#elif defined(__i386__)
#define SYS_setresuid   164
#define SYS_getresuid   165
#define SYS_setresgid   170
#define SYS_getresgid   171
#define SYS_faccessat2  439
#else
#error "plat_ids.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

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
#error "plat_ids.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long ret = raw_syscall(SYS_setresuid, (long)ruid, (long)euid, (long)suid, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	__ids_creds_cache_invalidate();
	return 0;
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long ret = raw_syscall(SYS_setresgid, (long)rgid, (long)egid, (long)sgid, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	__ids_creds_cache_invalidate();
	return 0;
}

/* ruid/euid/suid required: the kernel writes directly through all three
 * pointers on the success path with no NULL check of its own -- a NULL
 * argument here would be handed straight to the kernel as the
 * destination of a real write, faulting inside the syscall itself. Every
 * real call site in this tree (test/posix-unistd-ids.c) passes the
 * address of a real local, never NULL. */
int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	long ret = raw_syscall(SYS_getresuid, (long)ruid, (long)euid, (long)suid, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* rgid/egid/sgid required: same reasoning as getresuid() above. */
int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	long ret = raw_syscall(SYS_getresgid, (long)rgid, (long)egid, (long)sgid, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* euidaccess()/eaccess(): faccessat2(2) with AT_EACCESS asks the kernel to
 * run its real permission check against the caller's EFFECTIVE ids, more
 * correct than access.c's simplified owner-blind rwx-bit test.
 *
 * ENOSYS is real and reachable here: faccessat2(2) is a Linux 5.8+
 * addition, so a pre-5.8 kernel refuses the syscall outright. The
 * fallback reimplements the same decision by hand against geteuid()/
 * getegid(), not getuid()/getgid() -- the entire point of the "e". */
static int manual_eaccess(const char *path, int mode)
{
	struct stat st;
	uid_t eu;
	gid_t eg;
	mode_t bits;

	if (stat(path, &st) < 0) return -1;
	eu = geteuid();
	if (eu == 0) {
		/* root: X_OK still needs at least one real execute bit set
		 * (the one exception access(2)'s own semantics carve out for
		 * root); R_OK/W_OK are unconditional. */
		if ((mode & X_OK) && !(st.st_mode & 0111)) { errno = EACCES; return -1; }
		return 0;
	}
	eg = getegid();
	if (st.st_uid == eu) bits = (mode_t)((st.st_mode >> 6) & 7);
	else if (st.st_gid == eg) bits = (mode_t)((st.st_mode >> 3) & 7);
	else bits = (mode_t)(st.st_mode & 7);
	if ((mode & R_OK) && !(bits & 4)) { errno = EACCES; return -1; }
	if ((mode & W_OK) && !(bits & 2)) { errno = EACCES; return -1; }
	if ((mode & X_OK) && !(bits & 1)) { errno = EACCES; return -1; }
	return 0;
}

int euidaccess(const char *path, int mode)
{
	long ret = raw_syscall(SYS_faccessat2, (long)AT_FDCWD, (long)path, (long)mode, (long)AT_EACCESS, 0L, 0L);
	if (!is_sys_error(ret)) return 0;
	if ((int)-ret != ENOSYS) { errno = (int)-ret; return -1; }
	return manual_eaccess(path, mode);
}

int eaccess(const char *path, int mode) { return euidaccess(path, mode); }

// NOLINTEND(misc-include-cleaner)
